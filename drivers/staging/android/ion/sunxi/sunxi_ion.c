/*
 * Allwinner SUNXI ION Driver
 *
 * Copyright (c) 2017 Allwinnertech.
 *
 * Author: fanqinghua <fanqinghua@allwinnertech.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define pr_fmt(fmt) "Ion: " fmt

#include <linux/err.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/of.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include "../ion_priv.h"
#include "../ion.h"
#include "../ion_of.h"
#include "sunxi_ion.h"

struct sunxi_ion_dev {
	struct ion_heap	**heaps;
	struct ion_device *idev;
	struct ion_platform_data *data;
};
struct device *g_ion_dev;
EXPORT_SYMBOL(g_ion_dev);

struct ion_device *idev;
/* export for IMG GPU(sgx544) */
EXPORT_SYMBOL(idev);

static struct ion_of_heap sunxi_heaps[] = {
	PLATFORM_HEAP("allwinner,sys_user", 0,
		      ION_HEAP_TYPE_SYSTEM, "sys_user"),
	PLATFORM_HEAP("allwinner,sys_contig", 1,
		      ION_HEAP_TYPE_SYSTEM_CONTIG, "sys_contig"),
	PLATFORM_HEAP("allwinner,carveout", 2,
		      ION_HEAP_TYPE_CARVEOUT, "carveout"),
	PLATFORM_HEAP("allwinner,cma", ION_HEAP_TYPE_DMA, ION_HEAP_TYPE_DMA,
		      "cma"),
	PLATFORM_HEAP("allwinner,secure", ION_HEAP_TYPE_SECURE,
		      ION_HEAP_TYPE_SECURE, "secure"),
	{}
};

static unsigned int  ion_sunxi_drm_phy_addr, ion_sunxi_drm_tee_addr;
void sunxi_ion_probe_drm_info(u32 *drm_phy_addr, u32 *drm_tee_addr)
{
	*drm_phy_addr = ion_sunxi_drm_phy_addr;
	*drm_tee_addr = ion_sunxi_drm_tee_addr;
}
EXPORT_SYMBOL(sunxi_ion_probe_drm_info);

struct device *get_ion_dev(void)
{
	return g_ion_dev;
}

long sunxi_ion_ioctl(struct ion_client *client, unsigned int cmd, unsigned long arg)
{
	long ret = 0;
	struct ion_handle *ion_handle_get_by_id(struct ion_client *client, int id);

	switch (cmd) {
	case ION_IOC_SUNXI_PHYS_ADDR:
	{
		sunxi_phys_data data;
		struct ion_handle *handle;
		if (copy_from_user(&data, (void __user *)arg,
			sizeof(sunxi_phys_data)))
			return -EFAULT;
		handle = ion_handle_get_by_id(client, data.handle);
		if (IS_ERR(handle))
			return PTR_ERR(handle);
		data.size = 0;
		ret = ion_phys(client, handle,
				(ion_phys_addr_t *)&data.phys_addr,
				(size_t *)&data.size);
		ion_handle_put(handle);
		if (ret)
			return -EINVAL;
		if (copy_to_user((void __user *)arg, &data, sizeof(data)))
			return -EFAULT;
		break;
	}
	case ION_IOC_SUNXI_TEE_ADDR:
	{
		sunxi_phys_data data;
		struct ion_handle *handle;

		if (copy_from_user(&data, (void __user *)arg,
				sizeof(sunxi_phys_data)))
			return -EFAULT;

		handle = ion_handle_get_by_id(client, data.handle);
		if (IS_ERR(handle))
			return PTR_ERR(handle);

		data.size = 0xffff;
		ret = ion_phys(client, handle,
				(ion_phys_addr_t *)&data.phys_addr,
				(size_t *)&data.size);
		ion_handle_put(handle);
		if (ret)
			return -EINVAL;

		if (copy_to_user((void __user *)arg, &data, sizeof(data)))
			return -EFAULT;
		break;
	}
	default:
		pr_err("%s(%d) err: cmd(%u) not support!\n", __func__, __LINE__, cmd);
		return -ENOTTY;
	}

	return ret;
}

static int sunxi_ion_probe(struct platform_device *pdev)
{
	struct sunxi_ion_dev *ipdev;
	int i;

	ipdev = devm_kzalloc(&pdev->dev, sizeof(*ipdev), GFP_KERNEL);
	if (!ipdev)
		return -ENOMEM;

	g_ion_dev = &pdev->dev;
	platform_set_drvdata(pdev, ipdev);

	ipdev->idev = ion_device_create(sunxi_ion_ioctl);
	if (IS_ERR(ipdev->idev))
		return PTR_ERR(ipdev->idev);

	idev = ipdev->idev;

	ipdev->data = ion_parse_dt(pdev, sunxi_heaps);
	if (IS_ERR(ipdev->data)) {
		pr_err("%s: ion_parse_dt error!\n", __func__);
		return PTR_ERR(ipdev->data);
	}

	ipdev->heaps = devm_kzalloc(&pdev->dev,
				sizeof(struct ion_heap) * ipdev->data->nr,
				GFP_KERNEL);
	if (!ipdev->heaps) {
		ion_destroy_platform_data(ipdev->data);
		return -ENOMEM;
	}

	for (i = 0; i < ipdev->data->nr; i++) {
#ifdef CONFIG_TEE
		if (ipdev->data->heaps[i].type == ION_HEAP_TYPE_SECURE) {
			long tee_base;

			optee_probe_drm_configure(&ipdev->data->heaps[i].base,
						&ipdev->data->heaps[i].size, &tee_base);
			ion_sunxi_drm_phy_addr = ipdev->data->heaps[i].base;
			ion_sunxi_drm_tee_addr = tee_base;
		}
#endif

		ipdev->heaps[i] = ion_heap_create(&ipdev->data->heaps[i]);
		if (!ipdev->heaps) {
			ion_destroy_platform_data(ipdev->data);
			return -ENOMEM;
		} else if (ipdev->heaps[i] == ERR_PTR(-EINVAL)) {
			return 0;
		}
		ion_device_add_heap(ipdev->idev, ipdev->heaps[i]);
	}
	return 0;
}

static int sunxi_ion_remove(struct platform_device *pdev)
{
	struct sunxi_ion_dev *ipdev;
	int i;

	ipdev = platform_get_drvdata(pdev);

	for (i = 0; i < ipdev->data->nr; i++)
		ion_heap_destroy(ipdev->heaps[i]);

	ion_destroy_platform_data(ipdev->data);
	ion_device_destroy(ipdev->idev);

	return 0;
}

struct ion_client *sunxi_ion_client_create(const char *name)
{
	/*
	 * The assumption is that if there is a NULL device, the ion
	 * driver has not yet probed.
	 */
	if (IS_ERR_OR_NULL(idev))
		return ERR_PTR(-EPROBE_DEFER);

	if (IS_ERR(idev))
		return (struct ion_client *)idev;

	return ion_client_create(idev, name);
}

EXPORT_SYMBOL(sunxi_ion_client_create);

static const struct of_device_id sunxi_ion_match_table[] = {
	{.compatible = "allwinner,sunxi-ion"},
	{},
};

static struct platform_driver sunxi_ion_driver = {
	.probe = sunxi_ion_probe,
	.remove = sunxi_ion_remove,
	.driver = {
		.name = "ion-sunxi",
		.of_match_table = sunxi_ion_match_table,
	},
};

static int __init sunxi_ion_init(void)
{
	return platform_driver_register(&sunxi_ion_driver);
}
subsys_initcall(sunxi_ion_init);
