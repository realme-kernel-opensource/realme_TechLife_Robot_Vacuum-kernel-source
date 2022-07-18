/*
 * drivers/power/axp/axp2101/axp2101.c
 * (C) Copyright 2010-2016
 * Allwinner Technology Co., Ltd. <www.allwinnertech.com>
 * Pannan <pannan@allwinnertech.com>
 *
 * driver of axp2101
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 */

#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/reboot.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/i2c.h>
#include <linux/delay.h>
#include <linux/mfd/core.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/of_device.h>
#include <linux/err.h>
#include <linux/power/aw_pm.h>
#include "../axp-core.h"
#include "../axp-charger.h"
#include "../axp-regulator.h"
#include "axp2101.h"
#include "axp2101-regu.h"

static struct axp_dev  *axp2101_pm_power;
struct axp_config_info  axp2101_config;
struct wakeup_source   *axp2101_ws;
static int              axp2101_pmu_num;

static struct axp_regmap_irq_chip axp2101_regmap_irq_chip = {
	.name        = "axp2101_irq_chip",
	.status_base = axp2101_INTSTS1,
	.enable_base = axp2101_INTEN1,
	.num_regs    = 3,
};

static struct resource axp2101_pek_resources[] = {
	{
		axp2101_IRQ_PONN,
		axp2101_IRQ_PONN,
		"PEK_DBR",
		IORESOURCE_IRQ,
	},
	{
		axp2101_IRQ_PONP,
		axp2101_IRQ_PONP,
		"PEK_DBF",
		IORESOURCE_IRQ,
	},
};

static struct resource axp2101_charger_resources[] = {
	{
		axp2101_IRQ_VINSET,
		axp2101_IRQ_VINSET,
		"usb in",
		IORESOURCE_IRQ,
	},
	{
		axp2101_IRQ_VREMOV,
		axp2101_IRQ_VREMOV,
		"usb out",
		IORESOURCE_IRQ,
	},
	{
		axp2101_IRQ_BINSERT,
		axp2101_IRQ_BINSERT,
		"bat in",
		IORESOURCE_IRQ,
	},
	{
		axp2101_IRQ_BREMOV,
		axp2101_IRQ_BREMOV,
		"bat out",
		IORESOURCE_IRQ,
	},
	/* { */
		/* axp2101_IRQ_BWUT, */
		/* axp2101_IRQ_BWUT, */
		/* "bat untemp work", */
		/* IORESOURCE_IRQ, */
	/* }, */
	/* { */
		/* axp2101_IRQ_BWOT, */
		/* axp2101_IRQ_BWOT, */
		/* "bat ovtemp work", */
		/* IORESOURCE_IRQ, */
	/* }, */
	{
		axp2101_IRQ_BCUT,
		axp2101_IRQ_BCUT,
		"quit bat untemp chg",
		IORESOURCE_IRQ,
	},
	{
		axp2101_IRQ_BCOT,
		axp2101_IRQ_BCOT,
		"quit bat ovtemp chg",
		IORESOURCE_IRQ,
	},
	{
		axp2101_IRQ_CHGST,
		axp2101_IRQ_CHGST,
		"charging",
		IORESOURCE_IRQ,
	},
	{
		axp2101_IRQ_CHGDN,
		axp2101_IRQ_CHGDN,
		"charge over",
		IORESOURCE_IRQ,
	},
	{
		axp2101_IRQ_SOCWL1,
		axp2101_IRQ_SOCWL1,
		"low warning1",
		IORESOURCE_IRQ,
	},
	{
		axp2101_IRQ_SOCWL2,
		axp2101_IRQ_SOCWL2,
		"low warning2",
		IORESOURCE_IRQ,
	},
};

static struct mfd_cell axp2101_cells[] = {
	{
		.name = "axp2101-powerkey",
		.num_resources = ARRAY_SIZE(axp2101_pek_resources),
		.resources = axp2101_pek_resources,
	},
	{
		.name = "axp2101-regulator",
	},
	{
		.name = "axp2101-charger",
		.num_resources = ARRAY_SIZE(axp2101_charger_resources),
		.resources = axp2101_charger_resources,
		.of_compatible = "axp2101-charger",
	},
	{
		.name = "axp2101-gpio",
	},
};

static const struct axp_compatible_name_mapping axp2101_mapping[] = {
	{
		.device_name = "axp2101",
		.mfd_name = {
			.powerkey_name  = "axp2101-powerkey",
			.charger_name   = "axp2101-charger",
			.regulator_name = "axp2101-regulator",
			.gpio_name      = "axp2101-gpio",
		},
	},
};

void axp2101_power_off(void)
{
	uint8_t val;

	pr_info("[axp] send power-off command!\n");
	mdelay(20);

	if (axp2101_config.power_start != 1) {
		axp_regmap_read(axp2101_pm_power->regmap, axp2101_COMM_STAT1,
				&val);
		if (val & 0x10) {
			axp_regmap_read(axp2101_pm_power->regmap,
					axp2101_COMM_STAT1, &val);
			if ((axp2101_config.pmu_bat_unused == 0) &&
			    (val & 0x20) && (val & 0x10)) {
				pr_info("[axp] set flag!\n");
				axp_regmap_read(axp2101_pm_power->regmap,
						axp2101_BUFFERC, &val);
				if (0x0d != val)
					axp_regmap_write(
						axp2101_pm_power->regmap,
						axp2101_BUFFERC, 0x0f);

				mdelay(20);
				pr_info("[axp] reboot!\n");
				machine_restart(NULL);
				pr_warn("[axp] warning!!! arch can't reboot,"
					" maybe some error happend!\n");
			}
		}
	}

	axp_regmap_read(axp2101_pm_power->regmap, axp2101_BUFFERC, &val);
	if (0x0d != val)
		axp_regmap_write(axp2101_pm_power->regmap, axp2101_BUFFERC,
				 0x00);
	mdelay(20);

	axp_regmap_set_bits(axp2101_pm_power->regmap, axp2101_COMM_CFG, 0x01);
	mdelay(20);

	pr_warn("[axp] warning!!! axp can't power-off,"
		" maybe some error happend!\n");
}

static int axp2101_init_chip(struct axp_dev *axp2101)
{
	uint8_t chip_id, dcdc2_ctl;
	int err;

	err = axp_regmap_read(axp2101->regmap, axp2101_CHIP_ID, &chip_id);
	if (err) {
		pr_err("[%s] try to read chip id failed!\n",
		       axp_name[axp2101_pmu_num]);
		return err;
	}

	if (chip_id == 0x47)
		pr_info("[%s] chip id detect 0x%x !\n",
			axp_name[axp2101_pmu_num], chip_id);
	else
		pr_info("[%s] chip id not detect 0x%x !\n",
			axp_name[axp2101_pmu_num], chip_id);

	/* enable dcdc2 dvm */
	err = axp_regmap_read(axp2101->regmap, axp2101_DCDC2_CFG, &dcdc2_ctl);
	if (err) {
		pr_err("[%s] try to read dcdc dvm failed!\n",
		       axp_name[axp2101_pmu_num]);
		return err;
	}

	dcdc2_ctl |= (0x1 << 7);
	err = axp_regmap_write(axp2101->regmap, axp2101_DCDC2_CFG, dcdc2_ctl);
	if (err) {
		pr_err("[%s] try to enable dcdc2 dvm failed!\n",
		       axp_name[axp2101_pmu_num]);
		return err;
	}
	pr_info("[%s] enable dcdc2 dvm.\n", axp_name[axp2101_pmu_num]);

	/* init 16's reset pmu en */
	if (axp2101_config.pmu_reset)
		axp_regmap_set_bits(axp2101->regmap, axp2101_COMM_CFG, 0x04);
	else
		axp_regmap_clr_bits(axp2101->regmap, axp2101_COMM_CFG, 0x04);

	/* init irq wakeup en */
	if (axp2101_config.pmu_irq_wakeup)
		axp_regmap_set_bits(axp2101->regmap, axp2101_SLEEP_CFG, 0x80);
	else
		axp_regmap_clr_bits(axp2101->regmap, axp2101_SLEEP_CFG, 0x80);

	/* init pmu over temperature protection */
	if (axp2101_config.pmu_hot_shutdown)
		axp_regmap_set_bits(axp2101->regmap, axp2101_PWROFF_EN, 0x04);
	else
		axp_regmap_clr_bits(axp2101->regmap, axp2101_PWROFF_EN, 0x04);

	return 0;
}

static void axp2101_wakeup_event(void)
{
	__pm_wakeup_event(axp2101_ws, 0);
}

static s32 axp2101_usb_det(void)
{
	u8 value = 0;
	int ret = 0;

	axp_regmap_read(axp2101_pm_power->regmap, axp2101_COMM_STAT0, &value);

	if (value & 0x80) {
		axp_usb_connect = 1;
		ret = 1;
	}

	return ret;
}

static int axp2101_cfg_pmux_para(int num, struct aw_pm_info *api, int *pmu_id)
{
	char name[8];
	struct device_node *np;

	sprintf(name, "pmu%d", num);

	np = of_find_node_by_type(NULL, name);
	if (NULL == np) {
		pr_err("can not find device_type for %s\n", name);
		return -1;
	}

	if (!of_device_is_available(np)) {
		pr_err("can not find node for %s\n", name);
		return -1;
	}

	api->pmu_arg.twi_port = axp2101_pm_power->regmap->client->adapter->nr;
	api->pmu_arg.dev_addr = axp2101_pm_power->regmap->client->addr;
	*pmu_id = axp2101_config.pmu_id;

	return 0;
}

static const char *axp2101_get_pmu_name(void)
{
	return axp_name[axp2101_pmu_num];
}

static struct axp_dev *axp2101_get_pmu_dev(void)
{
	return axp2101_pm_power;
}

struct axp_platform_ops axp2101_platform_ops = {
	.usb_det        = axp2101_usb_det,
	.cfg_pmux_para  = axp2101_cfg_pmux_para,
	.get_pmu_name   = axp2101_get_pmu_name,
	.get_pmu_dev    = axp2101_get_pmu_dev,
	/* .powerkey_name  = { "axp2101-powerkey" }, */
	/* .charger_name   = { "axp2101-charger" }, */
	/* .regulator_name = { "axp2101-regulator" }, */
	/* .gpio_name      = { "axp2101-gpio" }, */
};

static const struct of_device_id axp2101_dt_ids[] = {
	{
		.compatible = "axp2101",
	},
	{},
};
MODULE_DEVICE_TABLE(of, axp2101_dt_ids);

#ifdef CONFIG_AXP_TWI_USED
static int axp2101_probe(struct i2c_client *client,
			 const struct i2c_device_id *id)
#else
static int axp2101_probe(struct platform_device *pdev)
#endif
{
	int ret;
	struct axp_dev *axp2101;
	struct device_node *node;
	struct device *device;

#ifdef CONFIG_AXP_TWI_USED
	node = client->dev.of_node;
	device = &client->dev;
#else
	node = pdev->dev.of_node;
	device = &pdev->dev;
#endif

	axp2101_pmu_num =
		axp_get_pmu_num(axp2101_mapping, ARRAY_SIZE(axp2101_mapping));
	if (axp2101_pmu_num < 0) {
		pr_err("%s get pmu num failed\n", __func__);
		return axp2101_pmu_num;
	}

	if (node) {
		/* get dt and sysconfig */
		if (!of_device_is_available(node)) {
			axp2101_config.pmu_used = 0;
			pr_err("%s: pmu_used = %u\n", __func__,
			       axp2101_config.pmu_used);
			return -EPERM;
		} else {
			axp2101_config.pmu_used = 1;
			ret = axp_dt_parse(node, axp2101_pmu_num,
					   &axp2101_config);
			if (ret) {
				pr_err("%s parse device tree err\n", __func__);
				return -EINVAL;
			}
		}
	} else {
		pr_err("axp2101x device tree err!\n");
		return -EBUSY;
	}

	axp2101 = devm_kzalloc(device, sizeof(*axp2101), GFP_KERNEL);
	if (!axp2101)
		return -ENOMEM;

	axp2101->dev      = device;
	axp2101->nr_cells = ARRAY_SIZE(axp2101_cells);
	axp2101->cells    = axp2101_cells;
	axp2101->pmu_num  = axp2101_pmu_num;

	ret = axp_mfd_cell_name_init(axp2101_mapping,
				     ARRAY_SIZE(axp2101_mapping),
				     axp2101->pmu_num, axp2101->nr_cells,
				     axp2101->cells);
	if (ret)
		return ret;

#ifdef CONFIG_AXP_TWI_USED
	axp2101->regmap = axp_regmap_init_i2c(device);
#else
	axp2101->regmap =
		axp_regmap_init_arisc_rsb(device, axp2101_RSB_RTSADDR);
#endif
	if (IS_ERR(axp2101->regmap)) {
		ret = PTR_ERR(axp2101->regmap);
		dev_err(device, "regmap init failed: %d\n", ret);
		return ret;
	}

#ifdef CONFIG_AXP_TWI_USED
	i2c_set_clientdata(client, axp2101);
#else
	platform_set_drvdata(pdev, axp2101);
#endif
	ret = axp2101_init_chip(axp2101);
	if (ret)
		return ret;

	axp2101_pm_power = axp2101;

	axp_platform_ops_set(axp2101->pmu_num, &axp2101_platform_ops);

	ret = axp_mfd_add_devices(axp2101);
	if (ret) {
		dev_err(axp2101->dev, "failed to add MFD devices: %d\n", ret);
		return ret;
	}

#ifdef CONFIG_AXP_TWI_USED
	axp2101->irq = client->irq;
#else
	axp2101->irq = irq_of_parse_and_map(pdev->dev.of_node, 0);
#endif
	axp2101->irq_data = axp_irq_chip_register(
		axp2101->regmap, axp2101->irq,
		IRQF_SHARED | IRQF_NO_SUSPEND,
		&axp2101_regmap_irq_chip, axp2101_wakeup_event);
	if (IS_ERR(axp2101->irq_data)) {
		ret = PTR_ERR(axp2101->irq_data);
		dev_err(device, "axp init irq failed: %d\n", ret);
		return ret;
	}

	if (!pm_power_off)
		pm_power_off = axp2101_power_off;

	/* wakeup-source process */
#ifndef CONFIG_AXP_TWI_USED
	if (of_property_read_bool(node, "wakeup-source"))
		axp2101_ws = axp_wakeup_source_init(axp2101->dev, axp2101->irq);
	else
#endif
		axp2101_ws = wakeup_source_register("axp2101_wakeup_source");

	return 0;
}

#ifdef CONFIG_AXP_TWI_USED
static int axp2101_remove(struct i2c_client *client)
#else
static int axp2101_remove(struct platform_device *pdev)
#endif
{
	struct axp_dev *axp2101;

#ifdef CONFIG_AXP_TWI_USED
	axp2101 = i2c_get_clientdata(client);
#else
	axp2101 = platform_get_drvdata(pdev);
#endif

	if (axp2101 == axp2101_pm_power) {
		axp2101_pm_power = NULL;
		pm_power_off = NULL;
	}

	axp_mfd_remove_devices(axp2101);
	axp_irq_chip_unregister(axp2101->irq, axp2101->irq_data);

	return 0;
}

static const struct i2c_device_id axp2101_id_table[] = { { "axp2101", 0 }, {} };

#ifdef CONFIG_AXP_TWI_USED
static struct i2c_driver axp2101_driver = {
#else
static struct platform_driver axp2101_driver = {
#endif
	.driver = {
		.name           = "axp2101",
		.owner          = THIS_MODULE,
		.of_match_table = axp2101_dt_ids,
	},
	.probe    = axp2101_probe,
	.remove   = axp2101_remove,
#ifdef CONFIG_AXP_TWI_USED
	.id_table = axp2101_id_table,
#endif
};

static int __init axp2101_init(void)
{
	int ret;

#ifdef CONFIG_AXP_TWI_USED
	ret = i2c_add_driver(&axp2101_driver);
#else
	ret = platform_driver_register(&axp2101_driver);
#endif
	if (ret != 0)
		pr_err("Failed to register axp2101x driver: %d\n", ret);

	return ret;
}
subsys_initcall_sync(axp2101_init);

static void __exit axp2101_exit(void)
{
#ifdef CONFIG_AXP_TWI_USED
	i2c_del_driver(&axp2101_driver);
#else
	platform_driver_unregister(&axp2101_driver);
#endif
}
module_exit(axp2101_exit);

MODULE_DESCRIPTION("Driver of axp2101");
MODULE_AUTHOR("HZJ");
MODULE_LICENSE("GPL");
