
/*
 * Copyright (c) 2014 Rdamicro Corporation
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <linux/fs.h>
#include <linux/etherdevice.h>
#include "linux_osl.h"
#include "wland_defs.h"
#include "wland_dbg.h"

#ifdef USE_MAC_FROM_RDA_NVRAM
#include <plat/md_sys.h>
#endif

#ifdef WLAND_LINUX_SUPPORT
#define WIFI_NVRAM_FILE_NAME    "/etc/WLANMAC"
#else
#define WIFI_NVRAM_FILE_NAME    "/data/misc/wifi/WLANMAC"
#endif

int wland_nvram_read(const char *filename, char *data, int size, int offset)
{
	struct file *filp;
	mm_segment_t fs;
	char *buf;
	int ret = -1;

	filp = filp_open(filename, O_RDONLY, 0666);
	if (IS_ERR(filp)) {
		WLAND_DBG(DEFAULT, WARNING, "[nvram_read] : failed to open %s!\n",filename);
		return ret;
	}
	buf = (char *)kzalloc(size+1, GFP_KERNEL);
	if (!buf)
		return -1;

	fs = get_fs();
	set_fs(KERNEL_DS);
	filp->f_pos = offset;
	ret = vfs_read(filp, buf, size, &(filp->f_pos));
	set_fs(fs);

	buf[size] = '\0';
	memcpy(data, buf, size);

	WLAND_DBG(DEFAULT, WARNING, "mac addr is %s\n", data);

	filp_close(filp, NULL);
	return ret;
}

int wland_nvram_write(char *filename, char *data , int size, int offset)
{
	struct file *filp;
	mm_segment_t fs;
	int ret = -1;

	filp = filp_open(filename, O_CREAT | O_RDWR, 0666);
	if(IS_ERR(filp)) {
		WLAND_ERR("[nvram_write] : failed to open!\n");
		return ret;
	}

	fs = get_fs();
	set_fs(KERNEL_DS);
	filp->f_pos = offset;
	ret = vfs_write(filp, data, size,&filp->f_pos);
	WLAND_DBG(DEFAULT, TRACE,
		"mac addr is %pM, ret is %d\n", data, ret);
	set_fs(fs);
	filp_close(filp,NULL);
	return ret;
}

int wland_file_write(char *filename, char *data , int size, int offset,
	u32 mode1, u32 mode2)
{
	struct file *filp;
	mm_segment_t fs;
	int ret = -1;

	filp = filp_open(filename, mode1, mode2);
	if(IS_ERR(filp)) {
		WLAND_ERR("failed to open!\n");
		return ret;
	}

	fs = get_fs();
	set_fs(KERNEL_DS);
	filp->f_pos = offset;
	ret = vfs_write(filp, data, size,&filp->f_pos);

	set_fs(fs);
	filp_close(filp,NULL);
	return ret;
}

int wland_get_mac_address(char *mac)
{
	int i, ret;
	char buf[20] = {0};
	char *c = buf;
	ret = wland_nvram_read(WIFI_NVRAM_FILE_NAME, buf, 17, 0);
	if (ret != 17) {
		WLAND_ERR("read nvrame fail, ret:%d\n", ret);
		return ret;
	}

	for (i=0; i<6; ++i) {
		if (*c>='a' && *c<='f')
			mac[i] = 16*((*c - 'a' ) + 10);
		else if (*c>='A' && *c<='Z')
			mac[i] = 16*((*c - 'A') + 10);
		else
			mac[i] = 16*(*c - '0');
		c++;
		if (*c>='a' && *c<='f')
			mac[i] += (*c - 'a' ) + 10;
		else if (*c>='A' && *c<='Z')
			mac[i] += (*c - 'A') + 10;
		else
			mac[i] += *c - '0';
		c++;
		c++;
	}
	if (!is_valid_ether_addr(mac)) {
		WLAND_ERR("nvram:get an invalid ether addr:%s,%pM\n", buf, mac);
		return -1;
	}
	return ETH_ALEN;
}

int wland_set_mac_address(char *mac)
{
	char buf[20];
	snprintf(buf, 20, "%pM", mac);

	return wland_nvram_write(WIFI_NVRAM_FILE_NAME, buf, 17, 0);
}

#ifdef USE_MAC_FROM_RDA_NVRAM
int wland_read_mac_from_nvram(char *buf)
{
	int ret;
	struct msys_device *wlan_msys = NULL;
	struct wlan_mac_info wlan_info;
	struct client_cmd cmd_set;
	int retry = 3;

	wlan_msys = rda_msys_alloc_device();
	if (!wlan_msys) {
		WLAND_ERR("nvram: can not allocate wlan_msys device\n");
		ret = -ENOMEM;
		goto err_handle_sys;
	}

	wlan_msys->module = SYS_GEN_MOD;
	wlan_msys->name = "rda-wlan";
	rda_msys_register_device(wlan_msys);

	//memset(&wlan_info, sizeof(wlan_info), 0);
	memset(&wlan_info, 0, sizeof(wlan_info));
	cmd_set.pmsys_dev = wlan_msys;
	cmd_set.mod_id = SYS_GEN_MOD;
	cmd_set.mesg_id = SYS_GEN_CMD_GET_WIFI_INFO;
	cmd_set.pdata = NULL;
	cmd_set.data_size = 0;
	cmd_set.pout_data = &wlan_info;
	cmd_set.out_size = sizeof(wlan_info);

	while (retry--) {
		ret = rda_msys_send_cmd(&cmd_set);
		if (ret) {
			WLAND_ERR("nvram:can not get wifi mac from nvram \n");
			ret = -EBUSY;
		} else {
			break;
		}
	}

	if (ret == -EBUSY) {
		goto err_handle_cmd;
	}

	if (wlan_info.activated != WIFI_MAC_ACTIVATED_FLAG) {
		WLAND_ERR("nvram:get invalid wifi mac address from nvram\n");
		ret = -EINVAL;
		goto err_invalid_mac;
	}

	memcpy(buf, wlan_info.mac_addr, ETH_ALEN);
	WLAND_DBG(DEFAULT, ERROR,
		"nvram: get wifi mac address [%02x:%02x:%02x:%02x:%02x:%02x].\n",
		buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
	ret = 0; /* success */

err_invalid_mac:
err_handle_cmd:
	rda_msys_unregister_device(wlan_msys);
	rda_msys_free_device(wlan_msys);
err_handle_sys:
	return ret;
}

int wland_write_mac_to_nvram(const char *buf)
{
	int ret;
	struct msys_device *wlan_msys = NULL;
	struct wlan_mac_info wlan_info;
	struct client_cmd cmd_set;

	wlan_msys = rda_msys_alloc_device();
	if (!wlan_msys) {
		WLAND_ERR("nvram: can not allocate wlan_msys device\n");
		ret = -ENOMEM;
		goto err_handle_sys;
	}

	wlan_msys->module = SYS_GEN_MOD;
	wlan_msys->name = "rda-wlan";
	rda_msys_register_device(wlan_msys);

	memset(&wlan_info, 0, sizeof(wlan_info));
	wlan_info.activated = WIFI_MAC_ACTIVATED_FLAG;
	memcpy(wlan_info.mac_addr, buf, ETH_ALEN);

	cmd_set.pmsys_dev = wlan_msys;
	cmd_set.mod_id = SYS_GEN_MOD;
	cmd_set.mesg_id = SYS_GEN_CMD_SET_WIFI_INFO;
	cmd_set.pdata = &wlan_info;
	cmd_set.data_size = sizeof(wlan_info);
	cmd_set.pout_data = NULL;
	cmd_set.out_size = 0;

	ret = rda_msys_send_cmd(&cmd_set);
	if (ret) {
		WLAND_ERR("nvram:can not set wifi mac to nvram \n");
		ret = -EBUSY;
		goto err_handle_cmd;
	}

	WLAND_DBG(DEFAULT, NOTICE,
		"nvram:set wifi mac address [%02x:%02x:%02x:%02x:%02x:%02x] to nvram success.\n",
		buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
	ret = 0;		/* success */

err_handle_cmd:
	rda_msys_unregister_device(wlan_msys);
	rda_msys_free_device(wlan_msys);
err_handle_sys:
	return ret;
}
#endif /*USE_MAC_FROM_RDA_NVRAM*/