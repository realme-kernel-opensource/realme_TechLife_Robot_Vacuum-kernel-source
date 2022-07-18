
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
#include <linuxver.h>
#include <linux_osl.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/if_ether.h>
#include <linux/spinlock.h>
#include <linux/skbuff.h>
#include <linux/if_arp.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/wireless.h>
#include <linux/ieee80211.h>
#include <linux/debugfs.h>
#include <linux/rtnetlink.h>
#include <net/cfg80211.h>
#include <net/rtnetlink.h>
#include <net/netlink.h>
#include <net/ieee80211_radiotap.h>
#include <linux/compat.h>

#include "wland_defs.h"
#include "wland_utils.h"
#include "wland_fweh.h"
#include "wland_dev.h"
#include "wland_dbg.h"
#include "wland_wid.h"
#include "wland_bus.h"
#include "wland_sdmmc.h"
#include "wland_android.h"
#include "wland_rf.h"
#include "wland_cfg80211.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
#define is_compat_task()		0
#endif
#ifdef WLAND_OLD_EFUSE_COMPATIBLE
bool wland_is_old_efuse(u8* value)
{
	if (value == NULL) {
		WLAND_ERR("bad efuse data!\n");
		return false;
	}
	if ((value[16] == 0x4e) && (value[17] == 0x46)) {//vendor id
		WLAND_ERR("This is old efuse!\n");
		return true;
	} else
		return false;
}
#endif

int wland_read_efuse(struct wland_if *ifp, u8* value)
{
	int ret = 0;
	ret = wland_fil_get_cmd_data(ifp, WID_GET_EFUSE_ALL_PAGE, value, 28);
	if (ret < 0) {
		WLAND_ERR("read efuse value failed:%d\n", ret);
		return ret;
	}
	//dump_buf(value, 28);
	return 0;
}
bool wland_efuse_canbe_overwrite (u8* be_writen, u8* write, u8 len)
{
	int i = 0;
	int j = 0;
	for (j=0; j<len; j++)
		for (i=0; i<8; i++) {
			if (((be_writen[j] & BIT(i)) != 0) && ((write[j] & BIT(i)) == 0)) {
				return false;
			}
	}
	return true;
}

bool wland_buf_equals(u8* data, u8 len, u8 comp)
{
	int i = 0;
	for(i=0; i<len; i++) {
		if(data[i] != comp)
			return false;
	}

	return true;
}

//if vendor id write in page 10 and crystal_cal_value in page 11.
#if 0
int wland_efuse_get_vendor_id(struct net_device *net,
	char *data, int len)
{
	int ret = 0;
	struct wland_if *ifp = netdev_priv(net);
	u8 efuse_value[28] = {0};

	WLAND_DBG(RFTEST, INFO, "get_vendor_id\n");

	if (wland_read_efuse(ifp, efuse_value))
		return -1;

	ret = snprintf(data, len, "vendor id:%02x%02x\n", efuse_value[17], efuse_value[16]);

	WLAND_DBG(RFTEST, INFO, "vendor id:%02x%02x\n", efuse_value[17], efuse_value[16]);

	return ret;
}


int wland_efuse_set_vendor_id(struct net_device *net,
	char *data, int len)
{
	int ret = 0;
	char *c= data;
	__le16 vendor_id;
	u8 efuse_value[28] = {0};
	struct wland_if *ifp = netdev_priv(net);
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;
	u8 write[4] = {0};

	vendor_id = simple_strtol(c, &c, 16);

	WLAND_DBG(RFTEST, INFO, "set_vendor_id%x\n", vendor_id);

	if (wland_read_efuse(ifp, efuse_value))
		return -1;

	if (wland_efuse_canbe_overwrite(&(efuse_value[16]), (u8*)(&vendor_id), 2) == false) {
		WLAND_ERR("one bit is already 1 can not write 0\n");
		return -1;
	}

	mutex_lock(&drvr->proto_block);
	memset(prot->buf, '\0', sizeof(prot->buf));

	write[0] = vendor_id & 0x00FF;
	write[1] = (vendor_id & 0xFF00) >> 8;
	write[2] = 0x0a;

	ret = wland_push_wid(buf, WID_SET_EFUSE_ONE_PAGE, write, 4, false);
	if (ret < 0) {
		WLAND_ERR("put wid error\n");
		goto done;
	}
	buf += ret;

	ret = wland_proto_cdc_data(drvr, buf-(prot->buf) + FMW_HEADER_LEN);
	if (ret < 0) {
		WLAND_ERR("WID Result Failed\n");
		goto done;
	}

done:
	mutex_unlock(&drvr->proto_block);
	return ret;

}


int wland_read_efuse_xtal_cal_val(struct net_device *net,
	 char *data, int len, u8 *cal_val)
{
	int ret = 0;
	struct wland_if *ifp = netdev_priv(net);
	u8 efuse_value[28] = {0};
	*cal_val = 0;

	WLAND_DBG(RFTEST, INFO, "read_efuse_xtal_cal_val\n");

	if (wland_read_efuse(ifp, efuse_value))
		return -1;

	if ((efuse_value[19] == 0) || (efuse_value[19] == 0xFF)){
		*cal_val = efuse_value[18];
	} else {
		*cal_val = efuse_value[19];
	}

	WLAND_DBG(RFTEST, INFO, "read cal_val from efuse:%02x\n", *cal_val);

	ret = snprintf(data, len, "frequency offset calibration value:0x%02x\n",
		*cal_val);

	return ret;
}

int wland_write_efuse_xtal_cal_val(struct net_device *net,
	char *data, int len)
{
	int ret = 0;
	struct wland_if *ifp = netdev_priv(net);
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 cal_val = 0;
	char *c = data;
	u8 efuse_value[28] = {0};
	u8 xtal_cal_efuse[2] = {0};
	u8 write[4] = {0};
	u8 *buf = prot->buf;

	WLAND_DBG(RFTEST, INFO, "write_efuse_xtal_cal_val:%s\n",data);
#if 1
	if(strncasecmp(c, "0x", strlen("0x")) != 0) {
		WLAND_ERR("not a hex value\n");
		return -1;
	}
#endif
	cal_val = simple_strtol(c, &c, 16);
	if ((cal_val >= 0xFF) || (cal_val == 0)) {
		WLAND_ERR("error:cal_val >= 0xFF || cal_val== 0\n");
		return -1;
	}
	cal_val = cal_val & 0xFE;

	WLAND_DBG(RFTEST, INFO, "write_efuse_xtal_cal_val:%02x\n", cal_val);

	if (wland_read_efuse(ifp, efuse_value))
		return -1;

	memcpy(xtal_cal_efuse, &efuse_value[18], 2);

	if (xtal_cal_efuse[1] == 0) {//bak buf not used
		if (wland_efuse_canbe_overwrite(&xtal_cal_efuse[0], &cal_val, 1) == true)
			xtal_cal_efuse[0] = cal_val;
		else
			xtal_cal_efuse[1] = cal_val;
	} else {
		if (wland_efuse_canbe_overwrite(&xtal_cal_efuse[1], &cal_val, 1) == true)
			xtal_cal_efuse[1] = cal_val;
		else {
			if (wland_efuse_canbe_overwrite(&xtal_cal_efuse[0], &cal_val, 1) == true) {
				xtal_cal_efuse[0] = cal_val;
				xtal_cal_efuse[1] = 0xFF;
			} else {
				WLAND_ERR("one bit is already 1, can not wirte 0\n");
				return -1;
			}
		}
	}

	mutex_lock(&drvr->proto_block);
	memset(prot->buf, '\0', sizeof(prot->buf));

	write[0] = xtal_cal_efuse[0];
	write[1] = xtal_cal_efuse[1];
	write[2] = 0x0b;

	ret = wland_push_wid(buf, WID_SET_EFUSE_ONE_PAGE, write, 4, false);
	if (ret < 0) {
		WLAND_ERR("put wid error\n");
		goto done;
	}
	buf += ret;

	ret = wland_proto_cdc_data(drvr, buf-(prot->buf) + FMW_HEADER_LEN);
	if (ret < 0) {
		WLAND_ERR("WID Result Failed\n");
		goto done;
	}

done:
	mutex_unlock(&drvr->proto_block);
	return ret;

}
#else

int wland_read_efuse_xtal_cal_val(struct net_device *net,
	 char *data, int len, u8 *cal_val)
{
	int ret = 0;
	struct wland_if *ifp = netdev_priv(net);
	u8 efuse_value[28] = {0};
	int i = 0;
	*cal_val = 0;

	WLAND_DBG(RFTEST, DEBUG, "read_efuse_xtal_cal_val\n");

	if (wland_read_efuse(ifp, efuse_value))
		return -1;

#ifdef WLAND_OLD_EFUSE_COMPATIBLE
	if (wland_is_old_efuse(efuse_value)) {
		//WLAND_DBG(RFTEST, WARNING, "Can not read xtal_cal_val *\n");
		//return -1;
		for (i=3; i>=2; i--) {
			if (efuse_value[16+i] != 0){
				*cal_val = efuse_value[16+i];
				break;
			}
		}

		if (i == 1) {
			WLAND_DBG(RFTEST, WARNING, "Can not read xtal_cal_val *\n");
			return -1;
		}

		WLAND_DBG(RFTEST, INFO, "read cal_val from efuse:%02x *\n", *cal_val);

		if(data != NULL)
			ret = snprintf(data, len, "frequency offset calibration value:0x%02x *\n",
				*cal_val);

		return ret;
	}
#endif

	for (i=3; i>=0; i--) {
		if (efuse_value[16+i] != 0){
			*cal_val = efuse_value[16+i];
			break;
		}
	}

	if (i == -1) {
		WLAND_DBG(RFTEST, WARNING, "Can not read xtal_cal_val\n");
		return -1;
	}

	WLAND_DBG(RFTEST, INFO, "read cal_val from efuse:%02x\n", *cal_val);

	if(data != NULL)
		ret = snprintf(data, len, "frequency offset calibration value:0x%02x\n",
			*cal_val);

	return ret;
}

int wland_write_efuse_xtal_cal_val(struct net_device *net,
	char *data, int len)
{
	int ret = 0;
	struct wland_if *ifp = netdev_priv(net);
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 cal_val = 0;
	char *c = data;
	u8 efuse_value[28] = {0};
	u8 xtal_cal_efuse[4] = {0};
	u8 write[4] = {0};
	u8 *buf = prot->buf;
	int i = 0;
	u8 cal_val_get = 0;

	WLAND_DBG(RFTEST, INFO, "write_efuse_xtal_cal_val:%s\n",data);

	if(strncasecmp(c, "0x", strlen("0x")) != 0) {
		WLAND_ERR("not a hex value\n");
		return -1;
	}

	cal_val = simple_strtol(c, &c, 16);
	if ((cal_val >= 0xFF) || (cal_val == 0)) {
		WLAND_ERR("error:cal_val >= 0xFF || cal_val== 0\n");
		return -1;
	}
	cal_val = cal_val & 0xFE;

	WLAND_DBG(RFTEST, INFO, "write_efuse_xtal_cal_val:%02x\n", cal_val);

	if (wland_read_efuse(ifp, efuse_value))
		return -1;

	memcpy(xtal_cal_efuse, &efuse_value[16], 4);

	if (xtal_cal_efuse[3] != 0) {
		if (wland_efuse_canbe_overwrite(&xtal_cal_efuse[3], &cal_val, 1) == false) {
			WLAND_ERR("can not write xtal_cal_val xtal_cal_efuse[3]:%x cal_val:%x\n",
				xtal_cal_efuse[3], cal_val);
			return -1;
		} else {
			xtal_cal_efuse[3] = cal_val;
			goto send;
		}
	}

	for (i=0; i<=3; i++) {//0 1 2 3
		if(xtal_cal_efuse[i] == 0)
			break;
	}

#ifdef WLAND_OLD_EFUSE_COMPATIBLE
	if (wland_is_old_efuse(efuse_value)) {
		xtal_cal_efuse[i] = cal_val;
		goto send;
	}
#endif

	if (i==0) {
		xtal_cal_efuse[0] = cal_val;
	} else {
		if (wland_efuse_canbe_overwrite(&xtal_cal_efuse[i-1], &cal_val, 1) == true)
			xtal_cal_efuse[i-1] = cal_val;
		else
			xtal_cal_efuse[i] = cal_val;
	}

send:
	mutex_lock(&drvr->proto_block);
	memset(prot->buf, '\0', sizeof(prot->buf));

	write[0] = xtal_cal_efuse[0];
	write[1] = xtal_cal_efuse[1];
	write[2] = 0x0a;

	ret = wland_push_wid(buf, WID_SET_EFUSE_ONE_PAGE, write, 4, false);
	if (ret < 0) {
		WLAND_ERR("put wid error\n");
		mutex_unlock(&drvr->proto_block);
		return ret;
	}
	buf += ret;

	write[0] = xtal_cal_efuse[2];
	write[1] = xtal_cal_efuse[3];
	write[2] = 0x0b;

	ret = wland_push_wid(buf, WID_SET_EFUSE_ONE_PAGE, write, 4, false);
	if (ret < 0) {
		WLAND_ERR("put wid error\n");
		mutex_unlock(&drvr->proto_block);
		return ret;
	}
	buf += ret;

	ret = wland_proto_cdc_data(drvr, buf-(prot->buf) + FMW_HEADER_LEN);
	mutex_unlock(&drvr->proto_block);
	if (ret < 0) {
		WLAND_ERR("WID Result Failed\n");
		return ret;
	}

	ret = wland_read_efuse_xtal_cal_val(ifp->ndev, NULL, 0, &cal_val_get);
	if ((ret < 0) || (cal_val_get == 0)
		|| ((cal_val_get & 0xFE) != (cal_val & 0xFE))) {
		WLAND_ERR("check failed\n");
		return -1;
	} else {
		WLAND_ERR("success!\n");
	}

	return ret;
}

#endif
int wland_efuse_get_mac_addr(struct net_device *net,
	char *data, int len, u8* mac_from_efuse)
{
	int ret = 0;
	u8 mac[ETH_ALEN];
	u8 mac_efuse[2*ETH_ALEN];
	struct wland_if *ifp = netdev_priv(net);
	u8 efuse_value[28] = {0};

	WLAND_DBG(RFTEST, INFO, "get_mac_addr\n");

	if (wland_read_efuse(ifp, efuse_value))
		return -1;

	memcpy(mac_efuse, &efuse_value[4], 2*ETH_ALEN);

#ifdef WLAND_OLD_EFUSE_COMPATIBLE
	if (wland_is_old_efuse(efuse_value)) {
		mac[0] = mac_efuse[1];
		mac[1] = mac_efuse[0];
		mac[2] = mac_efuse[3];
		mac[3] = mac_efuse[2];
		mac[4] = mac_efuse[5];
		mac[5] = mac_efuse[4];
	} else {
#endif
		if (wland_buf_equals(&mac_efuse[6], ETH_ALEN, 0)
			|| wland_buf_equals(&mac_efuse[6], ETH_ALEN, 0xFF))
			memcpy(mac, mac_efuse, ETH_ALEN);
		else
			memcpy(mac, &mac_efuse[6], ETH_ALEN);
#ifdef WLAND_OLD_EFUSE_COMPATIBLE
	}
#endif
	WLAND_DBG(RFTEST, INFO, "get_mac_addr from efuse:%pM\n", mac);

	if(data != NULL)
		ret = snprintf(data, len, "mac addr:%02x:%02x:%02x:%02x:%02x:%02x\n",
			mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	memcpy(mac_from_efuse, mac, ETH_ALEN);
	return ret;
}

int wland_efuse_set_mac_addr(struct net_device *net,
	char *data, int len)
{
	int i;
	int ret = 0;
	char *c= data;
	u8 mac[ETH_ALEN];
	u8 mac_get[ETH_ALEN] = {0};
	u8 mac_efuse[2*ETH_ALEN];
	u8 efuse_value[28] = {0};
	struct wland_if *ifp = netdev_priv(net);
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;
	u8 write[4] = {0};

	for (i=0; i<ETH_ALEN; ++i) {
		mac[i] = simple_strtol(c, &c, 16);
		c += 1;
	}

	WLAND_DBG(RFTEST, INFO, "set_mac_addr%pM\n", mac);

	if (wland_read_efuse(ifp, efuse_value))
		return -1;

	if ((mac[0] & BIT(0)) == 1) {
		WLAND_ERR("can not write multicast address\n");
		return -1;
	}

	if (wland_buf_equals(mac, ETH_ALEN, 0)) {
		WLAND_ERR("can not write all zero address\n");
		return -1;
	}

	memcpy(mac_efuse, &efuse_value[4], 2*ETH_ALEN);

	if (wland_buf_equals(&mac_efuse[6], ETH_ALEN, 0)) {//bak buf not used
		if (wland_efuse_canbe_overwrite(mac_efuse, mac, ETH_ALEN) == true)
			memcpy(mac_efuse, mac, ETH_ALEN);
		else
			memcpy(&mac_efuse[6], mac, ETH_ALEN);
	} else {
		if (wland_efuse_canbe_overwrite(&mac_efuse[6], mac, ETH_ALEN) == true)
			memcpy(&mac_efuse[6], mac, ETH_ALEN);
		else {
			if (wland_efuse_canbe_overwrite(mac_efuse, mac, ETH_ALEN) == true) {
				memcpy(mac_efuse, mac, ETH_ALEN);
				memset(&mac_efuse[6], 0xFF, ETH_ALEN);
			} else {
				WLAND_ERR("one bit is already 1, can not wirte 0\n");
				return -1;
			}
		}
	}

	mutex_lock(&drvr->proto_block);
	memset(prot->buf, '\0', sizeof(prot->buf));

	for (i=0; i<6; i++) {
		write[0] = mac_efuse[2*i];
		write[1] = mac_efuse[2*i+1];
		write[2] = 4+i;
		write[3] = 0;

		ret = wland_push_wid(buf, WID_SET_EFUSE_ONE_PAGE, write, 4, false);
		if (ret < 0) {
			WLAND_ERR("put wid error\n");
			mutex_unlock(&drvr->proto_block);
			return ret;
		}
		buf += ret;
		memset(write, 0, 4);
	}

	ret = wland_proto_cdc_data(drvr, buf-(prot->buf) + FMW_HEADER_LEN);
	mutex_unlock(&drvr->proto_block);
	if (ret < 0) {
		WLAND_ERR("WID Result Failed\n");
		return ret;
	} else {//read and check

		ret = wland_efuse_get_mac_addr(ifp->ndev, NULL, 0, mac_get);
		if (ret<0 || !is_valid_ether_addr(mac_get)) {
			WLAND_ERR("This mac address is not valid, ignored, ret:%d\n", ret);
			return -1;
		}

		if (memcmp(mac_get, mac, ETH_ALEN) != 0) {
			WLAND_ERR("mac get do not equals mac set!\n");
			return -5;
		} else {
			WLAND_ERR("success!\n");
		}
	}

	return ret;
}


int wland_get_rx_result(struct net_device *net,
	char *data, int len)
{
	int ret = 0;
	char buf_result[50];
	struct wland_if *ifp = netdev_priv(net);
	struct wland_private *drvr = ifp->drvr;

	WLAND_DBG(RFTEST, INFO, "get_rx_result\n");

	mutex_lock(&drvr->rf_result_block);
	ret = snprintf(buf_result, 50, "recv:%lld, fcs_passed:%lld",
		drvr->pkt_rx_complete, drvr->pkt_fcs_success);
	if (ret > 0)
		strcpy(data, buf_result);
	else
		WLAND_ERR("get rx result faild\n");

	drvr->pkt_rx_complete = 0;
	drvr->pkt_fcs_success = 0;
	mutex_unlock(&drvr->rf_result_block);
	return ret;
}

//WID_PHY_RF_REG_VAL just used for RF reg.
//WID_PHY_ACTIVE_REG and WID_11N_PHY_ACTIVE_REG_VAL used for PHY reg.
//0:1DA
//1:11F ~ 11g/n mode tx_power
//2:120 ~ 11b mode tx_power
int wland_set_hardware_param(struct net_device *net,
	char *data, int len, int func_num, u16 value_set)
{
	int ret = 0;
	struct wland_if *ifp = netdev_priv(net);
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;
	u16 function = 0, value = 0;
	char *c = data;
	u8 send[4] = {0};
	u8 phy_reg = 0;

	WLAND_DBG(RFTEST, DEBUG, "wland_set_hardware_param\n");

	if(data != NULL) {
		function = simple_strtol(c, &c, 10);
		if (c-data > len) {
			WLAND_ERR("error0\n");
			return -1;
		}

		if(strncasecmp(c+1, "0x", strlen("0x")) != 0) {
			WLAND_ERR("error1\n");
			return -1;
		}

		value = simple_strtol(c+1, &c, 16);
		if (c-data > len) {
			WLAND_ERR("error2\n");
			return -1;
		}
	} else {
		function = func_num;
		value = value_set;
	}

	if ((function != 0) && (function != 1) && (function != 2)) {
		WLAND_ERR("error3\n");
		return -1;
	}

	if ((value == 0) || (value > 0xFFFF)) {
		WLAND_ERR("error4\n");
		return -1;
	} else if ((function == 0) && (value >= 0xFF)) {
		WLAND_ERR("error5\n");
		return -1;
	}
#ifndef WLAND_SET_POWER_BY_RATE
	else if (function == 1){
		if ((drvr->current_mode == WLAND_N_MODE)
			&& ((value < WLAND_TXP_11F_BASE)
			|| (value > WLAND_TXP_11F_END))) {
				WLAND_ERR("current n mode, 11f:%02x~%02x, we set:%02x\n",
					WLAND_TXP_11F_BASE, WLAND_TXP_11F_END, value);
				return -1;
		} else if ((drvr->current_mode == WLAND_G_MODE)
			&& ((value < (WLAND_TXP_11F_BASE + drvr->power_g_n_offset))
			|| (value > (WLAND_TXP_11F_END + drvr->power_g_n_offset)))){
				WLAND_ERR("current g mode, 11f:%02x~%02x, we set:%02x\n",
					(WLAND_TXP_11F_BASE + drvr->power_g_n_offset),
					(WLAND_TXP_11F_END + drvr->power_g_n_offset),
					value);
				return -1;
		} else if (drvr->current_mode == WLAND_B_MODE) {
			WLAND_ERR("current b mode, can not set 11f\n");
			return -1;
		}
	} else if ((function == 2)
		&& ((value < WLAND_TXP_120_BASE) || (value > WLAND_TXP_120_END))) {
		WLAND_ERR("error8\n");
		return -1;
	}
#else
	else if ((function == 1) &&
		((value < WLAND_TXP_11F_BASE)||(value > WLAND_MAX_POWER_REG_VAL))) {
		WLAND_ERR("invalid value function:%d value:%x\n", function, value);
		return -1;
	} else if ((function == 2) &&
		((value < WLAND_TXP_120_BASE)||(value > WLAND_MAX_POWER_REG_VAL))) {
		WLAND_ERR("invalid value function:%d value:%x\n", function, value);
		return -1;
	}
#endif

	if (function == 0) {
		value = (((value & 0xFE) << 8) | 0x00CF);
		*(__le16 *) (&send[0]) = cpu_to_le16(value);
		*(__le16 *) (&send[2]) = cpu_to_le16(0x10DA);//0x1000 means write.

		ret = wland_fil_set_cmd_data(ifp, WID_PHY_RF_REG_VAL, send, 4);
		if (ret)
			WLAND_ERR("fil set cmd data fail!\n");
		return ret;

	} else if ((function == 1) || (function == 2)) {
		mutex_lock(&drvr->proto_block);
		memset(prot->buf, '\0', sizeof(prot->buf));

		phy_reg = 0xFF;
		ret = wland_push_wid(buf, WID_PHY_ACTIVE_REG, &phy_reg, 1, false);
		if (ret < 0) {
			WLAND_ERR("put wid error\n");
			goto phy_done;
		}
		buf += ret;

		memset(send, 0, 4);
		send[0] = 0x01;
		ret = wland_push_wid(buf, WID_11N_PHY_ACTIVE_REG_VAL, send, 4, false);
		if (ret < 0) {
			WLAND_ERR("put wid error\n");
			goto phy_done;
		}
		buf += ret;

		if (function == 1)
			phy_reg = 0x1F;
		else if (function == 2)
			phy_reg = 0x20;
		ret = wland_push_wid(buf, WID_PHY_ACTIVE_REG, &phy_reg, 1, false);
		if (ret < 0) {
			WLAND_ERR("put wid error\n");
			goto phy_done;
		}
		buf += ret;

		memset(send, 0, 4);
		*(__le16 *) (&send[0]) = cpu_to_le16(value);
		ret = wland_push_wid(buf, WID_11N_PHY_ACTIVE_REG_VAL, send, 4, false);
		if (ret < 0) {
			WLAND_ERR("put wid error\n");
			goto phy_done;
		}
		buf += ret;

		ret = wland_proto_cdc_data(drvr, buf-(prot->buf) + FMW_HEADER_LEN);
		if (ret < 0) {
			WLAND_ERR("WID Result Failed\n");
			goto phy_done;
		}

phy_done:
		mutex_unlock(&drvr->proto_block);
		return ret;

	} else {
		WLAND_ERR("error6\n");
		return -1;
	}
}

//rf_or_phy:0 rf 1 phy
int wland_rf_phy_reg_read(struct net_device *net, char *data,
	int len, u8 rf_or_phy)
{
	int ret = 0;
	struct wland_if *ifp = netdev_priv(net);
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;
	//u8 fun_num = 0;
	char *c= data;
	int skip = 0;
	u8 send[4] = {0};
	u8 result[4] = {0};
	u8 reg = 0;
	u16 addr = 0;
	u16 result_16_1 = 0;
	u16 result_16_2 = 0;
	u32 result_32 = 0;

	if (rf_or_phy == 0)
		skip = strlen(CMD_RF_REGR) + 1;
	else
		skip = strlen(CMD_PHY_REGR) + 1;

	if ((data != NULL) && (len > 0)) {
		c += skip;
		addr = simple_strtol(c, &c, 16);
	} else {
		WLAND_ERR("bad param!\n");
		return -1;
	}
	WLAND_DBG(RFTEST, INFO, "get reg(addr:%04x) value\n", addr);

	if (rf_or_phy == 0) {
		//tell fw the address

		send[2] = addr&0x00FF;
		send[3] = (addr&0x0F00) >> 8;

		ret = wland_fil_set_cmd_data(ifp, WID_PHY_RF_REG_VAL, send, 4);
		if (ret) {
			WLAND_ERR("fil set cmd data fail!\n");
			return -1;
		}
		ret = wland_fil_get_cmd_data(ifp, WID_PHY_RF_REG_VAL, result, 4);
		if (ret < 0) {
			WLAND_ERR("fil set cmd data fail!\n");
			return -1;
		}

		result_16_1 = MAKE_WORD16(result[0], result[1]);
		result_32 = result_16_1;

	} else if(rf_or_phy == 1) {

		mutex_lock(&drvr->proto_block);
		memset(prot->buf, '\0', sizeof(prot->buf));

		reg = 0xFF;
		ret = wland_push_wid(buf, WID_PHY_ACTIVE_REG, &reg, 1, false);
		if (ret < 0) {
			WLAND_ERR("put wid error\n");
			mutex_unlock(&drvr->proto_block);
			return -1;
		}
		buf += ret;

		memset(send, 0, 4);
		send[0] = (addr&0x0F00) >>8;//page
		ret = wland_push_wid(buf, WID_11N_PHY_ACTIVE_REG_VAL, send, 4, false);
		if (ret < 0) {
			WLAND_ERR("put wid error\n");
			mutex_unlock(&drvr->proto_block);
			return -1;
		}
		buf += ret;

		reg = addr&0x00FF;
		ret = wland_push_wid(buf, WID_PHY_ACTIVE_REG, &reg, 1, false);
		if (ret < 0) {
			WLAND_ERR("put wid error\n");
			mutex_unlock(&drvr->proto_block);
			return -1;
		}
		buf += ret;

		ret = wland_proto_cdc_data(drvr, buf-(prot->buf) + FMW_HEADER_LEN);
		if (ret < 0) {
			WLAND_ERR("WID Result Failed\n");
			mutex_unlock(&drvr->proto_block);
			return -1;
		}

		mutex_unlock(&drvr->proto_block);

		ret = wland_fil_get_cmd_data(ifp, WID_11N_PHY_ACTIVE_REG_VAL, result, 4);
		if (ret < 0) {
			WLAND_ERR("fil set cmd data fail!\n");
			return -1;
		}

		result_16_1 = MAKE_WORD16(result[0], result[1]);
		result_16_2 = MAKE_WORD16(result[2], result[3]);
		result_32 = MAKE_WORD32(result_16_1,result_16_2);

	} else {
		WLAND_ERR("invalid param\n");
		return -1;
	}



	if ((data != NULL) && (len > 0)) {
		ret = snprintf(data, len, "addr:%04x value:0x%02x\n",
			addr, result_32);
	} else {
		//*value = result_16;
		WLAND_ERR("invalid param!\n");
		return -1;
	}

	return ret;
}

int wland_rf_phy_reg_write(struct net_device *net,
	char *data, int len, u8 rf_or_phy, u16 addr_p, u32 value_p)
{
	int ret = 0;
	struct wland_if *ifp = netdev_priv(net);
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;
	//u16 function = 0, value = 0;
	char *c ;
	u8 send[4] = {0};
	u8 reg = 0;
	u16 addr = 0;
	u32 value = 0;
	u8 skip = 0;
	//int g_n_offset = drvr->power_g_n_offset;

	WLAND_DBG(RFTEST, DEBUG, "Enter\n");

	if (rf_or_phy == 0)
		skip = strlen(CMD_RF_REGW) + 1;
	else
		skip = strlen(CMD_PHY_REGW) + 1;

	if((data != NULL) && (len > 0)) {
		c = data + skip;
		addr = simple_strtol(c, &c, 16);
		if (c-data > len) {
			WLAND_ERR("error0\n");
			return -1;
		}

		value = simple_strtol(c+1, &c, 16);
		if (c-data > len) {
			WLAND_ERR("error2\n");
			return -1;
		}
	} else if (addr_p != 0) {
		addr = addr_p;
		value = value_p;
	} else {
		WLAND_ERR("bad param!\n");
		return -1;
	}

	WLAND_DBG(RFTEST, INFO, "set reg(addr:%04x) value:%04x\n", addr, value);

	if (rf_or_phy == 0) {
		u16 value_1 = value & 0x0000FFFF;
		*(__le16 *) (&send[0]) = cpu_to_le16(value_1);
		*(__le16 *) (&send[2]) = cpu_to_le16(addr);
		send[3] |= 0x10;//means write.

		ret = wland_fil_set_cmd_data(ifp, WID_PHY_RF_REG_VAL, send, 4);
		if (ret)
			WLAND_ERR("fil set cmd data fail!\n");
		return ret;

	} else if (rf_or_phy == 1) {
		mutex_lock(&drvr->proto_block);
		memset(prot->buf, '\0', sizeof(prot->buf));

		reg = 0xFF;
		ret = wland_push_wid(buf, WID_PHY_ACTIVE_REG, &reg, 1, false);
		if (ret < 0) {
			WLAND_ERR("put wid error\n");
			goto phy_done;
		}
		buf += ret;

		memset(send, 0, 4);
		send[0] = (addr&0x0F00) >> 8;
		ret = wland_push_wid(buf, WID_11N_PHY_ACTIVE_REG_VAL, send, 4, false);
		if (ret < 0) {
			WLAND_ERR("put wid error\n");
			goto phy_done;
		}
		buf += ret;

		reg = addr&0x00FF;
		ret = wland_push_wid(buf, WID_PHY_ACTIVE_REG, &reg, 1, false);
		if (ret < 0) {
			WLAND_ERR("put wid error\n");
			goto phy_done;
		}
		buf += ret;

		memset(send, 0, 4);
		*(__le32 *) (&send[0]) = cpu_to_le32(value);
		ret = wland_push_wid(buf, WID_11N_PHY_ACTIVE_REG_VAL, send, 4, false);
		if (ret < 0) {
			WLAND_ERR("put wid error\n");
			goto phy_done;
		}
		buf += ret;

		ret = wland_proto_cdc_data(drvr, buf-(prot->buf) + FMW_HEADER_LEN);
		if (ret < 0) {
			WLAND_ERR("WID Result Failed\n");
			goto phy_done;
		}

phy_done:
		mutex_unlock(&drvr->proto_block);
		return ret;

	} else {
		WLAND_ERR("error6\n");
		return -1;
	}
}

int wland_md(struct net_device *net, char *data, int len)
{
	int ret = 0;
	struct wland_if *ifp = netdev_priv(net);
	u32 addr = 0;
	u32 value = 0;
	char *c= data;
	int skip = strlen(CMD_MD) + 1;

	if ((data != NULL) && (len > 0)) {
		c += skip;
		addr = simple_strtol(c, &c, 16);
		if ((addr <0) || (addr > 0xFFFFFFFF)) {
			WLAND_ERR("addr invalid:%d!\n", addr);
			return -1;
		}
		if (c-data > len) {
			WLAND_ERR("rf test parameter error1:%s\n", data);
			return -1;
		}

	} else {
		WLAND_ERR("invalid param!\n");
		return -1;
	}

	WLAND_DBG(RFTEST, INFO, "get value addr:%04x\n", addr);

	ret = wland_get_memory_32bit(ifp, addr, &value);
	if(ret < 0) {
		WLAND_ERR("fil get cmd data failed!\n");
		return ret;
	}

	if ((data != NULL) && (len > 0)) {
		ret = snprintf(data, len, "addr:%04x value:%04x\n",
			addr, value);
	}

	return ret;
}

int wland_mw(struct net_device *net, char *data,
	int len, u32 addr_p, u32 value_p)
{
	int ret = 0;
	struct wland_if *ifp = netdev_priv(net);
	u32 addr = 0;
	u32 value = 0;
	char *c= data;
	int skip = strlen(CMD_MW) + 1;

	if ((data != NULL) && (len > 0)) {
		c += skip;
		addr = simple_strtol(c, &c, 16);
		if ((addr <0) || (addr > 0xFFFFFFFF)) {
			WLAND_ERR("addr invalid:%d!\n", addr);
			return -1;
		}
		if (c-data > len) {
			WLAND_ERR("rf test parameter error1:%s\n", data);
			return -1;
		}

		value = simple_strtol(c+1, &c, 16);
		if (c-data > len) {
			WLAND_ERR("rf test parameter error2:%s\n", data);
			return -1;
		}

	} else if (addr_p !=0) {
		addr = addr_p;
		value = value_p;
	} else {
		WLAND_ERR("invalid param!\n");
		return -1;
	}

	WLAND_DBG(RFTEST, INFO, "set addr:%04x value:%04x\n", addr, value);

	ret = wland_set_memory_32bit(ifp, addr, value);
	if(ret < 0) {
		WLAND_ERR("fil set cmd data failed!\n");
		return ret;
	}

	return 0;
}

int wland_get_hardware_param(struct net_device *net, char *data,
	int len, int func, u16 *value)
{
	int ret = 0;
	struct wland_if *ifp = netdev_priv(net);
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;
	u8 fun_num = 0;
	char *c= data;
	int skip = strlen(CMD_GET_PARAM) + 1;
	u8 send[4] = {0};
	u8 result[4] = {0};
	u8 phy_reg = 0;
	u16 result_16 = 0;

	if ((data != NULL) && (len > 0)) {
		c += skip;
		fun_num = simple_strtol(c, &c, 10);
	} else {
		fun_num = func;
	}
	WLAND_DBG(RFTEST, INFO, "get_hardware_param fun_num:%d\n", fun_num);

	if (fun_num == 0) {
		//tell fw the address

		*(__le16 *) (&send[2]) = cpu_to_le16(0x00DA);

		ret = wland_fil_set_cmd_data(ifp, WID_PHY_RF_REG_VAL, send, 4);
		if (ret) {
			WLAND_ERR("fil set cmd data fail!\n");
			return -1;
		}
		ret = wland_fil_get_cmd_data(ifp, WID_PHY_RF_REG_VAL, result, 4);
		if (ret < 0) {
			WLAND_ERR("fil set cmd data fail!\n");
			return -1;
		}

		result_16 = result[1] &= 0xFE;

	} else if((fun_num == 1) || (fun_num == 2)) {

		mutex_lock(&drvr->proto_block);
		memset(prot->buf, '\0', sizeof(prot->buf));

		phy_reg = 0xFF;
		ret = wland_push_wid(buf, WID_PHY_ACTIVE_REG, &phy_reg, 1, false);
		if (ret < 0) {
			WLAND_ERR("put wid error\n");
			mutex_unlock(&drvr->proto_block);
			return -1;
		}
		buf += ret;

		memset(send, 0, 4);
		send[0] = 0x01;
		ret = wland_push_wid(buf, WID_11N_PHY_ACTIVE_REG_VAL, send, 4, false);
		if (ret < 0) {
			WLAND_ERR("put wid error\n");
			mutex_unlock(&drvr->proto_block);
			return -1;
		}
		buf += ret;

		if (fun_num == 1)
			phy_reg = 0x1F;
		else if (fun_num == 2)
			phy_reg = 0x20;
		ret = wland_push_wid(buf, WID_PHY_ACTIVE_REG, &phy_reg, 1, false);
		if (ret < 0) {
			WLAND_ERR("put wid error\n");
			mutex_unlock(&drvr->proto_block);
			return -1;
		}
		buf += ret;

		ret = wland_proto_cdc_data(drvr, buf-(prot->buf) + FMW_HEADER_LEN);
		if (ret < 0) {
			WLAND_ERR("WID Result Failed\n");
			mutex_unlock(&drvr->proto_block);
			return -1;
		}

		mutex_unlock(&drvr->proto_block);

		ret = wland_fil_get_cmd_data(ifp, WID_11N_PHY_ACTIVE_REG_VAL, result, 4);
		if (ret < 0) {
			WLAND_ERR("fil set cmd data fail!\n");
			return -1;
		}

		result_16 = result[0];

	} else {
		WLAND_ERR("invalid func_num:%d\n",fun_num);
		return -1;
	}

	if ((data != NULL) && (len > 0)) {
		ret = snprintf(data, len, "fun_num:%d hardware_param:0x%x\n",
			fun_num, result_16);
	} else {
		*value = result_16;
	}

	return ret;
}

int wland_check_next_mode (int format, int rate)
{
	u8 b_rate[4] = {1,2,5,11};
	u8 g_rate[8] = {6,9,12,18,24,36,48,54};
	u8 n_rate[8] = {0,1,2,3,4,5,6,7};
	int i = 0;
	if (format == 0) {
		for(i=0; i<sizeof(b_rate); i++) {
			if(rate == b_rate[i])
				return WLAND_B_MODE;
		}
		for(i=0; i<sizeof(g_rate); i++) {
			if(rate == g_rate[i])
				return WLAND_G_MODE;
		}
		return WLAND_ERR_MODE;

	} else if ((format == 1) || (format == 2)) {
		for(i=0; i<sizeof(n_rate); i++) {
			if(rate == n_rate[i])
				return WLAND_N_MODE;
		}
		return WLAND_ERR_MODE;

	} else {
		return WLAND_ERR_MODE;
	}
}
//TX_TEST channel format bw op_band rate length
//RX_TEST channel format bw op_band
int wland_start_rf_test(struct net_device *net,
	char *data, int len, int tx)
{
	int ret = 0;
	struct wland_if *ifp = netdev_priv(net);
	u8 val;
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;
	char *c = data;
	int next_mode = WLAND_ERR_MODE;

	int channel = 0, format = 0, bw = 0, op_band = 0, rate = 0;
	u16 tx_len = 0, rx_stat = 1;
	WLAND_DBG(RFTEST, INFO, "RF TEST:%d\n", tx);


	WLAND_DBG(RFTEST, INFO, "RF TEST:%s(%d)\n", data, len);

	channel = simple_strtol(c, &c, 10);
	if (c-data > len) {
		WLAND_ERR("rf test parameter error1:%s\n", data);
		return -1;
	}

	format = simple_strtol(c+1, &c, 10);
	if (c-data > len) {
		WLAND_ERR("rf test parameter error2:%s\n", data);
		return -1;
	}

	bw = simple_strtol(c+1, &c, 10);
	if (c-data > len) {
		WLAND_ERR("rf test parameter error3:%s\n", data);
		return -1;
	}

	op_band = simple_strtol(c+1, &c, 10);
	if (c-data > len) {
		WLAND_ERR("rf test parameter error4:%s\n", data);
		return -1;
	}

	if (tx) {
		rate = simple_strtol(c+1, &c, 10);
		if (c-data > len) {
			WLAND_ERR("rf test parameter error5:%s\n", data);
			return -1;
		}

		tx_len = simple_strtol(c+1, &c, 10);
		if (c-data > len) {
			WLAND_ERR("rf test parameter error6:%s\n", data);
			return -1;
		}
	}

	WLAND_DBG(RFTEST, INFO,
		"channel:%d, format:%d, bw:%d, op_band:%d, rate:%d, tx_len:%d\n",
		channel, format, bw, op_band, rate, tx_len);
	if((tx && (channel <= 4) && (bw == 1) && (op_band == 1))
		|| (tx && (channel >= 10) && (bw == 1) && (op_band == 3))){
		WLAND_ERR("Invalid parameters!\n");
		return -1;
	}

//check current mode and set 11f value
	if (tx) {
		next_mode = wland_check_next_mode(format, rate);
		if (next_mode == WLAND_ERR_MODE) {
			WLAND_ERR("next mode is err mode, formate:%d, rate:%d",format, rate);
			return -1;
		}
#ifdef WLAND_SET_POWER_BY_RATE
		if (drvr->power_by_rate == 2) {
			int i = 0;
			u8 func = (next_mode == WLAND_B_MODE)?2:1;
			u8 begin, end;
			if (next_mode == WLAND_N_MODE) {
				begin = B_RATE_NUM + G_RATE_NUM;
				end = ALL_RATE_NUM;
			} else {
				begin = 0;
				end = B_RATE_NUM + G_RATE_NUM;
			}
			for(i=begin; i<end; i++) {
				if(rate == drvr->rates[i]) {
					ret = wland_set_hardware_param(net, NULL, 0, func,
						drvr->power_rates_value[i]);
					if (ret < 0) {
						WLAND_ERR("can not set 120 value\n");
						return ret;
					}
					break;
				}
			}
			if(i == ALL_RATE_NUM) {
				WLAND_ERR("invalid rate:%d\n", rate);
				return -1;
			}
		}
#else
		if (drvr->power_g_n_offset > 0) {
			int current_mode = drvr->current_mode;
			u16 value_11f = 0;

			if (((current_mode == WLAND_N_MODE) && (next_mode == WLAND_G_MODE))
				|| ((current_mode == WLAND_G_MODE) && (next_mode == WLAND_N_MODE))) {
				ret = wland_get_hardware_param(net, NULL, 0, 1, &value_11f);
				if (ret < 0) {
					WLAND_ERR("can not get 11f value\n");
					return ret;
				}

				if ((current_mode == WLAND_N_MODE) && (next_mode == WLAND_G_MODE)) {
					value_11f += drvr->power_g_n_offset;
				} else {
					value_11f -= drvr->power_g_n_offset;
				}

				ret = wland_set_hardware_param(net, NULL, 0, 1, value_11f);
				if (ret < 0) {
					WLAND_ERR("can not set 11f value\n");
					return ret;
				}

			}
		}
#endif
	}

	WLAND_DBG(RFTEST, INFO, "current mode:%d\n", drvr->current_mode);

	mutex_lock(&drvr->proto_block);
	memset(prot->buf, '\0', sizeof(prot->buf));

	val = format;
	ret = wland_push_wid(buf, WID_HUT_TX_FORMAT, &val, 1, false);
	if (ret < 0) {
		WLAND_ERR("put wid error\n");
		goto done;
	}
	buf += ret;

	if (tx) {
		if (format == 0) {
			val = rate;
			ret = wland_push_wid(buf, WID_CURRENT_TX_RATE, &val, 1, false);
			if (ret < 0) {
				WLAND_ERR("put wid error\n");
				goto done;
			}
			buf += ret;
		} else {
			val = rate;
			ret = wland_push_wid(buf, WID_11N_CURRENT_TX_MCS, &val, 1, false);
			if (ret < 0) {
				WLAND_ERR("put wid error\n");
				goto done;
			}
			buf += ret;
		}

		ret = wland_push_wid(buf, WID_HUT_FRAME_LEN, &tx_len, 2, false);
		if (ret < 0) {
			WLAND_ERR("put wid error\n");
			goto done;
		}
		buf += ret;
	}

	val = bw;
	ret = wland_push_wid(buf, WID_HUT_BANDWIDTH, &val, 1, false);
	if (ret < 0) {
		WLAND_ERR("put wid error\n");
		goto done;
	}
	buf += ret;

	val = op_band;
	ret = wland_push_wid(buf, WID_HUT_OP_BAND, &val, 1, false);
	if (ret < 0) {
		WLAND_ERR("put wid error\n");
		goto done;
	}
	buf += ret;

	val = channel;
	ret = wland_push_wid(buf, WID_CURRENT_CHANNEL, &val, 1, false);
	if (ret < 0) {
		WLAND_ERR("put wid error\n");
		goto done;
	}
	buf += ret;

	rx_stat = 0;
	ret = wland_push_wid(buf, WID_HUT_AUTO_HW_RX_STATS, &rx_stat, 2, false);
	if (ret < 0) {
		WLAND_ERR("put wid error\n");
		goto done;
	}
	buf += ret;

	mutex_lock(&drvr->rf_result_block);
	drvr->pkt_rx_complete = 0;
	drvr->pkt_fcs_success = 0;
	mutex_unlock(&drvr->rf_result_block);

	val = tx;
	ret = wland_push_wid(buf, WID_HUT_TEST_DIR, &val, 1, false);
	if (ret < 0) {
		WLAND_ERR("put wid error\n");
		goto done;
	}
	buf += ret;

	val = 1;
	ret = wland_push_wid(buf, WID_HUT_RESTART, &val, 1, false);
	if (ret < 0) {
		WLAND_ERR("put wid error\n");
		goto done;
	}
	buf += ret;

	ret = wland_proto_cdc_data(drvr, buf-(prot->buf) + FMW_HEADER_LEN);
	if (ret < 0) {
		WLAND_ERR("WID Result Failed\n");
		goto done;
	}
	drvr->current_mode = next_mode;

	if(tx == 0) {
		memset(prot->buf, '\0', sizeof(prot->buf));
		buf = prot->buf;
		rx_stat = 1;
		ret = wland_push_wid(buf, WID_HUT_AUTO_HW_RX_STATS, &rx_stat, 2, false);
		if (ret < 0) {
			WLAND_ERR("put wid error\n");
			goto done;
		}
		buf += ret;

		ret = wland_proto_cdc_data(drvr, buf-(prot->buf) + FMW_HEADER_LEN);
		if (ret < 0) {
			WLAND_ERR("WID Result Failed\n");
			goto done;
		}
	}

done:
	mutex_unlock(&drvr->proto_block);
	return ret;
}


int wland_stop_rx_test(struct net_device *net)
{
	int ret = 0;
	struct wland_if *ifp = netdev_priv(net);
	u16 rx_stat = 0;
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;

	WLAND_DBG(RFTEST, INFO, "Stop rx test.\n");

	mutex_lock(&drvr->proto_block);
	memset(prot->buf, '\0', sizeof(prot->buf));

	rx_stat = 0;
	ret = wland_push_wid(buf, WID_HUT_AUTO_HW_RX_STATS, &rx_stat, 2, false);
	if (ret < 0) {
		WLAND_ERR("put wid error\n");
		goto done;
	}
	buf += ret;

	ret = wland_proto_cdc_data(drvr, buf-(prot->buf) + FMW_HEADER_LEN);
	if (ret < 0)
		WLAND_ERR("WID Result Failed\n");

done:
	mutex_unlock(&drvr->proto_block);
	mutex_lock(&drvr->rf_result_block);
	drvr->pkt_rx_complete = 0;
	drvr->pkt_fcs_success = 0;
	mutex_unlock(&drvr->rf_result_block);
	return ret;
}

#if 0
//the case WLAND_TXP_NUM == 4
int wland_write_txpower_to_efuse(struct net_device *net,
	char *data, int len)
{
	int ret = 0;
	struct wland_if *ifp = netdev_priv(net);
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 tx_power_set[WLAND_TXP_NUM] = {0};
	char *c = data;
	int i = 0;
	u8 efuse_value[28] = {0};
	u8 write[4] = {0};
	u8 *buf = prot->buf;
	u8 tx_power_efuse[2*WLAND_TXP_NUM] = {0};

	WLAND_DBG(RFTEST, INFO, "wland_write_txpower_to_efuse:%s\n",data);

	for (i=0; i<WLAND_TXP_NUM; i++) {
		if(strncasecmp(c, "0x", strlen("0x")) != 0) {
			WLAND_ERR("not a hex value\n");
			return -1;
		}

		tx_power_set[i] = simple_strtol(c, &c, 16);
		if ((tx_power_set[i] >= 0xFF) || (tx_power_set[i] == 0)) {
			WLAND_ERR("invalid value!\n");
		}
		c++;
	}
	WLAND_DBG(RFTEST, INFO, "tx power value: %02x,%02x,%02x,%02x\n",
		tx_power_set[0], tx_power_set[1], tx_power_set[2], tx_power_set[3]);

	if (wland_read_efuse(ifp, efuse_value))
		return -1;

	memcpy(tx_power_efuse, &efuse_value[20], 2*WLAND_TXP_NUM);

	for (i=0; i<WLAND_TXP_NUM; i++) {

		if (tx_power_efuse[i+WLAND_TXP_NUM] == 0) {//bak buf not used
			if(wland_efuse_canbe_overwrite(&tx_power_efuse[i],&tx_power_set[i],1) == true)
				tx_power_efuse[i] = tx_power_set[i];
			else
				tx_power_efuse[i+WLAND_TXP_NUM] = tx_power_set[i];
		} else {
			if(wland_efuse_canbe_overwrite(&tx_power_efuse[i+WLAND_TXP_NUM],&tx_power_set[i],1))
				tx_power_efuse[i+WLAND_TXP_NUM] = tx_power_set[i];
			else {
				if(wland_efuse_canbe_overwrite(&tx_power_efuse[i],&tx_power_set[i],1) == true) {
					tx_power_efuse[i] = tx_power_set[i];
					tx_power_efuse[i+WLAND_TXP_NUM] = 0xFF;
				} else {
					WLAND_ERR("one bit is already 1, can not write 0\n");
					return -1;
				}
			}
		}
	}

	mutex_lock(&drvr->proto_block);
	memset(prot->buf, '\0', sizeof(prot->buf));

	for (i=0; i<WLAND_TXP_NUM; i++) {
		write[0] = tx_power_efuse[2*i];
		write[1] = tx_power_efuse[2*i+1];
		write[2] = 12+i;
		write[3] = 0;

		ret = wland_push_wid(buf, WID_SET_EFUSE_ONE_PAGE, write, 4, false);
		if (ret < 0) {
			WLAND_ERR("put wid error\n");
			goto done;
		}
		buf += ret;
		memset(write, 0, 4);
	}

	ret = wland_proto_cdc_data(drvr, buf-(prot->buf) + FMW_HEADER_LEN);
	if (ret < 0) {
		WLAND_ERR("WID Result Failed\n");
		goto done;
	}

done:
	mutex_unlock(&drvr->proto_block);
	return ret;

}

int wland_read_txpower_from_efuse(struct net_device *net,
	 char *data, int len, u8 *tx_power)
{
	int ret = 0;
	struct wland_if *ifp = netdev_priv(net);
	u8 value[WLAND_TXP_NUM] = {0};
	u8 efuse_value[28] = {0};
	u8 tx_power_efuse[2*WLAND_TXP_NUM] = {0};
	int i = 0;

	WLAND_DBG(RFTEST, INFO, "wland_read_txpower_from_efuse\n");

	if (wland_read_efuse(ifp, efuse_value))
		return -1;

	memcpy(tx_power_efuse, &efuse_value[20], 2*WLAND_TXP_NUM);

	for (i=0; i<WLAND_TXP_NUM; i++) {
		if ((tx_power_efuse[i+WLAND_TXP_NUM] == 0) || (tx_power_efuse[i+WLAND_TXP_NUM] == 0xFF))
			value[i] = tx_power_efuse[i];
		else
			value[i] = tx_power_efuse[i+WLAND_TXP_NUM];
	}

	ret = snprintf(data, len, "tx power value: %02x,%02x,%02x,%02x\n",
		value[0], value[1], value[2], value[3]);

	memcpy(tx_power, value, WLAND_TXP_NUM);

	return ret;
}
#endif
#if 0
//the case WLAND_TXP_NUM == 2 and use 8bit to contain 0x01-0xFE
int wland_write_txpower_to_efuse(struct net_device *net,
	char *data, int len)
{
	int ret = 0;
	struct wland_if *ifp = netdev_priv(net);
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 tx_power_set[WLAND_TXP_NUM] = {0};
	char *c = data;
	int i = 0;
	u8 efuse_value[28] = {0};
	u8 write[4] = {0};
	u8 *buf = prot->buf;
	u8 tx_power_efuse[8] = {0};

	WLAND_DBG(RFTEST, INFO, "wland_write_txpower_to_efuse:%s\n",data);

	for (i=0; i<WLAND_TXP_NUM; i++) {
		if(strncasecmp(c, "0x", strlen("0x")) != 0) {
			WLAND_ERR("not a hex value\n");
			return -1;
		}

		tx_power_set[i] = simple_strtol(c, &c, 16);

		if ((tx_power_set[i] >= 0xFF) || (tx_power_set[i] == 0)) {
			WLAND_ERR("invalid value!\n");
			return -1;
		}
		c++;
	}
	WLAND_DBG(RFTEST, INFO, "tx power value: 0x%02x,0x%02x\n",
		tx_power_set[0], tx_power_set[1]);

	if (wland_read_efuse(ifp, efuse_value))
		return -1;

	memcpy(tx_power_efuse, &efuse_value[20], 8);

	if (wland_buf_equals(&tx_power_efuse[6], 2, 0) == false) {
		if (wland_efuse_canbe_overwrite(&tx_power_efuse[6],
			tx_power_set, WLAND_TXP_NUM) == false) {
			WLAND_ERR("can not write txp\n");
			return -1;
		} else {
			tx_power_efuse[6] = tx_power_set[0];
			tx_power_efuse[7] = tx_power_set[1];
			goto send;
		}
	}

	for (i=0; i<=3; i++) {//0 1 2 3 :page
		if(wland_buf_equals(&tx_power_efuse[2*i], 2, 0) == true)
			break;
	}

	if (i==0) {
		tx_power_efuse[0] = tx_power_set[0];
		tx_power_efuse[1] = tx_power_set[1];
	} else {
		if (wland_efuse_canbe_overwrite(&tx_power_efuse[2*(i-1)],
			tx_power_set, WLAND_TXP_NUM) == true) {
			tx_power_efuse[2*(i-1)] = tx_power_set[0];
			tx_power_efuse[2*(i-1)+1] = tx_power_set[1];
		} else {
			tx_power_efuse[2*i] = tx_power_set[0];
			tx_power_efuse[2*i+1] = tx_power_set[1];
		}
	}

send:
	mutex_lock(&drvr->proto_block);
	memset(prot->buf, '\0', sizeof(prot->buf));

	for (i=0; i<4; i++) {
		write[0] = tx_power_efuse[2*i];
		write[1] = tx_power_efuse[2*i+1];
		write[2] = 12+i;
		write[3] = 0;

		ret = wland_push_wid(buf, WID_SET_EFUSE_ONE_PAGE, write, 4, false);
		if (ret < 0) {
			WLAND_ERR("put wid error\n");
			goto done;
		}
		buf += ret;
		memset(write, 0, 4);
	}

	ret = wland_proto_cdc_data(drvr, buf-(prot->buf) + FMW_HEADER_LEN);
	if (ret < 0) {
		WLAND_ERR("WID Result Failed\n");
		goto done;
	}

done:
	mutex_unlock(&drvr->proto_block);
	return ret;

}

int wland_read_txpower_from_efuse(struct net_device *net,
	 char *data, int len, u8 *tx_power)
{
	int ret = 0;
	struct wland_if *ifp = netdev_priv(net);
	u8 value[WLAND_TXP_NUM] = {0};
	u8 efuse_value[28] = {0};
	u8 tx_power_efuse[8] = {0};
	int i = 0;

	WLAND_DBG(RFTEST, INFO, "wland_read_txpower_from_efuse\n");

	if (wland_read_efuse(ifp, efuse_value))
		return -1;

	memcpy(tx_power_efuse, &efuse_value[20], 8);

	for (i=3; i>=0; i--) {
		if (wland_buf_equals(&tx_power_efuse[2*i], WLAND_TXP_NUM, 0) == false){
			value[0] = tx_power_efuse[2*i];
			value[1] = tx_power_efuse[2*i+1];
			break;
		}
	}

	if (i == -1) {
		WLAND_ERR("Can not read tx_p\n");
		return -1;
	}

	if(data != NULL)
		ret = snprintf(data, len, "tx power value: 0x%02x,0x%02x\n",
			value[0], value[1]);

	memcpy(tx_power, value, WLAND_TXP_NUM);

	return ret;
}

#endif
//the case WLAND_TXP_NUM == 2 and use 6bit to contain 0x**-0x**
int wland_write_txpower_to_efuse(struct net_device *net,
	char *data, int len)
{
	int ret = 0;
	struct wland_if *ifp = netdev_priv(net);
	u8 tx_power_set[WLAND_TXP_NUM] = {0};
	u8 tx_power_get[WLAND_TXP_NUM] = {0};
	u16 tx_power_write = 0;
	char *c = data;
	int i = 0;
	u8 efuse_value[28] = {0};
	u8 write[4] = {0};
	u8 tx_power_efuse[8] = {0};
	u16 tx_power_comp = 0;
	u8 send_page = 0;

	WLAND_DBG(RFTEST, INFO, "wland_write_txpower_to_efuse:%s\n",data);

	for (i=0; i<WLAND_TXP_NUM; i++) {
		if(strncasecmp(c, "0x", strlen("0x")) != 0) {
			WLAND_ERR("not a hex value\n");
			return -1;
		}

		tx_power_set[i] = simple_strtol(c, &c, 16);

		if ((tx_power_set[i] >= 0xFF) || (tx_power_set[i] == 0)) {
			WLAND_ERR("invalid value!\n");
			return -1;
		}
		c++;
	}

	if (((tx_power_set[0] < WLAND_TXP_11F_BASE)
		|| (tx_power_set[0] > WLAND_TXP_11F_END))
		|| ((tx_power_set[1] < WLAND_TXP_120_BASE)
		|| (tx_power_set[1] > WLAND_TXP_120_END))) {
		WLAND_ERR("invalid param!\n");
		return -1;
	}
	WLAND_DBG(RFTEST, INFO, "tx power value: 0x%02x,0x%02x\n",
		tx_power_set[0], tx_power_set[1]);

	tx_power_write = ((((tx_power_set[1] - WLAND_TXP_120_BASE) & 0x3F) << 6)
					| ((tx_power_set[0] - WLAND_TXP_11F_BASE) & 0x3F));

	if (wland_read_efuse(ifp, efuse_value))
		return -1;

	memcpy(tx_power_efuse, &efuse_value[20], 8);

	for (i=3; i>=0; i--) {
		tx_power_comp = ((MAKE_WORD16(tx_power_efuse[2*i], tx_power_efuse[2*i+1])) & 0x0FFF);
		if(tx_power_comp != 0)
			break;
	}

	if (i == 3) {
		tx_power_comp = ((tx_power_write & 0x0FFF) | ((tx_power_efuse[7] & 0xF0)<< 8));
		if (wland_efuse_canbe_overwrite(&tx_power_efuse[6],
			(u8*)(&tx_power_comp), WLAND_TXP_NUM) == false) {
			WLAND_ERR("can not write txp\n");
			return -1;
		} else {
			send_page = 3;
		}
	} else if (i == -1) {
		send_page = 0;
	} else {
		tx_power_comp = ((tx_power_write & 0x0FFF) | ((tx_power_efuse[2*i+1] & 0xF0)<< 8));
		if (wland_efuse_canbe_overwrite(&tx_power_efuse[2*i],
			(u8*)(&tx_power_comp), WLAND_TXP_NUM) == true) {
			send_page = i;
		} else {
			send_page = i+1;
		}
	}

	tx_power_comp = ((tx_power_write & 0x0FFF) | ((tx_power_efuse[2*send_page+1] & 0xF0)<< 8));
	write[0] = (tx_power_comp & 0x00FF);
	write[1] = ((tx_power_comp & 0xFF00) >> 8);
	write[2] = 12 + send_page;
	write[3] = 0;

	ret = wland_fil_set_cmd_data(ifp, WID_SET_EFUSE_ONE_PAGE, write, 4);
	if(ret < 0) {
		WLAND_ERR("fil set cmd data failed!\n");
		return ret;
	}

	ret = wland_read_txpower_from_efuse(ifp->ndev, NULL, 0, tx_power_get);
	if ((ret < 0) || (tx_power_get[0] == 0) || (tx_power_get[1] == 0)
		|| (tx_power_get[0] >= 0xFF) || (tx_power_get[1] >= 0xFF)
		|| (tx_power_get[0] != tx_power_set[0]) || (tx_power_get[1] != tx_power_set[1])) {
		WLAND_ERR("check failed\n");
		return -1;
	} else {
		WLAND_ERR("success!\n");
	}
	return ret;
}

int wland_read_txpower_from_efuse(struct net_device *net,
	 char *data, int len, u8 *tx_power)
{
	int ret = 0;
	struct wland_if *ifp = netdev_priv(net);
	u8 value[WLAND_TXP_NUM] = {0};
	u8 efuse_value[28] = {0};
	u8 tx_power_efuse[8] = {0};
	int i = 0;
	u16 efuse_comp = 0;
	bool find = false;

	WLAND_DBG(RFTEST, INFO, "wland_read_txpower_from_efuse\n");

	if (wland_read_efuse(ifp, efuse_value))
		return -1;

	memcpy(tx_power_efuse, &efuse_value[20], 8);

	for (i=3; i>=0; i--) {
		efuse_comp = ((MAKE_WORD16(tx_power_efuse[2*i], tx_power_efuse[2*i+1])) & 0xFFF);
		if(efuse_comp != 0) {
			find = true;
			break;
		}
	}

	if (find == false) {
		WLAND_DBG(RFTEST, WARNING, "Can not read tx_p\n");
		return -1;
	} else {
		value[0] = (efuse_comp & 0x003F) + WLAND_TXP_11F_BASE;//0x3F:0000 0000 0011 1111
		value[1] = ((efuse_comp & 0x0FC0) >> 6) + WLAND_TXP_120_BASE;//0xFC0 0000 1111 1100 0000
	}
	if (((value[0] < WLAND_TXP_11F_BASE)
		|| (value[0] > WLAND_TXP_11F_END))
		|| ((value[1] < WLAND_TXP_120_BASE)
		|| (value[1] > WLAND_TXP_120_END))) {
		WLAND_ERR("invalid data!\n");
		return -1;
	}

	if(data != NULL)
		ret = snprintf(data, len, "tx power value: 0x%02x,0x%02x\n",
			value[0], value[1]);

	memcpy(tx_power, value, WLAND_TXP_NUM);

	return ret;
}

int wland_get_efuse_data(struct net_device *net, char *data, int len)
{
	int ret = 0;
	struct wland_if *ifp = netdev_priv(net);
	u8 efuse_value[28] = {0};
	u8 num = 0;
	int i = 0;

	WLAND_DBG(RFTEST, INFO, "get_efuse_data\n");

	if (wland_read_efuse(ifp, efuse_value))
		return -1;

	num = snprintf(data, len, "efuse value:\n");
	data += num;
	ret += num;

	for(i=0; i<14; i++) {
		num = snprintf(data, len, "%d: %02x %02x\n",
			i+2, efuse_value[2*i], efuse_value[2*i+1]);
		data += num;
		ret += num;
	}

	return ret;
}

int wland_set_sdio_pin_level(struct net_device *net, char *data, int len)
{
#ifdef WLAND_USB_SUPPORT
	int ret = 0;
	struct wland_if *ifp = netdev_priv(net);
	char *c = data;
	u32 level = 0;
	u32 val;
	WLAND_DBG(RFTEST, INFO, "Enter\n");

	level = simple_strtol(c, &c, 10);
	if ((c-data > len) || len==0){
		WLAND_ERR("error0\n");
		return -1;
	}

	WLAND_DBG(RFTEST, INFO, "set sdio pin output level:%d\n", level);

	ret = wland_get_memory_32bit(ifp, 0x40001044, &val);
	if(ret < 0) {
		WLAND_ERR("fil set cmd data failed!\n");
		return ret;
	}
	WLAND_DBG(RFTEST, INFO, "get 0x40001044:%08x\n", val);

	val &= 0xFF00003F;
	val |= 0x249240;//ENABLE GIOP 14-19

	WLAND_DBG(RFTEST, INFO, "set 0x40001044:%08x\n", val);

	ret = wland_set_memory_32bit(ifp, 0x40001044, val);
	if(ret < 0) {
		WLAND_ERR("fil set cmd data failed!\n");
		return ret;
	}


	ret = wland_get_memory_32bit(ifp, 0x40001010, &val);
	if(ret < 0) {
		WLAND_ERR("fil set cmd data failed!\n");
		return ret;
	}
	WLAND_DBG(RFTEST, INFO, "get 0x40001010:%08x\n", val);

	val &= 0xFFF03FFF;//GIOP 14-19 OUTPUT

	WLAND_DBG(RFTEST, INFO, "set 0x40001010:%08x\n", val);

	ret = wland_set_memory_32bit(ifp, 0x40001010, val);
	if(ret < 0) {
		WLAND_ERR("fil set cmd data failed!\n");
		return ret;
	}

	ret = wland_get_memory_32bit(ifp, 0x40001008, &val);
	if(ret < 0) {
		WLAND_ERR("fil set cmd data failed!\n");
		return ret;
	}
	WLAND_DBG(RFTEST, INFO, "get 0x40001008:%08x\n", val);

	val &= 0xFFF03FFF;//GIOP 14-19 OUT VAL
	if (level)
		val |= 0xFC000;

	WLAND_DBG(RFTEST, INFO, "set 0x40001008:%08x\n", val);

	ret = wland_set_memory_32bit(ifp, 0x40001008, val);
	if(ret < 0) {
		WLAND_ERR("fil set cmd data failed!\n");
		return ret;
	}

	return 0;
#else
	WLAND_ERR("SDIO MODE\n");
	return -1;
#endif
}

//just for 0x8A
int wland_set_reg_for_one_channel(struct net_device *net, char *data, int len)
{
	int ret = 0;
	struct wland_if *ifp = netdev_priv(net);
	char *c = data;
	u8 val = 0;
	u16 reg = 0;
	u16 value_set = 0;
	u8 channel = 0;
	u16 reg_val[WLAND_CHANNEL_NUM] = {0};

	reg = simple_strtol(c, &c, 16);
	if ((c-data > len) || (reg != 0x8A)){
		WLAND_ERR("error0\n");
		return -1;
	}

	channel = simple_strtol(c+1, &c, 10);
	if ((c-data > len) || (channel < 1) || (channel > 14)) {
		WLAND_ERR("error1\n");
		return -1;
	}

	if(strncasecmp(c+1, "0x", strlen("0x")) != 0) {
		WLAND_ERR("error2\n");
		return -1;
	}

	value_set = simple_strtol(c+1, &c, 16);
	if ((c-data > len) || (value_set> 0xFFFF)) {
		WLAND_ERR("error3\n");
		return -1;
	}

	if (reg == 0x8A) {
		if ((value_set < 0x6820)
			|| (value_set > 0x6FA0)
			|| (((value_set & 0x00FF) != 0x0020)
			&& ((value_set & 0x00FF) != 0x00a0))) {
			WLAND_ERR("value for reg 0x8A is 0x6820~0x6FA0,"
				"and the little byte should be 0x20 or 0xA0\n");
			return -1;
		}
	}

	ret = wland_get_reg_for_channels(ifp, reg, reg_val);
	if (ret < 0) {
		WLAND_ERR("read value for reg:%x failed\n", reg);
		return -1;
	}

	reg_val[channel-1] = value_set;

	ret = wland_set_reg_for_channels(ifp, reg, reg_val);
	if (ret < 0) {
		WLAND_ERR("read value for reg:%x failed\n", reg);
		return -1;
	}

	val = 1;
	ret = wland_fil_set_cmd_data(ifp, WID_HUT_RESTART, &val, 1);
	if (ret < 0) {
		WLAND_ERR("hut restart failed!\n");
		return -1;
	}
	return 0;
}

int wland_get_reg_for_all_channels(struct net_device *net, char *data, int len)
{
	int ret = 0;
	struct wland_if *ifp = netdev_priv(net);
	u16 reg = 0;
	u16 reg_alue[WLAND_CHANNEL_NUM] = {0};
	int i = 0;
	int num = 0;
	int skip = strlen(CMD_GET_REG_CHAN) + 1;
	char *c = data+skip;

	reg = simple_strtol(c, &c, 16);
	if ((c-data > len) || (reg == 0)) {
		WLAND_ERR("rf test parameter error1:%s\n", data);
		return -1;
	}

	ret = wland_get_reg_for_channels(ifp, reg, reg_alue);
	if(ret < 0)	{
		WLAND_ERR("get reg value for %x failed\n", reg);
		return -1;
	}

	ret = 0;
	num = snprintf(data, len, "reg %02x:\n",reg);
	data += num;
	ret += num;
	for(i=0; i<WLAND_CHANNEL_NUM; i++) {
		num = snprintf(data, len, "channel%d: %02x\n", i+1, reg_alue[i]);
		data += num;
		ret += num;
	}

	return ret;

}

/*rda_tools wlan0 set_rssi_snr -1: cancel set rssi_snr, fw will not update the two values.
  rda_tools wlan0 set_rssi_snr n: n:0,1,2...,fw will update the two values each n+1 pkts,
  you can use rda_tools wlan0 get_rssi_snr to get the last values from fw.
*/
int wland_dev_set_rssi_snr_config(struct net_device * ndev,char *data, int len)
{
	struct wland_if *ifp = netdev_priv(ndev);
	int ret = 0;
	char *c = data;
	u32 rssi_snr_config_set = 0;

	rssi_snr_config_set = simple_strtol(c, &c, 10);
	//u32 rssi_snr_config_set = 0x0000c8ff;//the last byte is function enabled,the 2nd and 3rd bytes is pkt num of function interval
	WLAND_DBG(CFG80211, INFO, "set rssi_snr=%d\n",rssi_snr_config_set);
	if ((c-data > len) || len==0) {
		WLAND_ERR("error0\n");
		return -1;
	}
	if (rssi_snr_config_set == -1) {
		WLAND_DBG(CFG80211, INFO, "cancel set rssi_snr\n");
	} else {
		rssi_snr_config_set = (rssi_snr_config_set << 8) | 0xff;
		WLAND_DBG(CFG80211, INFO, "set rssi_snr=0x%0x\n",rssi_snr_config_set);
	}
	ret = wland_fil_set_cmd_data(ifp, WID_RSSI_SNR_CONFIG, &rssi_snr_config_set,sizeof(rssi_snr_config_set));
	if (ret < 0) {
		WLAND_ERR("Get RSSI failed!\n");
		return ret;
	}
	WLAND_DBG(DCMD, TRACE, "Done\n");
	return ret;
}
/*rssi_snr:byte0 is rssi,byte1 is snr*/
int wland_dev_get_rssi_snr(struct net_device * ndev,char *data, int len)
{
	struct wland_if *ifp = netdev_priv(ndev);
	int error = 0;
	u32 rssi_snr = 0;
	WLAND_DBG(DCMD, TRACE, "Enter\n");

	error = wland_fil_get_cmd_data(ifp, WID_RSSI_SNR, &rssi_snr,sizeof(rssi_snr));
	if (error < 0) {
		WLAND_ERR("Get RSSI_SNR failed!\n");
		return error;
	}
	error = snprintf(data, len, "rssi_snr=0x%0x,rssi=-%d,snr=%d,agc=%d.\n",rssi_snr,0xff-(rssi_snr&0x00ff),(rssi_snr&0xff00)>>8,(rssi_snr&0xff0000)>>16);
	return error;
}

#ifdef WLAND_SMART_CONFIG_SUPPORT
int wland_parse_and_set_channel(struct net_device * ndev,char *data, int len)
{
	struct wland_if *ifp = netdev_priv(ndev);
	int ret = 0;
	u8 channel = 0;
	char *c = data;
	WLAND_DBG(RFTEST, DEBUG, "Enter\n");

	if (!ifp->sniffer_enable) {
		WLAND_ERR("you can just set channel in sniffer mode!\n");
		return -1;
	}

	channel = simple_strtol(c, &c, 10);
	if ((c-data > len) || (channel == 0) || (channel > 14)) {
		WLAND_ERR("rf test parameter error1:%s\n", data);
		return -1;
	}
	WLAND_DBG(RFTEST, INFO, "set channel %d\n", channel);

	ret = wland_set_channel(ifp, channel);
	if (ret < 0) {
		WLAND_ERR("set channel failed!\n");
		return -1;
	}
	return 0;
}

//1:enable  2:disable
int wland_sniffer_enable(struct net_device * ndev,char *data, int len)
{
	struct wland_if *ifp = netdev_priv(ndev);
	int ret = 0;
	u8 enable = 0;
	char *c = data;

	WLAND_DBG(RFTEST, DEBUG, "Enter\n");

	if (ifp->vif->mode != WL_MODE_BSS) {
		WLAND_ERR("sniffer mode can only be setted from sta mode!\n");
		return -1;
	}

	enable = simple_strtol(c, &c, 10);
	if ((c-data > len) || ((enable != 1) && (enable != 2))) {
		WLAND_ERR("rf test parameter error1:%s\n", data);
		return -1;
	}

	WLAND_DBG(RFTEST, INFO, "enable:%d\n", enable);

	if(enable == 1) {
		if (ifp->sniffer_enable) {
			WLAND_ERR("sniffer already enabled\n");
			return 0;
		}
		ret = wland_sniffer_en_dis_able(ndev, true);
		if (ret < 0) {
			WLAND_ERR("enable sniffer failed!\n");
			return -1;
		} else {
			ifp->sniffer_enable = true;
		}
	} else {
		if (!ifp->sniffer_enable) {
			WLAND_ERR("sniffer already disabled\n");
			return 0;
		}
		ret = wland_sniffer_en_dis_able(ndev, false);
		if (ret < 0) {
			WLAND_ERR("disable sniffer failed!\n");
			return -1;
		} else {
			ifp->sniffer_enable = false;
		}
	}
	return 0;
}
#endif

/*
 * mode   0 - autorate         1 - bg        2 - 11n
 *
 * -----------------11n(mode 2)(Mbps)-----------------
 * rate	HT20				HT40
 *		GI(800ns)	GI(400ns)	GI(800ns)	GI(400ns)
 *  4		6.5		7.2		13.5		15
 *  5		13		14.2		27		30
 *  6		19.5		21.7		40.5		45
 *  7		26		28.9		54		60
 *  8		39		43.3		81		90
 *  9		52		57.8		108		120
 *  10		58.5		65		121.5		135
 *  11		65		72 		135		150
 *
 * --------------11bg(mode 1)(Mbps)-----------------
 * rate	data rate
 *  0		1
 *  1		2
 *  2		5.5
 *  3		6
 *  4		9
 *  5		11
 *  6		12
 *  7		18
 *  8		24
 *  9		36
 *  10		48
 *  11		54
 * --------------auto rate(mode 0)(Mbps)-----------------
 * rate	data rate
 * 255	auto rate
 */
int wland_set_data_rate(struct wland_if *ifp, u8 mode, u8 rate)
{
	int ret = 0;
	u8 send[2] = {0};
	u8 bg_rates[12] = {1,2,5,6,9,11,12,18,24,36,48,54};
	u8 index = 0;

	WLAND_DBG(RFTEST, INFO, "mode %d rate %d\r\n", mode, rate);

	if(mode == 0 && rate == 255) {//auto rate
		index = 0xFF;
	} else if(mode == 1) {//11bg
		for(index = 0; index<12; index++) {
			if(rate == bg_rates[index])
				break;
		}
		if (index == 12) {
			WLAND_ERR("invaild rate:%x mode:%d\n", rate, mode);
			goto done;
		}
	} else if(mode == 2) {//11n
		index = rate+4;
	} else {
		WLAND_ERR("parameter mode error:%d\n", mode);
		goto done;
	}
	WLAND_DBG(RFTEST, INFO, "mode %d index %d\r\n", mode, index);
	send[0] = index;
	send[1] = mode;

	ret = wland_fil_set_cmd_data(ifp, WID_SET_RATE_MODE, send, 2);
	if (ret < 0) {
		WLAND_ERR("failed to send rate\n");
	}

done:
	WLAND_DBG(RFTEST, DEBUG, "Done(err:%d)\n", ret);
	return ret;
}

int wland_set_rate(struct net_device *net, char *data, int len)
{
	u8 rate = 0;
	u8 mode = 0;
	char *c = data;
	struct wland_if *ifp = netdev_priv(net);
	struct wland_cfg80211_connect_info *conn_info = &ifp->vif->conn_info;

	WLAND_DBG(RFTEST, INFO, "wland_set_rate:%s\n", data);

	if (!test_bit(VIF_STATUS_CONNECTED, &ifp->vif->sme_state)) {
		WLAND_ERR("not connected, can not set rate!\n");
		return -1;
	}

	if (conn_info->n_enable)
		mode = 2;
	else
		mode = 1;

	rate = simple_strtol(c, &c, 10);
	if (rate == 255)
		mode = 0;

	if(mode == 1) {//11bg
		int i = 0;
		for (i=0; i<B_RATE_NUM+G_RATE_NUM; i++)
			if(ifp->drvr->rates[i] == rate)
				break;
		if (i== B_RATE_NUM+G_RATE_NUM) {
			WLAND_ERR("invalid rate:%d while mode is:%d\n", rate, mode);
			return -1;
		}
	} else if (mode == 2) {//11n
		if (rate > 7) {
			WLAND_ERR("invalid rate:%d while mode is:%d\n", rate, mode);
			return -1;
		}
	}

	return wland_set_data_rate(ifp, mode, rate);
}

int wland_set_tbtt_cnt(struct net_device * ndev,char *data, int len)
{
	struct wland_if *ifp = netdev_priv(ndev);
	int ret = 0;
	char *c = data;
	u8 tbtt_cnt = 0;

	tbtt_cnt = simple_strtol(c, &c, 10);
	WLAND_DBG(RFTEST, INFO, "set tbtt cnt=%d\n", tbtt_cnt);

	if ((c-data > len) || len==0) {
		WLAND_ERR("error0\n");
		return -1;
	}

	if(tbtt_cnt > 4) {
		WLAND_ERR("tbtt_cnt should less then 4\n");
	}

	ret = wland_fil_set_cmd_data(ifp, WID_TBTT_SLEEP_CNT, &tbtt_cnt, sizeof(tbtt_cnt));
	if (ret < 0) {
		WLAND_ERR("set tbtt cnt failed!\n");
		return ret;
	}
	WLAND_DBG(DCMD, TRACE, "Done\n");
	return ret;
}

int wland_rf_test_cmd(struct net_device *net, struct ifreq *ifr, int cmd)
{
#define PRIVATE_COMMAND_MAX_LEN	1024
	int ret = 0, bytes_written = 0;
	char *command = NULL;
	struct android_wifi_priv_cmd priv_cmd;

	WLAND_DBG(RFTEST, INFO, "Enter\n");

#if 0
	net_os_wake_lock(net);
#endif
	if (!ifr->ifr_data) {
		ret = -EINVAL;
		goto exit;
	}

#ifdef CONFIG_COMPAT
	if (is_compat_task()) {
		compat_android_wifi_priv_cmd compat_priv_cmd;
		if (copy_from_user(&compat_priv_cmd, ifr->ifr_data,
			sizeof(compat_android_wifi_priv_cmd))) {
			ret = -EFAULT;
			goto exit;

		}
		priv_cmd.buf = compat_ptr(compat_priv_cmd.buf);
		priv_cmd.used_len = compat_priv_cmd.used_len;
		priv_cmd.total_len = compat_priv_cmd.total_len;
	} else
#endif /* CONFIG_COMPAT */
	{
		if (copy_from_user(&priv_cmd, ifr->ifr_data,
				sizeof(struct android_wifi_priv_cmd))) {
			ret = -EFAULT;
			goto exit;
		}
	}

	if (priv_cmd.total_len > 1536) {
		WLAND_ERR("too long priavte command. %d\n", priv_cmd.total_len);
		ret = -EINVAL;
		priv_cmd.total_len = 1536;
	}
	command = memdup_user(priv_cmd.buf, priv_cmd.total_len);
	if (IS_ERR(command)) {
		WLAND_ERR("failed to allocate or write memory\n");
		ret= PTR_ERR(command);
		command = NULL;
		goto exit;
	}

	WLAND_DBG(RFTEST, INFO, "RF TEST cmd \"%s\" on %s\n", command,
		ifr->ifr_name);

	if (strncasecmp(command, CMD_TX_TEST, strlen(CMD_TX_TEST)) == 0) {
		int skip = strlen(CMD_RX_TEST) + 1;
		WLAND_DBG(RFTEST, DEBUG, "CMD_TX_TEST\n");
		bytes_written =	wland_start_rf_test(net, command + skip,
			priv_cmd.used_len- skip, 1);
	} else if (strncasecmp(command, CMD_RX_TEST, strlen(CMD_RX_TEST)) == 0) {
		int skip = strlen(CMD_RX_TEST) + 1;
		WLAND_DBG(RFTEST, DEBUG, "CMD_RX_TEST\n");
		bytes_written =	wland_start_rf_test(net, command + skip,
			priv_cmd.used_len - skip, 0);
	} else if (strncasecmp(command, CMD_RX_STOP, strlen(CMD_RX_STOP)) == 0) {
		WLAND_DBG(RFTEST, DEBUG, "CMD_RX_STOP\n");
		bytes_written =	wland_stop_rx_test(net);
	} else if (strncasecmp(command, CMD_RX_RESULT, strlen(CMD_RX_RESULT)) == 0) {
		WLAND_DBG(RFTEST, DEBUG, "CMD_RX_RESULT\n");
		bytes_written =	wland_get_rx_result(net, command, priv_cmd.total_len);
	} else if (strncasecmp(command, CMD_SET_MACADDR, strlen(CMD_SET_MACADDR)) == 0) {
		int skip = strlen(CMD_SET_MACADDR) + 1;
		WLAND_DBG(RFTEST, DEBUG, "CMD_SET_MACADDR\n");
		bytes_written =	wland_efuse_set_mac_addr(net, command + skip,
			priv_cmd.used_len - skip);
	} else if (strncasecmp(command, CMD_GET_MACADDR, strlen(CMD_GET_MACADDR)) == 0) {
		u8 mac[6] = {0};
		WLAND_DBG(RFTEST, DEBUG, "CMD_GET_MACADDR\n");
		bytes_written = wland_efuse_get_mac_addr(net, command, priv_cmd.total_len, mac);
	}
#if 0
	else if (strncasecmp(command, CMD_SET_VENDOR_ID, strlen(CMD_SET_VENDOR_ID)) == 0) {
		int skip = strlen(CMD_SET_VENDOR_ID) + 1;
		WLAND_DBG(RFTEST, DEBUG, "CMD_SET_VENDOR_ID\n");
		bytes_written = wland_efuse_set_vendor_id(net, command + skip,
			priv_cmd.used_len - skip);
	} else if (strncasecmp(command, CMD_GET_VENDOR_ID, strlen(CMD_GET_VENDOR_ID)) == 0) {
		WLAND_DBG(RFTEST, DEBUG, "CMD_GET_VENDOR_ID\n");
		bytes_written = wland_efuse_get_vendor_id(net, command, priv_cmd.total_len);
	}
#endif
	else if (strncasecmp(command, CMD_SET_PARAM, strlen(CMD_SET_PARAM)) == 0) {
		int skip = strlen(CMD_SET_PARAM) + 1;
		WLAND_DBG(RFTEST, DEBUG, "CMD_SET_PARAM\n");
		bytes_written =	wland_set_hardware_param(net, command + skip,
			priv_cmd.used_len - skip, -1, 0);
	}  else if (strncasecmp(command, CMD_WRITE_F_CAL_VAL, strlen(CMD_WRITE_F_CAL_VAL)) == 0) {
		int skip = strlen(CMD_WRITE_F_CAL_VAL) + 1;
		WLAND_DBG(RFTEST, DEBUG, "CMD_WRITE_F_CAL_VAL\n");
		bytes_written =	wland_write_efuse_xtal_cal_val(net, command + skip,
			priv_cmd.used_len - skip);
	} else if (strncasecmp(command, CMD_READ_F_CAL_VAL, strlen(CMD_READ_F_CAL_VAL)) == 0) {
		u8 cal_val = 0;
		WLAND_DBG(RFTEST, DEBUG, "CMD_READ_F_CAL_VAL\n");
		bytes_written = wland_read_efuse_xtal_cal_val(net, command,
			priv_cmd.total_len, &cal_val);
	} else if (strncasecmp(command, CMD_WRITE_TXPOWER, strlen(CMD_WRITE_TXPOWER)) == 0) {
		int skip = strlen(CMD_WRITE_TXPOWER) + 1;
		WLAND_DBG(RFTEST, DEBUG, "CMD_WRITE_TXPOWER\n");
		bytes_written =	wland_write_txpower_to_efuse(net, command + skip,
			priv_cmd.used_len - skip);
	} else if (strncasecmp(command, CMD_READ_TXPOWER, strlen(CMD_READ_TXPOWER)) == 0) {
		u8 tx_power[WLAND_TXP_NUM] = {0};
		WLAND_DBG(RFTEST, DEBUG, "CMD_READ_TXPOWER\n");
		bytes_written = wland_read_txpower_from_efuse(net, command,
			priv_cmd.total_len, tx_power);
	} else if (strncasecmp(command, CMD_GET_EFUSE, strlen(CMD_GET_EFUSE)) == 0) {
		WLAND_DBG(RFTEST, DEBUG, "CMD_GET_EFUSE\n");
		bytes_written = wland_get_efuse_data(net, command, priv_cmd.total_len);
	} else if (strncasecmp(command, CMD_GET_PARAM, strlen(CMD_GET_PARAM)) == 0) {
		u16 value = 0;
		WLAND_DBG(RFTEST, DEBUG, "CMD_GET_PARAM\n");
		bytes_written = wland_get_hardware_param(net, command, priv_cmd.total_len, -1, &value);
	} else if (strncasecmp(command, CMD_GET_REG_CHAN, strlen(CMD_GET_REG_CHAN)) == 0) {
		WLAND_DBG(RFTEST, DEBUG, "CMD_GET_REG_CHAN\n");
		bytes_written = wland_get_reg_for_all_channels(net, command,
			priv_cmd.total_len);
	} else if (strncasecmp(command, CMD_SET_REG_CHAN, strlen(CMD_SET_REG_CHAN)) == 0) {
		int skip = strlen(CMD_SET_REG_CHAN) + 1;
		WLAND_DBG(RFTEST, DEBUG, "CMD_SET_REG_CHAN\n");
		bytes_written =	wland_set_reg_for_one_channel(net, command + skip,
			priv_cmd.used_len - skip);
	} else if (strncasecmp(command, CMD_SET_SDIO_PIN, strlen(CMD_SET_SDIO_PIN)) == 0) {
		int skip = strlen(CMD_SET_SDIO_PIN) + 1;
		WLAND_DBG(RFTEST, DEBUG, "CMD_SET_SDIO_PIN\n");
		bytes_written = wland_set_sdio_pin_level(net, command + skip,
			priv_cmd.used_len - skip);
	} else if (strncasecmp(command, CMD_MD, strlen(CMD_MD)) == 0) {
		WLAND_DBG(RFTEST, DEBUG, "CMD_MD\n");
		bytes_written = wland_md(net, command, priv_cmd.total_len);
	} else if (strncasecmp(command, CMD_MW, strlen(CMD_MW)) == 0) {
		WLAND_DBG(RFTEST, DEBUG, "CMD_MW\n");
		bytes_written = wland_mw(net, command, priv_cmd.total_len, 0, 0);
	} else if (strncasecmp(command, CMD_RF_REGR, strlen(CMD_RF_REGR)) == 0) {
		WLAND_DBG(RFTEST, DEBUG, "CMD_RF_REGR\n");
		bytes_written = wland_rf_phy_reg_read(net, command, priv_cmd.total_len, 0);
	} else if (strncasecmp(command, CMD_RF_REGW, strlen(CMD_RF_REGW)) == 0) {
		WLAND_DBG(RFTEST, DEBUG, "CMD_RF_REGW\n");
		bytes_written = wland_rf_phy_reg_write(net, command, priv_cmd.total_len, 0, 0, 0);
	} else if (strncasecmp(command, CMD_PHY_REGR, strlen(CMD_PHY_REGR)) == 0) {
		WLAND_DBG(RFTEST, DEBUG, "CMD_PHY_REGR\n");
		bytes_written = wland_rf_phy_reg_read(net, command, priv_cmd.total_len, 1);
	} else if (strncasecmp(command, CMD_PHY_REGW, strlen(CMD_PHY_REGW)) == 0) {
		WLAND_DBG(RFTEST, DEBUG, "CMD_PHY_REGW\n");
		bytes_written = wland_rf_phy_reg_write(net, command, priv_cmd.total_len, 1, 0, 0);
	} else if (strncasecmp(command, CMD_SET_RSSI_SNR, strlen(CMD_SET_RSSI_SNR)) == 0) {
		int skip = strlen(CMD_SET_RSSI_SNR) + 1;
		WLAND_DBG(RFTEST, DEBUG, "CMD_SET_RSSI_SNR\n");
		bytes_written = wland_dev_set_rssi_snr_config(net, command + skip,priv_cmd.used_len - skip);
	} else if (strncasecmp(command, CMD_GET_RSSI_SNR, strlen(CMD_GET_RSSI_SNR)) == 0) {
		WLAND_DBG(RFTEST, DEBUG, "CMD_GET_RSSI_SNR\n");
		bytes_written = wland_dev_get_rssi_snr(net, command, priv_cmd.total_len);
	} else if (strncasecmp(command, CMD_GET_TX_STATUS, strlen(CMD_GET_TX_STATUS)) == 0) {
		WLAND_DBG(RFTEST, DEBUG, "CMD_GET_TX_STATUS\n");
		bytes_written = wland_dev_get_tx_status(net, command, priv_cmd.total_len);
	} else if (strncasecmp(command, CMD_SET_RATE, strlen(CMD_SET_RATE)) == 0) {
		int skip = strlen(CMD_SET_RATE) + 1;
		WLAND_DBG(RFTEST, DEBUG, "CMD_SET_RATE\n");
		bytes_written =	wland_set_rate(net, command + skip, priv_cmd.used_len - skip);
	}  else if (strncasecmp(command, CMD_SET_TBTT_CNT, strlen(CMD_SET_TBTT_CNT)) == 0) {
		int skip = strlen(CMD_SET_TBTT_CNT) + 1;
		WLAND_DBG(RFTEST, DEBUG, "CMD_SET_TBTT_CNT\n");
		bytes_written = wland_set_tbtt_cnt(net, command + skip, priv_cmd.used_len - skip);
	} 
#ifdef WLAND_SMART_CONFIG_SUPPORT
	else if (strncasecmp(command, CMD_SNIFFER_ENABLE, strlen(CMD_SNIFFER_ENABLE)) == 0) {
		int skip = strlen(CMD_SNIFFER_ENABLE) + 1;
		WLAND_DBG(RFTEST, DEBUG, "CMD_SNIFFER_ENABLE\n");
		bytes_written = wland_sniffer_enable(net, command + skip, priv_cmd.total_len);
	} else if (strncasecmp(command, CMD_SET_CHANNEL, strlen(CMD_SET_CHANNEL)) == 0) {
		int skip = strlen(CMD_SET_CHANNEL) + 1;
		WLAND_DBG(RFTEST, DEBUG, "CMD_SET_CHANNEL\n");
		bytes_written = wland_parse_and_set_channel(net, command + skip, priv_cmd.total_len);
	}
#endif
#ifdef WLAND_AP_RESET
	else if (strncasecmp(command, "ap_reset", strlen("ap_reset")) == 0) {
		ap_reseting = true;
		schedule_work(&wland_chip_reset_work);
		bytes_written = 0;
	}
#endif
    else {
		WLAND_DBG(RFTEST, ERROR,
			"Unknown RF command %s - ignored\n", command);
		snprintf(command, 3, "OK");
		bytes_written = strlen("OK");
	}

	if (bytes_written >= 0) {
		if ((bytes_written == 0) && (priv_cmd.total_len > 0))
			command[0] = '\0';
		if (bytes_written >= priv_cmd.total_len) {
			WLAND_ERR("bytes_written = %d\n", bytes_written);
			bytes_written = priv_cmd.total_len;
		} else {
			bytes_written++;
		}
		priv_cmd.used_len = bytes_written;
		if (copy_to_user(priv_cmd.buf, command, bytes_written)) {
			WLAND_ERR("failed to copy data to user buffer\n");
			ret = -EFAULT;
		} else
			ret = bytes_written;
	} else {
		ret = bytes_written;
	}

exit:
#if 0
	net_os_wake_unlock(net);
#endif
	//WLAND_DBG(RFTEST, INFO, "Done(%s, on:%s,ret:%d)\n", command, ifr->ifr_name, ret);

	if (command)
		kfree(command);

	return ret;
}

int wland_update_rf_rxtest_result(struct wland_private *drvr,
	u8* buffer)
{
	int ret = 0;
	u8 msg_type = 0, msg_id = 0;
	u16 msg_len = 0, wid_id = WID_NIL, wid_len = 0;
	char *result_buf = NULL, *cc = NULL;
	int rx_good = 0, rx_all = 0;
	/*
	 * parse type
	 */
	msg_type = buffer[0];

	/*
	 * Check whether the received message type is 'I'
	 */
	if (WLAND_WID_MSG_MAC_STATUS != msg_type) {
		WLAND_ERR("Received Message type incorrect.\n");
		return -EBADE;
	}

	/*
	 * Extract message ID
	 */
	msg_id = buffer[1];

	/*
	 * Extract message Length
	 */
	msg_len = MAKE_WORD16(buffer[2], buffer[3]);

	/*
	 * Extract WID ID [expected to be = WID_STATUS]
	 */
	wid_id = MAKE_WORD16(buffer[4], buffer[5]);

	if (wid_id != WID_HUT_LOG_STATS) {
		WLAND_ERR("Received Message wid incorrect.\n");
		return -EBADE;
	}

	/*
	 * Extract WID Length [expected to be = 1]
	 */
	wid_len = MAKE_WORD16(buffer[6], buffer[7]);

	//WLAND_ERR("len:%d buf:%s\n",wid_len, &buffer[8]);
	result_buf = &buffer[8];

	cc = strstr(result_buf, "=");
	if (cc == NULL) {
		WLAND_ERR("result_buf bad!\n");
		ret = -1;
		goto end;
	}

	rx_good = simple_strtol(cc+2, &cc, 10);
	if(rx_good < 0) {
		WLAND_ERR("rx_good < 0!\n");
		ret = -1;
		goto end;
	}

	cc = strstr(cc, "=");
	if (cc == NULL) {
		WLAND_ERR("result_buf bad!\n");
		ret = -1;
		goto end;
	}

	rx_all = simple_strtol(cc+2, &cc, 10);
	if(rx_all < 0) {
		WLAND_ERR("rx_all < 0!\n");
		ret = -1;
		goto end;
	}

	if(rx_good > rx_all){
		WLAND_ERR("rx_good(%d) > rx_all(%d)!\n",rx_good,rx_all);
		ret = -1;
		goto end;
	}

	mutex_lock(&drvr->rf_result_block);
	drvr->pkt_rx_complete += rx_all;
	drvr->pkt_fcs_success += rx_good;
	WLAND_DBG(RFTEST, INFO, "%d,%d,%lld,%lld\n", rx_good, rx_all,
		drvr->pkt_fcs_success, drvr->pkt_rx_complete);
	mutex_unlock(&drvr->rf_result_block);

end:
	return ret;
}
