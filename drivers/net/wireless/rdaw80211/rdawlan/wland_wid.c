
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
#include <net/cfg80211.h>
#include <net/rtnetlink.h>
#include <linux/mmc/sdio_func.h>

#include "wland_defs.h"
#include "wland_utils.h"
#include "wland_fweh.h"
#include "wland_dev.h"
#include "wland_dbg.h"
#include "wland_wid.h"
#include "wland_bus.h"
#include "wland_sdmmc.h"
#include "wland_trap.h"
#include "wland_p2p.h"
#include "wland_amsdu.h"
#include "wland_cfg80211.h"
#include "wland_usb.h"

int wland_proto_hdrpush(struct wland_private *drvr, s32 ifidx,
	struct sk_buff *pktbuf)
{
	WLAND_DBG(DCMD, TRACE, "ifidx:%d,Enter\n", ifidx);

	return 0;
}

int wland_proto_hdrpull(struct wland_private *drvr, s32 *ifidx,
	struct sk_buff *pktbuf)
{

#ifndef WLAND_5991H_MAC1_SUPPORT
	int i;
	struct ethhdr *eh;
	WLAND_DBG(EVENT, TRACE, "Enter(pktbuf->len:%d)\n", pktbuf->len);

	/*
	 * Pop BDC header used to convey priority for buses that don't
	 */
	if (pktbuf->len <= FMW_HEADER_LEN) {
		WLAND_ERR("rx data too short (%d <= %d)\n", pktbuf->len,
			FMW_HEADER_LEN);
		return -EBADE;
	}

	eh = (struct ethhdr *) (pktbuf->data);

	for (i = 0; i < WLAND_MAX_IFS; ++i) {
		if (drvr->iflist[i]) {
			if (memcmp(eh->h_dest, drvr->iflist[i]->mac_addr, ETH_ALEN) == 0) {
				*ifidx = i;
				return 0;
			}
		}
	}
	for (i = 0; i < WLAND_MAX_IFS; ++i) {
		if (drvr->iflist[i]) {
			if (memcmp(eh->h_source, drvr->iflist[i]->mac_addr, ETH_ALEN) == 0) {
				*ifidx = i;
				return 0;
			}
		}
	}

	///TODO: transport broadcast ether addr pkt for ap(wlan0). only RX
	///TODO: this is a bug,
	if (is_multicast_ether_addr(eh->h_dest)) {
		*ifidx = 0;
		return 0;
	}

	WLAND_ERR("couldn't find address%pm\n", pktbuf->data);
	return -EBADE;
#endif

	if (pktbuf->len == 0)
		return -ENODATA;

	return 0;
}

/* 91h, setup chip */
int wland_preinit_cmds_91h(struct wland_if *ifp)
{
	s32 ret = 0;
	//u32 u32Val = 0;
	u8 val = 0;
	//u16 join_timeout;
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	//struct wland_bus *bus_if = drvr->bus_if;
	u8 *buf = prot->buf;
	u8 mode = ifp->vif->profile.mode;
	//struct wland_11n_action action;

	mutex_lock(&drvr->proto_block);
	memset(prot->buf, '\0', sizeof(prot->buf));

#if 0// no reset version
	val = 0;
	ret = wland_push_wid(buf, WID_RESET, &val, sizeof(val), false);
	if (ret < 0) {
		WLAND_ERR("put wid error\n");
		goto done;
	}
	buf += ret;
#endif

	ret = 0xffffffff;
	ret = wland_push_wid(buf, WID_MEMORY_ADDRESS, &ret, 4, false);
	if (ret < 0) {
		WLAND_ERR("put wid error\n");
		goto done;
	}
	buf += ret;

	ret = wland_push_wid(buf, WID_MAC_ADDR, ifp->mac_addr, ETH_ALEN, false);
	if (ret < 0) {
		WLAND_ERR("put wid error\n");
		goto done;
	}
	buf += ret;
/*
	action.category = 0x07;
	action.action = 0x02;
	memset(action.bssid, 0, ETH_ALEN);
	action.tid = 0x00;
	action.max_msdu = 0x10;
	action.ack_policy = 0x00;
	action.ba_policy = 0x01;
	action.buff_size = cpu_to_be16(0x10);
	action.ba_timeout = cpu_to_be16(0x00);
	action.add_ba_timeout = cpu_to_be16(0x00);

	ret = wland_push_wid(buf, WID_11N_P_ACTION_REQ, &action, sizeof(action), false);
	if (ret < 0) {
		WLAND_ERR("put wid error\n");
		goto done;
	}
	buf += ret;
*/

#ifdef WLAND_SET_TID
	val = WLAND_TID_NUM;
	ret = wland_push_wid(buf, WID_SET_TID, &val, sizeof(val), false);
	if (ret < 0) {
		WLAND_ERR("put wid error\n");
		goto done;
	}
	buf += ret;
#else
	val = WLAND_TID_NUM;
	if (strncasecmp(rdawlan_firmware_path, "ap", strlen("ap")) == 0) {
		val = WLAND_TID_NUM;
		ret = wland_push_wid(buf, WID_SET_TID, &val, sizeof(val), false);
		if (ret < 0) {
			WLAND_ERR("put wid error\n");
			goto done;
		}
		buf += ret;
	}
#endif

#ifdef WLAND_ENHANCE_MODE
	if (strncasecmp(rdawlan_firmware_path, "sta", strlen("sta"))==0 ||
		strncasecmp(rdawlan_firmware_path, "p2p", strlen("p2p"))==0) {
		val = 1;
		ret = wland_push_wid(buf, WID_ENHANCE_MODE, &val, sizeof(val), false);
		if (ret < 0) {
			WLAND_ERR("put wid error\n");
			goto done;
		}
		buf += ret;
	}
#endif

#ifdef WLAND_AMSDU_TX
    if (amsdu_operation & BIT0) {
        /* STA&GC modes only currently */
    	if (strncasecmp(rdawlan_firmware_path, "sta", strlen("sta")) == 0 ||
    		strncasecmp(rdawlan_firmware_path, "p2p", strlen("p2p")) == 0) {
    		val = AMSDU_TX_MODE_AMSDU;
    		ret = wland_push_wid(buf, WID_HOST_AMSDU_TX, &val, sizeof(val), false);
    		if (ret < 0) {
    			WLAND_ERR("put wid error\n");
    			goto done;
    		}
    		buf += ret;
    	}
    }
#endif

#ifdef WLAND_DEAMSDU_RX
    if (amsdu_operation & BIT1) {
		val = 1;
		ret = wland_push_wid(buf, WID_HOST_DEAMSDU_RX, &val, sizeof(val), false);
		if (ret < 0) {
			WLAND_ERR("put wid error\n");
			goto done;
		}
		buf += ret;
	}
#endif

#if 1
	val = 1;
	ret = wland_push_wid(buf, WID_QOS_ENABLE, &val, sizeof(val), false);
	if (ret < 0) {
		WLAND_ERR("put wid error\n");
		goto done;
	}
	buf += ret;
#endif

#if 0
	join_timeout = 2000;
	ret = wland_push_wid(buf, WID_JOIN_TIMEOUT, &join_timeout, sizeof(join_timeout), false);
	if (ret < 0) {
		WLAND_ERR("put wid error\n");
		goto done;
	}
	buf += ret;
#endif

	val = 1;
	ret = wland_push_wid(buf, WID_11N_IMMEDIATE_BA_ENABLED, &val, sizeof(val), false);
	if (ret < 0) {
		WLAND_ERR("put wid error\n");
		goto done;
	}
	buf += ret;

	val = WIFI_LISTEN_INTERVAL;
	ret = wland_push_wid(buf, WID_LISTEN_INTERVAL, &val, sizeof(val), false);
	if (ret < 0) {
		WLAND_ERR("put wid error\n");
		goto done;
	}
	buf += ret;

	val = WIFI_LINK_LOSS_THRESHOLD_91H;
	ret = wland_push_wid(buf, WID_LINK_LOSS_THRESHOLD, &val, sizeof(val), false);
	if (ret < 0) {
		WLAND_ERR("put wid error\n");
		goto done;
	}
	buf += ret;

	val = 1;
	ret = wland_push_wid(buf, WID_11N_SHORT_GI_ENABLE, &val, sizeof(val), false);
	if (ret < 0) {
		WLAND_ERR("put wid error\n");
		goto done;
	}
	buf += ret;

	val = 1;
	ret = wland_push_wid(buf, WID_RIFS_MODE, &val, sizeof(val), false);
	if (ret < 0) {
		WLAND_ERR("put wid error\n");
		goto done;
	}
	buf += ret;

#if 0
	val = G_RTS_CTS_PROT;
	ret = wland_push_wid(buf, WID_11N_ERP_PROT_TYPE, &val, sizeof(val), false);
	if (ret < 0) {
		WLAND_ERR("put wid error\n");
		goto done;
	}
	buf += ret;
#endif
	if (mode == WLAND_B_MODE) {
		val = B_ONLY_MODE;
		ret = wland_push_wid(buf, WID_11G_OPERATING_MODE, &val, sizeof(val), false);
		if (ret < 0) {
			WLAND_ERR("put wid error\n");
			goto done;
		}
		buf += ret;
	}

	val = 1;
	ret = wland_push_wid(buf, WID_2040_ENABLE, &val, sizeof(val), false);
	if (ret < 0) {
		WLAND_ERR("put wid error\n");
		goto done;
	}
	buf += ret;

//20180903 tbtt sleep to save power in ap mode
#if defined WLAND_AP_LOW_POWER
	if(strncasecmp(rdawlan_firmware_path, "ap", strlen("ap"))==0) {

		val = 3; //default
		ret = wland_push_wid(buf, WID_TBTT_SLEEP_CNT, &val, sizeof(val), false);
		if (ret < 0) {
			WLAND_ERR("put wid error\n");
			goto done;
		}
		buf += ret;

		val = 1; //1-ap low power mode  0-not ap low power mode
		ret = wland_push_wid(buf, WID_AP_LOW_POWER, &val, sizeof(val), false);
		if (ret < 0) {
			WLAND_ERR("put wid error\n");
			goto done;
		}
		buf += ret;
	}
#endif

#ifdef WLAND_POWER_MANAGER
	if (ifp->drvr->sleep_flags & WLAND_SLEEP_ENABLE) {
		if (strncasecmp(rdawlan_firmware_path, "sta", strlen("sta"))==0 ||
			strncasecmp(rdawlan_firmware_path, "p2p", strlen("p2p"))==0) {
			val = MAX_FAST_PS;
			ret = wland_push_wid(buf, WID_POWER_MANAGEMENT, &val, sizeof(val), false);
			if (ret < 0) {
				WLAND_ERR("put wid error\n");
				goto done;
			}
			buf += ret;
		}
		/*
		if (ifp->drvr->sleep_flags & WLAND_SLEEP_PREASSO) {
			u32Val = WIFI_PREASSO_SLEEP;
			err = wland_fil_set_cmd_data(ifp, WID_PREASSO_SLEEP, &u32Val,
				sizeof(u32Val));
			if (err < 0)
				goto done;
		}
		val = 1;
		sdio_claim_host(sdiodev->func);
		err = wland_sdioh_request_byte(sdiodev, SDIOH_WRITE,
			URSDIO_FUNC1_INT_TO_DEVICE, &val);
		sdio_release_host(sdiodev->func);
		if (err) {
			WLAND_ERR("Write URSDIO_FUNC1_INT_TO_DEVICE failed!\n");
		}
		*/
	}
#endif /* WLAND_POWER_MANAGER */

#ifdef WLAND_USB_SUPPORT
	val = 15;
	ret = wland_push_wid(buf, WID_WDT_TIMEOUT, &val, sizeof(val), false);
	if (ret < 0) {
		WLAND_ERR("put wid error\n");
		goto done;
	}
	buf += ret;
#endif

#ifdef WLAND_STA_CSA_SUPPORT
	if (strncasecmp(rdawlan_firmware_path, "sta", strlen("sta"))==0 ||
		strncasecmp(rdawlan_firmware_path, "p2p", strlen("p2p"))==0) {
		val = 1;
		ret = wland_push_wid(buf, WID_STA_ENABLE_CSA, &val, sizeof(val), false);
		if (ret < 0) {
			WLAND_ERR("put wid error\n");
			goto done;
		}
		buf += ret;
	}
#endif

#ifdef WLAND_DESCENT_EDGE_WAKEUP_HOST
	//0-Descent edge 1-Rising edge
	val = 0;
	ret = wland_push_wid(buf, WID_WAKEUP_HOST, &val, sizeof(val), false);
	if (ret < 0) {
		WLAND_ERR("put wid error\n");
		goto done;
	}
	buf += ret;
#endif

#ifdef WLAND_TXLEN_1536
	ret = wland_proto_cdc_data(drvr, 1536-2);//first time
#else
	ret = wland_proto_cdc_data(drvr, buf-(prot->buf) + FMW_HEADER_LEN);
#endif
	if (ret < 0)
		WLAND_ERR("WID Result Failed\n");

done:
	mutex_unlock(&drvr->proto_block);
	WLAND_DBG(DCMD, DEBUG, "Done(err:%d)\n", ret);
	return ret;
}

int wland_stop_chip(struct net_device *ndev)
{
#if (defined WLAND_USB_SUPPORT)
	int err = -ENODEV;
	struct wland_if *ifp = netdev_priv(ndev);
	struct wland_private *drvr;
	u8 val = 0;

	WLAND_DBG(DCMD, INFO, "Enter\n");

	if (!ifp) {
		WLAND_ERR("ifp Empty!\n");
		goto fail;
	}

	drvr = ifp->drvr;

	if (!drvr->bus_if->chip_ready) {
		WLAND_ERR("Wifi chip is not ready!\n");
		return 0;
	}

	err = wland_fil_set_cmd_data_without_rsp(ifp, WID_WDT_TIMEOUT, &val, 1);
	if (err < 0)
		WLAND_ERR("reset fw Failed\n");
 	else
		drvr->bus_if->chip_ready = 0;

fail:
	WLAND_DBG(DCMD, TRACE, "Done(err:%d)\n", err);
	return err;
#else /*WLAND_USB_SUPPORT*/
	return 0;
#endif /*WLAND_USB_SUPPORT*/

}

int wland_start_chip(struct net_device *ndev)
{
	int err = -ENODEV;
	struct wland_if *ifp = netdev_priv(ndev);
	struct wland_private *drvr;
	u32 memory_address = 0;
	char firmware_version[20];
#ifdef WLAND_FIRMWARE_PATH_FILE
	char firmware_path[4] = {0};

	WLAND_DBG(DEFAULT, INFO, "Enter.\n");
#ifdef WLAND_DRIVER_RELOAD_FW
	if (first_download_fw) {
#endif
		if (wland_nvram_read(WLAND_FIRMWARE_PATH_FILE, firmware_path, 4, 0) >= 0) {
			WLAND_DBG(DEFAULT, ERROR, "Firmwate_path in file is %s.\n", firmware_path);
			if ((strncasecmp(firmware_path, "ap", strlen("ap")) == 0)
				|| (strncasecmp(firmware_path, "sta", strlen("sta")) == 0)) {
				strcpy(rdawlan_firmware_path, firmware_path);
				WLAND_DBG(DEFAULT, ERROR, "Change firmwate_path to %s!\n",
					firmware_path);
			}
		} else {
			WLAND_DBG(DEFAULT, ERROR, "can not open %s!\n", WLAND_FIRMWARE_PATH_FILE);
		}
#ifdef WLAND_DRIVER_RELOAD_FW
	}
#endif
#endif

	if (!ifp) {
		WLAND_ERR("ifp Empty!\n");
		goto fail;
	}
	drvr = ifp->drvr;

	if (drvr->bus_if->chip_ready) {
		WLAND_ERR("Wifi chip is already ready!\n");
		return 0;
	}

	err = wland_bus_active(drvr->bus_if);
	if (err < 0) {
		WLAND_ERR("active bus failed!\n");
		goto fail;
	}

	if (wland_nvram_read(RDA5995_TESTMODE_FILE, NULL, 0, 0) >= 0)
		strcpy(rdawlan_firmware_path, "rf");
#if 0
	if (strncasecmp(rdawlan_firmware_path, "p2p", strlen("p2p")) == 0)
		drvr->p2p_enable = true;
	else
		drvr->p2p_enable = false;
#endif
	if (strncasecmp(rdawlan_firmware_path, "rf", strlen("rf")) == 0) {
		WLAND_DBG(RFTEST, INFO, "RF Test Mode!\n");
		wland_set_test_mode(1);
	} else
		wland_set_test_mode(0);

	WLAND_ERR("firmware_path:%s\n", rdawlan_firmware_path);

	WLAND_DBG(DCMD, DEBUG, "%s PATCH Enter\n",
		wland_check_test_mode()? "Test_mode" : "Nomal_mode");

	if (drvr->bus_if->chip == WLAND_VER_91_H) {
#ifdef WLAND_SDIO_SUPPORT
		struct wland_sdio_dev *sdiodev = drvr->bus_if->bus_priv.sdio;
		struct wland_sdio *bus = sdiodev->bus;
		bus->intr = true;
		bus->poll = false;
#ifdef WLAND_RDAPLATFORM_SUPPORT
		rda_mmc_set_sdio_irq(1, true);
#endif /*WLAND_RDAPLATFORM_SUPPORT*/
#endif /*WLAND_SDIO_SUPPORT */

		WLAND_DBG(TRAP, INFO, "Enter\n");
		err = wland_fil_get_cmd_data(ifp, WID_MEMORY_ADDRESS,
			&memory_address, 4);
		//printk("#######memory_address:%x\n", memory_address);
		if (err < 0) {
			WLAND_ERR("get firmware state failed!\n");
			goto fail;
		} else if (memory_address == 0xffffffff) {
			WLAND_ERR("skip download firmware\n");
			goto preinit;
		}

		err = wland_download_codefile(ifp);
		if (err < 0) {
			WLAND_ERR("download firmware failed!\n");
			goto fail;
		}

		err = wland_download_datafile(ifp);
		if (err < 0) {
			WLAND_ERR("download datafile failed!\n");
			goto fail;
		}

		err = wland_run_firmware(ifp, RDA5991H_CODE_ADDR);
		if (err < 0) {
			WLAND_ERR("run firmware failed!\n");
			goto fail;
		}
preinit:
		if (wland_check_test_mode() == 0) {
#ifdef WLAND_MACADDR_EFUSE
			if (drvr->bus_if->up_data_mac) {
				err = wland_cfg80211_updata_mac(drvr->config);
				if (err < 0) {
					WLAND_ERR("updata mac addr fail\n");
					//goto fail;
				}
			}
#endif /*WLAND_MACADDR_EFUSE*/

			if (strcasecmp(rdawlan_firmware_path, "ap") != 0) {
				err = wland_preinit_cmds_91h(ifp);//firt write wid must be preinit wids,
				if (err < 0) {
					WLAND_ERR("preinit cmds failed!\n");
					goto fail;
				}

				err = wland_set_scan_timeout(ifp);
				if (err < 0) {
					WLAND_ERR("set scan timeout failed!\n");
					goto fail;
				}
			}
		}

		if (strcasecmp(rdawlan_firmware_path, "ap") != 0)
			wland_config_and_efuse(ifp);
	}

	drvr->bus_if->chip_ready = 1;

	err = wland_fil_get_cmd_data(ifp, WID_CHIP_VERSION, &(drvr->bus_if->chip_version), 1);
	if (err < 0) {
		WLAND_ERR("Failed to get chip version, set u04\n");
		drvr->bus_if->chip_version = 4;
		err = 0;
	} else
		pr_err("[RDAWLAN_DRIVER] Chip Version:u%02d\n", drvr->bus_if->chip_version);

	memset(firmware_version, 0, 20);
	err = wland_fil_get_cmd_data(ifp, WID_FIRMWARE_VERSION, firmware_version, 20);
	if (err < 0) {
		WLAND_ERR("Failed to get Firmware version\n");
		err = 0;
	} else {
		firmware_version[19] = '\0';
		pr_err("[RDAWLAN_DRIVER] Firmware Version:%s\n", firmware_version);
	}

fail:
	WLAND_DBG(DEFAULT, INFO, "Done(err:%d)\n", err);

	return err >= 0 ? 0 : err;
}

#ifdef WLAND_DRIVER_RELOAD_FW
struct work_struct wland_chip_repower_work;
void wland_chip_repower(struct work_struct *work)
{
	WLAND_DBG(DEFAULT, INFO, "Enter.\n");
#ifdef WLAND_SDIO_SUPPORT
	wland_sdio_exit();
	msleep(1000);
	wland_sdio_register();
#else

	wland_usb_exit();
	msleep(1000);
	wland_usb_register();

#endif
	WLAND_DBG(DEFAULT, INFO, "Done.\n");
}
DECLARE_WORK(wland_chip_repower_work, wland_chip_repower);

struct wland_bus *bus_if_backup = NULL;
bool wland_repowering_chip = false;
bool first_download_fw = false;
struct semaphore repowering_sem;
#define REPOWER_TIMEOUT	100000
void wland_repower_sem_up(bool check_flag)
{
	wland_repowering_chip = check_flag;
	up(&repowering_sem);
}
int wland_repower_chip(struct net_device *ndev, enum nl80211_iftype type)
{
	struct wland_if *ifp = netdev_priv(ndev);

	WLAND_DBG(DEFAULT, INFO, "Enter type:%d\n", type);

	if (type == NL80211_IFTYPE_AP)
		strcpy(rdawlan_firmware_path, "ap");
	else if (type == NL80211_IFTYPE_STATION)
		strcpy(rdawlan_firmware_path, "sta");

	sema_init(&repowering_sem, 0);
	bus_if_backup = ifp->drvr->bus_if;
	wland_repowering_chip = true;

	schedule_work(&wland_chip_repower_work);

	WLAND_DBG(DEFAULT, INFO, "Waiting for repower!\n");
	if ((down_timeout(&repowering_sem,
		msecs_to_jiffies(REPOWER_TIMEOUT)) != 0)
		|| (wland_repowering_chip)) {
		WLAND_ERR("repowering timeout or error, registration_check:%d\n",
			wland_repowering_chip);
		return -1;
	}
	WLAND_DBG(DEFAULT, INFO, "Chip repower success!\n");
	return 0;
}
#endif
