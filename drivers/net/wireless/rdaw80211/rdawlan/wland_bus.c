
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
#include <linux/if_arp.h>
#include <linux/etherdevice.h>
#include <linux/wireless.h>
#include <linux/ieee80211.h>
#include <linux/kthread.h>
#include <linux/printk.h>
//#include <linux/export.h>
#include <linux/netdevice.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/completion.h>
#include <linux/scatterlist.h>
#include <linux/semaphore.h>
#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/vmalloc.h>
#include <asm/unaligned.h>
#include <net/cfg80211.h>
#include <net/rtnetlink.h>

#include "wland_defs.h"
#include "wland_utils.h"
#include "wland_fweh.h"
#include "wland_dev.h"
#include "wland_dbg.h"
#include "wland_wid.h"
#include "wland_bus.h"
#include "wland_sdmmc.h"
#include "wland_p2p.h"
#include "wland_amsdu.h"
#include "wland_cfg80211.h"
#include "wland_rf.h"

void wland_txflowcontrol(struct device *dev, bool state)
{
	int i = 0;
	struct wland_bus *bus_if = dev_get_drvdata(dev);
	struct wland_private *drvr = bus_if->drvr;

	//struct wland_sdio_dev *sdiodev = bus_if->bus_priv.sdio;
	struct wland_fws_info *fws = drvr->fws;
	//struct wland_sdio     *bus     = sdiodev->bus;

	WLAND_DBG(BUS, TRACE, "Enter\n");
	if (state) {
		fws->stats.bus_flow_block++;
	}

	for (i = 0; i < WLAND_MAX_IFS; i++) {
		if (drvr->iflist[i]) {
			if (state)
				netif_stop_queue(drvr->iflist[i]->ndev);
			else
				netif_wake_queue(drvr->iflist[i]->ndev);
		}
	}
}

int wland_bus_start(struct device *dev)
{
	int ret = -EINVAL;
	struct wland_bus *bus_if = dev_get_drvdata(dev);
	struct wland_private *drvr = NULL;
	struct wland_if *ifp = NULL;

#ifdef WLAND_P2P_SUPPORT
	struct wland_if *p2p_ifp = NULL;
#endif /* WLAND_P2P_SUPPORT */

#if (defined USE_MAC_FROM_RDA_NVRAM) || (defined WLAND_MACADDR_DYNAMIC)
	u8 mac_addr[ETH_ALEN];
#else
	u8 mac_addr[ETH_ALEN] = {0x00, 0x50, 0xc2, 0x5e, 0x10, 0x83};//{ 0x59, 0x95, 0x4c, 0x33, 0x22, 0x11 };
	//u8 mac_addr[ETH_ALEN] = { 0x00, 0x50, 0xC2, 0x5E, 0x10, 0x8F};//SoftAP-for-test
#endif /* USE_MAC_FROM_RDA_NVRAM */

	WLAND_DBG(BUS, TRACE, "Enter\n");

	if (!bus_if) {
		WLAND_ERR("bus if empty!\n");
		return -EINVAL;
	}
	drvr = bus_if->drvr;
	if (!drvr) {
		WLAND_ERR("drvr == NULL.\n");
		return -EINVAL;
	}

#if defined(USE_MAC_FROM_RDA_NVRAM)
	ret = wland_read_mac_from_nvram(mac_addr);
	if (ret) {
		WLAND_ERR("nvram:get a random ether address\n");
		random_ether_addr(mac_addr);
		if (ret == -EINVAL)
			wland_write_mac_to_nvram(mac_addr);
	} else {
		if (!is_valid_ether_addr(mac_addr)) {
			mac_addr[0] &= 0xfe; /* clear multicast bit */
			mac_addr[0] |= 0x02; /* set local assignment bit (IEEE802) */
			WLAND_ERR("nvram:get an invalid ether addr\n");
		}
	}
#elif (defined(WLAND_MACADDR_FROM_USER) && defined(WLAND_MACADDR_EFUSE))
	printk("n_Wifi mac:%d, %pM\n", n_WifiMac, WifiMac);
	if ((n_WifiMac == ETH_ALEN) && (is_valid_ether_addr(WifiMac))) {
		//wland_set_mac_address(WifiMac);
		memcpy(mac_addr, WifiMac, ETH_ALEN);
	} else if (wland_get_mac_address(mac_addr) != ETH_ALEN) {
		WLAND_DBG(DEFAULT, INFO, "no mac addr in file\n");
		drvr->bus_if->up_data_mac = 1;
		random_ether_addr(mac_addr);
		mac_addr[0] &= 0xfe; /* clear multicast bit */
		mac_addr[0] |= 0x02; /* set local assignment bit (IEEE802) */
		if (wland_set_mac_address(mac_addr) < 0) {
			WLAND_ERR("set cur_etheraddr failed!\n");
			//return -ENODEV;
		}
	} else {
		WLAND_DBG(BUS, INFO, "get mac addr:%pM\n", mac_addr);
	}

#elif defined(WLAND_MACADDR_EFUSE)
	if (wland_get_mac_address(mac_addr) != ETH_ALEN) {
		WLAND_DBG(DEFAULT, INFO, "no mac addr in file\n");
		drvr->bus_if->up_data_mac = 1;
		random_ether_addr(mac_addr);
		mac_addr[0] &= 0xfe; /* clear multicast bit */
		mac_addr[0] |= 0x02; /* set local assignment bit (IEEE802) */
		if (wland_set_mac_address(mac_addr) < 0) {
			WLAND_ERR("set cur_etheraddr failed!\n");
			//return -ENODEV;
		}
	} else {
		WLAND_DBG(BUS, INFO, "get mac addr:%pM\n", mac_addr);
	}
#elif defined(WLAND_MACADDR_DYNAMIC)
	if (wland_get_mac_address(mac_addr) != ETH_ALEN) {
		WLAND_DBG(DEFAULT, INFO, "no mac addr in file\n");;
		random_ether_addr(mac_addr);
		mac_addr[0] &= 0xfe; /* clear multicast bit */
		mac_addr[0] |= 0x02; /* set local assignment bit (IEEE802) */
		if (wland_set_mac_address(mac_addr) < 0) {
			WLAND_ERR("set cur_etheraddr failed!\n");
			//return -ENODEV;
		}
	} else {
		WLAND_DBG(BUS, INFO, "get mac addr:%pM\n", mac_addr);
	}
#endif

	WLAND_DBG(CFG80211, INFO, "get mac addr:%pM\n", mac_addr);
	WLAND_DBG(CFG80211, INFO, "get amsdu:0x%x\n", amsdu_operation);
	/*
	 * add primary networking interface
	 */
	ifp = wland_add_if(drvr, 0, 0, "wlan%d", mac_addr);

	if (IS_ERR(ifp)) {
		WLAND_ERR("wland_add_if failed!\n");
		return PTR_ERR(ifp);
	}

#ifdef DEBUG_FILE
	ret = wland_proc_init(ifp->ndev);
	if (ret) {
		WLAND_ERR("proc init failed!\n");
		ret = 0;
	}
#endif

#ifdef WLAND_P2P_SUPPORT
	if (drvr->p2p_enable)
		p2p_ifp = wland_add_if(drvr, 1, 0, "p2p%d", NULL);
	else
		p2p_ifp = NULL;

	if (IS_ERR(p2p_ifp))
		p2p_ifp = NULL;
#endif /* WLAND_P2P_SUPPORT */

	ret = wland_fws_init(drvr);
	if (ret < 0)
		goto out;

	wland_fws_add_interface(ifp);

#if defined(WLAND_CFG80211_SUPPORT)
	drvr->config = wland_cfg80211_attach(drvr, bus_if->dev);
	if (!drvr->config) {
		WLAND_ERR("wland_cfg80211_attach failed\n");
		ret = -ENOMEM;
		goto out;
	}
#endif /* WLAND_CFG80211_SUPPORT */

	ret = wland_netdev_attach(ifp);
	if (ret < 0) {
		WLAND_ERR("netdev attach,failed:%d\n", ret);
		goto out;
	}

#ifdef WLAND_P2P_SUPPORT
	if (drvr->p2p_enable && p2p_ifp) {
		if (wland_netdev_p2p_attach(p2p_ifp) < 0) {
			WLAND_ERR("p2p attach failed: %d.\n", ret);
			drvr->p2p_enable = false;
			ret = -EBADE;
			goto netdev_p2p_attach_fail;
		}
	}
#endif /* WLAND_P2P_SUPPORT */

#ifdef WLAND_P2P_SUPPORT
	if (ret<0 && p2p_ifp && p2p_ifp->ndev) {
		WLAND_ERR("free_netdev p2p_ifp->ndev\n");
		unregister_netdev(p2p_ifp->ndev);
		drvr->iflist[1] = NULL;
	}
netdev_p2p_attach_fail:
#endif /* WLAND_P2P_SUPPORT */

	if (ret<0 && ifp && ifp->ndev) {
		WLAND_ERR("unregister netdev.\n");
		unregister_netdev(ifp->ndev);
		drvr->iflist[0] = NULL;
	}


	if (ret < 0) {
out:
		bus_if->state = WLAND_BUS_DOWN;
		if (drvr->config) {
			WLAND_ERR("cfg80211_detach\n");
			wland_cfg80211_detach(drvr->config);
		}

		if (drvr->fws) {
			WLAND_ERR("wland_fws_deinit\n");
			if (ifp)
				wland_fws_del_interface(ifp);
			wland_fws_deinit(drvr);
		}

		if (drvr->iflist[0]) {
			free_netdev(drvr->iflist[0]->ndev);
			drvr->iflist[0] = NULL;
		}
#ifdef WLAND_P2P_SUPPORT
		if (drvr->iflist[1]) {
			free_netdev(drvr->iflist[1]->ndev);
			drvr->iflist[1] = NULL;
		}
#endif /* WLAND_P2P_SUPPORT */

		wland_registration_sem_up(false);
	} else {
		/* notify insmod ko ok */
		wland_registration_sem_up(true);
	}

	WLAND_DBG(BUS, TRACE, "Done.(ret=%d)\n", ret);
	return ret;
}

void wland_txcomplete(struct device *dev, struct sk_buff *txp, bool success)
{
	struct wland_bus *bus_if = NULL;
	struct wland_private *drvr = NULL;
	struct wland_if *ifp;
	struct ethhdr *eh;
	s32 ifidx = 0;
	u16 type;
	int res;
	if(dev == NULL){
		WLAND_ERR("Invalid dev!\n");
		goto done;
	}
	bus_if = dev_get_drvdata(dev);

	if(bus_if == NULL){
		WLAND_ERR("Invalid bus_if!\n");
		goto done;
	}
	drvr = bus_if->drvr;
	WLAND_DBG(BUS, TRACE, "Enter,success:%d\n", success);

	if(txp == NULL || txp->dev == NULL){
		WLAND_ERR("Invalid txp!\n");
		return;
	}

	res = wland_proto_hdrpull(drvr, &ifidx, txp);
#ifndef WLAND_5991H_MAC1_SUPPORT
	ifp = drvr->iflist[ifidx];
	WLAND_ERR("tx complete config:%d\n", txp->dev == ifp->ndev);
	WLAND_ERR("%p:%p\n", txp->dev, drvr->iflist[ifidx]->ndev);
	WLAND_ERR("%d:%d\n", ((struct wland_if *)netdev_priv(txp->dev))->bssidx, ifidx);
#else
	ifp = netdev_priv(txp->dev);
#endif

	if (!ifp) {
		WLAND_ERR("ifp == NULL\n");
		goto done;
	}

	if (res == 0) {
		eh = (struct ethhdr *) (txp->data);
		type = ntohs(eh->h_proto);

		WLAND_DBG(BUS, TRACE, "type:%d\n", type);

		if (type == ETH_P_PAE) {
			atomic_dec(&ifp->pend_8021x_cnt);
			WLAND_DBG(DCMD, TRACE, "tx eapol com:%d, %d\n",
						ifp->bssidx, atomic_read(&ifp->pend_8021x_cnt));
			if (waitqueue_active(&ifp->pend_8021x_wait))
				wake_up(&ifp->pend_8021x_wait);
		}
	}
	/*if (!success)
		ifp->stats.tx_errors++;*/
done:
#ifndef WLAND_TX_AGGRPKTS
	if(txp == NULL){
		WLAND_ERR("txp == NULL!\n");
		return;
	}
	dev_kfree_skb_any(txp);
#endif
	WLAND_DBG(BUS, TRACE, "Done\n");
}

int wland_bus_active(struct wland_bus *bus_if)
{
	int ret = -1;

#ifdef WLAND_DRIVER_RELOAD_FW
	if(wland_repowering_chip == true)
		wland_repowering_chip = false;
#endif
	/*
	 * Bring up the bus
	 */
	ret = wland_bus_init(bus_if);
	if (ret < 0)
		WLAND_ERR("bus init failed %d\n", ret);
#ifdef WLAND_AP_RESET
	if(ap_reseting == true)
		ap_reseting = false;
#endif
	return ret;
}

int wland_bus_attach(uint bus_hdrlen, struct device *dev)
{
	int ret = 0;
	struct wland_bus *bus_if;
	struct wland_private *drvr = NULL;
#ifdef WLAND_SET_POWER_BY_RATE
	u8 powers[ALL_RATE_NUM] = {
		0x35, 0x35, 0x35, 0x35,//11b
		0x50, 0x50, 0x50, 0x50,//11g
		0x50, 0x50, 0x50, 0x50,
		0x45, 0x45, 0x45, 0x45,//11n
		0x45, 0x45, 0x45, 0x45
	};
#endif
	u8 rates[ALL_RATE_NUM] = {
		1,2,5,11,//11b
		6,9,12,18,24,36,48,54,//11g
		0,1,2,3,4,5,6,7 //11n
	};

	WLAND_DBG(BUS, TRACE, "Enter\n");

	if (!dev) {
		WLAND_ERR("Not Found Dev!\n");
		return -1;
	}
	bus_if = dev_get_drvdata(dev);

	/*
	 * Allocate primary wland_info
	 */
	drvr = kzalloc(sizeof(struct wland_private), GFP_KERNEL);
	if (!drvr) {
		WLAND_ERR("Drvr Malloc Failed!\n");
		return -ENOMEM;
	}

	mutex_init(&drvr->proto_block);

	mutex_init(&drvr->rf_result_block);
	drvr->pkt_fcs_success = 0;
	drvr->pkt_rx_complete = 0;
	drvr->power_g_n_offset = 0;
	drvr->current_mode = WLAND_N_MODE;

	/*
	 * Link to bus module
	 */
	drvr->hdrlen = bus_hdrlen;
	drvr->bus_if = bus_if;

	drvr->country_code = WLAND_DEFAULT_COUNTRY_CODE;

	drvr->power_11f = 0x45;
	drvr->power_120 = 0x35;
#ifdef WLAND_SET_POWER_BY_RATE
	memset(drvr->power_rates_gain, 0, ALL_RATE_NUM);
	memcpy(drvr->power_rates_value, powers, ALL_RATE_NUM);
	drvr->power_by_rate = 0;
#endif
	memcpy(drvr->rates, rates, ALL_RATE_NUM);

#ifdef WLAND_P2P_SUPPORT
	drvr->p2p_enable = true;
#endif /*WLAND_P2P_SUPPORT */

	/*
	 * setup chip sleep flag
	 */
#ifdef WLAND_POWER_MANAGER
	drvr->sleep_flags = WLAND_SLEEP_ENABLE | WLAND_SLEEP_PREASSO;
#endif /*WLAND_POWER_MANAGER */

	bus_if->drvr = drvr;

	/*
	 * create device debugfs folder
	 */
	wland_debugfs_attach(drvr);
	wland_debugfs_create(drvr);

	/*
	 * Attach and link in the protocol
	 */
	ret = wland_proto_attach(drvr);
	if (ret < 0) {
		WLAND_ERR("proto_attach failed\n");
		goto fail;
	}

	/*
	 * attach firmware event handler
	 */
	wland_fweh_attach(drvr);

	WLAND_DBG(BUS, TRACE, "Done\n");

	return ret;

fail:
	wland_bus_detach(dev);

	return ret;
}

void wland_bus_detach(struct device *dev)
{
	s32 i;
	struct wland_bus *bus_if;
	struct wland_private *drvr;

	WLAND_DBG(BUS, TRACE, "Enter\n");

	if (!dev) {
		WLAND_ERR("Not Found Dev!\n");
		return;
	}
	bus_if = dev_get_drvdata(dev);
	drvr = bus_if->drvr;

	if (!drvr) {
		WLAND_ERR("Not Found Private Val!\n");
		return;
	}

#ifdef DEBUG_FILE
	wland_proc_deinit();
#endif

	/*
	 * stop firmware event handling
	 */
	wland_fweh_detach(drvr);

	/*
	 * make sure primary interface removed last
	 */
	for (i = WLAND_MAX_IFS - 1; i > -1; i--) {
		if (drvr->iflist[i]) {
			wland_fws_del_interface(drvr->iflist[i]);
			wland_del_if(drvr, i);
		}
	}

	/*
	 * Stop the bus module
	 */
	if (drvr)
		wland_bus_stop(drvr->bus_if);

	if (drvr->prot)
		wland_proto_detach(drvr);

	wland_fws_deinit(drvr);
	wland_debugfs_detach(drvr);
	bus_if->drvr = NULL;
	kfree(drvr);
	WLAND_DBG(BUS, TRACE, "Done\n");
}

#ifdef WLAND_DRIVER_RELOAD_FW
void wland_bus_detach_repowering(struct device *dev)
{

	struct wland_bus *bus_if;
	struct wland_private *drvr;
	struct wland_if *ifp;

	WLAND_DBG(BUS, TRACE, "Enter\n");

	if (!dev) {
		WLAND_ERR("Not Found Dev!\n");
		return;
	}
	bus_if = dev_get_drvdata(dev);
	drvr = bus_if->drvr;
	if (!drvr) {
		WLAND_ERR("Not Found Private Val!\n");
		return;
	}

	ifp = drvr->iflist[0];
	if (!ifp) {
		WLAND_ERR("!ifp\n");
		return;
	}

#ifdef WLAND_SMART_CONFIG_SUPPORT
	ifp->sniffer_enable = false;
#endif
	cancel_work_sync(&(drvr->fweh.event_work));
	//wland_cfg80211_down(ifp->ndev); //done when wland_netdev_stop
	cancel_work_sync(&ifp->setmacaddr_work);
	cancel_work_sync(&ifp->multicast_work);
	if (drvr->config && !IS_ERR(drvr->config)) {
		struct wland_cfg80211_info *cfg = drvr->config;
		struct wland_cfg80211_vif *vif;
		//struct wland_cfg80211_vif *tmp;
		struct wland_bss_info_le *bss;
		struct wland_bss_info_le *bss_tmp;
		struct wland_cfg80211_connect_info *conn_info;
		struct wland_p2p_info *p2p = &cfg->p2p;
		struct wland_cfg80211_vif *vif_p2p =
			p2p->bss_idx[P2PAPI_BSSCFG_DEVICE].vif;
		/*wland_cfg80211_detach(drvr->config);*/
		list_for_each_entry(vif, &cfg->vif_list, list) {
			conn_info = &vif->conn_info;

			if (timer_pending(&conn_info->timer))
				del_timer_sync(&conn_info->timer);

			if (timer_pending(&conn_info->connect_restorework_timeout))
				del_timer_sync(&conn_info->connect_restorework_timeout);

			cancel_work_sync(&conn_info->work);
			cancel_work_sync(&conn_info->connect_restorework_timeout_work);

			vif->profile.mode = WLAND_ERR_MODE;
		}
		wland_abort_scanning(cfg);
		if (p2p) {
			cancel_delayed_work_sync(&p2p->delay_remain_onchannel_work);

			if (timer_pending(&p2p->p2p_alive_timer)) {
				del_timer_sync(&p2p->p2p_alive_timer);
			}
			cancel_work_sync(&p2p->p2p_alive_timeout_work);

			if (vif_p2p) {
				//wland_p2p_cancel_remain_on_channel(vif_p2p->ifp);
				//wland_p2p_deinit_discovery(p2p);
			}
		}
#if defined(WLAND_RSSIAVG_SUPPORT)
		wland_free_rssi_cache(&g_rssi_cache_ctrl);
#endif
#if defined(WLAND_BSSCACHE_SUPPORT)
		wland_release_bss_cache_ctrl(&g_bss_cache_ctrl);
#endif
		mutex_lock(&cfg->scan_result_lock);
		list_for_each_entry_safe(bss, bss_tmp, &cfg->scan_result_list, list) {
			//wland_free_bss(cfg, bss);
			list_del(&bss->list);
			if (cfg->scan_results.count == 0)
				WLAND_ERR("bss count error\n");
			cfg->scan_results.count --;

			if (bss->ie)
				kfree(bss->ie);
			kfree(bss);
		}
		mutex_unlock(&cfg->scan_result_lock);
	}

	wland_bus_stop(drvr->bus_if);
}
#endif
