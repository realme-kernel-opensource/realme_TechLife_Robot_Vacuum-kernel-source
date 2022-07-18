/*
 * Copyright (c) 2015 iComm-semi Ltd.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */



#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/nl80211.h>
#include <linux/kthread.h>
#include <linux/etherdevice.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0)
#include <crypto/hash.h>
#else
#include <linux/crypto.h>
#endif
#include <linux/rtnetlink.h>

#include <ssv_chip_id.h>
#include <ssv6200.h>
#include <hci/hctrl.h>
#include <ssv_version.h>
#include <ssv_firmware_version.h>
#include "ssv_skb.h"
#include "dev_tbl.h"
#include "dev.h"
#include "lib.h"
#include "ap.h"
#include "regd.h"
#include "efuse.h"
#include "wow.h"
#include "init.h"
#include "ssv_skb.h"
#include "ssv_cli.h"
#include "hw_scan.h"
#include <hal.h>
#include <linux_80211.h>

#ifdef CONFIG_SSV_SUPPORT_ANDROID
#include "ssv_pm.h"
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
#include "linux_2_6_35.h"
#endif

#ifdef CONFIG_SSV6XXX_DEBUGFS
#include "ssv6xxx_debugfs.h"
#endif

#ifdef CONFIG_PREALLOC_TRX_BIG_SKB
#include "../prealloc/ssv6xxx_prealloc_skb.h"

extern int ssv_tx_recycle_skb_size;
extern int ssv_rx_recycle_skb_size;
#endif

MODULE_AUTHOR("iComm-semi, Ltd");
MODULE_DESCRIPTION("Support for SSV6xxx wireless LAN cards.");
MODULE_SUPPORTED_DEVICE("SSV6xxx 802.11n WLAN cards");
MODULE_LICENSE("Dual BSD/GPL");

static const struct ieee80211_iface_limit ssv6xxx_p2p_limits[] = {
	{
		.max = 2,
		.types = BIT(NL80211_IFTYPE_STATION),
	},
	{
		.max = 1,
		.types = BIT(NL80211_IFTYPE_P2P_GO) |
		     BIT(NL80211_IFTYPE_P2P_CLIENT) |
             BIT(NL80211_IFTYPE_ADHOC) |
			 BIT(NL80211_IFTYPE_AP),
	},
};


static const struct ieee80211_iface_combination
ssv6xxx_iface_combinations_p2p[] = {
	{ .num_different_channels = 1,
	  .max_interfaces = SSV6200_MAX_VIF,
	  .beacon_int_infra_match = true,
	  .limits = ssv6xxx_p2p_limits,
	  .n_limits = ARRAY_SIZE(ssv6xxx_p2p_limits),
	},
};

extern struct ssv6xxx_cfg ssv_cfg;
static void ssv6xxx_stop_all_running_threads(struct ssv_softc *sc) ;

#define HT_CAP_RX_STBC_ONE_STREAM	0x1

void ssv6xxx_set_80211_hw_rate_config(struct ssv_softc *sc)
{
	struct ieee80211_hw *hw = sc->hw;
	
	hw->max_rates = 4;
	hw->max_rate_tries = HW_MAX_RATE_TRIES;
}

static void ssv6xxx_set_80211_hw_capab(struct ssv_softc *sc)
{
    struct ieee80211_hw *hw=sc->hw;
    struct ssv_hw *sh=sc->sh;
    struct ieee80211_sta_ht_cap *ht_info;

    /* see mac80211.h */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
    hw->flags = IEEE80211_HW_SIGNAL_DBM;
    hw->flags |= IEEE80211_HW_HAS_RATE_CONTROL;
#ifdef CONFIG_HW_SCAN
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)
    hw->flags |= IEEE80211_SINGLE_HW_SCAN_ON_ALL_BANDS;
#endif
#endif
#else
    ieee80211_hw_set(hw, SIGNAL_DBM);
    ieee80211_hw_set(hw, HAS_RATE_CONTROL);
#ifdef CONFIG_HW_SCAN
    ieee80211_hw_set(hw, SINGLE_SCAN_ON_ALL_BANDS);
#endif
#endif
    
    //hw->flags |= IEEE80211_HW_2GHZ_SHORT_SLOT_INCAPABLE;
    //hw->flags |= IEEE80211_HW_2GHZ_SHORT_PREAMBLE_INCAPABLE;
   
    // Freddie ToDo: Clarify the effect of IEEE80211_HW_SUPPORTS_PS and IEEE80211_HW_PS_NULLFUNC_STACK
#ifdef CONFIG_SSV_SUPPORT_ANDROID
    //hw->flags |= IEEE80211_HW_SUPPORTS_PS;
    //hw->flags |= IEEE80211_HW_PS_NULLFUNC_STACK;
#endif        
    /* Set rate control algorithm if enabled*/
	//rate control should always enabled
	SSV_RC_ALGORITHM(sc);

    /* set HT capability if hardware suppports HT mode */
    ht_info = &sc->sbands[INDEX_80211_BAND_2GHZ].ht_cap;

    if (sh->cfg.hw_caps & SSV6200_HW_CAP_HT) {
        if (sh->cfg.hw_caps & SSV6200_HW_CAP_AMPDU_RX) 
        {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
            hw->flags |= IEEE80211_HW_AMPDU_AGGREGATION;
            hw->flags |= IEEE80211_HW_SPECTRUM_MGMT;
#else
            ieee80211_hw_set(hw, AMPDU_AGGREGATION);
            ieee80211_hw_set(hw, SPECTRUM_MGMT); 
#endif
        }
        
        /*  SM Power Save disabled */
        ht_info->cap |= IEEE80211_HT_CAP_SM_PS; 
        
        if (sh->cfg.hw_caps & SSV6200_HW_CAP_GF)
            ht_info->cap |= IEEE80211_HT_CAP_GRN_FLD;

        if (sh->cfg.hw_caps & SSV6200_HW_CAP_STBC)
            ht_info->cap |= HT_CAP_RX_STBC_ONE_STREAM << IEEE80211_HT_CAP_RX_STBC_SHIFT;
            
        if (sh->cfg.hw_caps & SSV6200_HW_CAP_HT40)
            ht_info->cap |= IEEE80211_HT_CAP_SUP_WIDTH_20_40;
        
        if (sh->cfg.hw_caps & SSV6200_HW_CAP_SGI) {
            ht_info->cap |= IEEE80211_HT_CAP_SGI_20;
            if (sh->cfg.hw_caps & SSV6200_HW_CAP_HT40) {
                ht_info->cap |= IEEE80211_HT_CAP_SGI_40;
            }
        }
        
        if (0 == sh->cfg.ampdu_rx_size_cap) 
            ht_info->ampdu_factor = IEEE80211_HT_MAX_AMPDU_8K;
        else if (1 == sh->cfg.ampdu_rx_size_cap)
            ht_info->ampdu_factor = IEEE80211_HT_MAX_AMPDU_16K;
        else if (2 == sh->cfg.ampdu_rx_size_cap)
            ht_info->ampdu_factor = IEEE80211_HT_MAX_AMPDU_32K;
        else     
            ht_info->ampdu_factor = IEEE80211_HT_MAX_AMPDU_64K;
        
        ht_info->ampdu_density = IEEE80211_HT_MPDU_DENSITY_8;
        
        memset(&ht_info->mcs, 0, sizeof(ht_info->mcs));
        ht_info->mcs.rx_mask[0] = 0xff;
        ht_info->mcs.tx_params |= IEEE80211_HT_MCS_TX_DEFINED;
	    ht_info->mcs.rx_highest = cpu_to_le16(SSV6200_RX_HIGHEST_RATE);
        ht_info->ht_supported = true;
    }

    hw->wiphy->max_scan_ssids = 32;
    hw->wiphy->max_scan_ie_len = 512;
    hw->wiphy->interface_modes = BIT(NL80211_IFTYPE_STATION);
    hw->wiphy->interface_modes |= BIT(NL80211_IFTYPE_ADHOC);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
    if (sh->cfg.hw_caps & SSV6200_HW_CAP_P2P) {
        hw->wiphy->interface_modes |= BIT(NL80211_IFTYPE_P2P_CLIENT);
        hw->wiphy->interface_modes |= BIT(NL80211_IFTYPE_P2P_GO);

//        BIT(NL80211_IFTYPE_P2P_DEVICE)???
        
        hw->wiphy->iface_combinations = ssv6xxx_iface_combinations_p2p;
		hw->wiphy->n_iface_combinations = ARRAY_SIZE(ssv6xxx_iface_combinations_p2p);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0)
        hw->wiphy->flags |= WIPHY_FLAG_ENFORCE_COMBINATIONS;
#endif//3.5.0
    }
#endif


#if LINUX_VERSION_CODE > KERNEL_VERSION(3,5,0)
    hw->wiphy->flags |= WIPHY_FLAG_HAS_REMAIN_ON_CHANNEL;
#endif

    if (sh->cfg.hw_caps & SSV6200_HW_CAP_AP){
        hw->wiphy->interface_modes |= BIT(NL80211_IFTYPE_AP);
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,1,0)
        hw->wiphy->flags |= WIPHY_FLAG_AP_UAPSD;
#endif
    }
    
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,0,8)
    if (sh->cfg.hw_caps & SSV6200_HW_CAP_TDLS){
      hw->wiphy->flags |= WIPHY_FLAG_SUPPORTS_TDLS;
      hw->wiphy->flags |= WIPHY_FLAG_TDLS_EXTERNAL_SETUP;
      printk("TDLS function enabled in sta.cfg\n");
    }
#endif

    hw->wiphy->flags |= WIPHY_FLAG_IBSS_RSN;

    hw->queues = 4;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)	
	hw->channel_change_time = 5000;
#endif	
	hw->max_listen_interval = 1;
	//set hw support max rate and rate retry
	SSV_SET_80211HW_RATE_CONFIG(sc);
    hw->extra_tx_headroom = TXPB_OFFSET;
    if (sizeof(struct ampdu_hdr_st) > SSV_SKB_info_size)
        hw->extra_tx_headroom += sizeof(struct ampdu_hdr_st);
    else
        hw->extra_tx_headroom += SSV_SKB_info_size;

    if (sh->cfg.hw_caps & SSV6200_HW_CAP_2GHZ) {
		hw->wiphy->bands[INDEX_80211_BAND_2GHZ] =
			&sc->sbands[INDEX_80211_BAND_2GHZ];
    }

    if (sh->cfg.hw_caps & SSV6200_HW_CAP_5GHZ) {
        memcpy(&sc->sbands[INDEX_80211_BAND_5GHZ].ht_cap, ht_info,
            sizeof(struct ieee80211_sta_ht_cap));
		hw->wiphy->bands[INDEX_80211_BAND_5GHZ] =
			&sc->sbands[INDEX_80211_BAND_5GHZ];
    }
//    SET_IEEE80211_PERM_ADDR(hw, sh->cfg.maddr);
    
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
    /* Set rate control algorithm if enabled*/
    /* max rx aggr size will affect buffer size in addba response 
       and affect hw BA window size. For Cabrio, hw ba window size must be 64
       otherwise, it will get compatibility issue */
    
    /*if (sh->cfg.hw_caps & SSV6200_HW_CAP_AMPDU_TX)
        #ifdef PREFER_RX
        hw->max_rx_aggregation_subframes = 64; //SSV_AMPDU_TX_SUBFRAME_NUM;
        #else // PREFER_RX
        hw->max_rx_aggregation_subframes = 16; //SSV_AMPDU_RX_SUBFRAME_NUM;
        #endif // PREFER_RX
    else
        hw->max_rx_aggregation_subframes = 12; //SSV_AMPDU_RX_SUBFRAME_NUM;*/
        
    hw->max_rx_aggregation_subframes = sh->cfg.max_rx_aggr_size; 

    hw->max_tx_aggregation_subframes = 64; //SSV_AMPDU_TX_SUBFRAME_NUM;
#endif
    
    hw->sta_data_size = sizeof(struct ssv_sta_priv_data); /* drv_priv sizeof of struct ieee80211_sta */
    hw->vif_data_size = sizeof(struct ssv_vif_priv_data); /* drv_priv sizeof of struct ieee80211_vif */

    // Freddie ToDo: Get device configuration from device ID.

    /* Assign all mac addresses to wiphy */
    memcpy(sh->maddr[0].addr, &sh->cfg.maddr[0][0], ETH_ALEN);
    hw->wiphy->addresses = sh->maddr;
    hw->wiphy->n_addresses = 1;

    // Freddie ToDo:
    //  Add MAC address from hardware capability of # interfaces not P2P.
    //  Use mask instead of MAC address
    if (sh->cfg.hw_caps & SSV6200_HW_CAP_P2P) {
        int i;
        for (i = 1; i < SSV6200_MAX_HW_MAC_ADDR; i++) {
    		memcpy(sh->maddr[i].addr, sh->maddr[i-1].addr,
    		       ETH_ALEN);
    		sh->maddr[i].addr[5]++;
    		hw->wiphy->n_addresses++;
    	}
    }
    // If second MAC address exists in configuration, enable dual interface.
    if (!is_zero_ether_addr(sh->cfg.maddr[1]))
    {
        memcpy(sh->maddr[1].addr, sh->cfg.maddr[1], ETH_ALEN);
        if (hw->wiphy->n_addresses < 2)
            hw->wiphy->n_addresses = 2;
    }

#ifdef CONFIG_PM
    ssv6xxx_attach_wow(sc);
#endif

    if (sh->cfg.hw_caps & SSV6200_HW_CAP_REPORT_TX_ACK)
    {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
        hw->flags |= IEEE80211_HW_REPORTS_TX_ACK_STATUS;
#else
        ieee80211_hw_set(hw, REPORTS_TX_ACK_STATUS);
#endif
    }
}

static void ssv6xxx_preload_sw_cipher(void)
{
    return;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0))
static inline void house_keeping_timer_hdl(struct timer_list *in_timer)
{
	struct ssv_timer_list *ptimer = from_timer(ptimer, in_timer, timer);
	ptimer->function((unsigned long)ptimer->arg);
}
#endif

static int ssv6xxx_init_softc(struct ssv_softc *sc)
{
    int ret=0;
#ifdef CONFIG_THROUGHPUT_PROFILE
	int i = 0;
#endif

    mutex_init(&sc->mutex);
    mutex_init(&sc->mem_mutex);
    mutex_init(&sc->ampdu_stop_mutex);

    sc->config_wq= create_singlethread_workqueue("ssv6xxx_cong_wq");
    
    INIT_WORK(&sc->hw_restart_work, ssv6xxx_restart_hw);
    INIT_WORK(&sc->set_tim_work, ssv6200_set_tim_work);
    INIT_WORK(&sc->beacon_miss_work, ssv6xxx_beacon_miss_work);
    INIT_WORK(&sc->bcast_start_work, ssv6200_bcast_start_work);
    INIT_DELAYED_WORK(&sc->bcast_stop_work, ssv6200_bcast_stop_work);
    INIT_DELAYED_WORK(&sc->bcast_tx_work, ssv6200_bcast_tx_work);
    INIT_WORK(&sc->set_ampdu_rx_add_work, ssv6xxx_set_ampdu_rx_add_work);
    INIT_WORK(&sc->set_ampdu_rx_del_work, ssv6xxx_set_ampdu_rx_del_work);

#ifdef CONFIG_SSV_SUPPORT_ANDROID
#ifdef CONFIG_HAS_EARLYSUSPEND
    sc->early_suspend.level = EARLY_SUSPEND_LEVEL_BLANK_SCREEN + 20;
    sc->early_suspend.suspend = ssv6xxx_early_suspend;
    sc->early_suspend.resume = ssv6xxx_late_resume;
    register_early_suspend(&sc->early_suspend);
#endif //CONFIG_HAS_EARLYSUSPEND
    ssv_wakelock_init(sc);
#endif    
	//use to send mcast frame.
//	init_timer(&sc->bcast_timeout);	
//	sc->bcast_timeout.data = (unsigned long)sc;
//	sc->bcast_timeout.function = ssv6200_bcast_timer;
	

    /* By default, we apply staion decion table. */
    sc->mac_deci_tbl = sta_deci_tbl;
    
    /**
        * Initialize tx: 
        * Associate WMM AC queue to each hardward tx queue.
        * For hardware queue, queue 0 has the lowest priority.
        */
    memset((void *)&sc->tx, 0, sizeof(struct ssv_tx));
    sc->tx.hw_txqid[WMM_AC_VO] = 3; sc->tx.ac_txqid[3] = WMM_AC_VO;
    sc->tx.hw_txqid[WMM_AC_VI] = 2; sc->tx.ac_txqid[2] = WMM_AC_VI;
    sc->tx.hw_txqid[WMM_AC_BE] = 1; sc->tx.ac_txqid[1] = WMM_AC_BE;
    sc->tx.hw_txqid[WMM_AC_BK] = 0; sc->tx.ac_txqid[0] = WMM_AC_BK;   

    // init ampdu tx queue ==============================
    INIT_LIST_HEAD(&sc->tx.ampdu_tx_que);
    // init spinlock ===================================
    spin_lock_init(&sc->tx.ampdu_tx_que_lock);

    /**
        * Initialize rx: 
        * Allocate a dedicate skb for receiving data from interface (SDIO).
        */
    memset((void *)&sc->rx, 0, sizeof(struct ssv_rx));
    spin_lock_init(&sc->rx.rxq_lock);
    skb_queue_head_init(&sc->rx.rxq_head);
    sc->rx.rx_buf = ssv_skb_alloc(sc, MAX_FRAME_SIZE_DMG);
    if (sc->rx.rx_buf == NULL)
	    goto err_create_rx_buf;

	/* Initialize broadcast queue */
	memset(&sc->bcast_txq, 0, sizeof(struct ssv6xxx_bcast_txq));
	spin_lock_init(&sc->bcast_txq.txq_lock);
	skb_queue_head_init(&sc->bcast_txq.qhead);

	/* Initialize power saver spin lock */
	spin_lock_init(&sc->ps_state_lock);
	/* Initialize tx_pkt_run_no lock */
	spin_lock_init(&sc->tx_pkt_run_no_lock);

	/* Initialize sta_info protection semaphore */
	init_rwsem(&sc->sta_info_sem);

    /* p2p */
#ifdef CONFIG_P2P_NOA
	spin_lock_init(&sc->p2p_noa.p2p_config_lock);
#endif
	
    /* Initialize channels & rates */
    if (ssv6xxx_update_hw_channel(sc) < 0)
	    goto err_create_channel_list;

	sc->cur_channel = NULL;
	sc->hw_chan = (-1);

    // Wait queue for TX/RX
    init_waitqueue_head(&sc->tx_wait_q);
    skb_queue_head_init(&sc->tx_skb_q);
    #ifdef CONFIG_SSV6XXX_DEBUGFS
    sc->max_tx_skb_q_len = 0;
    #endif // CONFIG_SSV6XXX_DEBUGFS
    sc->tx_q_empty = false;
    skb_queue_head_init(&sc->tx_done_q);
    skb_queue_head_init(&sc->tx_eapol_q);

    // Wait queue for TX/RX
    init_waitqueue_head(&sc->rx_wait_q);
    sc->rx_wait_q_woken = 0;
    skb_queue_head_init(&sc->rx_skb_q);
    sc->rx_task = kthread_run(ssv6xxx_rx_task, sc, "ssv6xxx_rx_task");

#ifdef SMAC_RX_TASKLET
	skb_queue_head_init(&sc->mac80211_rx_q);
	tasklet_init(&sc->mac80211_rx_tasklet, ssv6xxx_mac80211_recv_rx_tasklet, (unsigned long)sc);
#endif

    if (SSV_NEED_SW_CIPHER(sc->sh)){
        ssv6xxx_preload_sw_cipher();
    }

    init_waitqueue_head(&sc->fw_wait_q);

	/* Enable HWIF log*/
	sc->log_ctrl = LOG_HWIF;
	sc->sh->priv->dbg_control = true;

	sc->cmd_data.log_to_ram = false;
	sc->cmd_data.dbg_log.size = 0;
	sc->cmd_data.dbg_log.totalsize = 0;
	sc->cmd_data.dbg_log.data = NULL;

    /* House keeping */
	sc->house_keeping.function = ssv6xxx_house_keeping;
	sc->house_keeping.arg = (void *)sc;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0))
    timer_setup(&sc->house_keeping.timer, house_keeping_timer_hdl, 0);
    sc->house_keeping.timer.expires = jiffies + msecs_to_jiffies(HOUSE_KEEPING_TIMEOUT);
#else
    init_timer(&sc->house_keeping.timer);
    sc->house_keeping.timer.expires = jiffies + msecs_to_jiffies(HOUSE_KEEPING_TIMEOUT);
    sc->house_keeping.timer.function = ssv6xxx_house_keeping;
    sc->house_keeping.timer.data = (unsigned long)sc;
#endif
    sc->house_keeping_wq= create_singlethread_workqueue("ssv6xxx_house_keeping_wq");
    INIT_WORK(&sc->check_fw_status_work, ssv6xxx_check_fw_status_process);
    INIT_WORK(&sc->mib_edca_work, ssv6xxx_mib_edca_process);
    INIT_WORK(&sc->tx_poll_work, ssv6xxx_tx_poll_process);
    INIT_WORK(&sc->flowctl_work, ssv6xxx_flowctl_process);

    sc->mac80211_dev_started = false;
    add_timer(&sc->house_keeping.timer);

    /* tx done handler */
    sc->tx_done_wq= create_singlethread_workqueue("ssv6xxx_tx_done_wq");
    INIT_WORK(&sc->tx_done_work, ssv6xxx_tx_done_process);
    
    /* hw scan handler */
    sc->scan_wq= create_singlethread_workqueue("ssv6xxx_scan_wq");
    INIT_DELAYED_WORK(&sc->scan_work, ssv6xxx_scan_process); 
    INIT_DELAYED_WORK(&sc->scan_ignore_work, ssv6xxx_scan_ignore_process); 
    
    /* Directly ack flow control */
    sc->sc_flags |= SC_OP_DIRECTLY_ACK;
    atomic_set(&sc->tx_frame, 0);
	
    // init flag of force disable directly ack tx frame
    sc->force_disable_directly_ack_tx = false; 

    init_completion(&sc->wakeup_done);
    init_completion(&sc->hold_on3);
	
    skb_queue_head_init(&sc->ampdu_recycle_list);

#ifdef CONFIG_THROUGHPUT_PROFILE
	sc->tp_skb_ts_cnt = 0;
	sc->tp_smac_tx_total_len = 0;
	sc->tp_smac_tx_pre_ts = 0;
	for (i = 0; i < 5; i++) {
		memset(&(sc->tp_pro_hci_hwq[i]), 0x0, sizeof(struct _ssv_tp_pro_hci_hwq_st));
		sc->tp_pro_hci_hwq[i].empty_min_period = 0xFFFFFFFF;
	}
#endif
    return ret;

err_create_channel_list:
	kfree(sc->rx.rx_buf);
err_create_rx_buf:
    return -ENOMEM;
}


static int ssv6xxx_deinit_softc(struct ssv_softc *sc)
{
    void *channels;
	struct sk_buff* skb;
    u8 remain_size;
    
    printk("%s():\n", __FUNCTION__);
    if (sc->sh->cfg.hw_caps & SSV6200_HW_CAP_2GHZ) {
        channels = sc->sbands[INDEX_80211_BAND_2GHZ].channels;
        kfree(channels);
    }
    if (sc->sh->cfg.hw_caps & SSV6200_HW_CAP_5GHZ) {
        channels = sc->sbands[INDEX_80211_BAND_5GHZ].channels;
        kfree(channels);
    }
#ifdef CONFIG_SSV_SUPPORT_ANDROID    
#ifdef CONFIG_HAS_EARLYSUSPEND
    unregister_early_suspend(&sc->early_suspend);
#endif //CONFIG_HAS_EARLYSUSPEND
    ssv_wakelock_destroy(sc);
#endif
    ssv_skb_free(sc, sc->rx.rx_buf);
   
    sc->rx.rx_buf = NULL;

    /* Release broadcast frames. */
	do{
		skb = ssv6200_bcast_dequeue(&sc->bcast_txq, &remain_size);
		if(skb)
            ssv6xxx_txbuf_free_skb(skb, (void*)sc);//dev_kfree_skb_any(skb);
		else
			break;
	}while(remain_size);

    printk("%s(): Clean Tx Eapol queues.\n", __func__);
    while ((skb = skb_dequeue(&sc->tx_eapol_q)) != NULL) {
        dev_kfree_skb_any(skb);
    }

    printk("%s(): Clean RX queues.\n", __func__);
    while ((skb = skb_dequeue(&sc->rx_skb_q)) != NULL) {
        dev_kfree_skb_any(skb);
    }

    printk("%s(): Clean AMPDU recycle list.\n", __func__);
    while ((skb = skb_dequeue(&sc->ampdu_recycle_list)) != NULL) {
        dev_kfree_skb_any(skb);
    }

	if (sc->cmd_data.dbg_log.data)
		kfree(sc->cmd_data.dbg_log.data);

    destroy_workqueue(sc->config_wq);
    // remove house keeping
    del_timer_sync(&sc->house_keeping.timer);
    destroy_workqueue(sc->house_keeping_wq);
    // remove tx done 
    destroy_workqueue(sc->tx_done_wq);
    // remove scan 
    destroy_workqueue(sc->scan_wq);
    
    return 0;
}

static void ssv6xxx_deinit_hwsh(struct ssv_softc *sc)
{
    struct ssv_hw *sh = sc->sh;
    struct list_head *pos, *q;
    struct ssv_hw_cfg *entry;

    mutex_lock(&sh->hw_cfg_mutex);
    list_for_each_safe(pos, q, &sh->hw_cfg) {
        entry = list_entry(pos, struct ssv_hw_cfg, list);
        list_del(pos);
        kfree(entry);
    }
    mutex_unlock(&sh->hw_cfg_mutex);
    
    if (sh->page_count)
        kfree(sh->page_count);

    kfree(sc->sh);
}

extern char *cfgfirmwarepath ;

int ssv6xxx_load_firmware(struct ssv_hw *sh)
{
    int ret=0;
    u8 firmware_name[SSV_FIRMWARE_MAX] = "";
    u8 temp_path[SSV_FIRMWARE_PATH_MAX] = "";

    if (sh->cfg.external_firmware_name[0] != 0x00)
    {
        printk(KERN_INFO "Forced to use firmware \"%s\".\n",
               sh->cfg.external_firmware_name);
        
        strncpy(firmware_name, sh->cfg.external_firmware_name,
                SSV_FIRMWARE_MAX-1);
    }
    else
    {
        SSV_GET_FW_NAME(sh, firmware_name);

        printk(KERN_INFO "Using firmware \"%s\".\n", firmware_name); 
    }

    if (firmware_name[0] == 0x00)
    {
        printk(KERN_INFO "Not match correct CHIP identity\n");
        return -1;
    }

    if (cfgfirmwarepath != NULL)
    {
        snprintf(temp_path, SSV_FIRMWARE_PATH_MAX, "%s%s", cfgfirmwarepath, 
                 firmware_name);
        // Open firmware by open file api
        ret = SMAC_LOAD_FW(sh,temp_path, 1);
        printk(KERN_INFO "Using firmware at %s\n", temp_path);
    }
    else if (sh->cfg.firmware_path[0] != 0x00)
    {
        snprintf(temp_path, SSV_FIRMWARE_PATH_MAX, "%s%s", 
                 sh->cfg.firmware_path, firmware_name);
         // Open firmware by open file api
        ret = SMAC_LOAD_FW(sh,temp_path, 1);
        printk(KERN_INFO "Using firmware at %s\n", temp_path);
    }
    else
    {
        //Default firmware
        //printk(KERN_INFO "Firmware name =%s\n", firmware_name);
         // Open firmware by request api
        ret = SMAC_LOAD_FW(sh,firmware_name, 0);
    }

    return ret;
}

int ssv6xxx_init_mac(struct ssv_hw *sh)
{
    struct ssv_softc *sc=sh->sc;
    int    ret=0;
//-----------------------------------------------------------------------------------------------------------------------------------------
    printk(KERN_INFO "SVN version %d\n", ssv_root_version);
    printk(KERN_INFO "SVN ROOT URL %s \n", SSV_ROOT_URl);
    printk(KERN_INFO "COMPILER HOST %s \n", COMPILERHOST);
    printk(KERN_INFO "COMPILER DATE %s \n", COMPILERDATE);
    printk(KERN_INFO "COMPILER OS %s \n", COMPILEROS);
    printk(KERN_INFO "COMPILER OS ARCH %s \n", COMPILEROSARCH);


//-----------------------------------------------------------------------------------------------------------------------------------------
//for power saving
    if(sc->ps_status == PWRSV_ENABLE){

#ifdef CONFIG_SSV_SUPPORT_ANDROID    
        printk(KERN_INFO "%s: wifi Alive lock timeout after 3 secs!\n",__FUNCTION__);
        {
            ssv_wake_timeout(sc, 3);
            printk(KERN_INFO "wifi Alive lock!\n");
        }
#endif


        if (USE_MAC80211_RX(sh)){
            HAL_SET_RX_FLOW(sh, RX_DATA_FLOW, RX_HCI); 
        } else {
            HAL_SET_RX_FLOW(sh, RX_DATA_FLOW, RX_CIPHER_MIC_HCI);
        }

        HAL_SET_RX_FLOW(sh, RX_MGMT_FLOW, RX_HCI);

        SSV_SET_RX_CTRL_FLOW(sh);
        
        //ACTION_DO_NOTHING, FRAME_ACCEPT 0x11F8  /* 0 001000 111111 00 1 */       //Beacon
        HAL_UPDATE_DECISION_TABLE_6(sc->sh, sc->mac_deci_tbl[6]);
        return ret;
    }

    /* force RX reset to avoid pbuf allocating out-of-order address */
    SSV_PHY_ENABLE(sh, false);
    
    // init mac hw  
    ret = HAL_INIT_MAC(sh);
    if (ret) {
        printk("HAL INIT MAC FAIL\n");
        goto exit;
    }
    
    SSV_PLL_CHK(sh);

    SSV_PHY_ENABLE(sh, true); 

exit:
    return ret;
}

void ssv6xxx_deinit_mac(struct ssv_softc *sc)
{
// ToDo: After deinit, device should be reset before init again. Why free pbuf?
#ifdef SSV6200_ECO
    int i;

    for(i = 0; i < MAX_STA_NUM; i++){
        if(sc->sh->hw_buf_ptr[i]){
            SSV_FREE_PBUF(sc, sc->sh->hw_buf_ptr[i]);
        }
    }
#else // SSV6200_ECO
    if(sc->sh->hw_buf_ptr){
	    SSV_FREE_PBUF(sc, sc->sh->hw_buf_ptr[i]);
    }
#endif // SSV6200_ECO
}


void inline ssv6xxx_deinit_hw(struct ssv_softc *sc)
{
    printk("%s(): \n", __FUNCTION__);
    ssv6xxx_deinit_mac(sc);
    /* it cannot detect usb if insmod/rmmod usb-core modules */
#if 0
    HAL_RESET_CPU(sc->sh);
    // Set ILM/DLM back for turismo C0/D0
    HAL_SET_SRAM_MODE(sc->sh, SRAM_MODE_ILM_64K_DLM_128K);

	// TODO, it should verify why to set this register
    //HAL_DETACH_USB_HCI(sc->sh);
    // disable power domain ON3 
    SSV_SET_ON3_ENABLE(sc->sh, false);
#endif
}

static void ssv6xxx_update_tx_waitnum_opertaion(struct ssv_softc *sc, u32 val)
{
    struct sk_buff *skb = NULL;
    struct cfg_host_cmd *host_cmd = NULL;
    int ret = 0;

    skb = dev_alloc_skb(HOST_CMD_HDR_LEN + sizeof(u32));
    if (skb == NULL) {
        printk("%s(): Fail to alloc cmd buffer.\n", __FUNCTION__);
        return;
    }

    skb_put(skb, HOST_CMD_HDR_LEN + sizeof(u32));
    host_cmd = (struct cfg_host_cmd *)skb->data;
    memset(host_cmd, 0x0, sizeof(struct cfg_host_cmd)+sizeof(u32));
    host_cmd->c_type = HOST_CMD;
    host_cmd->h_cmd = (u8)SSV6XXX_HOST_CMD_TX_OPS;
    host_cmd->sub_h_cmd = (u32)SSV6XXX_TX_CMD_WAIT_NUM;
    host_cmd->un.dat32[0] = val;
    host_cmd->blocking_seq_no = (((u16)SSV6XXX_HOST_CMD_TX_OPS << 16)|(u16)SSV6XXX_TX_CMD_WAIT_NUM);
    host_cmd->len = HOST_CMD_HDR_LEN + sizeof(u32);
    ret = HCI_SEND_CMD(sc->sh, skb);
    if (ret)
        printk("%s(): Fail to send tx operation\n", __FUNCTION__);
    dev_kfree_skb(skb);
}

static void ssv6xxx_update_tx_checkhwqnum_opertaion(struct ssv_softc *sc, u32 val)
{
    struct sk_buff *skb = NULL;
    struct cfg_host_cmd *host_cmd = NULL;
    int ret = 0;

    skb = dev_alloc_skb(HOST_CMD_HDR_LEN + sizeof(u32));
    if (skb == NULL) {
        printk("%s(): Fail to alloc cmd buffer.\n", __FUNCTION__);
        return;
    }

    skb_put(skb, HOST_CMD_HDR_LEN + sizeof(u32));
    host_cmd = (struct cfg_host_cmd *)skb->data;
    memset(host_cmd, 0x0, sizeof(struct cfg_host_cmd)+sizeof(u32));
    host_cmd->c_type = HOST_CMD;
    host_cmd->h_cmd = (u8)SSV6XXX_HOST_CMD_TX_OPS;
    host_cmd->sub_h_cmd = (u32)SSV6XXX_TX_CMD_CHECK_HWQ_NUM;
    host_cmd->un.dat32[0] = val;
    host_cmd->blocking_seq_no = (((u16)SSV6XXX_HOST_CMD_TX_OPS << 16)|(u16)SSV6XXX_TX_CMD_CHECK_HWQ_NUM);
    host_cmd->len = HOST_CMD_HDR_LEN + sizeof(u32);
    ret = HCI_SEND_CMD(sc->sh, skb);
    if (ret)
        printk("%s(): Fail to send tx operation\n", __FUNCTION__);
    dev_kfree_skb(skb);
}

static void ssv6xxx_update_tx_duration_operation(struct ssv_softc *sc, u32 duration, u32 period)
{
    struct sk_buff *skb = NULL;
    struct cfg_host_cmd *host_cmd = NULL;
    struct ssv_tx_duration *ptr = NULL;
    int ret = 0;

    skb = dev_alloc_skb(HOST_CMD_HDR_LEN + sizeof(struct ssv_tx_duration));
    if (skb == NULL) {
        printk("%s(): Fail to alloc cmd buffer.\n", __FUNCTION__);
        return;
    }

    skb_put(skb, HOST_CMD_HDR_LEN + sizeof(struct ssv_tx_duration));
    host_cmd = (struct cfg_host_cmd *)skb->data;
    memset(host_cmd, 0x0, sizeof(struct cfg_host_cmd)+sizeof(struct ssv_tx_duration));
    host_cmd->c_type = HOST_CMD;
    host_cmd->h_cmd = (u8)SSV6XXX_HOST_CMD_TX_OPS;
    host_cmd->sub_h_cmd = (u32)SSV6XXX_TX_CMD_DURATION;
    host_cmd->blocking_seq_no = (((u16)SSV6XXX_HOST_CMD_TX_OPS << 16)|(u16)SSV6XXX_TX_CMD_DURATION);
    host_cmd->len = HOST_CMD_HDR_LEN + sizeof(struct ssv_tx_duration);
    ptr = (struct ssv_tx_duration *)host_cmd->un.dat8;
    ptr->duration = (u16)duration;
    ptr->period = (u16)period;
    ret = HCI_SEND_CMD(sc->sh, skb);
    if (ret)
        printk("%s(): Fail to send tx operation\n", __FUNCTION__);
    dev_kfree_skb(skb);
}

static int ssv6xxx_init_hw(struct ssv_hw *sh)
{
    struct ssv_softc *sc = sh->sc;
    u32 dev_type = HCI_DEVICE_TYPE(sh->hci.hci_ctrl);
    int ret = 0;
    u32 regval = 0;

    ssv_cabrio_reg *rf_tbl, *phy_tbl ;
    
    /* ssv6200 hardware parameter settings. */
    sh->tx_desc_len = HAL_GET_TX_DESC_SIZE(sh);
    sh->rx_desc_len = HAL_GET_RX_DESC_SIZE(sh);
    sh->rx_pinfo_pad = 0x04;
	sh->rx_mode = RX_NORMAL_MODE;
    
    HAL_SET_XTAL_CLK(sh);

    HAL_RESET_CPU(sh);
    // disable power domain ON3 
    SSV_SET_ON3_ENABLE(sh, false);
    
    // enable power domain ON3 
    SSV_SET_ON3_ENABLE(sh, true);
    
    // wait USB_ROM_CODE_READY
    HAL_WAIT_USB_ROM_READY(sh);
    
    if (dev_type == SSV_HWIF_INTERFACE_USB)
        SSV_DISABLE_USB_ACC(sc, 0x4); 
         
    if ((ret = HAL_RESET_HW_MAC(sh)) != 0) {
        printk(KERN_ERR "Fail to init hw procedure\n");
        goto err;
    }
    
    if (dev_type == SSV_HWIF_INTERFACE_USB)
        SSV_ENABLE_USB_ACC(sc, 0x4); 
         
    
    if ((ret = HAL_INIT_HCI_RX_AGGR(sh)) != 0) {
        printk(KERN_ERR "Fail to init hw procedure\n");
        goto err;
    }
    
    // update tx/rx page
    if (dev_type == SSV_HWIF_INTERFACE_USB) {
        if ((sc->sh->cfg.usb_hw_resource & USB_HW_RESOURCE_CHK_FORCE_OFF) == 0) {
            sc->sh->cfg.usb_hw_resource = ( USB_HW_RESOURCE_CHK_TXID | USB_HW_RESOURCE_CHK_TXPAGE);
        } else {
            sc->sh->cfg.usb_hw_resource &= ~( USB_HW_RESOURCE_CHK_TXID | USB_HW_RESOURCE_CHK_TXPAGE);
        }
    }
    HAL_UPDATE_PAGE_ID(sh);
    mdelay(10); 
    
    if ((ret = ssv6xxx_load_firmware(sh)) != 0) {
        printk(KERN_ERR "Fail to load firmware\n");
        goto err;
    }

    HAL_GET_FW_VERSION(sh, &regval);
    if (regval == FIRWARE_NOT_MATCH_CODE){
        printk(KERN_INFO "Firmware check CHIP ID fail[0x%08x]!!\n",regval);
        goto err;
    } else {
        printk(KERN_INFO "Firmware version %d\n", regval);
        if (regval != ssv_firmware_version)
        {
            if (sh->cfg.ignore_firmware_version == 0) {
                printk(KERN_INFO "Firmware version mapping not match[0x%08x]!!\n",regval);
                printk(KERN_INFO "It's should be [0x%08x]!!\n",ssv_firmware_version);
                goto err;
            }
            else
                printk(KERN_INFO "Force ignore_firmware_version\n");
        }
    }
 
    // Set FW tx operation
    if (0 != sc->sh->cfg.fw_tx_waitnum)
        ssv6xxx_update_tx_waitnum_opertaion(sc, sc->sh->cfg.fw_tx_waitnum);
    if (0 != sc->sh->cfg.fw_tx_chkhwqnum)
        ssv6xxx_update_tx_checkhwqnum_opertaion(sc, sc->sh->cfg.fw_tx_chkhwqnum);
    if (0 != sc->sh->cfg.fw_tx_duration)
        ssv6xxx_update_tx_duration_operation(sc, sc->sh->cfg.fw_tx_duration, sc->sh->cfg.fw_tx_duration_period);
   
    HAL_INIT_GPIO_CFG(sh);

    HAL_LOAD_PHY_TABLE(sh, &phy_tbl);
    HAL_LOAD_RF_TABLE(sh, &rf_tbl);
    
	//write phy RF table and initial PLL
    if ((ret = HAL_SET_PLL_PHY_RF(sh, rf_tbl, phy_tbl)) != 0) {
        printk(KERN_ERR "Fail to initial PLL\n");
        goto err;
    }

    //Switch clock to PLL output of RF
    if ((ret = HAL_CHG_CLK_SRC(sh)) != 0) {
        printk(KERN_ERR "Fail to CLK SRC\n");
        goto err;
    }

    //PHY and security table
    if ((ret = HAL_INI_HW_SEC_PHY_TABLE(sh->sc)) != 0) {
        printk(KERN_ERR "Fail to init security table\n");
        goto err;
    }
    /**
        * The ordering of PHY/RF default register setting, IQ Calibration and 
        * channel calibration is (from bernie's suggestion)
        *
        *   1. channel calibration (to lock on a channel)
        *   2. IQ calibration
        *   3. set default PHY registers
        *   4. set default RF registers
        *   5. channel calibration ...................
        */
    {
        struct ieee80211_channel chan, *pchan;

        memset(&chan, 0 , sizeof( struct ieee80211_channel));

        chan.hw_value =  sh->cfg.def_chan;
        pchan = &chan;
    
        if ( ret == 0){
             HAL_SET_CHANNEL_CHECK(sh->sc, pchan, NL80211_CHAN_HT20, false, ret);
        }

    }

    // enable all phy sub-mode, without phy mode enabled.
    // phy mode should be enable at init mac.
    HAL_SET_PHY_MODE(sh, true);
err:
    return ret;
}

static void ssv6xxx_save_hw_config(void *param, u32 addr, u32 value)
{
	struct ssv_softc *sc = (struct ssv_softc *)param;
    struct ssv_hw *sh = sc->sh;
    struct list_head *pos, *q;
    struct ssv_hw_cfg *entry;
    struct ssv_hw_cfg *new_cfg;
    bool find = false;
    
    // Don't save the hardware config for following condition
    // 1. online reset function disable
    // 2. online reset is processing
    if (!(sc->sh->cfg.online_reset & ONLINE_RESET_ENABLE) || (sc->sc_flags & SC_OP_HW_RESET))
        return;

    mutex_lock(&sh->hw_cfg_mutex);
    list_for_each_safe(pos, q, &sh->hw_cfg) {
        entry = list_entry(pos, struct ssv_hw_cfg, list);
        if (entry->addr == addr) {
            entry->value = value;
            find = true;
            break;
        }
    }
    
    if (!find) {
        new_cfg = (struct ssv_hw_cfg *)kmalloc(sizeof(struct ssv_hw_cfg), GFP_KERNEL);
        memset(new_cfg, 0, sizeof(struct ssv_hw_cfg));
        new_cfg->addr = addr;
        new_cfg->value = value;
        list_add_tail(&(new_cfg->list), &(sh->hw_cfg));
    }
    mutex_unlock(&sh->hw_cfg_mutex);
}

static void ssv6xxx_clear_sta_info(struct ssv_softc *sc)
{
    struct ssv_sta_priv_data *sta_priv_dat = NULL;
    struct ssv_sta_info *sta_info = NULL;
    struct ssv_vif_info *vif_info = NULL;
    struct ieee80211_vif *vif = NULL;
    s8 hw_wsid = -1;
    int i = 0;

    down_write(&sc->sta_info_sem);
    for(i = 0; i < SSV_NUM_STA; i++)
    {
        sta_info = &sc->sta_info[i];
        if(sta_info->sta)
        {
            hw_wsid = sta_info->hw_wsid;
            HCI_TXQ_LOCK_BY_STA(sc->sh, hw_wsid);
            HCI_TX_PAUSE_BY_STA(sc->sh, hw_wsid);
            HCI_TXQ_FLUSH_BY_STA(sc->sh, hw_wsid);
            sta_priv_dat = (struct ssv_sta_priv_data *)sta_info->sta->drv_priv;
            memset((void *)sta_info, 0, sizeof(*sta_info));
            sta_priv_dat->sta_idx = -1;
            list_del(&sta_priv_dat->list);
            HCI_TX_RESUME_BY_STA(sc->sh, hw_wsid);
            HCI_TXQ_UNLOCK_BY_STA(sc->sh, hw_wsid);
        }
    }
    up_write(&sc->sta_info_sem);
    for(i = 0; i < SSV_NUM_VIF; i++)
    {
        vif_info = &sc->vif_info[i];
        vif = vif_info->vif;
        if(vif)
        {
#ifdef CONFIG_SSV6XXX_DEBUGFS
            ssv6xxx_debugfs_remove_interface(sc, vif);
#endif
            if (vif->type == NL80211_IFTYPE_AP)
            {
                /* In normal ap mode, release bcast frame and stop worker */
                if (sc->bq4_dtim)
                {
                    sc->bq4_dtim = false;
                    ssv6200_release_bcast_frame_res(sc, vif);
                    SSV_UNHALT_MNGQ_UNTIL_DTIM(sc->sh);
                    printk("Config Q4 to normal Q \n");
                }

                /* Relase skb of beacon frame */
                ssv6xxx_beacon_release(sc);
                sc->ap_vif = NULL;

#ifdef CONFIG_SSV_SUPPORT_ANDROID
                if(vif->p2p == 0)
                {
                    ssv_wake_unlock(sc);
                    printk(KERN_INFO "AP mode destroy wifi_alive_lock\n");
                }
#endif
            }
            memset(vif_info, 0, sizeof(*vif_info));
            if(sc->nvif != 0)
            {
                sc->nvif--;
            }
        }
    }
    sc->isAssoc = false;
}

void ssv6xxx_restart_hw(struct work_struct *work)
{
    struct ssv_softc *sc = container_of(work, struct ssv_softc, hw_restart_work);
    int i = 0;

    printk("**************************\n");
    printk("*** Software MAC reset ***\n");
    printk("**************************\n");

    if (sc->sc_flags & SC_OP_HW_RESET) {
        printk("Reset is running.\n");
        return;
    }

    sc->sc_flags |= SC_OP_HW_RESET;
    sc->restart_counter++;
    HCI_IGNORE_CMD(sc->sh, true);

    // wait for scan completion
    while (sc->bScanning) {
        if(sc->hw_scan_start) {
            ssv6xxx_cancel_hw_scan(sc);
        }
        mdelay(100);
        if (++i > 10000) 
            return;
    }
    HCI_STOP(sc->sh);

    // lock for all changes to network configuration
    rtnl_lock();
    // lock for ssv changes
    mutex_lock(&sc->mutex);
    printk("%s() start\n", __FUNCTION__);
    SSV_BEACON_LOSS_DISABLE(sc->sh);
    //Disable PHY
    SSV_PHY_ENABLE(sc->sh, false);
    mdelay(50); //Delay for wait no packet in firmware.
    SSV_SAVE_HW_STATUS(sc);
    SSV_RESET_SYSPLF(sc->sh);


    // Ep0 -> Ep1
    HCI_REVERSE_CONFIG_DEVICE(sc->sh->hci.hci_ctrl);
	
	
    udelay(50);
    HAL_RESET_CPU(sc->sh);
    sc->beacon_info[0].pubf_addr = 0x00;
    sc->beacon_info[1].pubf_addr = 0x00;
    ssv6xxx_clear_sta_info(sc);
    HCI_IGNORE_CMD(sc->sh, false);
    ssv6xxx_init_hw(sc->sh);
    mutex_unlock(&sc->mutex);
    rtnl_unlock();

    ieee80211_restart_hw(sc->hw);

    if (sc->isAssoc)
    {
        SSV_BEACON_LOSS_ENABLE(sc->sh);
    }

    // restart hw
    sc->sc_flags &= (~(SC_OP_HW_RESET));
}

static void ssv6xxx_check_mac2(struct ssv_hw *sh)
{
	 const u8 addr_mask[6]={0xfd, 0xff, 0xff, 0xff, 0xff, 0xfc};
	 u8 i;
	 bool invalid = false;
	
	 for ( i=0; i<6; i++) {
       if ((ssv_cfg.maddr[0][i] & addr_mask[i]) != 
               (ssv_cfg.maddr[1][i] & addr_mask[i])){
           invalid = true;
           printk (" i %d , mac1[i] %x, mac2[i] %x, mask %x \n",i, ssv_cfg.maddr[0][i] ,ssv_cfg.maddr[1][i],addr_mask[i]);
           break;
       }
   }
  
   if (invalid){
       memcpy(&ssv_cfg.maddr[1][0], &ssv_cfg.maddr[0][0], 6);
       ssv_cfg.maddr[1][5] ^= 0x01;
       if (ssv_cfg.maddr[1][5] < ssv_cfg.maddr[0][5]){
       //swap mac1 mac2, let lower number be MAC1
           u8 temp;
           
           temp = ssv_cfg.maddr[0][5];
           ssv_cfg.maddr[0][5] = ssv_cfg.maddr[1][5];
           ssv_cfg.maddr[1][5] = temp;
           sh->cfg.maddr[0][5] = ssv_cfg.maddr[0][5];
       }
       printk("MAC 2 address invalid!!\n" );       
       printk("After modification, MAC1 %pM, MAC2 %pM\n",ssv_cfg.maddr[0], 
           ssv_cfg.maddr[1]);           
   }
}

static int ssv6xxx_read_configuration(struct ssv_hw *sh)
{
 
    // cp settings from configure to sh
    memcpy(&sh->cfg, &ssv_cfg, sizeof(struct ssv6xxx_cfg));

    /**
    * Read configuration from external module, 
    * such as flash/eeprom...,etc.
    * rf bin configuration 
    */
    // update by efuse
    efuse_read_all_map(sh);
    // update by rf bin
    SSV_FLASH_READ_ALL_MAP(sh);

    if (!(is_valid_ether_addr(&sh->cfg.maddr[0][0]))){
        printk("invalid mac addr 1 !!\n");
        WARN_ON(1);
        return 1;
    }

    if (SSV_IF_CHK_MAC2(sh)) {
        ssv6xxx_check_mac2(sh);
        memcpy(&sh->cfg.maddr[1][0], &ssv_cfg.maddr[1][0], ETH_ALEN); // overwrite mac2 after check mac2
    }

    //Xtal setting 0-26M 1-40M 2-24M
    #if 0
    if(sh->cfg.crystal_type == 26)
        sh->cfg.crystal_type = SSV6XXX_IQK_CFG_XTAL_26M;
    else if(sh->cfg.crystal_type == 40)
        sh->cfg.crystal_type = SSV6XXX_IQK_CFG_XTAL_40M;
    else if(sh->cfg.crystal_type == 24)
        sh->cfg.crystal_type = SSV6XXX_IQK_CFG_XTAL_24M;
    else if(sh->cfg.crystal_type == 25)
        sh->cfg.crystal_type = SSV6XXX_IQK_CFG_XTAL_25M;
    else
    {
        printk("Please redefine xtal_clock(wifi.cfg)!!\n");
        WARN_ON(1);
        return 1;
    }
    #endif
    
    switch (sh->cfg.crystal_type){
        case 16:
            sh->cfg.crystal_type = SSV6XXX_IQK_CFG_XTAL_16M;
            break;
        case 24:
            sh->cfg.crystal_type = SSV6XXX_IQK_CFG_XTAL_24M;
            break;
        case 26:
            sh->cfg.crystal_type = SSV6XXX_IQK_CFG_XTAL_26M;
            break;
        case 40:
            sh->cfg.crystal_type = SSV6XXX_IQK_CFG_XTAL_40M;
            break;
        case 12:
            sh->cfg.crystal_type = SSV6XXX_IQK_CFG_XTAL_12M;
            break;
        case 20:
            sh->cfg.crystal_type = SSV6XXX_IQK_CFG_XTAL_20M;
            break;
        case 25:
            sh->cfg.crystal_type = SSV6XXX_IQK_CFG_XTAL_25M;
            break;
        case 32:
            sh->cfg.crystal_type = SSV6XXX_IQK_CFG_XTAL_32M;
            break; 
        default:
            printk("Please redefine xtal_clock(wifi.cfg)!!\n");
            WARN_ON(1);
            return 1;
            break;      
    }
    
    // flash bin configuration higher priority
    if (!sh->flash_config.exist) {
        //volt regulator(DCDC-0 LDO-1)
        if(sh->cfg.volt_regulator < 2)
            sh->cfg.volt_regulator = ssv_cfg.volt_regulator;
        else
        {
            printk("Please redefine volt_regulator(wifi.cfg)!!\n");
            WARN_ON(1);
            return 1;
        }
    }

    SSV_ADJ_CONFIG(sh);     // adjust configuration to fit each model.

    HAL_UPDATE_RF_TABLE(sh); // transfer efuse/flash.bin to rf table
 
    return 0;
}

static int ssv6xxx_hci_rx_mode(void *args)
{
	struct ssv_softc *sc = (struct ssv_softc *)args;
    struct ssv_hw *sh = sc->sh;

	return sh->rx_mode;
}

static int ssv6xxx_read_hw_info(struct ssv_softc *sc)
{
    struct ssv_hw *sh = sc->sh;

    //CHIP TAG
    SSV_GET_IC_TIME_TAG(sh);
    printk(KERN_INFO "CHIP TAG: %llx \n", sh->chip_tag);
    
    //Read configuraion from extern configuraion.
    if (ssv6xxx_read_configuration(sh))
        return -ENOMEM;

    /* HCI register parameters */      
    sh->hci.hci_post_tx_cb= ssv6xxx_post_tx_cb;
#ifdef CONFIG_THROUGHPUT_PROFILE
	sh->hci.hci_pkt_tstamp_cb = ssv6xxx_pkt_tstamp_cb;
#endif

    sh->hci.hci_tx_q_empty_cb = ssv6xxx_tx_q_empty_cb;

    sh->hci.hci_tx_buf_free_cb = ssv6xxx_txbuf_free_skb;

    sh->hci.hci_rx_mode_cb = ssv6xxx_hci_rx_mode;
    
    sh->hci.skb_alloc = ssv_skb_alloc;
    sh->hci.skb_free = ssv_skb_free;
    
	sh->hci.dbgprint = ssv6xxx_hci_dbgprint;
	
    sh->hci.write_hw_config_cb = ssv6xxx_save_hw_config;
   
    sh->hci.hci_txtput_reason_cb = ssv6xxx_hci_txtput_reason_cb;
    sh->hci.hci_tx_desc_cb = ssv6xxx_hci_tx_desc_cb;
    sh->hci.hci_update_wep_cb = ssv6xxx_hci_update_wep_cb;
    sh->hci.hci_update_flowctl_cb = ssv6xxx_hci_update_flowctl_cb;
    
    /* SSV_HW register paramater */
    sh->write_hw_config_cb = ssv6xxx_save_hw_config;
    sh->write_hw_config_args = (void *)sc;
    
    return 0;
}

static int ssv6xxx_init_device(struct ssv_softc *sc, const char *name)
{
#ifndef CONFIG_SSV6XXX_HW_DEBUG
    struct ieee80211_hw *hw = sc->hw;
#endif
    struct ssv_hw       *sh = NULL;
    bool                 hci_tx_aggr = false;
    int                  error = 0;
    struct ssv6xxx_hci_ctrl *hci_ctrl;
    
    BUG_ON(!sc->dev->platform_data);

    /* Initialize ssv6xxx HAL layer function*/
    if ((error = ssv6xxx_init_hal(sc)) != 0) {
        goto err;
    }
    sh = sc->sh;
    
    /* Use original configuration to decide hci_tx_aggr function */
    if (ssv_cfg.hw_caps & SSV6200_HW_CAP_HCI_TX_AGGR)
	    hci_tx_aggr = true;
    
    /* HCI driver initialization */
    if ((error = ssv6xxx_hci_register(&sh->hci, hci_tx_aggr)) != 0)
        goto err_sh;
    
    /* copy configuation to sh->cfg */
    if ((error = ssv6xxx_read_hw_info(sc)) != 0) {
        goto err_hci;
    }

    if (sh->cfg.hw_caps == 0) {
        error = -1;
        goto err_hci;
    }
   
    /* If hci layer cannot alloc skb for hci-tx-aggr, it must turn off HCI_TX_AGGR capability */
    hci_ctrl = sh->hci.hci_ctrl;
    if (NULL == hci_ctrl->p_tx_aggr_skb) {
        printk("Cannot alloc tx aggr skb, force turn off hci tx aggr\n");
        sh->cfg.hw_caps = sh->cfg.hw_caps & (~(SSV6200_HW_CAP_HCI_TX_AGGR));
    }
    
    if (sh->cfg.hw_caps & SSV6200_HW_CAP_HCI_TX_AGGR) {
        HCI_SET_CAP(sc->sh, HCI_CAP_TX_AGGR, true);
    }
    
    // set hci tx task trigger condition
    HCI_SET_TRIGGER_QLEN(sc->sh, sh->cfg.hci_trigger_qlen);

#ifdef CONFIG_PREALLOC_TRX_BIG_SKB
    {
        u32 ampdu_max_len = (sc->sh->cfg.ampdu_pkt_max_size != 0) ? sc->sh->cfg.ampdu_pkt_max_size : SSV_AMPDU_SIZE_1_2(sc->sh);
        u32 rx_agg_max_len = MAX_HCI_RX_AGGR_SIZE;

        if (ssv_tx_recycle_skb_size < ampdu_max_len) {
            printk("%s(): ssv_tx_recycle_skb_size %d < ampdu_max_len %u\n", __func__, ssv_tx_recycle_skb_size, ampdu_max_len);
            error = -1;
            goto err_hci;
        }

        if (ssv_rx_recycle_skb_size < rx_agg_max_len) {
            printk("%s(): ssv_rx_recycle_skb_size %d < rx_agg_max_len %u\n", __func__, ssv_rx_recycle_skb_size, rx_agg_max_len);
            error = -1;
            goto err_hci;
        }
    }
#endif

    /* Initialize software control structure */
    if ((error = ssv6xxx_init_softc(sc)) != 0) {
        goto err_softc;
    }

    hci_ctrl=sh->hci.hci_ctrl;
#ifdef CONFIG_THROUGHPUT_PROFILE
    HCI_RX_TASK(hci_ctrl, hci_ctrl->shi->hci_rx_cb, hci_ctrl->shi->hci_is_rx_q_full, (void *)(SSV_SC(hci_ctrl)), 
        &hci_ctrl->rx_pkt, sh->cfg.rx_max_recv_cnt, hci_ctrl->shi->hci_get_smac_cfg_cb);
#else //#ifdef CONFIG_THROUGHPUT_PROFILE
    HCI_RX_TASK(hci_ctrl, hci_ctrl->shi->hci_rx_cb, hci_ctrl->shi->hci_is_rx_q_full, 
            (void *)(SSV_SC(hci_ctrl)), &hci_ctrl->rx_pkt, sh->cfg.rx_max_recv_cnt);
#endif
    HCI_IRQ_SET_MASK(hci_ctrl, ~(hci_ctrl->int_mask));
    HCI_IRQ_TRIGGER(hci_ctrl);
    HCI_IRQ_ENABLE(hci_ctrl);

    /* Set ssv6200 hardware capabilities to mac80211 stack */
    ssv6xxx_set_80211_hw_capab(sc);
    
    /* Initialize ssv6200 hardware */
    if ((error = ssv6xxx_init_hw(sc->sh)) != 0) {
        goto err_hw;
    }

#ifndef CONFIG_SSV6XXX_HW_DEBUG
    /* Register to mac80211 stack */
    if ((error = ieee80211_register_hw(hw)) != 0) {
        printk(KERN_ERR "Failed to register w. %d.\n", error);
        goto err_hw;
    }
#endif
    
#ifndef CONFIG_SSV6XXX_HW_DEBUG
    ssv_init_cli(dev_name(&hw->wiphy->dev), &sc->cmd_data);
#else
    ssv_init_cli(dev_name(sc->dev), &sc->cmd_data);
#endif

#ifdef CONFIG_SSV6XXX_DEBUGFS
    ssv6xxx_init_debugfs(sc, name);
#endif // CONFIG_SSV6200_DEBUGFS

#ifdef CONFIG_SSV_SMARTLINK 
    {
        extern int ksmartlink_init(void);
        (void)ksmartlink_init();
    }
#endif

/* Device is ready */
    sc->sc_flags |= SC_OP_DEV_READY;

    return 0;

err_hw:
    ssv6xxx_deinit_hw(sc);
err_softc:
    ssv6xxx_deinit_softc(sc);
err_hci:
    ssv6xxx_hci_deregister(&sh->hci);
err_sh:
    ssv6xxx_deinit_hwsh(sc);
err: 
    return error;
}


static void ssv6xxx_deinit_device(struct ssv_softc *sc)
{
    printk("%s(): \n", __FUNCTION__);

    /* Device is not ready */
    sc->sc_flags &= ~SC_OP_DEV_READY;

#ifdef CONFIG_SSV_SMARTLINK
    {
        extern void ksmartlink_exit(void);
        ksmartlink_exit();
    }
#endif

#ifdef CONFIG_SSV6XXX_DEBUGFS
    ssv6xxx_deinit_debugfs(sc);
#endif // CONFIG_SSV6200_DEBUGFS

#ifndef CONFIG_SSV6XXX_HW_DEBUG
    ssv_deinit_cli(dev_name(&sc->hw->wiphy->dev), &sc->cmd_data);
#else
    ssv_deinit_cli(dev_name(sc->dev), &sc->cmd_data);
#endif    

#ifndef CONFIG_SSV6XXX_HW_DEBUG
    ieee80211_unregister_hw(sc->hw);
#endif
    ssv6xxx_deinit_hw(sc);
    ssv6xxx_deinit_softc(sc);
    ssv6xxx_hci_deregister(&sc->sh->hci);
    ssv6xxx_deinit_hwsh(sc);
}


extern struct ieee80211_ops ssv6200_ops;


int ssv6xxx_dev_probe(struct platform_device *pdev)
{
    struct ssv_softc *sc;
    struct ieee80211_hw *hw;
    int ret;

    if (!pdev->dev.platform_data) {
        dev_err(&pdev->dev, "no platform data specified!\n");
        return -EINVAL;
    }
    
    printk("%s(): SSV6X5X device \"%s\" found !\n", __FUNCTION__, pdev->name);
#ifdef SSV_MAC80211
	hw = ieee80211_alloc_hw_nm(sizeof(struct ssv_softc), &ssv6200_ops,"icomm");
#else
	hw = ieee80211_alloc_hw(sizeof(struct ssv_softc), &ssv6200_ops);
#endif
	if (hw == NULL) {
        dev_err(&pdev->dev, "No memory for ieee80211_hw\n");
        return -ENOMEM;
    }

    SET_IEEE80211_DEV(hw, &pdev->dev);
    dev_set_drvdata(&pdev->dev, hw);

    memset((void *)hw->priv, 0, sizeof(struct ssv_softc));
    sc = hw->priv;
    sc->hw = hw;
    sc->dev = &pdev->dev;
    sc->platform_dev = pdev;
    
    ret = ssv6xxx_init_device(sc, pdev->name);
    if (ret) {
        dev_err(&pdev->dev, "Failed to initialize device\n");
        ieee80211_free_hw(hw);
        return ret;
    }

    wiphy_info(hw->wiphy, "%s\n", "SSV6X5X of iComm-semi");
    
    return 0;
}

EXPORT_SYMBOL(ssv6xxx_dev_probe);

void ssv6xxx_cancel_work_sync(struct ssv_softc *sc) {
    /* cancel beacon_miss_handler workqueue */
    cancel_work_sync(&sc->beacon_miss_work);
    cancel_delayed_work_sync(&sc->bcast_tx_work);

    // cancel house keeping work  
    cancel_work_sync(&sc->rx_stuck_work);
    cancel_work_sync(&sc->mib_edca_work);
    cancel_work_sync(&sc->tx_poll_work);
    cancel_work_sync(&sc->flowctl_work);
    cancel_work_sync(&sc->check_fw_status_work);
    cancel_work_sync(&sc->hw_restart_work);
	// cancel tx done work  
    cancel_work_sync(&sc->tx_done_work);
	// cancel scan work 
    cancel_delayed_work_sync(&sc->scan_ignore_work);
    if (sc->hw_scan_start)
        cancel_delayed_work_sync(&sc->scan_work);
}

static void ssv6xxx_stop_all_running_threads(struct ssv_softc *sc) {

    if (sc->ssv_txtput.txtput_tsk) {
        printk(KERN_ERR "Stopping txtput task...\n");
        kthread_stop(sc->ssv_txtput.txtput_tsk);
        while (sc->ssv_txtput.txtput_tsk != NULL) {
            msleep(1);
        }
        printk(KERN_ERR "txtput task is stopped.\n");        
    }

    ssv6xxx_cancel_work_sync(sc);

    if (sc->rx_task != NULL)
    {
        printk(KERN_ERR "Stopping RX task...\n");
        kthread_stop(sc->rx_task);
        while (sc->rx_task != NULL) {
            msleep(1);
        }
        printk(KERN_ERR "RX task is stopped.\n");    
    }

    if(sc->sh->hci.hci_ctrl->hci_tx_task != NULL) {
        printk(KERN_ERR "Stopping HCI TX task...\n");
        kthread_stop(sc->sh->hci.hci_ctrl->hci_tx_task);
        while(sc->sh->hci.hci_ctrl->hci_tx_task != NULL) {
            msleep(1);
        }
        printk(KERN_ERR "HCI TX task is stopped.\n");
    }

}

int ssv6xxx_dev_remove(struct platform_device *pdev)
{
    struct ieee80211_hw *hw=dev_get_drvdata(&pdev->dev);
    struct ssv_softc *sc=hw->priv;
    
    printk("ssv6xxx_dev_remove(): pdev=%p, hw=%p\n", pdev, hw);    
    HCI_IGNORE_CMD(sc->sh, true);

    // Makes house keeping do nothing.
    sc->mac80211_dev_started = false;

    ssv6xxx_stop_all_running_threads(sc);

    ssv6xxx_deinit_device(sc);

    printk("ieee80211_free_hw(): \n");
    ieee80211_free_hw(hw);
    pr_info("ssv6200: Driver unloaded\n");
    return 0;
}

EXPORT_SYMBOL(ssv6xxx_dev_remove);



static const struct platform_device_id ssv6xxx_id_table[] = {
    #ifdef SSV_SUPPORT_SSV6006
    {
        .name = SSV6006A,
        .driver_data = 0,
    },
    {
        .name = SSV6006C,
        .driver_data = 0,
    },
    {
        .name = SSV6006D,
        .driver_data = 0,
    }, 
    #endif // SSV_SUPPORT_SSV6006
    {}, /* Terminating Entry */
};
MODULE_DEVICE_TABLE(platform, ssv6xxx_id_table);


static struct platform_driver ssv6xxx_driver =
{
    .probe          = ssv6xxx_dev_probe,
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
    .remove         = __devexit_p(ssv6xxx_dev_remove),
#else
    .remove         = ssv6xxx_dev_remove,
#endif
    .id_table       = ssv6xxx_id_table,
    .driver     = {
        .name       = SSV_DRVER_NAME,
        .owner      = THIS_MODULE,
    }
};

static int device_match_by_alias(struct device *dev, void *data)
{
	struct device_driver *driver = dev->driver;
	struct _pattern {
		char driver_name[32];
		char device_name[32];
	} *pattern;

	pattern = (struct _pattern *)data;
	if (!strcmp(driver->name, pattern->driver_name) && !strcmp(dev_name(dev), pattern->device_name))
		return 1;
    if (!strcmp(driver->name, pattern->driver_name) && !strcmp("", pattern->device_name))
        return 1;
	else {
	    printk("%s: driver[%s][%s], device[%s][%s]\n", __FUNCTION__, driver->name, pattern->driver_name, 
		    dev_name(dev), pattern->device_name);
		return 0;
    }
}

struct ssv_softc *ssv6xxx_driver_attach(char *driver_name)
{
	struct device *dev;
    struct ieee80211_hw *hw;
    struct ssv_softc *sc;
	struct _pattern {
		char driver_name[32];
		char device_name[32];
	} pattern;

    memset(&pattern, 0, sizeof(struct _pattern));
	sprintf(pattern.driver_name, "%s", driver_name);

	dev = driver_find_device(&ssv6xxx_driver.driver, NULL,
			(void *)&pattern, device_match_by_alias);
	if (!dev) {
		printk("Cannot find the driver[%s]\n", driver_name);
		return NULL;
	}
    
    hw = dev_get_drvdata(dev);
    sc = hw->priv;

    return sc;
}

void ssv6xxx_umac_hci_start(char *driver_name, char *device_name)
{
	struct device *dev;
    struct ieee80211_hw *hw;
    struct ssv_softc *sc;
	struct _pattern {
		char driver_name[32];
		char device_name[32];
	} pattern;

	sprintf(pattern.driver_name, "%s", driver_name);
	sprintf(pattern.device_name, "%s", device_name);

	dev = driver_find_device(&ssv6xxx_driver.driver, NULL,
			(void *)&pattern, device_match_by_alias);
	if (!dev) {
		printk("Cannot find the device[%s] driver[%s]\n", device_name, driver_name);
		return;
	}

	hw = dev_get_drvdata(dev);
	sc = hw->priv;
    HCI_STOP(sc->sh);
    HCI_START(sc->sh);
}
EXPORT_SYMBOL(ssv6xxx_umac_hci_start);

void ssv6xxx_umac_test(char *driver_name, char *device_name, struct sk_buff *skb, int size)
{
    struct device *dev;
    struct ieee80211_hw *hw;
    struct ssv_softc *sc;
    struct ssv_hw *sh;
    struct ssv6xxx_platform_data *priv;
    u32 ret;
        struct _pattern {
                char driver_name[32];
                char device_name[32];
        } pattern;

        sprintf(pattern.driver_name, "%s", driver_name);
        sprintf(pattern.device_name, "%s", device_name);

        dev = driver_find_device(&ssv6xxx_driver.driver, NULL,
                        (void *)&pattern, device_match_by_alias);
        if (!dev) {
                printk("Cannot find the device[%s] driver[%s]\n", device_name, driver_name);
                return;
        }

        hw = dev_get_drvdata(dev);
        sc = hw->priv;
        sh = sc->sh;
        priv = sh->priv;
     
        ret = priv->ops->load_fw(dev ,0x0 ,skb->data ,size);

}
EXPORT_SYMBOL(ssv6xxx_umac_test);

void ssv6xxx_umac_reg_read(char *driver_name, char *device_name, u32 addr, u32 *regval)
{
	int retval = 0;
	struct device *dev;
    struct ieee80211_hw *hw;
    struct ssv_softc *sc;
	struct _pattern {
		char driver_name[32];
		char device_name[32];
	} pattern;

	sprintf(pattern.driver_name, "%s", driver_name);
	sprintf(pattern.device_name, "%s", device_name);

	dev = driver_find_device(&ssv6xxx_driver.driver, NULL,
			(void *)&pattern, device_match_by_alias);
	if (!dev) {
		printk("Cannot find the device[%s] driver[%s]\n", device_name, driver_name);
		return;
	}

	hw = dev_get_drvdata(dev);
	sc = hw->priv;
    retval = SMAC_REG_READ(sc->sh, addr, regval);
	if (retval != 0)
		printk("Fail to read register");
}
EXPORT_SYMBOL(ssv6xxx_umac_reg_read);

void ssv6xxx_umac_reg_write(char *driver_name, char *device_name, u32 addr, u32 value)
{
	int retval = 0;
	struct device *dev;
    struct ieee80211_hw *hw;
    struct ssv_softc *sc;
	struct _pattern {
		char driver_name[32];
		char device_name[32];
	} pattern;

	sprintf(pattern.driver_name, "%s", driver_name);
	sprintf(pattern.device_name, "%s", device_name);

	dev = driver_find_device(&ssv6xxx_driver.driver, NULL,
			(void *)&pattern, device_match_by_alias);
	if (!dev) {
		printk("Cannot find the device[%s] driver[%s]\n", device_name, driver_name);
		return;
	}

	hw = dev_get_drvdata(dev);
	sc = hw->priv;
    retval = SMAC_REG_WRITE(sc->sh, addr, value);
	if (retval != 0)
		printk("Fail to read register");

}
EXPORT_SYMBOL(ssv6xxx_umac_reg_write);

void ssv6xxx_umac_tx_frame(char *driver_name, char *device_name, struct sk_buff *skb)
{
	struct device *dev;
    struct ieee80211_hw *hw;
    struct ssv_softc *sc;
	struct _pattern {
		char driver_name[32];
		char device_name[32];
	} pattern;

	sprintf(pattern.driver_name, "%s", driver_name);
	sprintf(pattern.device_name, "%s", device_name);

	dev = driver_find_device(&ssv6xxx_driver.driver, NULL,
			(void *)&pattern, device_match_by_alias);
	if (!dev) {
		printk("Cannot find the device[%s] driver[%s]\n", device_name, driver_name);
		return;
	}

	hw = dev_get_drvdata(dev);
	sc = hw->priv;
    HCI_SEND_CMD(sc->sh, skb);
}
EXPORT_SYMBOL(ssv6xxx_umac_tx_frame);

int ssv6xxx_umac_attach(char *driver_name, char *device_name, struct ssv6xxx_umac_ops *umac_ops)
{
	struct device *dev;
    struct ieee80211_hw *hw;
    struct ssv_softc *sc;
	struct _pattern {
		char driver_name[32];
		char device_name[32];
	} pattern;

	sprintf(pattern.driver_name, "%s", driver_name);
	sprintf(pattern.device_name, "%s", device_name);

	dev = driver_find_device(&ssv6xxx_driver.driver, NULL,
			(void *)&pattern, device_match_by_alias);
	if (!dev) {
		printk("Cannot find the device[%s] driver[%s]\n", device_name, driver_name);
		return -1;
	}

	hw = dev_get_drvdata(dev);
	sc = hw->priv;
	sc->umac = umac_ops;

	return 0;
}
EXPORT_SYMBOL(ssv6xxx_umac_attach);

int ssv6xxx_umac_deattach(char *driver_name, char *device_name)
{
	struct device *dev;
    struct ieee80211_hw *hw;
    struct ssv_softc *sc;
	struct _pattern {
		char driver_name[32];
		char device_name[32];
	} pattern;

	sprintf(pattern.driver_name, "%s", driver_name);
	sprintf(pattern.device_name, "%s", device_name);
	dev = driver_find_device(&ssv6xxx_driver.driver, NULL,
			(void *)&pattern, device_match_by_alias);
	if (!dev) {
		printk("Cannot find the device[%s] driver[%s]\n", device_name, driver_name);
		return -1;
	}

	hw = dev_get_drvdata(dev);
	sc = hw->priv;
	sc->umac = NULL;

	return 0;
}
EXPORT_SYMBOL(ssv6xxx_umac_deattach);



#if (defined(CONFIG_SSV_SUPPORT_ANDROID)||defined(CONFIG_SSV_BUILD_AS_ONE_KO))
int ssv6xxx_init(void)
#else
static int __init ssv6xxx_init(void)
#endif
{
    return platform_driver_register(&ssv6xxx_driver);
}
#if (defined(CONFIG_SSV_SUPPORT_ANDROID)||defined(CONFIG_SSV_BUILD_AS_ONE_KO))
void ssv6xxx_exit(void)
#else
static void __exit ssv6xxx_exit(void)
#endif
{
    platform_driver_unregister(&ssv6xxx_driver);
}
#if (defined(CONFIG_SSV_SUPPORT_ANDROID)||defined(CONFIG_SSV_BUILD_AS_ONE_KO))
EXPORT_SYMBOL(ssv6xxx_init);
EXPORT_SYMBOL(ssv6xxx_exit);
#else
module_init(ssv6xxx_init);
module_exit(ssv6xxx_exit);
#endif


