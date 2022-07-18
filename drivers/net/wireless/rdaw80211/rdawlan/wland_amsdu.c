/*
 * Copyright (c) 2018 Rdamicro Corporation
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
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/if_arp.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/wireless.h>
#include <linux/ieee80211.h>
#include <linux/debugfs.h>
#include <net/cfg80211.h>
#include <net/rtnetlink.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_arp.h>
#include <linux/ppp_defs.h>

#include "ethernet.h"
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
#include "wland_android.h"
#include "wland_rf.h"
#include "wland_rx.h"

uint amsdu_operation = AMSDU_OPERATION_DEF;

#ifdef WLAND_AMSDU_TX
static void _wland_amsdu_tx_timer(unsigned long data)
{
    struct wland_amsdu_tid_info *amsdu_tid = (struct wland_amsdu_tid_info *)data;
    struct wland_if *ifp = (struct wland_if *)(amsdu_tid->parent);
    struct sk_buff *aggr_pkt;
    int len;

	spin_lock_bh(&amsdu_tid->aggr_lock);
    aggr_pkt = amsdu_tid->aggr_pkt;
    len = amsdu_tid->curr_aggr_sz;

    amsdu_tid->aggr_pkt = NULL;
    amsdu_tid->curr_aggr_cnt = 0;
    amsdu_tid->curr_aggr_sz = 0;
	spin_unlock_bh(&amsdu_tid->aggr_lock);

    if (aggr_pkt) {
        if (ifp) {
            /* update WID header */            
            skb_put(aggr_pkt, len);
#ifdef WLAND_DMA_TX1536_BLOCKS
            len |= (PKT_TYPE_AGGR_MAC0 << CDC_DCMD_LEN_SHIFT);
#else
            len |= (PKT_TYPE_REQ << CDC_DCMD_LEN_SHIFT);
#endif
        	*(__le16 *)(aggr_pkt->data) = cpu_to_le16(len);

            WLAND_DBG(DATA, DEBUG, "AMSDU:[%d] to skb %p, sz %d %ld -> %ld\n",
                                                             ifp->ifidx,
                                                             aggr_pkt,
                                                             (len & 0xfff),
                                                             amsdu_tid->tx_time,
                                                             jiffies);

            wland_bus_txdata(ifp->drvr->bus_if, aggr_pkt);
        } else
            dev_kfree_skb(aggr_pkt);
    }

    return;
}

void wland_amsdu_tx_init(struct wland_if *ifp)
{
	struct wland_cfg80211_connect_info *conn_info = &ifp->vif->conn_info;
    struct wland_amsdu_info *amsdu_info = &conn_info->amsdu_info;
    struct wland_amsdu_tid_info *amsdu_tid;
    int i;

    WLAND_DBG(DATA, DEBUG, "AMSDU:[%d]init j %d\n", ifp->ifidx,
                                                    jiffies_to_msecs(1));

    amsdu_info = &conn_info->amsdu_info;
    spin_lock_init(&amsdu_info->amsdu_lock);
    amsdu_info->aggr_enabled = 0;
    for (i = 0, amsdu_tid = amsdu_info->amsdu_tid;
         i < 8;
         i++, amsdu_tid++) {
        amsdu_tid->parent = (void *)ifp;
        spin_lock_init(&amsdu_tid->aggr_lock);
        init_timer(&amsdu_tid->aggr_timer);
		amsdu_tid->aggr_timer.data = (unsigned long)amsdu_tid;
		amsdu_tid->aggr_timer.function = _wland_amsdu_tx_timer;
        amsdu_tid->aggr_pkt = NULL;
        amsdu_tid->curr_aggr_cnt = 0;
        amsdu_tid->curr_aggr_sz = 0;
        amsdu_tid->curr_bypass = 0;
        amsdu_tid->max_aggr_cnt = DEFAULT_AMSDU_TX_CNT;
        amsdu_tid->max_aggr_sz = DEFAULT_AMSDU_TX_SIZE;
        amsdu_tid->max_aggr_to = DEFAULT_AMSDU_TX_TIMEOUT;
    }

    return;
}

void wland_amsdu_tx_deinit(struct wland_if *ifp)
{
	struct wland_cfg80211_connect_info *conn_info = &ifp->vif->conn_info;
    struct wland_amsdu_info *amsdu_info = &conn_info->amsdu_info;
    struct wland_amsdu_tid_info *amsdu_tid;
    int i;

    WLAND_DBG(DATA, DEBUG, "AMSDU:[%d]deinit\n", ifp->ifidx);

    amsdu_info = &conn_info->amsdu_info;
	spin_lock_bh(&amsdu_info->amsdu_lock);
    amsdu_info->aggr_enabled = 0;
	spin_unlock_bh(&amsdu_info->amsdu_lock);
    for (i = 0, amsdu_tid = amsdu_info->amsdu_tid;
         i < 8;
         i++, amsdu_tid++) {
    	spin_lock_bh(&amsdu_tid->aggr_lock);
        amsdu_tid->aggr_pkt = NULL;
        amsdu_tid->curr_aggr_cnt = 0;
        amsdu_tid->curr_aggr_sz = 0;
        amsdu_tid->curr_bypass = 0;
        amsdu_tid->max_aggr_cnt = 0;
        amsdu_tid->max_aggr_sz = 0;
        amsdu_tid->max_aggr_to = 0;
        amsdu_tid->parent = NULL;
    	spin_unlock_bh(&amsdu_tid->aggr_lock);
        if (timer_pending(&amsdu_tid->aggr_timer))
            del_timer_sync(&amsdu_tid->aggr_timer);
    }

    return;
}

void wland_amsdu_tx_conf(struct wland_if *ifp, u8 tid, u8 enable)
{
	struct wland_cfg80211_connect_info *conn_info = &ifp->vif->conn_info;
    struct wland_amsdu_info *amsdu_info = &conn_info->amsdu_info;
    struct wland_amsdu_tid_info *amsdu_tid;
    u8 pre_aggr_enabled;

    WLAND_DBG(DATA, INFO,"AMSDU:[%d]conf tid %d, enable %d\n", ifp->ifidx,
                                                               tid,
                                                               enable);

    if (tid > 7)
        return;

    if (!(atomic_read(&conn_info->tid_map) & BIT(tid)))
        return;

    amsdu_tid = &amsdu_info->amsdu_tid[tid];

    spin_lock_bh(&amsdu_info->amsdu_lock);
    pre_aggr_enabled = amsdu_info->aggr_enabled;
    if (enable)
        amsdu_info->aggr_enabled |= BIT(tid);
    else
        amsdu_info->aggr_enabled &= ~BIT(tid);

    if (pre_aggr_enabled != amsdu_info->aggr_enabled) {
        if (amsdu_tid->aggr_pkt)
            dev_kfree_skb(amsdu_tid->aggr_pkt);
        amsdu_tid->aggr_pkt = NULL;
        amsdu_tid->curr_aggr_sz = 0;
        amsdu_tid->curr_aggr_cnt = 0;
        amsdu_tid->curr_bypass = 0;
    }
    spin_unlock_bh(&amsdu_info->amsdu_lock);

    return;
}

int _wland_amsdu_tx_decision(struct wland_if *ifp, struct sk_buff *pktbuf)
{
	struct wland_cfg80211_connect_info *conn_info;
    struct wland_amsdu_info *amsdu_info;
    struct wland_amsdu_tid_info *amsdu_tid;
	struct ethhdr *eh;
	struct iphdr *iph;
    u8 tid;

    /* TODO: now only allowe TCP-ACK data in STA modes. */

    if ((ifp->bssidx != 0) || (ifp->vif->mode != WL_MODE_BSS))
        return -1;

    eh = (struct ethhdr *)(pktbuf->data);
    if (is_multicast_ether_addr(eh->h_dest))
        return -2;

    conn_info = &ifp->vif->conn_info;
    if (!(conn_info->wmm_enable && conn_info->n_enable))
        return -3;

    if (pktbuf->protocol != htons(ETH_P_IP))
        return -4;

    iph = (struct iphdr *)(pktbuf->data + ETH_HLEN);
    if(iph->protocol != IPPROTO_TCP)
        return -5;

    if (pktbuf->len > AMSDU_TX_MSDU_SZ)
        return -6;

    tid = iph->tos >> 5;
    if (tid > 7)
        return -7;
    
    amsdu_info = &conn_info->amsdu_info;
    spin_lock_bh(&amsdu_info->amsdu_lock);
    if (!(amsdu_info->aggr_enabled & BIT(tid))) {
        spin_unlock_bh(&amsdu_info->amsdu_lock);
        return -8;
    }
    spin_unlock_bh(&amsdu_info->amsdu_lock);

    amsdu_tid = &amsdu_info->amsdu_tid[tid];
    spin_lock_bh(&amsdu_tid->aggr_lock);
    if (amsdu_tid->parent == NULL) {
        spin_unlock_bh(&amsdu_tid->aggr_lock);
        return -9;
    }
    if (amsdu_tid->curr_bypass++ < DEFAULT_AMSDU_TX_BYPASS) {
        spin_unlock_bh(&amsdu_tid->aggr_lock);
        return -10;
    }
    spin_unlock_bh(&amsdu_tid->aggr_lock);

    return (int)tid;
}

int wland_amsdu_tx(struct wland_if *ifp, struct sk_buff *pktbuf)
{
    struct wland_private *drvr = ifp->drvr;
	struct wland_cfg80211_profile *profile = &ifp->vif->profile;
	struct wland_cfg80211_connect_info *conn_info = &ifp->vif->conn_info;
    struct wland_amsdu_info *amsdu_info = &conn_info->amsdu_info;
    struct wland_amsdu_tid_info *amsdu_tid;
    struct sk_buff *aggr_pkt, *pre_aggr_pkt = NULL;
    u8 snap_hdr[SNAP_HDR_LEN] = { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00};
    u8 *ptr;
    int len;
    int tid;

    tid = _wland_amsdu_tx_decision(ifp, pktbuf);
    if (tid < 0) {
        WLAND_DBG(DATA, DEBUG, "AMSDU:[%d]decision ret %d\n", ifp->ifidx, tid);

        return -1;
    }

    amsdu_tid = &amsdu_info->amsdu_tid[tid];

    spin_lock_bh(&amsdu_tid->aggr_lock);

again:
    if (amsdu_tid->aggr_pkt == NULL) {
        amsdu_tid->aggr_pkt = dev_alloc_skb(amsdu_tid->max_aggr_sz);
        if (amsdu_tid->aggr_pkt == NULL) {
            spin_unlock_bh(&amsdu_tid->aggr_lock);
            //dev_kfree_skb(pktbuf);
            return -2;
        }

        /* reset context */
        amsdu_tid->curr_aggr_cnt = 0;
        aggr_pkt = amsdu_tid->aggr_pkt;
        ptr = aggr_pkt->data;
        aggr_pkt->priority = tid;
        aggr_pkt->dev = pktbuf->dev;
        aggr_pkt->protocol = pktbuf->protocol;

        /* build Host-AMSDU dummy header */
        memcpy(ptr + WID_HEADER_LEN, profile->bssid, 6);
        memcpy(ptr + WID_HEADER_LEN + 6, ifp->mac_addr, 6);
        *(__le16 *)(ptr + WID_HEADER_LEN + 12) = cpu_to_le16(AMSDU_TX_DUMMY_HDR_TYPE);

        amsdu_tid->curr_aggr_sz = WID_HEADER_LEN + AMSDU_TX_DUMMY_HDR_SZ;
    } else {
        aggr_pkt = amsdu_tid->aggr_pkt;
        ptr = aggr_pkt->data;

        /* send current aggr_pkt if can't insert new one */
        if ((amsdu_tid->curr_aggr_cnt >= amsdu_tid->max_aggr_cnt) ||
            ((amsdu_tid->curr_aggr_sz + (pktbuf->len + SNAP_HDR_LEN + 4)) >
                                                      amsdu_tid->max_aggr_sz)) {
            /* update WID header */
            len = amsdu_tid->curr_aggr_sz;
            skb_put(aggr_pkt, len);
#ifdef WLAND_DMA_TX1536_BLOCKS
            len |= (PKT_TYPE_AGGR_MAC0 << CDC_DCMD_LEN_SHIFT);
#else
            len |= (PKT_TYPE_REQ << CDC_DCMD_LEN_SHIFT);
#endif
        	*(__le16 *)ptr = cpu_to_le16(len);

            pre_aggr_pkt = aggr_pkt;

            /* go through new one again */
            amsdu_tid->aggr_pkt = NULL;
            goto again;
        }
    }

    /* next MSDU should start at 4-byte boundary */
    len = amsdu_tid->curr_aggr_sz - WID_HEADER_LEN - AMSDU_TX_DUMMY_HDR_SZ;
    BUG_ON(len < 0);
    if (len & 0x3)
         amsdu_tid->curr_aggr_sz += (4 - (len & 0x3));

    /* insert 802.3 header */
    len = pktbuf->len - ETH_HLEN;
    ptr += amsdu_tid->curr_aggr_sz;
    memcpy(ptr, pktbuf->data, 12);
    *(__be16 *)(ptr + 12) = cpu_to_be16(len + SNAP_HDR_LEN);

    /* insert SNAP header */
    memcpy(ptr + ETH_HLEN, snap_hdr, SNAP_HDR_LEN);

    /* insert Payload */
    memcpy(ptr + ETH_HLEN + SNAP_HDR_LEN, pktbuf->data + ETH_HLEN, len);

    /* finally, update the context */
    amsdu_tid->curr_aggr_sz += (ETH_HLEN + SNAP_HDR_LEN + len);
    amsdu_tid->curr_aggr_cnt++;

    spin_unlock_bh(&amsdu_tid->aggr_lock);

    /* start flush timer */
    amsdu_tid->tx_time = jiffies;
    mod_timer(&amsdu_tid->aggr_timer,
              jiffies + msecs_to_jiffies(amsdu_tid->max_aggr_to));

    WLAND_DBG(DATA, DEBUG, "AMSDU:[%d]txd pre_aggr_pkt %p %p, sz %d cnt %d\n",
                                                      ifp->ifidx,
                                                      pre_aggr_pkt,
                                                      amsdu_tid->aggr_pkt,
                                                      amsdu_tid->curr_aggr_sz,
                                                      amsdu_tid->curr_aggr_cnt);


    if (pre_aggr_pkt)
        wland_bus_txdata(drvr->bus_if, pre_aggr_pkt);

    dev_kfree_skb(pktbuf);

	return 0;
}
#endif

#ifdef WLAND_DEAMSDU_RX
void wland_deamsdu_rx_free(void *deamsdu_frame)
{
    struct recv_frame *recv_frame = (struct recv_frame *)deamsdu_frame;

    WLAND_DBG(DATA, DEBUG, "DEAMSDU:free %p", deamsdu_frame);

    if (recv_frame) {
        struct list_head *deamsdu_list = &recv_frame->deamsdu_list;
        struct wland_rx_info *rx_info;
        struct recv_frame *msdu, *msdu_tmp;

        BUG_ON(recv_frame->preorder_ctrl == NULL);

        rx_info = recv_frame->preorder_ctrl->rx_info;

        if (!list_empty(deamsdu_list)) {
			list_for_each_entry_safe(msdu, msdu_tmp, deamsdu_list, deamsdu_list) {
                list_del(&msdu->deamsdu_list);
                if (msdu->pkt) {
                    dev_kfree_skb(msdu->pkt);
                    msdu->pkt = NULL;
                }
                wland_recvframe_enq(&rx_info->free_recv_lock,
                                    &rx_info->free_recv_queue,
                                    &msdu->list2,
                                    &rx_info->free_recv_cnt);
            }
        }

        if (recv_frame->pkt) {
            dev_kfree_skb(recv_frame->pkt);
            recv_frame->pkt = NULL;
        }
        wland_recvframe_enq(&rx_info->free_recv_lock,
                            &rx_info->free_recv_queue,
                            &recv_frame->list2,
                            &rx_info->free_recv_cnt);
    } else {
        WLAND_ERR("free deamsdu NULL?\n");
    }

    return;
}

static void _wland_deamsdu_rx_indicatepkt(void *deamsdu_frame,
                                          struct wland_bus *bus_if)
{
    struct recv_frame *recv_frame = (struct recv_frame *)deamsdu_frame;
    struct wland_rx_info *rx_info;
    struct sk_buff *skb = NULL;

    WLAND_DBG(DATA, DEBUG, "DEAMSDU: %p seq %d cnt %d order %d", recv_frame,
                                                    recv_frame->deamsdu_cnt,
                                                    recv_frame->attrib.seq_num,
                                                    recv_frame->deamsdu_order);

    BUG_ON(recv_frame->preorder_ctrl == NULL);

    rx_info = recv_frame->preorder_ctrl->rx_info;

    skb = recv_frame->pkt;
    if (skb == NULL) {
        WLAND_ERR("skb is NULL, precv_frame %p\n", recv_frame);

        return;
    }

    skb->data = recv_frame->rx_data;

    skb_set_tail_pointer(skb, recv_frame->len);

    skb->len = recv_frame->len;

    wland_process_8023_pkt(bus_if, skb);

    recv_frame->pkt = NULL;

    return;
}

int wland_deamsdu_rx_indicatepkt(void *deamsdu_frame, struct wland_bus *bus_if)
{
    struct recv_frame *recv_frame = (struct recv_frame *)deamsdu_frame;
    struct list_head *deamsdu_list = &recv_frame->deamsdu_list;
    struct recv_frame *msdu, *msdu_tmp;
    int cnt = recv_frame->deamsdu_cnt;

    WLAND_DBG(DATA, DEBUG, "DEAMSDU: %p cnt %d", recv_frame, cnt);

    BUG_ON(!(recv_frame->deamsdu_order & BIT0));

    cnt--;
    _wland_deamsdu_rx_indicatepkt((void *)recv_frame, bus_if);

	list_for_each_entry_safe(msdu, msdu_tmp, deamsdu_list, deamsdu_list) {
        cnt--;
        _wland_deamsdu_rx_indicatepkt((void *)msdu, bus_if);
	}

    if (cnt != 0) {
        WLAND_ERR("unsync MSDU cnt %d\n", cnt);
    }

    wland_deamsdu_rx_free((void *)recv_frame);

	return 0;
}

enum deamsdu_proc_e wland_deamsdu_rx_process(void *deamsdu_frame, u16 seq)
{
    struct recv_frame *recv_frame = (struct recv_frame *)deamsdu_frame;
	struct recv_reorder_ctrl* reorder_ctrl = recv_frame->preorder_ctrl;
    enum deamsdu_rx_state_e curr_state, next_state;
    struct recv_frame *curr_deamsdu = (struct recv_frame *)(reorder_ctrl->curr_deamsdu);
    u8 deamsdu_order = recv_frame->deamsdu_order;
    enum deamsdu_proc_e ret = DEAMSDU_PROC_ERROR;

    curr_state =
    next_state = reorder_ctrl->wait_deamsdu_state;

    /* this is new head MSDU */
    if (reorder_ctrl->wait_deamsdu_seq != seq) {
        if (curr_state != DEAMSDU_STATE_COMPLETE) {
            BUG_ON(!curr_deamsdu);

            WLAND_ERR("lost some deamsdu? seq %d\n", curr_deamsdu->attrib.seq_num);

            /* current MSDUs not completed and free it. */
            wland_deamsdu_rx_free((void *)curr_deamsdu);
        }

        reorder_ctrl->wait_deamsdu_seq = seq;
        reorder_ctrl->curr_deamsdu = NULL;
        curr_state = next_state = DEAMSDU_STATE_WAIT_FIRST_MSDU;
    } else {
        if (curr_state == DEAMSDU_STATE_COMPLETE) {
            WLAND_ERR("duplicated deamsdu %p? seq %d order %d\n", recv_frame,
                                                                  seq,
                                                                  deamsdu_order);

            goto done;
        }
    }

    if (deamsdu_order == (BIT0 | BIT1)) {
        reorder_ctrl->curr_deamsdu = (void *)recv_frame;
        next_state = DEAMSDU_STATE_COMPLETE;
        recv_frame->deamsdu_cnt++;

        /* this is a normal MSDU or single AMSDU */
        ret = DEAMSDU_PROC_MSDUS_DONE;
    } else {
        if ((deamsdu_order & BIT0) &&
            (curr_state == DEAMSDU_STATE_WAIT_FIRST_MSDU)) {
            recv_frame->deamsdu_cnt++;
            reorder_ctrl->curr_deamsdu = (void *)recv_frame;
            next_state = DEAMSDU_STATE_WAIT_LAST_MSDU;

            /* first MSDU comes and record it */
            ret = DEAMSDU_PROC_WAIT_NEXT;
        } else if ((deamsdu_order == 0) &&
                   (curr_state == DEAMSDU_STATE_WAIT_LAST_MSDU)) {
            curr_deamsdu->deamsdu_cnt++;
            list_add_tail(&recv_frame->deamsdu_list,
                          &curr_deamsdu->deamsdu_list);
            next_state = DEAMSDU_STATE_WAIT_LAST_MSDU;

            /* middle MSDUs come and insert it */
            ret = DEAMSDU_PROC_WAIT_NEXT;
        } else if ((deamsdu_order & BIT1) &&
                   (curr_state == DEAMSDU_STATE_WAIT_LAST_MSDU)) {
            curr_deamsdu->deamsdu_cnt++;
            list_add_tail(&recv_frame->deamsdu_list,
                          &curr_deamsdu->deamsdu_list);
            next_state = DEAMSDU_STATE_COMPLETE;

            /* report head MSDU to rx reorder */
            ret = DEAMSDU_PROC_MSDUS_DONE;
        } else {
            WLAND_ERR("unexpected deamsdu, seq %d status %d order %d\n",
                                                                 seq,
                                                                 curr_state,
                                                                 deamsdu_order);
        }
    }

done:
    reorder_ctrl->wait_deamsdu_state = next_state;

    WLAND_DBG(DATA, DEBUG, "DEAMSDU: proc curr_state %d next_state %d ret %d",
                                                                     curr_state,
                                                                     next_state,
                                                                     ret);

    return ret;
}
#endif

