
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
#include <linux/netdevice.h>
#include <linux/interrupt.h>
#include <linux/completion.h>
#include <linux/scatterlist.h>
#include <linux/mmc/sdio.h>
#include <linux/mmc/sdio_func.h>
#include <linux/mmc/card.h>
#include <linux/mmc/host.h>
#include <linux/semaphore.h>
#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/vmalloc.h>
#include <asm/unaligned.h>
#include <net/cfg80211.h>
#include <net/rtnetlink.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/signal.h>
#else
#include <linux/sched.h>
#endif

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
#include "wland_rx.h"

static const char wland_version_string[WLAND_VER_MAX][15] = {
	"Unknow chip",
	"RDA5990_D",
	"RDA5990_E",
	"RDA5991_D",
	"RDA5991_E",
	"RDA5991_F",
	"RDA5991_G",
	"RDA5995",
};

void wland_pkt_word_align(struct sk_buff *p)
{
	uint datalign = ALIGNMENT;
	uint offset = ((unsigned long) (p->data) & (datalign - 1));

	if (offset)
		skb_reserve(p, (datalign - offset));

}

/* Turn backplane clock on or off */
static int wland_sdio_htclk(struct wland_sdio *bus, bool on)
{

	WLAND_DBG(SDIO, TRACE, "(%s): Enter\n", on ? " Open" : "Stop");

	if (on) {

		/*
		 * Mark clock available
		 */
		bus->clkstate = CLK_AVAIL;
		bus->activity = true;
		BUS_WAKE(bus);
		WLAND_DBG(SDIO, TRACE, "CLKCTL: turned ON\n");
	} else {
		bus->clkstate = CLK_NONE;
		bus->activity = false;
		WLAND_DBG(SDIO, TRACE, "CLKCTL: turned OFF\n");
	}

	WLAND_DBG(SDIO, TRACE, "(%s): Done.\n", on ? " Open" : "Stop");

	return 0;
}

int wland_chip_wake_up(struct wland_sdio *bus)
{

	int ret = 0;

#ifdef	WLAND_POWER_MANAGER
	u8 val = 1;
#endif

	WLAND_DBG(SDIO, TRACE, "Enter\n");

	//Tx complete, check whether go to sleep.
	if (!bus->activity && (bus->sdiodev->card_sleep)) {
#ifdef	WLAND_POWER_MANAGER
		if (!wland_check_test_mode() && bus->sdiodev->bus_if->chip_ready) {
			WLAND_DBG(SDIO, TRACE,
				"WIFI chip wake up <<<<<<<<< \n");
			if (bus->sdiodev->bus_if->chip == WLAND_VER_91_H) {
				int retry = 500;
				if (!(strncasecmp(rdawlan_firmware_path, "ap", strlen("ap"))==0)) {
					sdio_claim_host(bus->sdiodev->func);
					ret = wland_sdioh_request_byte(bus->sdiodev, SDIOH_WRITE,
						URSDIO_FUNC1_INT_TO_DEVICE, &val);

					if (ret) {
						ret = -1;
						WLAND_ERR("Write URSDIO_FUNC1_INT_TO_DEVICE failed!\n");
					}

					//5991h query URSDIO_FUNC1_INT_PENDING BIT4=1.
					while (retry) {
						ret = wland_sdioh_request_byte(bus->sdiodev, SDIOH_READ,
							URSDIO_FUNC1_INT_PENDING, &val);
						retry --;
						if (ret==0 && val&BIT4) {
							break;
						}
					//udelay(1000);	//msleep(1);
					}
					sdio_release_host(bus->sdiodev->func);
					//WLAND_ERR("Wake up Polling INT_PENDING:%d\n", 500-retry);
				}

				if (retry == 0) {
					ret = -1;
					WLAND_ERR("wait fw wakeup failed, 500!\n");
				} else
					bus->sdiodev->card_sleep = false;

			} else {
				sdio_claim_host(bus->sdiodev->func);
				ret = wland_sdioh_request_byte(bus->sdiodev, SDIOH_WRITE,
					URSDIO_FUNC1_INT_TO_DEVICE, &val);
				sdio_release_host(bus->sdiodev->func);
				if (ret)
					WLAND_ERR("Write URSDIO_FUNC1_INT_TO_DEVICE failed!\n");
				else {
					bus->sdiodev->card_sleep = false;
					wland_sched_timeout(10);
				}
			}
		}
#endif
		if (!wland_sdio_htclk(bus, true)) {
			WLAND_DBG(SDIO, TRACE, "WIFI chip waked up and MOD timer. \n");
			wland_sdio_wd_timer(bus, bus->save_ms);
		}
	}
	WLAND_DBG(SDIO, TRACE, "Done.\n");
	return ret;
}

int wland_chip_goto_sleep(struct wland_sdio *bus)
{
	int ret = 0;

	struct wland_sdio_dev *sdiodev = bus->sdiodev;
	struct wland_bus *bus_if = sdiodev->bus_if;
	struct wland_private *drvr = bus_if->drvr;
	struct wland_if *ifp = drvr->iflist[0];
	struct wland_cfg80211_info *cfg;
	struct wland_cfg80211_connect_info *conn_info;

#ifdef	WLAND_POWER_MANAGER
	u8 val;
	if (bus_if->chip == WLAND_VER_91_H)
		val = BIT4;//0x10
	else
		val = BIT7;//0x80
#endif

	WLAND_DBG(SDIO, TRACE, "Enter\n");

	if (bus_if->state == WLAND_BUS_DOWN) {
#ifdef	WLAND_POWER_MANAGER
		//5991h p2p doesn't support powermanager, so we won't sleep when p2p is working
		if (!test_bit(VIF_STATUS_P2P, &(ifp->vif->sme_state))) {
			sdio_claim_host(bus->sdiodev->func);
			ret = wland_sdioh_request_byte(bus->sdiodev, SDIOH_WRITE,
				URSDIO_FUNC1_INT_PENDING, &val);
			sdio_release_host(bus->sdiodev->func);
			if (ret) {
				WLAND_ERR("Write URSDIO_FUNC1_INT_PENDING failed!\n");
			}
			bus->sdiodev->card_sleep = true;
		}
#endif
		wland_sdio_wd_timer(bus, 0);
		return ret;
	}
	cfg = wiphy_priv(ifp->vif->wdev.wiphy);
	conn_info = &ifp->vif->conn_info;

	//Tx complete, check whether go to sleep.
	if (bus->activity &&
		!wland_check_test_mode() &&
#ifdef WLAND_SMART_CONFIG_SUPPORT
		!ifp->sniffer_enable &&
#endif
		!test_bit(SCAN_STATUS_BUSY, &cfg->scan_status) &&
		!test_bit(VIF_STATUS_CONNECTING, &ifp->vif->sme_state) &&
		//test_bit(VIF_STATUS_CONNECTED, &ifp->vif->sme_state) &&
		//5991h p2p doesn't support powermanager, so we won't sleep when p2p is working
		!test_bit(VIF_STATUS_P2P, &(ifp->drvr->iflist[0]->vif->sme_state)) &&
		!timer_pending(&conn_info->connect_restorework_timeout) &&
		((strncasecmp(rdawlan_firmware_path, "sta", strlen("sta"))==0 || strncasecmp(rdawlan_firmware_path, "p2p", strlen("p2p"))==0))) {
#ifdef	WLAND_POWER_MANAGER
			if (!wland_check_test_mode() && drvr->bus_if->chip_ready) {
				WLAND_DBG(SDIO, TRACE,
					"WIFI chip enter sleep. >>>>>>>>>>> \n");
				sdio_claim_host(bus->sdiodev->func);
				ret = wland_sdioh_request_byte(bus->sdiodev, SDIOH_WRITE,
					URSDIO_FUNC1_INT_PENDING, &val);
#if 0
				ret = wland_sdioh_request_byte(bus->sdiodev, SDIOH_READ,
					URSDIO_FUNC1_INT_PENDING, &val);
#endif
				sdio_release_host(bus->sdiodev->func);
				//WLAND_ERR("URSDIO_FUNC1_INT_PENDING = %02x, bit4:%x\n", val, val&BIT4);
				if (ret) {
					WLAND_ERR
						("Write URSDIO_FUNC1_INT_PENDING failed!\n");
				}
				bus->sdiodev->card_sleep = true;
		}
#endif
			WLAND_DBG(SDIO, TRACE, "turn OFF clock and delete wd timer.\n");
			wland_sdio_htclk(bus, false);
			wland_sdio_wd_timer(bus, 0);
	} else {
			if((strncasecmp(rdawlan_firmware_path, "ap", strlen("ap"))==0)
				&& (test_bit(VIF_STATUS_AP_CREATED, &ifp->vif->sme_state))) {
				bus->sdiodev->card_sleep = true;
				wland_sdio_htclk(bus, false);
				wland_sdio_wd_timer(bus, 0);
				//printk("!!!ap created!\n");
			} else {
				BUS_WAKE(bus);
				wland_sdio_wd_timer(bus, bus->save_ms);
			}
	}

	WLAND_DBG(SDIO, TRACE, "Done.\n");
	return ret;
}

/* Change idle/active SD state,Transition SD and backplane clock readiness */
int wland_sdio_clkctl(struct wland_sdio *bus, uint target)
{
	int ret = 0;
	uint oldstate = bus->clkstate;

	WLAND_DBG(SDIO, TRACE, "=========>OldState(%d),ExpectState(%d),Enter\n",
		bus->clkstate, target);
	if (bus->sdiodev->bus_if->state == WLAND_BUS_DOWN) {
		WLAND_ERR("bus_if is down, can't operate sdio clock!\n");
		ret = -1;
		return ret;
	}

	/*
	 * Early exit if we're already there
	 */
	if (bus->clkstate == target) {
		if (target == CLK_AVAIL) {
			BUS_WAKE(bus);
			wland_sdio_wd_timer(bus, bus->save_ms);
		}
		return ret;
	}

	switch (target) {
	case CLK_AVAIL:
		/*
		 * Make sure SD clock is available
		 */
		WLAND_DBG(SDIO, TRACE, "CLK_NONE --> CLK_AVAIL\n");
		wland_chip_wake_up(bus);
		break;

	case CLK_NONE:
		/*
		 * Now remove the SD clock
		 */
		WLAND_DBG(SDIO, TRACE, "CLK_AVAIL --> CLK_NONE\n");
		wland_chip_goto_sleep(bus);
		break;
	}

	WLAND_DBG(SDIO, TRACE, "=========>OldState(%d)--->NewState(%d),Done\n",
		oldstate, bus->clkstate);

	return ret;
}

static struct sk_buff *wland_pkt_buf_get_suitable_skb(struct wland_sdio *bus,
	struct sk_buff *skb, u16 *len)
{
	struct sk_buff *skb2 = skb;
	u16 base_len = *len;
	u16 size = *len;
	int ret = 0;

	WLAND_DBG(SDIO, TRACE, "Enter, size=%d\n", size);

	//for sdio must 4 bytes align
	if (size & (ALIGNMENT - 1))
		size = roundup(size, ALIGNMENT);

	size = wland_get_align_size(bus, size);

	if (!skb) {		// just get a suitable skb.
		skb2 = wland_pkt_buf_get_skb(size + ALIGNMENT - 1);
		if (!skb2) {
			WLAND_ERR("couldn't allocate new %d-byte packet\n",
				size + ALIGNMENT - 1);
			ret = -ENOMEM;
		} else {
			wland_pkt_word_align(skb2);
		}
		goto done;
	} else if (size - base_len >= 3) {
		skb2 = wland_pkt_buf_get_skb(size);
		if (!skb2) {
			WLAND_ERR("couldn't allocate new %d-byte packet\n",
				size);
			ret = -ENOMEM;
			goto done;
		} else {
			wland_pkt_word_align(skb2);
		}
	} else if ((size - base_len < 3)
		&& !IS_ALIGNED((unsigned long) skb->data, ALIGNMENT)) {
		skb2 = wland_pkt_buf_get_skb(size + ALIGNMENT - 1);
		if (!skb2) {
			WLAND_ERR("couldn't allocate new %d-byte packet\n",
				size + ALIGNMENT - 1);
			ret = -ENOMEM;
			goto done;
		} else {
			wland_pkt_word_align(skb2);
		}

	}

done:
	if (skb2){
		*len = size;
		skb2->len = size;
		WLAND_DBG(SDIO, TRACE, "Done.\n");
		return skb2;
	} else {
		WLAND_DBG(SDIO, TRACE, "Done.\n");
		return NULL;
	}
}

/* Writes a HW/SW header into the packet and sends it. */

/* Assumes: (a) header space already there, (b) caller holds lock */
static int wland_sdio_txpkt(struct wland_sdio *bus, struct sk_buff *pkt)
{
	int ret = 0;
	u8 *frame;
	u16 len = 0;
	struct wland_bus *bus_if = dev_get_drvdata(bus->sdiodev->dev);
#ifdef WLAND_TX_SOFT_MAC
	u8 *data = pkt->data;
#endif

	WLAND_DBG(SDIO, TRACE, "Enter(bus_state:%d)\n", bus_if->state);

	if (bus_if->state == WLAND_BUS_DOWN) {
		WLAND_ERR("Bus state is down and reject the pkt!\n");
		return -EINVAL;
	}

	frame = (u8 *) (pkt->data);
#ifdef WLAND_DMA_TX1536_BLOCKS
	len = pkt->len;
#else
	len = pkt->len & CDC_DCMD_LEN_MASK;
#endif

	WLAND_DBG(SDIO, DEBUG, "pkt->len=%x, frame:%x, addr(pkt->data)=%p\n", len,
		*(__le16 *) frame, pkt->data);

	if (len & (ALIGNMENT - 1))
		len = roundup(len, ALIGNMENT);

	len = wland_get_align_size(bus, len);

	WLAND_DBG(SDIO, TRACE,
		"len=%d, pkt->len=%d, pkt->data:0x%p\n", len, pkt->len, pkt->data);
	WLAND_DUMP(TX_MSDU, pkt->data, len, "MSDU len:%u\n", pkt->len);
	ret = wland_sdio_send_pkt(bus, pkt, len);
	if (ret)
		WLAND_DBG(SDIO,INFO,"wland_sdio_send_pkt fail%d\n", ret);

#ifndef WLAND_TX_AGGRPKTS
#ifdef WLAND_TX_SOFT_MAC
	skb_pull(pkt, data[3]);
#else
	skb_pull(pkt, WID_HEADER_LEN);
#endif
#endif

	wland_txcomplete(bus->sdiodev->dev, pkt, (ret == 0));
	return ret;
}

#ifdef WLAND_TX_AGGRPKTS
void wland_txdata_buf_reset(struct wland_sdio* bus)
{
	struct sk_buff *tx_buf = bus->txdata_buf;
	tx_buf->data = bus->txdata_buf_data;
	bus->txdata_offset = bus->txdata_buf_data;
	tx_buf->len = 0;
	atomic_set(&bus->aggr_count, 0);
}
static int wland_add_aggr_ptks(struct wland_sdio* bus, struct sk_buff *pkt)
{
	u8 *data = pkt->data;
#if 0
	u16 adjust_len = 0;
	u16 real_len = pkt->len;
	u8 adjust_str[4] = {0xFF, 0xFF, 0xFF, 0xFF};
#endif
	u8 pkt_type = (u8)data[1] >> 4;
	u8 aggr_type = 0;
	u16 cached_len = 0;

	cached_len = bus->txdata_offset - bus->txdata_buf->data;
	if ((cached_len + pkt->len) > (WLAND_AGGR_TXPKT_LEN-2)) {
		WLAND_ERR("overstep aggr pkt buf length\n");
		skb_pull(pkt, WID_HEADER_LEN);
		wland_pkt_buf_free_skb(pkt);
		return -1;
	}

	if (pkt_type == PKT_TYPE_REQ) {
		aggr_type = PKT_TYPE_AGGR_MAC0;
		data[1] = (data[1] & (0x0F)) | (aggr_type << 4);
	} else if (pkt_type == PKT_TYPE_DATA_MAC1) {
		aggr_type = PKT_TYPE_AGGR_MAC1;
		data[1] = (data[1] & (0x0F)) | (aggr_type << 4);
	} else if ((pkt_type == PKT_TYPE_AGGR_MAC0) || (pkt_type == PKT_TYPE_AGGR_MAC1)) {
		//Nothing todo;
	} else {
		WLAND_ERR("Bad pkt type!\n");
		skb_pull(pkt, WID_HEADER_LEN);
		wland_pkt_buf_free_skb(pkt);
		return -1;
	}
#if 0
	if (real_len & (ALIGNMENT - 1)) { //four bytes align;
		adjust_len = roundup(real_len, ALIGNMENT);
		memcpy(&(data[real_len]), adjust_str, (adjust_len - real_len));
		skb_put(pkt, (adjust_len - real_len));
	}
#endif
	memcpy(bus->txdata_offset, data, pkt->len);
	bus->txdata_offset += pkt->len;

	bus->txdata_buf->dev = pkt->dev;
	skb_pull(pkt, WID_HEADER_LEN);
	wland_pkt_buf_free_skb(pkt);

	atomic_inc(&bus->aggr_count);
	return 0;
}

static void wland_send_aggr_ptks(struct wland_sdio* bus)
{
	struct sk_buff *tx_buf = bus->txdata_buf;
	u8 *offset = bus->txdata_offset;
	int ret = 0;
	u16 cached_len = 0;

	cached_len = bus->txdata_offset - bus->txdata_buf->data;
	if (bus->txdata_offset - bus->txdata_buf->data > WLAND_AGGR_TXPKT_LEN-2) {
		//WLAND_ERR("aggr pkt len:%zu:%u\n", bus->txdata_offset - bus->txdata_buf->data, cached_len);
	} else {
		offset[0] = 0;
		offset[1] = 0;
		bus->txdata_offset += 2;
		tx_buf->len = bus->txdata_offset - tx_buf->data;
	}

	ret = wland_sdio_txpkt(bus, tx_buf);
	if (!ret)
		wland_txdata_buf_reset(bus);
	else
		WLAND_DBG(SDIO,INFO,"Cache tx buf! ret:%d\n",ret);
		//WLAND_ERR("Cache tx buf! ret:%d\n",ret);
}

static void wland_sendpkt_without_aggr(struct wland_sdio *bus,
	struct sk_buff *pkt)
{
	struct sk_buff *pkt1;
	u8 *data;
	u16 real_len = pkt->len;
#if 0
	u16 adjust_len = 0;
	u8 adjust_str[4] = {0xFF, 0xFF, 0xFF, 0xFF};
#endif
	int ret = 0;

#if 0
	if (real_len & (ALIGNMENT - 1)) { //four Bytes align;
		adjust_len = roundup(real_len, ALIGNMENT);
		memcpy(&(data[real_len]), adjust_str, (adjust_len - real_len));
		skb_put(pkt, (adjust_len - real_len));
		real_len = adjust_len;
	}
#endif

	if (pkt->end < pkt->tail+2) {
		WLAND_ERR("malloc skb buf\n");
		pkt1 = __dev_alloc_skb(pkt->len + 2 + 4, GFP_KERNEL);
		if (pkt1 == NULL) {
			WLAND_ERR("malloc skb buf fail\n");
			skb_pull(pkt, WID_HEADER_LEN);
			dev_kfree_skb(pkt);
			return;
		}
		skb_put(pkt1, pkt->len);
		memcpy(pkt1->data, pkt->data, pkt->len);
		pkt1->dev = pkt->dev;

		skb_pull(pkt, WID_HEADER_LEN);
		dev_kfree_skb(pkt);

		pkt = pkt1;
	}

	data = pkt->data;
	data[real_len] = 0;
	data[real_len + 1] = 0;
	skb_put(pkt, 2);

	ret = wland_sdio_txpkt(bus, pkt);
	if (!ret) {
		skb_pull(pkt, WID_HEADER_LEN);
		dev_kfree_skb(pkt);
	} else {
		pkt->tail += -2;
		pkt->len  += -2;
		if (wland_add_aggr_ptks(bus, pkt)) {
			wland_txdata_buf_reset(bus);
			WLAND_ERR("!!!!!!!add aggr pkts failed!\n");
		}
		WLAND_DBG(SDIO,INFO,"Cache tx buf! ret:%d\n",ret);
		//WLAND_ERR("Cache tx buf! ret:%d\n",ret);
	}
}
#endif
static uint wland_sdio_sendfromq(struct wland_sdio *bus)
{
	struct sk_buff *pkt;
	uint cnt = 0;
	unsigned long flags = 0;
	struct wland_if *ifp = bus->sdiodev->bus_if->drvr->iflist[0];
#ifdef WLAND_TX_AGGRPKTS
	u16 cached_len = 0;
	int retry_times = 0;
	int max_times = 10;
#endif

	WLAND_DBG(BUS, TRACE, "Enter\n");

	/*
	 * Send frames until the limit or some other event
	 */
	wland_dhd_os_sdlock_txq(bus, &flags);
	pkt = wland_pktq_mdeq(&bus->txq);
	if (pkt == NULL) {
		WLAND_ERR("pkt == NULL and go out.\n");
		wland_dhd_os_sdunlock_txq(bus, &flags);
		goto done;
	}
	atomic_dec(&bus->tx_dpc_tskcnt);
	wland_dhd_os_sdunlock_txq(bus, &flags);

#ifdef WLAND_TX_AGGRPKTS

send:
		cached_len = bus->txdata_offset - bus->txdata_buf->data;
		if ((pkt->protocol == htons(ETH_P_ARP)) ||
			(pkt->protocol == htons(ETH_P_PAE))
#ifdef DHCP_PKT_MEMCOPY_BEFORE_SEND
			|| (pkt->protocol == htons(0x0801))
#endif
			) { //inform these pkts whithout aggr!

			wland_sendpkt_without_aggr(bus, pkt);

			if((atomic_read(&bus->tx_dpc_tskcnt) == 0)
				&& (atomic_read(&bus->aggr_count) != 0)
				&& (cached_len != 0))
				wland_send_aggr_ptks(bus);
			goto flowcontrol;
		} else if ((atomic_read(&bus->aggr_count) == 0) &&
			(cached_len == 0)) {
			if (atomic_read(&bus->tx_dpc_tskcnt) == 0) { //just one pkt inform it!
				wland_sendpkt_without_aggr(bus, pkt);
				goto flowcontrol;
			} else { //cache and check the next pkt!
				if(wland_add_aggr_ptks(bus, pkt)) {
					wland_txdata_buf_reset(bus);
					WLAND_ERR("add aggr pkts failed!\n");
				}
				//return 0;
				goto flowcontrol;
			}
		} else if ((atomic_read(&bus->aggr_count) != 0) &&
			(cached_len != 0)) {				//there is cache data!
			if (((cached_len + pkt->len) > (WLAND_AGGR_TXPKT_LEN-2))
				|| (atomic_read(&bus->aggr_count) >= 18)) {

				wland_send_aggr_ptks(bus);
				retry_times ++;
				if(retry_times >= max_times){
					WLAND_DBG(SDIO,INFO, "Retry %d times, reset tx buf!\n",max_times);
					wland_txdata_buf_reset(bus);
				}
				goto send;
			} else {
				if (wland_add_aggr_ptks(bus, pkt)) {
					wland_txdata_buf_reset(bus);
					WLAND_ERR("add aggr pkts failed!\n");

					//return 0;
					goto flowcontrol;
				}

				if (atomic_read(&bus->tx_dpc_tskcnt) == 0) {	//no more pkt send it!
					wland_send_aggr_ptks(bus);
				} else										//check the next pkt!
					//return 0;
					goto flowcontrol;
			}
		} else {
			WLAND_ERR("Aggr_count and offset different! count:%d len:%d\n"
				, atomic_read(&bus->aggr_count), cached_len);
			wland_sendpkt_without_aggr(bus, pkt);
			wland_txdata_buf_reset(bus);
		}

#else
	wland_sdio_txpkt(bus, pkt);
#endif

	WLAND_DBG(BUS, TRACE,
		"After wland_sdio_txpkt(), pktq len=%d, bus->tx_dpc_tskcnt=%d\n",
		bus->txq.len, atomic_read(&bus->tx_dpc_tskcnt));

#ifdef WLAND_TX_AGGRPKTS
flowcontrol:
#endif
	/*
	 * Deflow-control stack if needed
	 */
	if ((bus->sdiodev->bus_if->state == WLAND_BUS_DATA) && ifp->tx_flowblock
		&& (bus->txq.len < TXLOW)) {
		ifp->tx_flowblock = false;

		wland_txflowcontrol(bus->sdiodev->dev, false);
	}

done:
	WLAND_DBG(BUS, TRACE, "Done\n");
	return cnt;
}

static int wland_sdio_intr_set(struct wland_sdio_dev *sdiodev, bool enable)
{
	u8 val;
	int ret;

	WLAND_DBG(SDIO, TRACE, "Enter(interrupt %s)\n",
		enable ? "enable" : "disable");

	if (enable)
		val = 0x07;
	else
		val = 0x00;

	/*
	 * set chip interrupt
	 */
	ret = wland_sdioh_request_byte(sdiodev, SDIOH_WRITE,
		URSDIO_FUNC1_REGISTER_MASK, &val);
	return ret;
}

static int wland_read_pktlen(struct wland_sdio *bus)
{
	u16 size = 0;
	u8 size_l = 0, size_h = 0;
	int ret = 0;

	ret = wland_sdioh_request_byte(bus->sdiodev, SDIOH_READ,
		URSDIO_FUNC1_RPKTLEN_LO, &size_l);
	if (ret) {
		WLAND_ERR("Read SDIO_AHB2SDIO_PKTLEN_L failed!\n");
		return -1;
	}
	ret = wland_sdioh_request_byte(bus->sdiodev, SDIOH_READ,
		URSDIO_FUNC1_RPKTLEN_HI, &size_h);
	if (ret) {
		WLAND_ERR("Read SDIO_AHB2SDIO_PKTLEN_H failed!\n");
		return -1;
	}
	size = (size_l | ((size_h & 0x7F) << 8)) * 4;
	return size;
}

static int wland_sdio_intr_get(struct wland_sdio_dev *sdiodev, u8 *intrstatus)
{
	int ret = 0;

	if (!intrstatus)
		return -EBADE;

	if (sdiodev->bus_if->state == WLAND_BUS_DOWN) {
		/*
		 * disable interrupt
		 */
		*intrstatus = 0;
		WLAND_ERR("Bus is down!\n");
	} else {
		if (sdiodev->bus_if->chip == WLAND_VER_91_H) {
#ifdef WLAND_DMA_RX1536_BLOCKS
			ret = wland_sdioh_request_byte(sdiodev, SDIOH_READ,
				URSDIO_FUNC1_INT_PENDING, intrstatus);
#else
#ifdef WLAND_RXLEN_1536
			if (sdiodev->bus_if->chip_ready == 0)
				ret = wland_sdioh_request_byte(sdiodev, SDIOH_READ,
					URSDIO_FUNC1_INT_PENDING, intrstatus);
			else
				*intrstatus = ((7<<5) | I_AHB2SDIO);
#else
			ret = wland_sdioh_request_byte(sdiodev, SDIOH_READ,
				URSDIO_FUNC1_INT_PENDING, intrstatus);
			//WLAND_ERR("URSDIO_FUNC1_INT_PENDING:0x%02x\n", *intrstatus);
#endif /*WLAND_RXLEN_1536*/
			switch ((*intrstatus & 0xE0) >> 5) {
			case 0:
				sdiodev->data_len = 16;
				break;
			case 1:
				sdiodev->data_len = 32;
				break;
			case 2:
				sdiodev->data_len = 64;
				break;
			case 3:
				sdiodev->data_len = 128;
				break;
			case 4:
				sdiodev->data_len = 256;
				break;
			case 5:
				sdiodev->data_len = 512;
				break;
			case 6:
				sdiodev->data_len = 1024;
				break;
			case 7:
				sdiodev->data_len = 1536;
				break;
			default:
				sdiodev->data_len = 16;
				break;
			}
			//WLAND_ERR("data_len:%u\n", sdiodev->data_len);
			*intrstatus = (*intrstatus) & 0x1F;
#endif
		} else
			ret = wland_sdioh_request_byte(sdiodev, SDIOH_READ,
				URSDIO_FUNC1_INT_STATUS, intrstatus);
	}

	WLAND_DBG(SDIO, TRACE, "Enter(interrupt status: 0x%x)\n",
		(uint) *intrstatus);

	return ret;
}

static void wland_sdio_bus_stop(struct device *dev)
{
	struct wland_bus *bus_if = dev_get_drvdata(dev);
	struct wland_sdio_dev *sdiodev = bus_if->bus_priv.sdio;
	struct wland_sdio *bus = sdiodev->bus;
	int ret;

	WLAND_DBG(SDIO, TRACE, "Enter\n");

	if (bus->watchdog_tsk) {
		send_sig(SIGTERM, bus->watchdog_tsk, 1);
#ifndef CONFIG_PLATFORM_ANYKA
		kthread_stop(bus->watchdog_tsk);
#endif
		bus->watchdog_tsk = NULL;
	}

	bus_if->state = WLAND_BUS_DOWN;
	/*
	 * Turn off the backplane clock (only)
	 */
	ret = down_interruptible(&bus->txclk_sem);
	if (ret)
		WLAND_ERR("Can not request bus->txclk_sem.wland_sdio_bus_stop\n");

	wland_sdio_clkctl(bus, CLK_NONE);
	if (!ret)
		up(&bus->txclk_sem);
	/*
	 * Clear the data packet queues
	 */
	wland_pktq_flush(&bus->txq, true, NULL, NULL);

	/*
	 * Clear rx control and wake any waiters
	 */

	wland_dhd_os_ioctl_resp_wake(bus);
	WLAND_DBG(SDIO, TRACE, "Done.\n");
}

/*
 * wland_sdio_readframes() - just process skb as firmware event.
 *
 * If the packet buffer contains a firmware event message it will
 * dispatch the event to a registered handler (using worker).
 */

struct sk_buff *wland_sdio_readframes(struct wland_sdio *bus)
{
	int ret = 0;
	//u8 size_l = 0, size_h = 0;
#ifndef WLAND_RX_AGGRPKTS
	u16 rcv_len = 0;
#endif
	u16 size = 0;
	struct sk_buff *skb = NULL;
	struct wland_bus *bus_if = dev_get_drvdata(bus->sdiodev->dev);

	WLAND_DBG(DEFAULT, TRACE, "Enter\n");
	if (bus_if->state == WLAND_BUS_DOWN) {
		WLAND_ERR("Bus is down and go out!\n");
		goto done;
	}

	if (bus->sdiodev->bus_if->chip == WLAND_VER_91_H) {
#ifdef WLAND_DMA_RX1536_BLOCKS
		size = wland_read_pktlen(bus);
		if(size <= 0)
			goto done;
#else
		size = bus->sdiodev->data_len;
#endif
	} else {
		size = wland_read_pktlen(bus);
		if(size < 0)
			goto done;
	}

	if ((size > WLAND_MAX_BUFSZ) || (size < FMW_HEADER_LEN)) {
		WLAND_ERR("received buffer is invalid(size:%d) and go out.\n", size);
		goto done;
	}

	WLAND_DBG(SDIO, TRACE, "received buffer size:%d.\n", size);

	//skb =  dev_alloc_skb(size + NET_IP_ALIGN + WID_HEADER_LEN + 3);
	skb =  __dev_alloc_skb(size+NET_IP_ALIGN+WID_HEADER_LEN+3, GFP_KERNEL);
	if (!skb) {
		WLAND_ERR("dev_alloc_skb alloc skb failed ,len:%d\n",
			(size + NET_IP_ALIGN + WID_HEADER_LEN + 3));
		goto done;
	}

	skb_reserve(skb, NET_IP_ALIGN);
	//4byte align
	wland_pkt_word_align(skb);

	ret = wland_sdio_recv_pkt(bus, skb, size);
	if (ret) {
		WLAND_ERR("receive skb failed\n");
		dev_kfree_skb(skb);
		skb = NULL;
		goto done;
	}

#ifndef WLAND_RX_AGGRPKTS
	rcv_len = (u16)(skb->data[0] | ((skb->data[1]&0x0f) << 8));
	if (rcv_len > size) {
		WLAND_ERR("SDIO read payload_len invalid! \n");
		dev_kfree_skb(skb);
		skb = NULL;
		goto done;
	}
	skb_put(skb, rcv_len);
#endif
#if 0
	if (bus->sdiodev->bus_if->chip == WLAND_VER_91_H) {
		u8 val = BIT5;
		wland_sdioh_request_byte(bus->sdiodev, SDIOH_WRITE,
			URSDIO_FUNC1_INT_PENDING, &val);
	}
#endif
done:
	WLAND_DBG(DEFAULT, TRACE, "Done\n");
	return skb;
}

static int wland_sdio_txctl_frames(struct wland_sdio *bus)
{
	int err = 0;
	u16 payload_len, bytes;
	u8 *payload = bus->ctrl_frame_buf;
	struct sk_buff *pkt = NULL;
	int retry = 0;
	WLAND_DBG(DEFAULT, TRACE, "Enter\n");
	bytes = bus->ctrl_frame_len;
	payload_len = bus->ctrl_frame_len;

	WLAND_DBG(DEFAULT, TRACE, "bus->ctrl_frame_len=%d\n",
		bus->ctrl_frame_len);
	pkt = wland_pkt_buf_get_suitable_skb(bus, NULL, &bytes);
	if (!pkt) {
		WLAND_ERR("get pkt failed,len: %d\n", bytes);
		return -ENOMEM;
	} else {
		wland_dhd_os_sdlock(bus);
		memcpy(pkt->data, payload, payload_len);
		wland_dhd_os_sdunlock(bus);
	}

	WLAND_DBG(DEFAULT, TRACE, "payloadLen:%d, nbytes:%d, pkt->data=%p\n",
		payload_len, bytes, pkt->data);
	WLAND_DUMP(TX_CTRL, pkt->data, bytes, "TX ctrl nbytes:%u\n", bytes);

__retry:
	err = wland_sdio_send_pkt(bus, pkt, bytes);
	if (err) {
		WLAND_ERR("wland_sdio_send_pkt fail%d\n", err);
		if (retry++ < 5) {
			goto __retry;
		}
	}
	wland_pkt_buf_free_skb(pkt);

	wland_dhd_os_sdlock(bus);
	bus->ctrl_frame_stat = false;
	if (!err)
		bus->ctrl_frame_send_success= true;
	else {
		bus->ctrl_frame_send_success= false;
		WLAND_ERR("wland_sdio_send_pkt fail%d\n", err);
	}
	wland_dhd_os_sdunlock(bus);

	WLAND_DBG(BUS, TRACE, "Done(err:%d)\n", err);

	return err;
}

static int wland_sdio_tx_dpc(struct wland_sdio *bus)
{
	int err = 0;
	int queue_len;
#ifdef WLAND_NO_TXDATA_SCAN
	struct wland_cfg80211_info *cfg = bus->sdiodev->bus_if->drvr->config;
#endif

	WLAND_DBG(BUS, TRACE, "Enter\n");

	if (bus->sdiodev->bus_if->state == WLAND_BUS_DOWN) {
		WLAND_ERR("Bus is down and go out.\n");
		goto done;
	}

	queue_len = wland_pktq_mlen(&bus->txq, ~bus->rx_info->flowcontrol);
	//printk("%d,", queue_len);
	queue_len = min(queue_len, (int)24);
#ifdef WLAND_NO_TXDATA_SCAN
	if (queue_len && (!test_bit(SCAN_STATUS_BUSY, &cfg->scan_status))) {
#else /*WLAND_NO_TXDATA_SCAN*/
	if (queue_len) {
#endif /*WLAND_NO_TXDATA_SCAN*/
		if (down_interruptible(&bus->txclk_sem)) {
			WLAND_ERR("Can not request bus->txclk_sem.1 \n");
			goto done;
		}
		wland_sdio_clkctl(bus, CLK_AVAIL);
		if (bus->clkstate != CLK_AVAIL) {
			WLAND_ERR("Can not request SDMMC clock and go out.\n");
			up(&bus->txclk_sem);
			goto done;
		}

		while (wland_pktq_mlen(&bus->txq, ~bus->rx_info->flowcontrol)) {
			/* Send queued frames (limit 1 if rx may still be pending) */
			WLAND_DBG(BUS, TRACE, "TXQ_len = %d, tx_dpc_tskcnt=%d\n",
				wland_pktq_mlen(&bus->txq, ~bus->rx_info->flowcontrol),
				atomic_read(&bus->tx_dpc_tskcnt));
			WLAND_DBG(BUS, TRACE, "******SendData.\n");

#ifndef WLAND_TX_AGGRPKTS
#ifdef WLAND_SDIO_FC_SUPPORT
			if(bus->fw_rxbuf == false) {
				if ((err = wland_sdio_flow_ctrl(bus->sdiodev))) {
					bus->fw_rxbuf = false;
					WLAND_ERR("wland_sdio_flow_ctrl failed!\n");
					break;
				} else
					bus->fw_rxbuf = true;
			}
#endif
#endif

			wland_sdio_sendfromq(bus);
			if (--queue_len <= 0)
				break;
		}
		up(&bus->txclk_sem);
	}

	if (bus->ctrl_frame_stat) {
		if (down_interruptible(&bus->txclk_sem)) {
			WLAND_ERR("Can not request bus->txclk_sem.2 \n");
			goto done;
		}
		wland_sdio_clkctl(bus, CLK_AVAIL);
		if (bus->clkstate != CLK_AVAIL) {
			WLAND_ERR("Can not request clock and go out.\n");
			up(&bus->txclk_sem);
			goto done;
		}

#ifndef WLAND_TX_AGGRPKTS
#ifdef WLAND_SDIO_FC_SUPPORT
		if(bus->fw_rxbuf == false) {
			if ((err = wland_sdio_flow_ctrl(bus->sdiodev))) {
				bus->fw_rxbuf = false;
				WLAND_ERR("wland_sdio_flow_ctrl failed!\n");
				up(&bus->txclk_sem);
				goto done;
			} else
				bus->fw_rxbuf = true;
		}
#endif
#endif
		err = wland_sdio_txctl_frames(bus);
		up(&bus->txclk_sem);
		if (err < 0)
			bus->sdcnt.tx_sderrs++;
		wland_dhd_os_wait_event_wakeup(bus);
		/*atomic_dec(&bus->tx_dpc_tskcnt);
		WLAND_DBG(BUS, TRACE,
			"Processing TXCTL. bus->tx_dpc_tskcnt=%d\n",
			atomic_read(&bus->tx_dpc_tskcnt));*/
	}
	WLAND_DBG(BUS, TRACE, "Done(bus->tx_dpc_tskcnt:%d)\n",
		atomic_read(&bus->tx_dpc_tskcnt));
	return 0;
done:
	//wland_dhd_os_sdunlock(bus);
	return -1;
}

static struct pktq *wland_sdio_bus_gettxq(struct device *dev)
{
	struct wland_bus *bus_if = dev_get_drvdata(dev);
	struct wland_sdio *bus = bus_if->bus_priv.sdio->bus;

	return &bus->txq;
}

/* Conversion of 802.1D priority to precedence level */
static uint wland_pkt_prio2prec(u32 prio)
{
	return (prio == PRIO_8021D_NONE || prio == PRIO_8021D_BE) ?
		(prio ^ 2) : prio;
}

static int wland_sdio_bus_txdata(struct device *dev, struct sk_buff *pkt)
{
	uint prec;
	int ret = -EBADE;
	struct wland_bus *bus_if = dev_get_drvdata(dev);
	struct wland_sdio_dev *sdiodev = bus_if->bus_priv.sdio;
	struct wland_sdio *bus = sdiodev->bus;
	unsigned long flags = 0;
	struct wland_if *ifp = netdev_priv(pkt->dev);

	WLAND_DBG(SDIO, TRACE, "Enter\n");

	/*
	 * precondition: IS_ALIGNED((unsigned long)(pkt->data), 2)
	 */
	prec = wland_pkt_prio2prec((pkt->priority & PRIOMASK));

	/*
	 * Check for existing queue, current flow-control, pending event, or pending clock
	 */
	WLAND_DBG(SDIO, TRACE, "deferring pktq len:%d,prec:%d.\n", bus->txq.len,
		prec);

	/*
	 * Priority based enq
	 */
	wland_dhd_os_sdlock_txq(bus, &flags);
	if (!wland_prec_enq(bus->sdiodev->dev, &bus->txq, pkt, prec)) {
		wland_dhd_os_sdunlock_txq(bus, &flags);
		wland_txcomplete(bus->sdiodev->dev, pkt, false);
		WLAND_ERR("bus->txq is over flow!!!\n");
		ifp->tx_flowblock = true;
		wland_txflowcontrol(bus->sdiodev->dev, true);
		return -ENOSR;
	} else {
		ret = 0;
	}

	if (bus_if->state != WLAND_BUS_DATA) {
		WLAND_ERR("bus has stop\n");
		wland_dhd_os_sdunlock_txq(bus, &flags);
		return -1;
	}

	atomic_inc(&(bus)->tx_dpc_tskcnt);
	wland_dhd_os_sdunlock_txq(bus, &flags);
	WAKE_TX_WORK(bus);

	if (bus->txq.len >= TXHI) {
		ifp->tx_flowblock = true;
		wland_txflowcontrol(bus->sdiodev->dev, true);
	}

	WLAND_DBG(SDIO, TRACE, "TXDATA Wake up DPC work, pktq len:%d\n",
		bus->txq.len);
	WLAND_DBG(SDIO, TRACE,
		"TX Data Wake up TX DPC work,  bus->tx_dpc_tskcnt:%d,  pktq len:%d\n",
		atomic_read(&bus->tx_dpc_tskcnt), bus->txq.len);

	return ret;
}

static int wland_sdio_bus_txctl(struct device *dev, u8 *msg, uint msglen)
{
	int ret = -1;
	struct wland_bus *bus_if = dev_get_drvdata(dev);
	struct wland_sdio_dev *sdiodev = bus_if->bus_priv.sdio;
	struct wland_sdio *bus = sdiodev->bus;

	WLAND_DBG(SDIO, TRACE, "Enter\n");

	/*
	 * Need to lock here to protect txseq and SDIO tx calls
	 */
	wland_dhd_os_sdlock(bus);

	bus->ctrl_frame_stat = true;
	bus->ctrl_frame_send_success = false;
	/*
	 * Send from dpc
	 */
	bus->ctrl_frame_buf = msg;
	bus->ctrl_frame_len = msglen;
	wland_dhd_os_sdunlock(bus);
	if (bus_if->state != WLAND_BUS_DATA) {
		WLAND_ERR("bus has stop\n");
		return -1;
	}
	WAKE_TX_WORK(bus);

	/*WLAND_DBG(BUS, TRACE,
		"TXCTL Wake up TX DPC work,  bus->tx_dpc_tskcnt:%d\n",
		atomic_read(&bus->tx_dpc_tskcnt));*/
	if (bus->ctrl_frame_stat)
		ret = wland_dhd_os_wait_for_event(bus, &bus->ctrl_frame_stat);

	if (!bus->ctrl_frame_stat && bus->ctrl_frame_send_success) {
		WLAND_DBG(SDIO, DEBUG, "send success\n");
		ret = 0;
	}  else if (ret == -ERESTARTSYS) {
		WLAND_ERR("send cancelled\n");
	}  else {
		WLAND_ERR("send faild, ctrl_frame_stat:%d, ctrl_frame_send_success:%d, ret:%d \n",
			bus->ctrl_frame_stat, bus->ctrl_frame_send_success, ret);
		ret = -EIO;
	}
	if (ret)
		bus->sdcnt.tx_ctlerrs++;
	else
		bus->sdcnt.tx_ctlpkts++;

	return ret;
}

static int wland_sdio_bus_rxctl(struct device *dev, u8 *msg, uint msglen)
{
	int timeleft;
	uint rxlen = 0;
	bool pending = false;
	struct wland_bus *bus_if = dev_get_drvdata(dev);
	struct wland_sdio_dev *sdiodev = bus_if->bus_priv.sdio;
	struct wland_sdio *bus = sdiodev->bus;
	struct wland_rx_info* rx_info = bus->rx_info;
	WLAND_DBG(SDIO, TRACE, "Enter\n");

	/*
	 * Wait until control frame is available
	 */
	timeleft = wland_dhd_os_ioctl_resp_wait(bus, &rx_info->rxlen, &pending);

	if (rx_info->rxlen > 0) {
		spin_lock_bh(&rx_info->rxctl_lock);
		rxlen = rx_info->rxlen;
		memcpy(msg, rx_info->rxctl, min(msglen, rxlen));
		rx_info->rxlen = 0;
		spin_unlock_bh(&rx_info->rxctl_lock);
	}

	if (rxlen) {
		WLAND_DBG(SDIO, TRACE,
			"resumed on rxctl frame, got %d expected %d\n", rxlen, msglen);
	} else if (timeleft == 0) {
		WLAND_ERR("resumed on timeout\n");
	} else if (pending) {
		WLAND_ERR("cancelled\n");
		return -ERESTARTSYS;
	} else {
		WLAND_ERR("resumed for unknown reason\n");
	}

	if (rxlen)
		bus->sdcnt.rx_ctlpkts++;
	else {
		bus->sdcnt.rx_ctlerrs++;
		WLAND_ERR("rxlen == 0\n");
	}

	return rxlen ? (int) rxlen : -ETIMEDOUT;
}

static int wland_sdio_bus_init(struct device *dev)
{
	struct wland_bus *bus_if = dev_get_drvdata(dev);
	struct wland_sdio_dev *sdiodev = bus_if->bus_priv.sdio;
	struct wland_sdio *bus = sdiodev->bus;
	int ret = 0;

	WLAND_DBG(BUS, TRACE, "Enter\n");

	/*
	 * Start the watchdog timer
	 */
	bus->sdcnt.tickcnt = 0;

	ret = wland_sdio_intr_register(bus->sdiodev);
	if (ret != 0)
		WLAND_ERR("intr register failed:%d\n", ret);

	bus_if->state = WLAND_BUS_DATA;

	WLAND_DBG(BUS, TRACE, "Done\n");
	return ret;
}

/* sdio read and write worker */
static void wland_sdio_TxWorker(struct work_struct *work)
{
	struct wland_sdio *bus = container_of(work, struct wland_sdio, TxWork);

	WLAND_DBG(BUS, TRACE, "Enter\n");

	while ((atomic_read(&bus->tx_dpc_tskcnt) > 0) || (bus->ctrl_frame_stat == true)) {
		if (wland_sdio_tx_dpc(bus))
			break;
		schedule();
	}
}


static void wland_enq_rxpkt(struct wland_sdio *bus, struct sk_buff *pkt)
{

	struct wland_rx_info* rx_info = bus->rx_info;
#ifdef WLAND_USE_RXQ
	unsigned long flags = 0;
	wland_dhd_os_sdlock_rxq(rx_info, &flags);
	if (!wland_prec_enq(bus->sdiodev->dev, &rx_info->rxq, pkt, 0)) {
			wland_dhd_os_sdunlock_rxq(rx_info, &flags);
			WLAND_ERR("rx_info->rxq is over flow!!!\n");
			wland_pkt_buf_free_skb(pkt);
			return;
	}
	wland_dhd_os_sdunlock_rxq(rx_info, &flags);
	//printk("enq, pri:%d, num:%d. %02x %02x skblen:%d\n", rx_info->rxq.hi_prec, rx_info->rxq.len,
		//pkt->data[0], pkt->data[1], pkt->len);
	atomic_inc(&rx_info->rx_dpc_tskcnt);
	WLAND_DBG(BUS, TRACE,
		"Watch dog wake up RX Work, rx_info->rx_dpc_tskcnt=%d\n",
		atomic_read(&rx_info->rx_dpc_tskcnt));
#else
	atomic_inc(&rx_info->rx_dpc_tskcnt);
	WLAND_DBG(BUS, TRACE,
		"Get a pkt and will process it, bus->rx_info->rx_dpc_tskcnt=%d\n",
		atomic_read(&rx_info->rx_dpc_tskcnt));
	wland_process_rxframes(rx_info, pkt);
#endif /*WLAND_USE_RXQ*/
}

static void wland_sdio_poll_data(struct wland_sdio *bus)
{
	struct sk_buff *pkt = NULL;
	u8 intstatus = 0;
	/*
	 * Reset poll tick
	 */
	bus->polltick = 0;
	WLAND_DBG(BUS, TRACE,
		"(bus->intr:%d,bus->sdcnt.intrcount:%d,bus->sdcnt.lastintrs:%d)\n",
		bus->intr, bus->sdcnt.intrcount, bus->sdcnt.lastintrs);

	/*
	 * Check device if no interrupts
	 */
	if (!bus->intr || (bus->sdcnt.intrcount == bus->sdcnt.lastintrs)) {
		sdio_claim_host(bus->sdiodev->func);

		if (wland_sdio_intr_get(bus->sdiodev, &intstatus) < 0) {
			WLAND_ERR("read status failed!\n");
		}

		if (intstatus & I_AHB2SDIO) {
			WLAND_DBG(BUS, TRACE, "Frame Ind!\n");
			bus->sdcnt.pollcnt++;
			pkt = wland_sdio_readframes(bus);
			sdio_release_host(bus->sdiodev->func);
			if (pkt)
				wland_enq_rxpkt(bus, pkt);
		} else
			sdio_release_host(bus->sdiodev->func);
	}

	/*
	 * Update interrupt tracking
	 */
	bus->sdcnt.lastintrs = bus->sdcnt.intrcount;
}

static int wland_sdio_watchdog_thread(void *data)
{
	struct wland_sdio *bus = (struct wland_sdio *) data;
	unsigned long flags = 0;

	allow_signal(SIGTERM);

	/*
	 * Run until signal received
	 */
#if 1
	while (!signal_pending(current)) {
#else
	while (1) {
#endif
		if (kthread_should_stop()) {
			wland_sdio_wd_timer(bus, 0);
			WLAND_DBG(BUS, ERROR, "watchdog thread stoped.\n");
			break;
		}
		if (!wait_for_completion_interruptible(&bus->watchdog_wait)) {

			WLAND_DBG(BUS, TRACE,
				"(bus->poll:%d,bus->polltick:%d,bus->pollrate:%d)\n",
				bus->poll, bus->polltick, bus->pollrate);

			SMP_RD_BARRIER_DEPENDS();

			/*
			 * Poll period: check device if appropriate.
			 */
			if (bus->poll && (++bus->polltick >= bus->pollrate))
				wland_sdio_poll_data(bus);

			WLAND_DBG(BUS, TRACE,
				"(bus->activity:%d,bus->idlecount:%d,bus->idletime:%d,bus->clkstate:%d)\n",
				bus->activity, bus->idlecount, bus->idletime,
				bus->clkstate);
			/*
			 * On idle timeout clear activity flag and/or turn off clock
			 */
			if ((bus->idletime > 0) && (bus->clkstate == CLK_AVAIL)) {
				WLAND_DBG(BUS, TRACE,
					"bus->idletime=%d, bus->idlecount=%d\n",
					bus->idletime, bus->idlecount);
				if (++bus->idlecount >= bus->idletime) {
					if (down_interruptible(&bus->txclk_sem)) {
						WLAND_ERR("Can not request bus->txclk_sem.watchdaothread \n");
						continue;
					}
					wland_sdio_clkctl(bus, CLK_NONE);
					up(&bus->txclk_sem);
				} else {
					if (!timer_pending(&bus->timer))
						wland_sdio_wd_timer(bus, bus->save_ms);
				}
			}
			flags = wland_dhd_os_spin_lock(bus);
			/*
			 * Count the tick for reference
			 */
			bus->sdcnt.tickcnt++;

			wland_dhd_os_spin_unlock(bus, flags);

		} else {
			WLAND_DBG(BUS, INFO,
				"<WDOG-TRD>watchdog thread no signal.\n");
			continue;
		}
	}

	wland_sdio_wd_timer(bus, 0);
	WLAND_DBG(DEFAULT, INFO, "signal_pending:%d\n",
		signal_pending(current));
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
static void wland_bus_watchdog(struct timer_list *t)
{
	struct wland_sdio *bus = from_timer(bus, t, timer);
#else
static void wland_bus_watchdog(ulong data)
{
	struct wland_sdio *bus = (struct wland_sdio *) data;
#endif
	WLAND_DBG(BUS, TRACE, "=======*****=====>Enter\n");

	if (!(bus && bus->sdiodev && bus->sdiodev->bus_if)) {
		WLAND_ERR("something is NULL!\n");
		wland_dhd_os_ioctl_resp_wake(bus);
		return;
	}

	if (bus->sdiodev->bus_if->state == WLAND_BUS_DOWN) {
		WLAND_DBG(BUS, TRACE,
			"=======*****=====>(bus_if->state == WLAND_BUS_DOWN)\n");

		/*
		 * Clear rx control and wake any waiters
		 */
		wland_dhd_os_ioctl_resp_wake(bus);
		return;
	}

	if (bus->watchdog_tsk){
		WLAND_DBG(BUS, TRACE, "Wake up watchdog thread!\n");
		complete(&bus->watchdog_wait);
	}
}

static void wland_sdioh_irqhandler(struct sdio_func *func)
{
	struct wland_bus *bus_if = dev_get_drvdata(&func->dev);
	struct wland_sdio_dev *sdiodev = NULL;
	struct wland_sdio *bus = NULL;
	struct wland_rx_info* rx_info = NULL;
	u8 intstatus = 0;
	struct sk_buff *pkt = NULL;

#if defined WLAND_RXLEN_1536 || defined WLAND_DMA_RX1536_BLOCKS
	int max_count = 1;
#else
	int max_count = 16;
#endif

	if (!bus_if) {
		WLAND_ERR("bus is null pointer, exiting\n");
		return;
	}
	sdiodev = bus_if->bus_priv.sdio;
	if (!sdiodev) {
		WLAND_ERR("sdiodev is null.\n");
		return;
	}
	bus = sdiodev->bus;
	if (!bus) {
		WLAND_ERR("bus is null.\n");
		return;
	}
	rx_info = bus->rx_info;
	if (!rx_info) {
		WLAND_ERR("rx_info is null.\n");
		return;
	}

	if (bus_if->state == WLAND_BUS_DOWN) {
		WLAND_ERR("bus is down. we have nothing to do\n");
		return;
	}

	/*
	 * Disable additional interrupts
	 */
	if (!bus->intr) {
		WLAND_DBG(SDIO, INFO,
			"isr w/o interrupt is disabled, so do nothing and return\n");
		return;
	}

	bus->intdis = true;
	while (max_count--) {
		//printk("%x", 16-max_count);
		wland_sdio_intr_get(bus->sdiodev, &intstatus);

		//atomic_set(&bus->intstatus, intstatus);

		WLAND_DBG(SDIO, TRACE, "sdio_intstatus:%x\n", intstatus);

		/*
		 * On frame indication, read available frames
		 */
		if (intstatus & I_AHB2SDIO) {
			bus->sdcnt.intrcount++;
			pkt = wland_sdio_readframes(bus);
		} else if (intstatus & I_ERROR) {
			u8 val = I_ERROR;
			WLAND_DBG(SDIO, ERROR,
				"ERROR Interrupt(bus->clkstate:%d,bus->ctrl_frame_stat:%d).\n",
				bus->clkstate, bus->ctrl_frame_stat);
			bus->sdcnt.intrcount++;
			wland_sdioh_request_byte(bus->sdiodev, SDIOH_WRITE,
				URSDIO_FUNC1_INT_PENDING, &val);
			WLAND_ERR("int_error!\n");
			break;
		} else {
			WLAND_DBG(SDIO, ERROR,
				"No Interrupt(bus->clkstate:%d,bus->ctrl_frame_stat:%d).\n",
				bus->clkstate, bus->ctrl_frame_stat);
			break;
		}

		if (pkt)
			wland_enq_rxpkt(bus, pkt);
	}

#ifdef WLAND_USE_RXQ
	WAKE_RX_WORK(rx_info);
#endif

	WLAND_DBG(SDIO, TRACE,
		"IRQ schedule work, rx_info->rx_dpc_tskcnt:%d, Done\n",
		atomic_read(&rx_info->rx_dpc_tskcnt));
}

int wland_sdio_intr_register(struct wland_sdio_dev *sdiodev)
{
	int ret;

	sdio_claim_host(sdiodev->func);
	sdio_claim_irq(sdiodev->func, wland_sdioh_irqhandler);
	ret = wland_sdio_intr_set(sdiodev, true);
	sdio_release_host(sdiodev->func);

	WLAND_DBG(SDIO, TRACE, "Enter(ret:%d)\n", ret);

	return ret;
}

int wland_sdio_intr_unregister(struct wland_sdio_dev *sdiodev)
{

#ifdef WLAND_SDIO_SUPPORT
#ifdef WLAND_RDAPLATFORM_SUPPORT
	rda_mmc_set_sdio_irq(1, false);
#endif /*WLAND_RDAPLATFORM_SUPPORT*/
#endif /* WLAND_SDIO_SUPPORT */

	/*
	 * disable interrupt
	 */
	sdio_claim_host(sdiodev->func);
	wland_sdio_intr_set(sdiodev, false);
	sdio_release_irq(sdiodev->func);
	sdio_release_host(sdiodev->func);

	WLAND_DBG(SDIO, TRACE, "Done\n");
	return 0;
}

void wland_sdio_wd_timer(struct wland_sdio *bus, uint wdtick)
{
	ulong flags;
	uint timeout;

	WLAND_DBG(BUS, TRACE, "------------>Enter(wdtick:%d)\n", wdtick);

	if (!bus)
		return;

	if (wdtick)
		wland_dhd_os_wd_wake_lock(bus);

	flags = wland_dhd_os_spin_lock(bus);

	/*
	 * don't start the wd until fw is loaded
	 */
	if (bus->sdiodev->bus_if->state == WLAND_BUS_DOWN && wdtick) {
		wland_dhd_os_spin_unlock(bus, flags);
		wland_dhd_os_wd_wake_unlock(bus);
		WLAND_DBG(BUS, INFO,
			"------------>Done(bus_if->state == WLAND_BUS_DOWN)\n");
		return;
	}

	/*
	 * Totally stop the timer
	 */
	if (!wdtick) {
		if (timer_pending(&bus->timer)) {
			WLAND_DBG(BUS, TRACE, "delete timer bus->timer!\n");
			del_timer_sync(&bus->timer);
		}
		bus->wd_timer_valid = false;
		wland_dhd_os_spin_unlock(bus, flags);
		wland_dhd_os_wd_wake_unlock(bus);
		WLAND_DBG(BUS, TRACE, "Watchdog timer release!\n");
		return;
	}

	if (wdtick) {
		bus->save_ms = wdtick;
		/*
		 * Convert timeout in millsecond to jiffies
		 */
		timeout = msecs_to_jiffies(bus->save_ms);
		bus->wd_timer_valid = true;
		/*
		 * Re arm the timer, at last watchdog period
		 */
		mod_timer(&bus->timer, jiffies + timeout);
		WLAND_DBG(BUS, TRACE, "reset watch dog timer(timer bus->timer)! timeout=%d\n",
			bus->save_ms);
	}

	wland_dhd_os_spin_unlock(bus, flags);

	WLAND_DBG(BUS, TRACE, "------------>Done(bus->save_ms:%d)\n",
		bus->save_ms);
}

static struct wland_bus_ops wland_sdio_bus_ops = {
	.stop = wland_sdio_bus_stop,
	.init = wland_sdio_bus_init,
	.txdata = wland_sdio_bus_txdata,
	.txctl = wland_sdio_bus_txctl,
	.rxctl = wland_sdio_bus_rxctl,
	.gettxq = wland_sdio_bus_gettxq,
};

/* Detach and free everything */
void wland_sdio_release(struct wland_sdio *bus)
{
	struct wland_bus *bus_if;
	struct wland_rx_info* rx_info = NULL;

	WLAND_DBG(SDIO, TRACE, "Enter\n");

	if (!bus) {
		WLAND_ERR("bus empty!\n");
		return;
	}

	bus_if = dev_get_drvdata(bus->sdiodev->dev);

	/*
	 * De-register interrupt handler
	 */
	wland_sdio_intr_unregister(bus->sdiodev);
	bus_if->state = WLAND_BUS_DOWN;

	cancel_work_sync(&bus->TxWork);
	if (bus->wland_txwq) {
		destroy_workqueue(bus->wland_txwq);
		bus->wland_txwq = NULL;
	}

#ifdef WLAND_TX_AGGRPKTS
	if(bus->txdata_buf)
		dev_kfree_skb(bus->txdata_buf);
#endif

	if (bus->sdiodev->dev) {
#ifdef WLAND_DRIVER_RELOAD_FW
		if (!wland_repowering_chip)
#endif
			wland_bus_detach(bus->sdiodev->dev);
#ifdef WLAND_DRIVER_RELOAD_FW
		else{
			wland_bus_detach_repowering(bus->sdiodev->dev);
			WLAND_DBG(DEFAULT, INFO, "chip repowering, not release bus!\n");
		}
#endif
	}

	rx_info = bus->rx_info;
	if(rx_info != NULL)
		wland_rx_uinit(rx_info);

#ifdef CONFIG_HAS_WAKELOCK
	bus->wakelock_counter = 0;
	bus->wakelock_wd_counter = 0;
	bus->wakelock_rx_timeout_enable = 0;
	bus->wakelock_ctrl_timeout_enable = 0;

	wake_lock_destroy(&bus->wl_wifi);
	wake_lock_destroy(&bus->wl_rxwake);
	wake_lock_destroy(&bus->wl_ctrlwake);
	wake_lock_destroy(&bus->wl_wdwake);
#endif /* CONFIG_HAS_WAKELOCK */
	kfree(bus);

	WLAND_DBG(DEFAULT, INFO, "Done\n");
}

void *wland_sdio_probe(struct wland_sdio_dev *sdiodev)
{
	int ret;
	struct wland_sdio *bus;
	struct wland_bus *bus_if;
	struct wland_rx_info* rx_info;

	pr_err("[RDAWLAN_DRIVER] wland_sdio_probe Enter\n");

	/*
	 * Allocate private bus interface state
	 */

	bus = kzalloc(sizeof(struct wland_sdio), GFP_KERNEL);
	if (!bus)
		goto fail;

	memset(&(bus->sdcnt), 0, sizeof(struct wland_sdio_count));

	/*
	 * pointer each other
	 */
	bus->sdiodev = sdiodev;
	sdiodev->bus = bus;

	/*
	 * Initialize Wakelock stuff
	 */
	spin_lock_init(&bus->wakelock_spinlock);

	bus->wakelock_counter = 0;
	bus->wakelock_wd_counter = 0;
	bus->wakelock_rx_timeout_enable = 0;
	bus->wakelock_ctrl_timeout_enable = 0;

#ifdef CONFIG_HAS_WAKELOCK
	wake_lock_init(&bus->wl_wifi, WAKE_LOCK_SUSPEND, "wlan_wake");
	wake_lock_init(&bus->wl_rxwake, WAKE_LOCK_SUSPEND, "wlan_rx_wake");
	wake_lock_init(&bus->wl_ctrlwake, WAKE_LOCK_SUSPEND, "wlan_ctrl_wake");
	wake_lock_init(&bus->wl_wdwake, WAKE_LOCK_SUSPEND, "wlan_wd_wake");
#endif /* CONFIG_HAS_WAKELOCK */
	wland_dhd_os_wd_wake_lock(bus);


	bus_if = sdiodev->bus_if;
	bus_if->chip_ready = 0;
	bus_if->up_data_mac = 0;

	/*
	 * attempt to attach to the chip
	 */
#ifdef WLAND_RDAPLATFORM_SUPPORT
	bus_if->chip = (rda_wlan_version() & CHIP_ID_MASK);
#else
	bus_if->chip = WLAND_VER_91_H;
#endif /*WLAND_RDAPLATFORM_SUPPORT*/

	WLAND_DBG(SDIO, INFO, "--------------- Chipid: 0x%x(%s) ---------------\n",
		bus_if->chip, wland_version_string[bus_if->chip]);

	/*
	 * Address of cores for new chips should be added here
	 */
	switch (bus_if->chip) {
	case WLAND_VER_91_H:
		break;
	default:
		WLAND_ERR("chipid 0x%x is not supported\n", bus_if->chip);
		goto fail;
	}

	rx_info = wland_rx_init(bus);
	if(!rx_info) {
		WLAND_ERR("rx info init failed!\n");
		goto fail;
	}

	bus->rx_info = rx_info;

	wland_pktq_init(&bus->txq, (PRIOMASK + 1), TXQLEN);

	/*
	 * setup bus control parameters
	 */
	bus->txbound = WLAND_TXBOUND;
	bus->rxbound = WLAND_RXBOUND;
	bus->txminmax = WLAND_TXMINMAX;
	/*
	 * default sdio bus header length for tx packet
	 */
	bus->tx_hdrlen = FMW_HEADER_LEN;
	bus->clkstate = CLK_SDONLY;
	bus->idletime = WLAND_IDLE_INTERVAL;
	bus->save_ms = WLAND_WD_POLL_MS;
	/*
	 * Set roundup accordingly
	 */
	bus->blocksize = sdiodev->func->cur_blksize;
	/*
	 * Set the poll and interrupt flags(default poll then intr)
	 */
	bus->intr = false;
	bus->poll = true;
	bus->intdis = false;
	bus->polltick = 0;
	bus->activity = false;

#ifndef WLAND_TX_AGGRPKTS
	bus->fw_rxbuf = false;
#endif

	if (bus->poll)
		bus->pollrate = 1;

#ifdef WLAND_TX_AGGRPKTS
	atomic_set(&bus->aggr_count, 0);
	bus->txdata_buf = __dev_alloc_skb(WLAND_AGGR_TXPKT_LEN+ALIGNMENT-1, GFP_KERNEL);
	if(!bus->txdata_buf) {
		WLAND_ERR("Alloc bus->txdata_buf failed!\n");
		goto fail;
	}
	wland_pkt_word_align(bus->txdata_buf);
	bus->txdata_buf_data = bus->txdata_buf->data;
	bus->txdata_offset = bus->txdata_buf->data;
#endif

	/*
	 * Assign bus interface call back,Attach chip version to sdio device
	 */
	bus_if->dev = sdiodev->dev;
	bus_if->ops = &wland_sdio_bus_ops;
	bus_if->state = WLAND_BUS_DOWN;

	/*
	 * disable/enable host interrupt
	 */
#ifdef WLAND_RDAPLATFORM_SUPPORT
	rda_mmc_set_sdio_irq(1, bus->intdis);
#endif /*WLAND_RDAPLATFORM_SUPPORT*/

	INIT_WORK(&bus->TxWork, wland_sdio_TxWorker);
	bus->wland_txwq = create_singlethread_workqueue("wland_txwq");
	if (!bus->wland_txwq) {
		WLAND_ERR("insufficient memory to create txworkqueue.\n");
		goto fail;
	}

	spin_lock_init(&bus->txqlock);
	sema_init(&bus->txclk_sem,1);

	init_waitqueue_head(&bus->ctrl_wait);
	init_waitqueue_head(&bus->dcmd_resp_wait);

	/*
	 * Set up the watchdog timer
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
	timer_setup(&bus->timer, wland_bus_watchdog, 0);
#else
	init_timer(&bus->timer);
	bus->timer.data = (ulong) bus;
	bus->timer.function = wland_bus_watchdog;
#endif
	/*
	 * Initialize watchdog thread
	 */
	init_completion(&bus->watchdog_wait);
	bus->watchdog_tsk =
		kthread_run(wland_sdio_watchdog_thread, bus, "wland_watchdog");
	if (IS_ERR(bus->watchdog_tsk)) {
		WLAND_ERR("watchdog thread failed to create!\n");
		bus->watchdog_tsk = NULL;
	}
	/*
	 * Initialize thread based operation and lock
	 */
	sema_init(&bus->sdsem, 1);

	bus->threads_only = true;

	/*
	 * Initialize DPC thread
	 */
	atomic_set(&bus->tx_dpc_tskcnt, 0);

	/*
	 * Attach to the common layer, reserve hdr space
	 */
#ifdef WLAND_DRIVER_RELOAD_FW
	if (wland_repowering_chip)
		WLAND_DBG(DEFAULT, INFO, "chip repowering do not bus attach!\n");
	else {
#endif
		ret = wland_bus_attach(0, sdiodev->dev);
		if (ret < 0) {
			WLAND_ERR("bus_attach failed\n");
			goto fail;
		}
#ifdef WLAND_DRIVER_RELOAD_FW
	}
#endif
	/*
	 * Allocate buffers
	 */
	if (bus_if->drvr->maxctl) {
		rx_info->rxblen =
			roundup((bus_if->drvr->maxctl),	ALIGNMENT) + WLAND_SDALIGN;
		rx_info->rxbuf = kzalloc(bus->rx_info->rxblen, GFP_KERNEL);
		if (!rx_info->rxbuf) {
			WLAND_ERR("rxbuf malloc failed.\n");
			goto fail;
		}
		memset(rx_info->rxbuf, '\0', rx_info->rxblen);
	}

	WLAND_DBG(SDIO, DEBUG, "(maxctl:%d)<====>(rxblen:%d)\n",
		bus_if->drvr->maxctl, rx_info->rxblen);

	/*
	 * if firmware path present try to download and bring up bus
	 */
#ifdef WLAND_DRIVER_RELOAD_FW
	if (wland_repowering_chip) {
		WLAND_DBG(DEFAULT, INFO, "chip repowering do not bus start!\n");
	} else {
#endif
		ret = wland_bus_start(sdiodev->dev);
		if (ret < 0) {
			WLAND_ERR("Bus Start Failed\n");
			goto fail;
		}
#ifdef WLAND_DRIVER_RELOAD_FW
	}
#endif
	WLAND_DBG(SDIO, TRACE, "SuccessFull Probe Done.\n");
	return bus;

fail:
	wland_sdio_release(bus);
	sdiodev->bus = NULL;

	return NULL;
}
