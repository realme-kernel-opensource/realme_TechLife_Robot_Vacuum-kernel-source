
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
#include <linux/kernel.h>
#include <linux/if_arp.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/wireless.h>
#include <linux/ieee80211.h>
#include <linux/debugfs.h>
#include <net/cfg80211.h>
#include <net/rtnetlink.h>

#include "wland_defs.h"
#include "wland_utils.h"
#include "wland_fweh.h"
#include "wland_dev.h"
#include "wland_dbg.h"
#include "wland_wid.h"
#include "wland_bus.h"
#include "wland_p2p.h"
#include "wland_amsdu.h"
#include "wland_cfg80211.h"

static void wland_fws_macdesc_set_name(struct wland_fws_info *fws,
	struct wland_mac_descriptor *desc)
{
	if (desc == &fws->desc.other)
		strlcpy(desc->name, "MAC-OTHER", sizeof(desc->name));
	else if (desc->mac_handle)
		scnprintf(desc->name, sizeof(desc->name), "MAC-%d:%d",
			desc->mac_handle, desc->interface_id);
	else
		scnprintf(desc->name, sizeof(desc->name), "MACIF:%d",
			desc->interface_id);
}

static void wland_fws_hanger_cleanup(struct wland_fws_info *fws,
	bool(*fn) (struct sk_buff *, void *), int ifidx)
{
	struct wland_fws_hanger *h = &fws->hanger;
	struct sk_buff *skb;
	int i;
	enum wland_fws_hanger_item_state s;

	for (i = 0; i < ARRAY_SIZE(h->items); i++) {
		s = h->items[i].state;
		if (s == FWS_HANGER_ITEM_STATE_INUSE ||
			s == FWS_HANGER_ITEM_STATE_INUSE_SUPPRESSED) {
			skb = h->items[i].pkt;
			if (fn == NULL || fn(skb, &ifidx)) {
				/*
				 * suppress packets freed from psq
				 */
				if (s == FWS_HANGER_ITEM_STATE_INUSE)
					wland_pkt_buf_free_skb(skb);
				h->items[i].state = FWS_HANGER_ITEM_STATE_FREE;
			}
		}
	}
}

void wland_fws_macdesc_cleanup(struct wland_fws_info *fws,
	struct wland_mac_descriptor *entry, int ifidx)
{
	if (entry->occupied && (ifidx == -1 || ifidx == entry->interface_id)) {
		bool(*matchfn) (struct sk_buff *, void *) = NULL;
		struct sk_buff *skb;
		struct pktq *q = &entry->psq;
		int prec;

		for (prec = 0; prec < q->num_prec; prec++) {
			skb = wland_pktq_pdeq_match(q, prec, matchfn, &ifidx);
			while (skb) {
				wland_pkt_buf_free_skb(skb);
				skb = wland_pktq_pdeq_match(q, prec, matchfn,
					&ifidx);
			}
		}

		entry->occupied = ! !(entry->psq.len);
	}
}

static void wland_fws_bus_txq_cleanup(struct wland_fws_info *fws,
	bool(*fn) (struct sk_buff *, void *), int ifidx)
{
	struct wland_fws_hanger_item *hi;
	struct pktq *txq = wland_bus_gettxq(fws->drvr->bus_if);
	struct sk_buff *skb;
	int prec;
	u32 hslot;

	if (IS_ERR(txq)) {
		WLAND_DBG(DEFAULT, TRACE, "no txq to clean up\n");
		return;
	}

	for (prec = 0; prec < txq->num_prec; prec++) {
		skb = wland_pktq_pdeq_match(txq, prec, fn, &ifidx);

		while (skb) {
			hslot = 0;
			hi = &fws->hanger.items[hslot];
			//WARN_ON(skb != hi->pkt);
			hi->state = FWS_HANGER_ITEM_STATE_FREE;
			wland_pkt_buf_free_skb(skb);
			skb = wland_pktq_pdeq_match(txq, prec, fn, &ifidx);
		}
	}
}

static void wland_fws_cleanup(struct wland_fws_info *fws, int ifidx)
{
	int i;
	struct wland_mac_descriptor *table;

	bool(*matchfn) (struct sk_buff *, void *) = NULL;

	if (fws == NULL)
		return;

	/*
	 * cleanup individual nodes
	 */
	table = &fws->desc.nodes[0];

	for (i = 0; i < ARRAY_SIZE(fws->desc.nodes); i++)
		wland_fws_macdesc_cleanup(fws, &table[i], ifidx);

	wland_fws_macdesc_cleanup(fws, &fws->desc.other, ifidx);
	wland_fws_bus_txq_cleanup(fws, matchfn, ifidx);
	wland_fws_hanger_cleanup(fws, matchfn, ifidx);
}

void wland_fws_macdesc_init(struct wland_mac_descriptor *desc, u8 *addr,
	u8 ifidx)
{
	if (!desc)
		return;

	WLAND_DBG(DEFAULT, TRACE, "enter: desc %p ea=%pM, ifidx=%u\n", desc,
		addr, ifidx);

	desc->occupied = 1;
	desc->state = FWS_STATE_OPEN;
	desc->requested_credit = 0;
	desc->requested_packet = 0;
	/*
	 * depending on use may need ifp->bssidx instead
	 */
	desc->interface_id = ifidx;
	desc->ac_bitmap = 0xFF;	/* update this when handling APSD */
	if (addr)
		memcpy(&desc->ea[0], addr, ETH_ALEN);
}

void wland_fws_macdesc_deinit(struct wland_mac_descriptor *desc)
{
	WLAND_DBG(DEFAULT, TRACE, "enter: ea=%pM, ifidx=%u\n", desc->ea,
		desc->interface_id);
	desc->occupied = 0;
	desc->state = FWS_STATE_CLOSE;
	desc->requested_credit = 0;
	desc->requested_packet = 0;
}

void wland_fws_add_interface(struct wland_if *ifp)
{
	struct wland_fws_info *fws = ifp->drvr->fws;
	struct wland_mac_descriptor *entry = &fws->desc.iface[ifp->ifidx];

	WLAND_DBG(DEFAULT, TRACE, "added %s,Enter\n", entry->name);

	if (!ifp->ndev)
		return;

	ifp->fws_desc = entry;

	wland_fws_macdesc_init(entry, ifp->mac_addr, ifp->ifidx);

	wland_fws_macdesc_set_name(fws, entry);

	wland_pktq_init(&entry->psq, WLAND_FWS_PSQ_PREC_COUNT,
		WLAND_FWS_PSQ_LEN);

	WLAND_DBG(DEFAULT, TRACE, "added %s,Done\n", entry->name);
}

void wland_fws_del_interface(struct wland_if *ifp)
{
	struct wland_mac_descriptor *entry = ifp->fws_desc;
	ulong flags;

	if (!entry)
		return;

	WLAND_DBG(DEFAULT, TRACE, "deleting %s\n", entry->name);

	spin_lock_irqsave(&ifp->drvr->fws->spinlock, flags);
	ifp->fws_desc = NULL;
	wland_fws_macdesc_deinit(entry);
	wland_fws_cleanup(ifp->drvr->fws, ifp->ifidx);
	spin_unlock_irqrestore(&ifp->drvr->fws->spinlock, flags);
}

int wland_fws_init(struct wland_private *drvr)
{
	struct wland_fws_info *fws;
	int rc, i;

	WLAND_DBG(DEFAULT, TRACE, "Enter\n");
	drvr->fws = kzalloc(sizeof(*(drvr->fws)), GFP_KERNEL);
	if (!drvr->fws) {
		rc = -ENOMEM;
		goto fail;
	}

	fws = drvr->fws;

	spin_lock_init(&fws->spinlock);
	/*
	 * set linkage back
	 */
	fws->drvr = drvr;

	/*
	 * Setting the iovar may fail if feature is unsupported
	 * * so leave the rc as is so driver initialization can
	 * * continue. Set mode back to none indicating not enabled.
	 */
	for (i = 0; i < ARRAY_SIZE(fws->hanger.items); i++) {
		fws->hanger.items[i].state = FWS_HANGER_ITEM_STATE_FREE;
	}

	wland_fws_macdesc_init(&fws->desc.other, NULL, 0);

	wland_fws_macdesc_set_name(fws, &fws->desc.other);

	wland_pktq_init(&fws->desc.other.psq, WLAND_FWS_PSQ_PREC_COUNT,
		WLAND_FWS_PSQ_LEN);
	WLAND_DBG(DEFAULT, TRACE, "Done success\n");
	return 0;

fail:
	WLAND_ERR("Done Failed\n");

	return rc;
}

void wland_fws_deinit(struct wland_private *drvr)
{
	struct wland_fws_info *fws = drvr->fws;
	ulong flags;

	if (!fws)
		return;
	/*
	 * cleanup
	 */
	spin_lock_irqsave(&fws->spinlock, flags);
	wland_fws_cleanup(fws, -1);
	drvr->fws = NULL;
	spin_unlock_irqrestore(&fws->spinlock, flags);

	/*
	 * free top structure
	 */
	kfree(fws);
}
