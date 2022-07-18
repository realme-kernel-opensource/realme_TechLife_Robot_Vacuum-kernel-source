
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

#include "wland_defs.h"
#include "wland_utils.h"
#include "wland_fweh.h"
#include "wland_dev.h"
#include "wland_dbg.h"
#include "wland_wid.h"
#include "wland_bus.h"
#include "wland_trap.h"
#include "wland_p2p.h"
#include "wland_amsdu.h"
#include "wland_cfg80211.h"

#ifdef DEBUG
#define WLAND_ENUM_DEF(id, val)  	{ val, #id },

struct wland_fweh_event_name {
	enum wland_fweh_event_code code;
	const char *name;
};

/* array for mapping code to event name */
static struct wland_fweh_event_name fweh_event_names[] = {
	FIRMW_EVENT_ENUM_DEFLIST
};

#undef WLAND_ENUM_DEF
#endif /* DEBUG */

static const char *wland_fweh_get_event_name(enum wland_fweh_event_code code)
{
#ifdef DEBUG
	int i;

	for (i = 0; i < ARRAY_SIZE(fweh_event_names); i++) {
		if (fweh_event_names[i].code == code)
			return fweh_event_names[i].name;
	}
	return "unknown";
#else
	return "nodebug";
#endif
}

#if 0

/* This function extracts the 'from ds' bit from the MAC header of the input */

/* frame.                                                                    */

/* Returns the value in the LSB of the returned value.                       */
static inline u8 wland_get_from_ds(u8 * header)
{
	return ((header[1] & 0x02) >> 1);
}

/* This function extracts the 'to ds' bit from the MAC header of the input   */

/* frame.                                                                    */

/* Returns the value in the LSB of the returned value.                       */
static inline u8 wland_get_to_ds(u8 * header)
{
	return (header[1] & 0x01);
}

/* This function extracts the BSSID from the incoming WLAN packet based on   */

/* the 'from ds' bit, and updates the MAC Address in the allocated 'addr'    */

/* variable.                                                                 */
static void wland_get_BSSID(u8 * data, u8 * bssid)
{
	if (wland_get_from_ds(data) == 1)
		memcpy(bssid, data + 10, 6);
	else if (wland_get_to_ds(data) == 1)
		memcpy(bssid, data + 4, 6);
	else
		memcpy(bssid, data + 16, 6);
}
#endif

/*
 * wland_fweh_dequeue_event() - get event from the queue.
 *
 * @fweh: firmware event handling info.
 */
static struct wland_fweh_queue_item *wland_fweh_dequeue_event(struct wland_fw_info
	*fweh)
{
	struct wland_fweh_queue_item *event = NULL;
	ulong flags;

	spin_lock_irqsave(&fweh->evt_q_lock, flags);
	if (!list_empty(&fweh->event_q)) {
		event = list_first_entry(&fweh->event_q,
			struct wland_fweh_queue_item, q);
		list_del(&event->q);
	}
	spin_unlock_irqrestore(&fweh->evt_q_lock, flags);

	return event;
}

/*
 * wland_fweh_event_worker() - firmware event worker.
 *
 * @work: worker object.
 */
static void wland_fweh_event_worker(struct work_struct *work)
{
	struct wland_fw_info *fweh =
		container_of(work, struct wland_fw_info, event_work);
	struct wland_private *drvr =
		container_of(fweh, struct wland_private, fweh);
	struct wland_fweh_queue_item *event;
	struct wland_event_msg *emsg_be;
	struct wland_if *ifp = NULL;
	int err = 0;

	while ((event = wland_fweh_dequeue_event(fweh))) {
		WLAND_DBG(EVENT, TRACE,
			"event:%s(%u), status:%u, reason:%u, ifidx:%u, bsscfg:%u, addr:%pM\n",
			wland_fweh_get_event_name(event->code), event->code,
			event->emsg.status, event->emsg.reason,
			event->emsg.ifidx, event->emsg.bsscfgidx,
			event->emsg.addr);

		/*
		 * convert event message
		 */
		emsg_be = &event->emsg;

		/*
		 * special handling of interface event
		 */
		if (emsg_be->ifidx >= WLAND_MAX_IFS) {
			WLAND_ERR("invalid interface index: %u\n",
				emsg_be->ifidx);

			goto event_free;
		}
#if 0
		for (i=0; i<WLAND_MAX_IFS; ++i)
			if(memcmp(drvr->iflist[i].mac_addr, emsg_be->addr) == 0)
				ifp = drvr->iflist[i];
#else
			ifp = drvr->iflist[emsg_be->bsscfgidx];
#endif
		if (event->code == WLAND_E_IF_ADD) {
			WLAND_DBG(EVENT, DEBUG, "adding %s (%pM)\n",
				emsg_be->ifname, emsg_be->addr);

			ifp = wland_add_if(drvr, emsg_be->bsscfgidx,
				emsg_be->ifidx, emsg_be->ifname, emsg_be->addr);
			if (IS_ERR(ifp))
				goto event_free;
			wland_fws_add_interface(ifp);

		} else if (event->code == WLAND_E_IF_CHANGE) {
			WLAND_DBG(EVENT, DEBUG, "enter: idx=%d\n", ifp->bssidx);

			wland_fws_macdesc_init(ifp->fws_desc, ifp->mac_addr,
				ifp->ifidx);
		} else if (event->code == WLAND_E_IF_DEL) {
			wland_fws_del_interface(ifp);
			wland_del_if(drvr, emsg_be->bsscfgidx);
		}

		/*
		 * handle the event if valid interface and handler
		 */
		if (fweh->evt_handler[emsg_be->event_code])
			err = fweh->evt_handler[emsg_be->event_code] (
				drvr->iflist[emsg_be->bsscfgidx], emsg_be, event->data);
		else
			WLAND_ERR("unhandled event %d ignored\n", emsg_be->event_code);

		if (err < 0) {
			WLAND_ERR("event handler failed (%d)\n", event->code);
			err = 0;
		}
event_free:
		kfree(event);
	}
}

/*
 * wland_fweh_push_event() - generate self event code.
 *
 * @drvr    : driver information object.
 * @code    : event code.
 * @data    : event data.
 */
void wland_fweh_push_event(struct wland_private *drvr,
	struct wland_event_msg *event_packet, void *data)
{
	struct wland_fw_info *fweh = &drvr->fweh;
	struct wland_fweh_queue_item *event;
	gfp_t alloc_flag = GFP_KERNEL;
	ulong flags;

	if (event_packet->event_code >= WLAND_E_LAST) {
		WLAND_ERR("invalid event code %d\n", event_packet->event_code);
		return;
	}

	if (!fweh->evt_handler[event_packet->event_code]) {
		WLAND_ERR("event code %d unregistered\n",
			event_packet->event_code);
		return;
	}

	WLAND_DBG(EVENT, TRACE, "push event for %s.\n",
		wland_fweh_get_event_name(event_packet->event_code));

	if (in_interrupt())
		alloc_flag = GFP_ATOMIC;

	event = kzalloc(sizeof(*event) + event_packet->datalen, alloc_flag);
	if (!event) {
		WLAND_ERR("No memory\n");
		return;
	}

	event->code = event_packet->event_code;
	event->ifidx = event_packet->ifidx;

	/*
	 * use memcpy to get aligned event message
	 */
	memcpy(&event->emsg, event_packet, sizeof(event->emsg));
	if (data)
		memcpy(event->data, data, event_packet->datalen);
	memcpy(event->ifaddr, event_packet->addr, ETH_ALEN);

	/*
	 * create and queue event.
	 */
	spin_lock_irqsave(&fweh->evt_q_lock, flags);
	list_add_tail(&event->q, &fweh->event_q);
	spin_unlock_irqrestore(&fweh->evt_q_lock, flags);

	/*
	 * schedule work
	 */
	schedule_work(&fweh->event_work);
}

/*
 * wland_firmweh_register() - register handler for given event code.
 *
 * @drvr    : driver information object.
 * @code    : event code.
 * @handler : handler for the given event code.
 */
int wland_fweh_register(struct wland_private *drvr,
	enum wland_fweh_event_code code, fw_handler_t handler)
{
	if (drvr->fweh.evt_handler[code]) {
		WLAND_ERR("event code %d already registered\n", code);
		return -ENOSPC;
	}
	drvr->fweh.evt_handler[code] = handler;

	WLAND_DBG(EVENT, TRACE, "event handler registered for %s\n",
		wland_fweh_get_event_name(code));
	return 0;
}

/*
 * wland_firmweh_unregister() - remove handler for given code.
 *
 * @drvr: driver information object.
 * @code: event code.
 */
void wland_fweh_unregister(struct wland_private *drvr,
	enum wland_fweh_event_code code)
{
	WLAND_DBG(EVENT, TRACE, "event handler cleared for %s\n",
		wland_fweh_get_event_name(code));
	if (drvr->fweh.evt_handler[code])
		drvr->fweh.evt_handler[code] = NULL;
}

/*
 * wland_fweh_attach() - initialize firmware event handling.
 *
 * @drvr: driver information object.
 */
void wland_fweh_attach(struct wland_private *drvr)
{
	struct wland_fw_info *fweh = &drvr->fweh;

	INIT_WORK(&fweh->event_work, wland_fweh_event_worker);
	spin_lock_init(&fweh->evt_q_lock);
	INIT_LIST_HEAD(&fweh->event_q);
}

/*
 * wland_fweh_detach() - cleanup firmware event handling.
 *
 * @drvr: driver information object.
 */
void wland_fweh_detach(struct wland_private *drvr)
{
	struct wland_fw_info *fweh = &drvr->fweh;

	/*
	 * cancel the worker
	 */
	cancel_work_sync(&fweh->event_work);
	WARN_ON(!list_empty(&fweh->event_q));
	memset(fweh->evt_handler, 0, sizeof(fweh->evt_handler));
}
