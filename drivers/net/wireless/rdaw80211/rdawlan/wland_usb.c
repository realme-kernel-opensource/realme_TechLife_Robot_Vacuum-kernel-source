
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


#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/firmware.h>
#include <linux/usb.h>
#include <linux/vmalloc.h>

#include "wland_defs.h"
#include "wland_utils.h"
#include "wland_bus.h"
#include "wland_dbg.h"
#include "wland_usb.h"
#include "wland_wid.h"
#include "wland_amsdu.h"
#include "wland_cfg80211.h"
#include "wland_p2p.h"
#include "wland_fweh.h"
#include "wland_usb.h"
#include "wland_rx.h"

static bool wland_usb_qempty(struct wland_usbdev_info *devinfo,
	struct list_head *q, spinlock_t *qlock)
{
	unsigned long flags;
	int ret;
	spin_lock_irqsave(qlock, flags);
	ret = !!list_empty(q);
	spin_unlock_irqrestore(qlock, flags);

	return ret;
}

static struct wland_usbreq *wland_usb_deq(struct wland_usbdev_info *devinfo,
	struct list_head *q, int *counter, spinlock_t *qlock)
{
	unsigned long flags;
	struct wland_usbreq *req;

	spin_lock_irqsave(qlock, flags);
	if (list_empty(q)) {
		spin_unlock_irqrestore(qlock, flags);
		return NULL;
	}
	req = list_entry(q->next, struct wland_usbreq, list);
	list_del_init(q->next);
	if (counter)
		(*counter)--;
	spin_unlock_irqrestore(qlock, flags);

	return req;
}

static void wland_usb_enq(struct wland_usbdev_info *devinfo,
	struct list_head *q, struct wland_usbreq *req, int *counter,
	spinlock_t *qlock)
{
	unsigned long flags;

	spin_lock_irqsave(qlock, flags);
	list_add_tail(&req->list, q);
	if (counter)
		(*counter)++;
	spin_unlock_irqrestore(qlock, flags);
}

static void wland_usb_del_fromq(struct wland_usbdev_info *devinfo,
	struct wland_usbreq *req, spinlock_t *qlock)
{
	unsigned long flags;

	spin_lock_irqsave(qlock, flags);
	list_del_init(&req->list);
	spin_unlock_irqrestore(qlock, flags);
}

#ifdef WLAND_USE_USB_TXQ
void wland_tx_pkt_reinit(struct wland_rx_info *rx_info)
{
	struct wland_usbdev_info *devinfo = rx_info->devinfo;
	struct wland_usbreq *req;
	while(!list_empty(&devinfo->tx_postq)){
		req = wland_usb_deq(devinfo, &devinfo->tx_postq,
			&devinfo->tx_postcount, &devinfo->tx_postq_lock);
		if(req->skb){
			dev_kfree_skb(req->skb);
			req->skb = NULL;
		}
		wland_usb_enq(devinfo, &devinfo->tx_freeq, req,
			&devinfo->tx_freecount, &devinfo->tx_freeq_lock);
	}
}
static void wland_usb_tx_dpc(struct wland_usbdev_info *devinfo)
{
	struct wland_usbreq *req;
	int ret = 0;
	struct device *dev = devinfo->dev;
	u8* data = NULL;
	struct wland_bus *bus_if = dev_get_drvdata(dev);
	struct wland_if *ifp = bus_if->drvr->iflist[0];
#ifdef WLAND_NO_TXDATA_SCAN
	struct wland_cfg80211_info *cfg = ifp->drvr->config;
	while(!list_empty(&devinfo->tx_postq)
		&& (!test_bit(SCAN_STATUS_BUSY, &cfg->scan_status))){
#else
	while(!list_empty(&devinfo->tx_postq)) {
#endif

		if (devinfo->bus_pub.state != USB_STATE_UP) {
			WLAND_ERR("usb state is not up!\n");
			return;
		}

		if (atomic_read(&bus_if->software_reset)) {
			msleep(100);
			break;
		}

		req = wland_usb_deq(devinfo, &devinfo->tx_postq,
			&devinfo->tx_postcount, &devinfo->tx_postq_lock);
		if(!req) {
			WLAND_ERR("can not get req from tx_postq!\n");
			return;
		}
		data = req->skb->data;

		ret = usb_submit_urb(req->urb, GFP_ATOMIC);
		if (ret) {
			WLAND_DBG(USB, ERROR, "wland_usb_bus_tx usb_submit_urb FAILED\n");
			goto fail;
		}
		/*wland_usb_enq(devinfo, &devinfo->tx_pendingq, req,
			&devinfo->tx_pendingcount, &devinfo->tx_pendingq_lock);*/

		continue;

fail:

#ifdef WLAND_TX_SOFT_MAC
		skb_pull(req->skb, data[3]);
#else
		skb_pull(req->skb, WID_HEADER_LEN);
#endif
		dev_kfree_skb(req->skb);
		req->skb = NULL;
		//wland_usb_del_fromq(devinfo, req, &devinfo->q_lock);
		wland_usb_enq(devinfo, &devinfo->tx_freeq, req,
			&devinfo->tx_freecount, &devinfo->tx_freeq_lock);

	}

}

static void wland_usb_TxWorker(struct work_struct *work)
{
	struct wland_usbdev_info *devinfo =
		container_of(work, struct wland_usbdev_info, TxWork);

	WLAND_DBG(BUS, TRACE, "Enter\n");

	if (devinfo->tx_postcount > 0) {
		wland_usb_tx_dpc(devinfo);
	}

	WLAND_DBG(BUS, TRACE, "Done\n");
}
#endif

//static void wland_usb_rx_refill(struct wland_usbdev_info *devinfo,
//	struct wland_usbreq *req);

static struct usb_device_id wland_usb_devid_table[] = {
	{USB_DEVICE(USB_VENDOR_ID_RDAMICRO, USB_DEVICE_ID_RDA599X)},
	/*
	 * special entry for device with firmware loaded and running
	 */
	//{USB_DEVICE(USB_VENDOR_ID_RDAMICRO, USB_DEVICE_ID_BCMFW)},
	{}
};


static struct wland_usbdev_info *wland_usb_get_businfo(struct device *dev)
{
	struct wland_bus *bus_if = dev_get_drvdata(dev);

	return bus_if->bus_priv.usb->devinfo;
}

static int wland_usb_ioctl_resp_wait(struct wland_usbdev_info *devinfo)
{
	return wait_event_timeout(devinfo->ioctl_resp_wait,
		devinfo->ctl_completed, msecs_to_jiffies(IOCTL_RESP_TIMEOUT));
}

void wland_usb_data_resp_wake(struct wland_usbdev_info *devinfo)
{
	if (waitqueue_active(&devinfo->data_resp_wait))
		wake_up(&devinfo->data_resp_wait);
}

static void wland_usb_ioctl_resp_wake(struct wland_usbdev_info *devinfo)
{
	if (waitqueue_active(&devinfo->ioctl_resp_wait))
		wake_up(&devinfo->ioctl_resp_wait);
}

static int wland_usb_data_resp_wait(struct wland_usbdev_info *devinfo)
{
	return wait_event_timeout(devinfo->data_resp_wait,
		devinfo->rx_info->rxlen, msecs_to_jiffies(IOCTL_RESP_TIMEOUT));
}

static void wland_usb_ctl_complete(struct wland_usbdev_info *devinfo, int type,
	int status)
{
	struct wland_bus *bus_if = NULL;
	WLAND_DBG(USB, TRACE, "Enter, status=%d\n", status);

	if (unlikely(devinfo == NULL))
		return;

	bus_if = dev_get_drvdata(devinfo->dev);

	if (type == WLAND_USB_CBCTL_READ) {
		if (status == 0)
			devinfo->bus_pub.stats.rx_ctlpkts++;
		else
			devinfo->bus_pub.stats.rx_ctlerrs++;
	} else if (type == WLAND_USB_CBCTL_WRITE) {
		if (status == 0)
			devinfo->bus_pub.stats.tx_ctlpkts++;
		else
			devinfo->bus_pub.stats.tx_ctlerrs++;
	}

	devinfo->ctl_urb_status = status;
	devinfo->ctl_completed = true;

	if (1 || bus_if->chip_ready != 1)
		wland_usb_ioctl_resp_wake(devinfo);
}

#if 0 //rda wlan chip receive wid_rsp in bulk urb
static void wland_usb_ctlread_complete(struct urb *urb)
{
	struct wland_usbdev_info *devinfo =
		(struct wland_usbdev_info *) urb->context;

	WLAND_DBG(USB, TRACE, "Enter\n");

	devinfo->ctl_urb_actual_length = urb->actual_length;

	wland_usb_ctl_complete(devinfo, WLAND_USB_CBCTL_READ, urb->status);
}
#endif

static void wland_usb_ctlwrite_complete(struct urb *urb)
{
	struct wland_usbdev_info *devinfo =
		(struct wland_usbdev_info *) urb->context;

	WLAND_DBG(USB, TRACE, "Enter\n");

	wland_usb_ctl_complete(devinfo, WLAND_USB_CBCTL_WRITE, urb->status);
}

static int wland_usb_send_ctl(struct wland_usbdev_info *devinfo, u8 * buf,
	int len)
{
	int ret;
	struct wland_bus *bus_if = NULL;

	WLAND_DBG(USB, TRACE, "Enter\n");

	if (devinfo == NULL || buf == NULL || len == 0
		|| devinfo->bulk_urb == NULL)
		return -EINVAL;

	bus_if = dev_get_drvdata(devinfo->dev);

	if ((bus_if->chip_ready != 1) && (len > 64)){
		u16 adjust_len = len;
		if(adjust_len % 512)
			len += 512 - adjust_len % 512;
		len += 4;
	}

	//dump_buf(buf, MIN(len, 32));

#if 1 //rda wlan chip send wid in bulk urb
	usb_fill_bulk_urb(devinfo->bulk_urb,
		devinfo->usbdev,
		devinfo->tx_pipe,
		buf, len, (usb_complete_t) wland_usb_ctlwrite_complete, devinfo);
	devinfo->bulk_urb->transfer_flags |= URB_ZERO_PACKET;

	//devinfo->ctl_completed = false;

	ret = usb_submit_urb(devinfo->bulk_urb, GFP_ATOMIC);
	if (ret) {
		WLAND_ERR("usb_submit_urb failed %d\n", ret);
		return ret;
	}
#else
	devinfo->ctl_write.wLength = cpu_to_le16p(&size);
	devinfo->ctl_urb->transfer_buffer_length = size;
	devinfo->ctl_urb_status = 0;
	devinfo->ctl_urb_actual_length = 0;

	usb_fill_control_urb(devinfo->ctl_urb,
		devinfo->usbdev,
		devinfo->ctl_out_pipe,
		(u8 *) & devinfo->ctl_write,
		buf,
		size, (usb_complete_t) wland_usb_ctlwrite_complete, devinfo);

	ret = usb_submit_urb(devinfo->ctl_urb, GFP_ATOMIC);
#endif
if (ret < 0)
		WLAND_ERR("usb_submit_urb failed %d\n", ret);

	return ret;
}

#if 0 //rda wlan chip receive wid_rsp in bulk urb
static int wland_usb_recv_ctl(struct wland_usbdev_info *devinfo, u8 *buf,
	int len)
{
	int ret;
	u16 size;

	WLAND_DBG(USB, TRACE, "Enter\n");

	if ((devinfo == NULL) || (buf == NULL) || (len == 0)
		|| (devinfo->ctl_urb == NULL))
		return -EINVAL;

	size = len;
	devinfo->ctl_read.wLength = cpu_to_le16p(&size);
	devinfo->ctl_urb->transfer_buffer_length = size;

	devinfo->ctl_read.bRequestType =
		USB_DIR_IN | USB_TYPE_CLASS | USB_RECIP_INTERFACE;
	devinfo->ctl_read.bRequest = 1;

	usb_fill_control_urb(devinfo->ctl_urb,
		devinfo->usbdev,
		devinfo->ctl_in_pipe,
		(u8 *) & devinfo->ctl_read,
		buf,
		size, (usb_complete_t) wland_usb_ctlread_complete, devinfo);

	ret = usb_submit_urb(devinfo->ctl_urb, GFP_ATOMIC);
	if (ret < 0)
		WLAND_ERR("usb_submit_urb failed %d\n", ret);

	return ret;
}
#endif

static int wland_usb_bus_txctl(struct device *dev, u8 *buf, u32 len)
{
	int err = 0, timeout = 0;
	struct wland_usbdev_info *devinfo = wland_usb_get_businfo(dev);
	struct wland_bus *bus_if = dev_get_drvdata(dev);

	WLAND_DBG(USB, TRACE, "Enter\n");

	if (devinfo->bus_pub.state != USB_STATE_UP)
		return -EIO;

	if (atomic_read(&bus_if->software_reset)) {
		WLAND_ERR("software reset status!\n");
		msleep(100);
		return -EIO;
	}

	if (test_and_set_bit(0, &devinfo->ctl_op)) {
		WLAND_ERR("In a control frame option, can't tx!\n");
		return -EIO;
	}

	devinfo->ctl_completed = false;

	err = wland_usb_send_ctl(devinfo, buf, len);
	if (err) {
		WLAND_ERR("fail %d bytes: %d\n", err, len);
		clear_bit(0, &devinfo->ctl_op);
		return err;
	}

	if (1 || bus_if->chip_ready != 1) {
		timeout = wland_usb_ioctl_resp_wait(devinfo);
		if (!timeout) {
			if (devinfo->bulk_urb)
				usb_kill_urb(devinfo->bulk_urb);
			clear_bit(0, &devinfo->ctl_op);
			WLAND_ERR("Txctl wait timed out\n");
			err = -EIO;
		}
	}

	clear_bit(0, &devinfo->ctl_op);
	return err;
}

static int wland_usb_bus_rxctl(struct device *dev, u8 *buf, u32 len)
{
	int err = 0, timeout = 0;
	u32 rxlen = 0;
	struct wland_usbdev_info *devinfo = wland_usb_get_businfo(dev);
	struct wland_rx_info* rx_info = devinfo->rx_info;

	WLAND_DBG(USB, TRACE, "Enter\n");

	if (devinfo->bus_pub.state != USB_STATE_UP)
		return -EIO;

	if (test_and_set_bit(0, &devinfo->ctl_op)) {
		WLAND_ERR("In a control frame option, can't rx!\n");
		return -EIO;
	}

	devinfo->ctl_completed = false;

#if 1 //rda wlan chip receive wid_rsp in bulk urb
	timeout = wland_usb_data_resp_wait(devinfo);
	clear_bit(0, &devinfo->ctl_op);

	if (timeout == 0) {
			WLAND_ERR("resumed on timeout\n");
			return -ETIMEDOUT;
	} else if ((rx_info->rxlen > 0) && (devinfo->bus_pub.state == USB_STATE_UP)) {
		spin_lock_bh(&rx_info->rxctl_lock);
		rxlen = rx_info->rxlen;
		memcpy(buf, rx_info->rxctl, min(len, rxlen));
		rx_info->rxlen = 0;
		spin_unlock_bh(&rx_info->rxctl_lock);
	}
	err = rxlen>0 ? (int)rxlen : -ETIMEDOUT;
	return err;
#else
	err = wland_usb_recv_ctl(devinfo, buf, len);
	if (err) {
		WLAND_ERR("fail %d bytes: %d\n", err, len);
		clear_bit(0, &devinfo->ctl_op);
		return err;
	}

	timeout = wland_usb_ioctl_resp_wait(devinfo);
	err = devinfo->ctl_urb_status;
	clear_bit(0, &devinfo->ctl_op);

	if (!timeout) {
		WLAND_ERR("rxctl wait timed out\n");
		err = -EIO;
	}

	if (!err)
		return devinfo->ctl_urb_actual_length;
	else
		return err;
#endif
}

static struct wland_usbreq *wland_usbdev_qinit(struct list_head *q, int qsize)
{
	int i;
	struct wland_usbreq *req, *reqs;

	reqs = kcalloc(qsize, sizeof(struct wland_usbreq), GFP_ATOMIC);

	if (reqs == NULL)
		return NULL;

	req = reqs;

	for (i = 0; i < qsize; i++) {
		req->urb = usb_alloc_urb(0, GFP_ATOMIC);
		if (!req->urb)
			goto fail;

		INIT_LIST_HEAD(&req->list);
		list_add_tail(&req->list, q);
		req++;
	}
	return reqs;
fail:
	WLAND_ERR("fail!\n");
	while (!list_empty(q)) {
		req = list_entry(q->next, struct wland_usbreq, list);

		if (req && req->urb)
			usb_free_urb(req->urb);
		list_del(q->next);
	}
	return NULL;
}

static void wland_usb_free_q(struct list_head *q, bool pending, spinlock_t *qlock)
{
	struct wland_usbreq *req, *next;
	int i = 0;
	unsigned long flags;

	spin_lock_irqsave(qlock, flags);
	list_for_each_entry_safe(req, next, q, list) {
	spin_unlock_irqrestore(qlock, flags);
		if (!req->urb) {
			WLAND_ERR("bad req\n");
			spin_lock_irqsave(qlock, flags);
			break;
		}
		i++;
		if (pending) {
			usb_kill_urb(req->urb);
		} else {
			usb_free_urb(req->urb);
			list_del_init(&req->list);
		}
		spin_lock_irqsave(qlock, flags);
	}
	spin_unlock_irqrestore(qlock, flags);

}

static void wland_usb_tx_complete(struct urb *urb)
{
	unsigned long flags;
	struct wland_usbreq *req = (struct wland_usbreq *) urb->context;
	struct wland_usbdev_info *devinfo = req->devinfo;
	struct sk_buff *skb = req->skb;
	struct wland_private *drvr = devinfo->bus_pub.bus->drvr;
	struct wland_if *ifp = drvr->iflist[0];
#ifdef WLAND_TX_SOFT_MAC
	u8 *data = skb->data;
#endif

	WLAND_DBG(USB, TRACE, "Enter, urb->status=%d, skb=%p\n", urb->status,
		req->skb);

#ifdef WLAND_TX_SOFT_MAC
	skb_pull(skb, data[3]);
#else
	skb_pull(skb, WID_HEADER_LEN);
#endif

	wland_txcomplete(devinfo->bus_pub.bus->dev, skb, urb->status == 0);
	req->skb = NULL;

	//wland_usb_del_fromq(devinfo, req, &devinfo->q_lock);
	devinfo->tx_pendingcount --;
	wland_usb_enq(devinfo, &devinfo->tx_freeq, req,
		&devinfo->tx_freecount, &devinfo->tx_freeq_lock);

	spin_lock_irqsave(&devinfo->tx_flowblock_lock, flags);
	if (devinfo->tx_freecount > devinfo->tx_high_watermark
		&& ifp->tx_flowblock) {
		wland_txflowcontrol(devinfo->dev, false);
		ifp->tx_flowblock = false;
	}
	spin_unlock_irqrestore(&devinfo->tx_flowblock_lock, flags);
}

static void wland_usb_rx_complete(struct urb *urb)
{
	struct wland_usbreq *req = (struct wland_usbreq *) urb->context;
	struct wland_usbdev_info *devinfo = req->devinfo;
	struct wland_rx_info* rx_info = devinfo->rx_info;
	struct sk_buff *skb = NULL;
#ifdef WLAND_USE_RXQ
	uint prec = 0;
	unsigned long flags = 0;
#endif

	WLAND_DBG(USB, TRACE, "ENTER\n");

	wland_usb_del_fromq(devinfo, req, &devinfo->rx_postq_lock);
	devinfo->rx_postcount --;

	skb = req->skb;
	req->skb = NULL;

	if (urb->actual_length > urb->transfer_buffer_length) {
		WLAND_DBG(USB, WARNING, "actual_length%d > transfer_buffer_length:%d\n",
			urb->actual_length, urb->transfer_buffer_length);
		wland_pkt_buf_free_skb(skb);
		wland_usb_enq(devinfo, &devinfo->rx_freeq, req, NULL,
			&devinfo->rx_freeq_lock);
		schedule_work(&devinfo->rx_refill_work);
		return;
	}

	/*
	 * zero lenght packets indicate usb "failure". Do not refill
	 */
	if (urb->status != 0 || !urb->actual_length) {
		WLAND_DBG(USB, DEBUG, "urb->status=%d\n", urb->status);
		wland_pkt_buf_free_skb(skb);
		wland_usb_enq(devinfo, &devinfo->rx_freeq, req, NULL,
			&devinfo->rx_freeq_lock);
		schedule_work(&devinfo->rx_refill_work);
		return;
	}

	if (devinfo->bus_pub.state == USB_STATE_UP) {
		skb_put(skb, urb->actual_length);

	//dump_buf(skb->data, MIN(skb->len, 32));

#ifdef WLAND_USE_RXQ
		//prec = prio2prec((skb->priority & PRIOMASK));
		wland_dhd_os_sdlock_rxq(rx_info, &flags);
		if(!wland_prec_enq(devinfo->dev, &rx_info->rxq, skb, prec)){
			wland_dhd_os_sdunlock_rxq(rx_info, &flags);
			WLAND_ERR("rx_info->rxq is over flow!!!\n");
			wland_pkt_buf_free_skb(skb);
			wland_usb_enq(devinfo, &devinfo->rx_freeq, req, NULL,
				&devinfo->rx_freeq_lock);
			schedule_work(&devinfo->rx_refill_work);
			return;
		}
		wland_dhd_os_sdunlock_rxq(rx_info, &flags);
		WLAND_DBG(USB, TRACE,
				"IRQ Wake up RX Work, rx_info->rx_dpc_tskcnt=%d\n",
				atomic_read(&rx_info->rx_dpc_tskcnt));
		WLAND_DBG(USB, TRACE,"rxq_len=%d\n", wland_pktq_mlen(&rx_info->rxq, ~rx_info->flowcontrol));
		atomic_inc(&rx_info->rx_dpc_tskcnt);
		WAKE_RX_WORK(rx_info);
#else
		atomic_inc(&rx_info->rx_dpc_tskcnt);
		WLAND_DBG(USB, TRACE,
				"IRQ get a pkt and will process it, rx_info->rx_dpc_tskcnt=%d\n",
				atomic_read(&rx_info->rx_dpc_tskcnt));
		wland_process_rxframes(rx_info, skb);
#endif

		//wland_process_rxframes(devinfo->rx_info, skb);
		//wland_usb_rx_frames(devinfo->dev, skb);

		//wland_usb_rx_refill(devinfo, req);

		wland_usb_enq(devinfo, &devinfo->rx_freeq, req, NULL,
			&devinfo->rx_freeq_lock);
		schedule_work(&devinfo->rx_refill_work);

	} else {
		wland_pkt_buf_free_skb(skb);
		wland_usb_enq(devinfo, &devinfo->rx_freeq, req, NULL,
			&devinfo->rx_freeq_lock);
	}
}

static int wland_usb_rx_refill(struct wland_usbdev_info *devinfo,
	struct wland_usbreq *req)
{
	struct sk_buff *skb;
	int ret;

	WLAND_DBG(USB, DEBUG, "Enter\n");

	if (!req || !devinfo
#ifdef WLAND_DRIVER_RELOAD_FW
		|| wland_repowering_chip
#endif
	)
		return -1;

	if (devinfo->bus_pub.state != USB_STATE_UP) {
		WLAND_ERR("usb state is not up!\n");
		wland_usb_enq(devinfo, &devinfo->rx_freeq, req, NULL,
			&devinfo->rx_freeq_lock);
		return -1;
	}

	//skb = dev_alloc_skb(devinfo->bus_pub.bus_mtu);
	skb = __dev_alloc_skb(devinfo->bus_pub.bus_mtu, GFP_KERNEL);
	if (!skb) {
		wland_usb_enq(devinfo, &devinfo->rx_freeq, req, NULL,
			&devinfo->rx_freeq_lock);
		return -1;
	}

	req->skb = skb;

	usb_fill_bulk_urb(req->urb,
		devinfo->usbdev,
		devinfo->rx_pipe,
		skb->data, skb_tailroom(skb), wland_usb_rx_complete, req);

	req->devinfo = devinfo;

	wland_usb_enq(devinfo, &devinfo->rx_postq, req, &devinfo->rx_postcount,
		&devinfo->rx_postq_lock);

	ret = usb_submit_urb(req->urb, GFP_ATOMIC);
	if (ret) {
		WLAND_ERR("usb submit rx urb fail:%d\n", ret);
		wland_usb_del_fromq(devinfo, req, &devinfo->rx_postq_lock);

		wland_pkt_buf_free_skb(req->skb);
		req->skb = NULL;
		wland_usb_enq(devinfo, &devinfo->rx_freeq, req, NULL,
			&devinfo->rx_freeq_lock);
		msleep(100);
	}
	return 0;
}
static void wland_usb_rx_fill_all(struct wland_usbdev_info *devinfo)
{
	struct wland_usbreq *req;
	if (devinfo->bus_pub.state != USB_STATE_UP) {
		WLAND_DBG(USB, WARNING, "bus is not up=%d\n", devinfo->bus_pub.state);
		return;
	}

	while((req = wland_usb_deq(devinfo, &devinfo->rx_freeq, NULL,
		&devinfo->rx_freeq_lock)) != NULL) {
		if (wland_usb_rx_refill(devinfo, req)) {
			WLAND_DBG(USB, DEBUG, "usb rx refill fail\n");
			if (!wland_usb_qempty(devinfo, &devinfo->rx_postq, &devinfo->rx_postq_lock) ||
				(devinfo->bus_pub.state != USB_STATE_UP))
				return;
		}
	}
}

static void wland_usb_state_change(struct wland_usbdev_info *devinfo, int state)
{
	struct wland_bus *bcmf_bus = devinfo->bus_pub.bus;
	int old_state;

	WLAND_DBG(USB, INFO, "Enter, current state=%d, new state=%d\n",
		devinfo->bus_pub.state, state);

	if (devinfo->bus_pub.state == state)
		return;

	old_state = devinfo->bus_pub.state;
	devinfo->bus_pub.state = state;

	/*
	 * update state of upper layer
	 */
	if (state == USB_STATE_DOWN) {
		WLAND_DBG(USB, TRACE, "DBUS is down\n");
		bcmf_bus->state = WLAND_BUS_DOWN;
	} else if (state == USB_STATE_UP) {
		WLAND_DBG(USB, TRACE, "DBUS is up\n");
		bcmf_bus->state = WLAND_BUS_DATA;
	} else {
		WLAND_DBG(USB, TRACE, "DBUS current state=%d\n", state);
	}
}

#ifdef USB_INTR_ENDPOINT
static void wland_usb_intr_complete(struct urb *urb)
{
	struct wland_usbdev_info *devinfo =
		(struct wland_usbdev_info *) urb->context;
	int err;

	WLAND_DBG(USB, INFO, "Enter, urb->status=%d\n", urb->status);

	if (devinfo == NULL)
		return;

	if (unlikely(urb->status)) {
		if (urb->status == -ENOENT ||
			urb->status == -ESHUTDOWN || urb->status == -ENODEV) {
			wland_usb_state_change(devinfo, USB_STATE_DOWN);
		}
	}

	if (devinfo->bus_pub.state == USB_STATE_DOWN) {
		WLAND_ERR("intr cb when DBUS down, ignoring\n");
		return;
	}

	if (devinfo->bus_pub.state == USB_STATE_UP) {
		err = usb_submit_urb(devinfo->intr_urb, GFP_ATOMIC);
		if (err)
			WLAND_ERR("usb_submit_urb, err=%d\n", err);
	}
}
#endif /*USB_INTR_ENDPOINT*/

static int wland_usb_bus_txdata(struct device *dev, struct sk_buff *skb)
{
	u8 *buf;
	u16 buf_len = 0;
	struct wland_usbreq *req;
	int ret = 0;
	unsigned long flags;
	struct wland_usbdev_info *devinfo = NULL;
	struct wland_private *drvr = NULL;
	struct wland_if *ifp = NULL;
#ifndef WLAND_USE_USB_TXQ
	struct wland_bus *bus_if = dev_get_drvdata(dev);
#endif /*WLAND_USE_USB_TXQ*/
	WLAND_DBG(USB, TRACE, "Enter, skb=%p\n", skb);

#ifdef WLAND_DRIVER_RELOAD_FW
	if (wland_repowering_chip) {
		WLAND_DBG(USB, TRACE, "chip repowering!\n");
		dev_kfree_skb_any(skb);
		return -EIO;
	}
#endif

	devinfo = wland_usb_get_businfo(dev);
	drvr = devinfo->bus_pub.bus->drvr;
	ifp = drvr->iflist[0];

	if (devinfo->bus_pub.state != USB_STATE_UP) {
		WLAND_ERR("usb state is not up!\n");
		wland_txcomplete(dev, skb, false);
		return -EIO;
	}

	req = wland_usb_deq(devinfo, &devinfo->tx_freeq,
		&devinfo->tx_freecount, &devinfo->tx_freeq_lock);
	if (!req) {
		WLAND_DBG(USB,INFO,"no req to send\n");
		WLAND_ERR("free:%d, post:%d\n", devinfo->tx_freecount,
			devinfo->tx_postcount);
		wland_txcomplete(dev, skb, false);
		ret = -ENOMEM;
		goto flow_ctrl;
	}
#if 0
	skb_push(skb, WID_HEADER_LEN);
	if (skb->len > CDC_DCMD_LEN_MASK) {
		WLAND_ERR("pktbuf->len is over flow!\n");
		skb_pull(skb, WID_HEADER_LEN);
		dev_kfree_skb(skb);
		return -EINVAL;
	}

	buf = skb->data;
	buf_len = skb->len & CDC_DCMD_LEN_MASK;
	*(__le16 *) buf = cpu_to_le16(buf_len | (PKT_TYPE_REQ << CDC_DCMD_LEN_SHIFT));
#endif
	buf = skb->data;
	buf_len = skb->len & CDC_DCMD_LEN_MASK;

	if (buf_len <= 1536) {
		u16 adjust_len = buf_len % 512;
		if (adjust_len != 0) {
			if (adjust_len > 64) {
				buf_len += 512 - adjust_len;
				buf_len += 4;
			}
		} else {
			buf_len += 4;//512 1024 1536
		}

		/*if(skb_tailroom(skb) < (buf_len - (skb->len & CDC_DCMD_LEN_MASK)))
			buf_len = skb->len & CDC_DCMD_LEN_MASK;*/
	}

	req->skb = skb;
	req->devinfo = devinfo;
	//dump_buf(buf, MIN(128, buf_len));
	usb_fill_bulk_urb(req->urb, devinfo->usbdev, devinfo->tx_pipe,
		buf, buf_len, wland_usb_tx_complete, req);
	req->urb->transfer_flags |= URB_ZERO_PACKET;

#ifdef WLAND_USE_USB_TXQ
	wland_usb_enq(devinfo, &devinfo->tx_postq, req,
		&devinfo->tx_postcount, &devinfo->tx_postq_lock);
	if (devinfo->wland_txwq)
		queue_work(devinfo->wland_txwq, &devinfo->TxWork);
	ret = 0;
#else
	if (atomic_read(&bus_if->software_reset)) {
		WLAND_ERR("software reset status!\n");
		msleep(100);
		goto fail;
	}

	ret = usb_submit_urb(req->urb, GFP_ATOMIC);
	if (ret) {
		WLAND_DBG(USB, ERROR, "wland_usb_bus_tx usb_submit_urb FAILED\n");
		goto fail;
	}

#endif

flow_ctrl:
	spin_lock_irqsave(&devinfo->tx_flowblock_lock, flags);
	if (devinfo->tx_freecount < devinfo->tx_low_watermark
		&& !ifp->tx_flowblock) {
		WLAND_DBG(USB,DEBUG,"c=%d\n",devinfo->tx_freecount);
		wland_txflowcontrol(dev, true);
		ifp->tx_flowblock = true;
	}
	spin_unlock_irqrestore(&devinfo->tx_flowblock_lock, flags);

	return ret;

#ifndef WLAND_USE_USB_TXQ
fail:
#ifdef WLAND_TX_SOFT_MAC
	skb_pull(skb, buf[3]);
#else
	skb_pull(skb, WID_HEADER_LEN);
#endif
	wland_txcomplete(dev, skb, false);
	req->skb = NULL;
	//wland_usb_del_fromq(devinfo, req, &devinfo->q_lock);
	wland_usb_enq(devinfo, &devinfo->tx_freeq, req,
		&devinfo->tx_freecount, &devinfo->tx_freeq_lock);
	return ret;
#endif
}

static int wland_usb_bus_up(struct device *dev)
{
	u16 ifnum;
	struct wland_usbdev_info *devinfo = wland_usb_get_businfo(dev);

	WLAND_DBG(USB, INFO, "Enter\n");

	if (devinfo->bus_pub.state == USB_STATE_UP)
		return 0;

	/*
	 * Success, indicate devinfo is fully up
	 */
	wland_usb_state_change(devinfo, USB_STATE_UP);

#ifdef USB_INTR_ENDPOINT
	if (devinfo->intr_urb) {
		usb_fill_int_urb(devinfo->intr_urb,
			devinfo->usbdev,
			devinfo->intr_pipe,
			&devinfo->intr,
			devinfo->intr_size,
			(usb_complete_t) wland_usb_intr_complete,
			devinfo, devinfo->interval);

		ret = usb_submit_urb(devinfo->intr_urb, GFP_ATOMIC);
		if (ret) {
			WLAND_ERR("USB_SUBMIT_URB failed with status %d\n",
				ret);
			return -EINVAL;
		}
	}
#endif
	if (devinfo->ctl_urb) {
		devinfo->ctl_in_pipe = usb_rcvctrlpipe(devinfo->usbdev, 0);
		devinfo->ctl_out_pipe = usb_sndctrlpipe(devinfo->usbdev, 0);

		ifnum = IFDESC(devinfo->usbdev, CONTROL_IF).bInterfaceNumber;

		/*
		 * CTL Write
		 */
		devinfo->ctl_write.bRequestType =
			USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE;
		devinfo->ctl_write.bRequest = 0;
		devinfo->ctl_write.wValue = cpu_to_le16(0);
		devinfo->ctl_write.wIndex = cpu_to_le16p(&ifnum);

		/*
		 * CTL Read
		 */
		devinfo->ctl_read.bRequestType =
			USB_DIR_IN | USB_TYPE_CLASS | USB_RECIP_INTERFACE;
		devinfo->ctl_read.bRequest = 1;
		devinfo->ctl_read.wValue = cpu_to_le16(0);
		devinfo->ctl_read.wIndex = cpu_to_le16p(&ifnum);
	}
	wland_usb_rx_fill_all(devinfo);

#ifdef WLAND_USE_USB_TXQ
	wland_tx_pkt_reinit(devinfo->rx_info);
#endif
	return 0;
}

static void wland_usb_bus_down(struct device *dev)
{
	struct wland_usbdev_info *devinfo = wland_usb_get_businfo(dev);

	WLAND_DBG(USB, INFO, "Enter\n");

	if (devinfo == NULL)
		return;

	if (devinfo->bus_pub.state == USB_STATE_DOWN)
		return;

	wland_usb_state_change(devinfo, USB_STATE_DOWN);
#ifdef USB_INTR_ENDPOINT
	if (devinfo->intr_urb)
		usb_kill_urb(devinfo->intr_urb);
#endif
	if (devinfo->ctl_urb)
		usb_kill_urb(devinfo->ctl_urb);

	if (devinfo->bulk_urb)
		usb_kill_urb(devinfo->bulk_urb);

	wland_usb_free_q(&devinfo->tx_postq, true, &devinfo->tx_postq_lock);
	wland_usb_free_q(&devinfo->rx_postq, true, &devinfo->rx_postq_lock);
}

static void wland_usb_detach(struct wland_usbdev_info *devinfo)
{
	WLAND_DBG(USB, INFO, "Enter, devinfo %p\n", devinfo);


#ifdef WLAND_USE_USB_TXQ
	cancel_work_sync(&devinfo->TxWork);
	if (devinfo->wland_txwq) {
		destroy_workqueue(devinfo->wland_txwq);
		devinfo->wland_txwq = NULL;
	}
#endif

	cancel_work_sync(&devinfo->rx_refill_work);
	wland_usb_free_q(&devinfo->rx_freeq, false, &devinfo->rx_freeq_lock);
	wland_usb_free_q(&devinfo->tx_freeq, false, &devinfo->tx_freeq_lock);
#ifdef USB_INTR_ENDPOINT
	usb_free_urb(devinfo->intr_urb);
#endif
	usb_free_urb(devinfo->ctl_urb);
	usb_free_urb(devinfo->bulk_urb);

	kfree(devinfo->tx_reqs);
	kfree(devinfo->rx_reqs);
}

static void wland_rx_refill_worker(struct work_struct *work)
{
	struct wland_usbdev_info *devinfo =
		container_of(work, struct wland_usbdev_info,
		rx_refill_work);

	WLAND_DBG(USB, DEBUG, "Enter\n");

	wland_usb_rx_fill_all(devinfo);
}
static struct wland_usb_dev *wland_usb_attach(struct wland_usbdev_info *devinfo,
	int nrxq, int ntxq)
{
	WLAND_DBG(USB, TRACE, "Enter\n");

	devinfo->bus_pub.nrxq = nrxq;
	devinfo->rx_low_watermark = nrxq / 2;
	devinfo->bus_pub.devinfo = devinfo;
	devinfo->bus_pub.ntxq = ntxq;
	devinfo->bus_pub.state = USB_STATE_DOWN;

	/*
	 * flow control when too many tx urbs posted
	 */
	devinfo->tx_low_watermark = ntxq / 4;
	devinfo->tx_high_watermark = devinfo->tx_low_watermark * 3;
	devinfo->bus_pub.bus_mtu = USB_MAX_PKT_SIZE;

	/*
	 * Initialize other structure content
	 */
	init_waitqueue_head(&devinfo->ioctl_resp_wait);
	init_waitqueue_head(&devinfo->data_resp_wait);

	/*
	 * Initialize the spinlocks
	 */
	spin_lock_init(&devinfo->tx_freeq_lock);
	spin_lock_init(&devinfo->tx_postq_lock);
	spin_lock_init(&devinfo->q_lock);
	spin_lock_init(&devinfo->rx_freeq_lock);
	spin_lock_init(&devinfo->rx_postq_lock);

	spin_lock_init(&devinfo->tx_flowblock_lock);

	INIT_LIST_HEAD(&devinfo->rx_freeq);
	INIT_LIST_HEAD(&devinfo->rx_postq);
	INIT_LIST_HEAD(&devinfo->tx_pendingq);

	INIT_LIST_HEAD(&devinfo->tx_freeq);
	INIT_LIST_HEAD(&devinfo->tx_postq);

	//devinfo->tx_flowblock = false;

	devinfo->rx_reqs = wland_usbdev_qinit(&devinfo->rx_freeq, nrxq);
	if (!devinfo->rx_reqs)
		goto error;

	devinfo->tx_reqs = wland_usbdev_qinit(&devinfo->tx_freeq, ntxq);
	if (!devinfo->tx_reqs)
		goto error;

	devinfo->tx_freecount = ntxq;
	devinfo->tx_postcount = 0;
	devinfo->tx_pendingcount = 0;
	devinfo->rx_postcount = 0;
	//printk("freecount=%d\n",devinfo->tx_freecount);
#ifdef USB_INTR_ENDPOINT
	devinfo->intr_urb = usb_alloc_urb(0, GFP_ATOMIC);
	if (!devinfo->intr_urb) {
		WLAND_ERR("usb_alloc_urb (intr) failed\n");
		goto error;
	}
#endif
	devinfo->ctl_urb = usb_alloc_urb(0, GFP_ATOMIC);
	if (!devinfo->ctl_urb) {
		WLAND_ERR("usb_alloc_urb (ctl) failed\n");
		goto error;
	}

	devinfo->bulk_urb = usb_alloc_urb(0, GFP_ATOMIC);
	if (!devinfo->bulk_urb) {
		WLAND_ERR("usb_alloc_urb (bulk) failed\n");
		goto error;
	}

	INIT_WORK(&devinfo->rx_refill_work,
		wland_rx_refill_worker);

	WLAND_DBG(USB, TRACE, "Start fw downloading\n");

	WLAND_DBG(USB, TRACE, "Exit.\n");

	return &devinfo->bus_pub;

error:
	WLAND_ERR("failed!\n");
	wland_usb_detach(devinfo);
	return NULL;
}

static struct wland_bus_ops wland_usb_bus_ops = {
	.txdata = wland_usb_bus_txdata,
	.init = wland_usb_bus_up,
	.stop = wland_usb_bus_down,
	.txctl = wland_usb_bus_txctl,
	.rxctl = wland_usb_bus_rxctl,
};

static int wland_usb_probe(struct usb_interface *intf,
	const struct usb_device_id *id)
{
	int ep, ret = 0, num_of_eps;
	u8 endpoint_num;
	struct usb_endpoint_descriptor *endpoint;
	struct usb_device *usb = interface_to_usbdev(intf);
	struct wland_usbdev_info *devinfo;
	struct wland_bus *bus ;
	struct wland_usb_dev *bus_pub = NULL;
	struct device *dev = NULL;
	struct wland_rx_info* rx_info = NULL;

	WLAND_DBG(USB, ERROR, "Enter\n");

	devinfo = kzalloc(sizeof(*devinfo), GFP_ATOMIC);
	if (devinfo == NULL)
		return -ENOMEM;

	devinfo->usbdev = usb;
	devinfo->dev = &usb->dev;

	usb_set_intfdata(intf, devinfo);

	/*
	 * Check that the device supports only one configuration
	 */
	if (usb->descriptor.bNumConfigurations != 1) {
		ret = -1;
		goto fail;
	}

	if (usb->descriptor.bDeviceClass != 0x00) {
		ret = -1;
		goto fail;
	}

	/*
	 * Only the BDC interface configuration is supported:
	 *      Device class: USB_CLASS_VENDOR_SPEC
	 *      if0 class:    USB_CLASS_VENDOR_SPEC
	 *      if0/ep0: control
	 *      if0/ep1: bulk in
	 *      if0/ep2: bulk out (ok if swapped with bulk in)
	 */

	if (CONFIGDESC(usb)->bNumInterfaces != 1) {
		ret = -1;
		goto fail;
	}

	/*
	 * Check interface
	 */
	if (IFDESC(usb, CONTROL_IF).bInterfaceClass != USB_CLASS_VENDOR_SPEC ||
		IFDESC(usb, CONTROL_IF).bInterfaceSubClass != 0xff ||
		IFDESC(usb, CONTROL_IF).bInterfaceProtocol != 0xff) {
		WLAND_ERR
			("invalid control interface: class %d, subclass %d, proto %d\n",
			IFDESC(usb, CONTROL_IF).bInterfaceClass, IFDESC(usb,
				CONTROL_IF).bInterfaceSubClass, IFDESC(usb,
				CONTROL_IF).bInterfaceProtocol);
		ret = -1;
		goto fail;
	}

	/*
	 * Check control endpoint
	 */
	endpoint = &IFEPDESC(usb, CONTROL_IF, 0);
/*
	if ((endpoint->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK) !=
		USB_ENDPOINT_XFER_INT) {
		WLAND_ERR("invalid control endpoint %d\n",
			endpoint->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK);
		ret = -1;
		goto fail;
	}
*/
	endpoint_num = endpoint->bEndpointAddress & USB_ENDPOINT_NUMBER_MASK;
	devinfo->intr_pipe = usb_rcvintpipe(usb, endpoint_num);
	devinfo->rx_pipe = 0;
	devinfo->rx_pipe2 = 0;
	devinfo->tx_pipe = 0;
	devinfo->tx_pipe2 = 0;
	num_of_eps = IFDESC(usb, BULK_IF).bNumEndpoints - 1;

	/*
	 * Check data endpoints and get pipes
	 */
	for (ep = 0; ep <= num_of_eps; ep++) {
		endpoint = &IFEPDESC(usb, BULK_IF, ep);

		if ((endpoint->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK) !=
			USB_ENDPOINT_XFER_BULK) {
			WLAND_ERR("invalid data endpoint %d\n", ep);
			ret = -1;
			goto fail;
		}

		endpoint_num =
			endpoint->bEndpointAddress & USB_ENDPOINT_NUMBER_MASK;

		if ((endpoint->bEndpointAddress & USB_ENDPOINT_DIR_MASK) ==
			USB_DIR_IN) {
			if (!devinfo->rx_pipe) {
				devinfo->rx_pipe =
					usb_rcvbulkpipe(usb, endpoint_num);

				//printk("rx_pipe=%x\n",endpoint_num);
			} else {
				devinfo->rx_pipe2 =
					usb_rcvbulkpipe(usb, endpoint_num);

				//printk("rx_pipe2=%x\n",endpoint_num);
			}
		} else {
			if (!devinfo->tx_pipe)
			{
				devinfo->tx_pipe =
					usb_sndbulkpipe(usb, endpoint_num);
				//printk("tx_pipe=%x\n",endpoint_num);
			}else{
				devinfo->tx_pipe2 =
					usb_sndbulkpipe(usb, endpoint_num);

				//printk("tx_pipe2=%x\n",endpoint_num);
				}
		}
	}

	/*
	 * Allocate interrupt URB and data buffer
	 */
	/*
	 * RNDIS says 8-byte intr, our old drivers used 4-byte
	 */
	if (IFEPDESC(usb, CONTROL_IF, 0).wMaxPacketSize == cpu_to_le16(16))
		devinfo->intr_size = 8;
	else
		devinfo->intr_size = 4;

	devinfo->interval = IFEPDESC(usb, CONTROL_IF, 0).bInterval;

	if (usb->speed == USB_SPEED_HIGH)
		WLAND_DBG(USB, TRACE, "Rdamicro high speed USB wireless device detected\n");
	else
		WLAND_DBG(USB, TRACE, "Rdamicro full speed USB wireless device detected\n");

	dev = devinfo->dev;

	if (strncasecmp(rdawlan_firmware_path, "ap", strlen("ap"))==0)
		bus_pub = wland_usb_attach(devinfo, 50, 50);
	else
		bus_pub = wland_usb_attach(devinfo, WLAND_USB_NRXQ, WLAND_USB_NTXQ);
	if (!bus_pub) {
		WLAND_ERR("usb attach fail\n");
		ret = -1;
		goto fail;
	}

#ifdef WLAND_DRIVER_RELOAD_FW
	if (wland_repowering_chip) {
		WLAND_DBG(DEFAULT, INFO, "chip repowering use backup bus!\n");
		bus = bus_if_backup;
	} else {
#endif
		bus = kzalloc(sizeof(struct wland_bus), GFP_ATOMIC);
		if (!bus){
			WLAND_ERR("alloc wland_bus fail\n");
			ret = -1;
			goto fail2;
		}
#ifdef WLAND_DRIVER_RELOAD_FW
	}
#endif
	bus->dev = dev;
	bus_pub->bus = bus;
	bus->bus_priv.usb = bus_pub;
	atomic_set(&bus->software_reset, 0);

	dev_set_drvdata(dev, bus);

	bus->ops = &wland_usb_bus_ops;

	bus->chip_ready = 0;
	bus->up_data_mac = 0;
	/*
	 * attempt to attach to the chip
	 */
#ifdef WLAND_FPGA_SUPPORT
	bus->chip = WLAND_VER_91_H;
#else
	//bus->chip = (rda_wlan_version() & CHIP_ID_MASK);
	bus->chip = WLAND_VER_91_H;
#endif

	bus_pub->devid = bus->chip;

	rx_info = wland_rx_init(devinfo);
	if(!rx_info) {
		WLAND_ERR("rx init failed\n");
		ret = -1;
		goto fail1;
	}

	devinfo->rx_info = rx_info;

	/*
	 * Attach to the common driver interface
	 */
#ifdef WLAND_DRIVER_RELOAD_FW
	if (wland_repowering_chip)
		WLAND_DBG(DEFAULT, INFO, "chip repowering do not bus attach!\n");
	else {
#endif
		ret = wland_bus_attach(0, dev);
		if (ret < 0) {
			WLAND_ERR("bus_attach failed\n");
			goto fail1;
		}
#ifdef WLAND_DRIVER_RELOAD_FW
	}
#endif
	/*
	 * Allocate buffers
	 */
	if (bus->drvr->maxctl) {
		rx_info->rxblen =
			roundup((bus->drvr->maxctl),
			ALIGNMENT) + WLAND_SDALIGN;
		rx_info->rxbuf = kmalloc(rx_info->rxblen, GFP_ATOMIC);
		if (!rx_info->rxbuf) {
			WLAND_ERR("rxbuf malloc failed.\n");
			ret = -1;
			goto fail;
		}
		memset(rx_info->rxbuf, '\0', rx_info->rxblen);
	}

	WLAND_DBG(USB, DEBUG, "(maxctl:%d)<====>(rxblen:%d)\n",
		bus->drvr->maxctl, rx_info->rxblen);

#ifdef WLAND_USE_USB_TXQ
	INIT_WORK(&devinfo->TxWork, wland_usb_TxWorker);

	devinfo->wland_txwq = create_singlethread_workqueue("wland_txwq");
	if (!devinfo->wland_txwq) {
		WLAND_ERR("insufficient memory to create txworkqueue.\n");
		ret = -1;
		goto fail1;
	}
#endif
#ifdef WLAND_DRIVER_RELOAD_FW
	if (wland_repowering_chip) {
		WLAND_DBG(DEFAULT, INFO, "chip repowering do not bus start!\n");
	} else {
#endif
		ret = wland_bus_start(dev);
		if (ret < 0) {
			WLAND_ERR("chip is not responding\n");
			goto fail1;
		}
#ifdef WLAND_DRIVER_RELOAD_FW
	}
#endif
	/*
	 * Success
	 */
#ifdef WLAND_DRIVER_RELOAD_FW
	if (wland_repowering_chip) {
		ret = wland_start_chip(bus->drvr->iflist[0]->ndev);
		if (ret < 0) {
			WLAND_ERR("start chip failed, while repowering.\n");
			wland_repower_sem_up(true);
			return ret;
		}
		wland_repower_sem_up(false);
	}
#endif
	return 0;
fail1:
	wland_bus_detach(dev);
	kfree(bus);
fail2:
	wland_usb_detach(devinfo);
fail:
	WLAND_ERR("failed with errno %d\n", ret);
	kfree(devinfo);
	usb_set_intfdata(intf, NULL);
	return ret;
}

static void wland_usb_disconnect(struct usb_interface *intf)
{
	struct wland_usbdev_info *devinfo =
		(struct wland_usbdev_info *) usb_get_intfdata(intf);

	WLAND_DBG(USB, INFO, "Enter\n");

	if (!devinfo)
		return;

#ifdef WLAND_DRIVER_RELOAD_FW
	if (!wland_repowering_chip) {
#endif
		wland_bus_detach(devinfo->dev);
		kfree(devinfo->bus_pub.bus);
#ifdef WLAND_DRIVER_RELOAD_FW
	} else {
		wland_bus_detach_repowering(devinfo->dev);
		WLAND_DBG(USB, INFO, "chip repowering, not release bus!\n");
	}
#endif
	wland_usb_detach(devinfo);

	if (devinfo->rx_info)
		wland_rx_uinit(devinfo->rx_info);

	kfree(devinfo);

	WLAND_DBG(USB, TRACE, "Exit\n");
}

/* only need to signal the bus being down and update the state. */
static int wland_usb_suspend(struct usb_interface *intf, pm_message_t state)
{
	struct usb_device *usb = interface_to_usbdev(intf);
	struct wland_usbdev_info *devinfo = wland_usb_get_businfo(&usb->dev);

	WLAND_DBG(USB, INFO, "Enter\n");

	wland_usb_state_change(devinfo, USB_STATE_SLEEP);

	//wland_bus_detach(&usb->dev);
	wland_bus_stop(devinfo->bus_pub.bus);
	return 0;
}

/* (re-) start the bus. */
static int wland_usb_resume(struct usb_interface *intf)
{
	struct usb_device *usb = interface_to_usbdev(intf);
	struct wland_usbdev_info *devinfo = wland_usb_get_businfo(&usb->dev);

	WLAND_DBG(USB, INFO, "Enter\n");


	if (devinfo->bus_pub.state == USB_STATE_UP)
		return 0;

	//if (!wland_bus_attach(0, devinfo->dev)) {
		//return wland_bus_start(&usb->dev);
	//}

	wland_bus_init(devinfo->bus_pub.bus);

	return 0;
}

static int wland_usb_reset_resume(struct usb_interface *intf)
{
	//struct usb_device *usb = interface_to_usbdev(intf);
	//struct wland_usbdev_info *devinfo = wland_usb_get_businfo(&usb->dev);

	WLAND_DBG(USB, INFO, "Enter\n");

	return wland_usb_resume(intf);

}

MODULE_DEVICE_TABLE(usb, wland_usb_devid_table);
static void wland_ops_usb_shutdown(struct device *dev);
static struct usb_driver wland_usbdrvr = {
	.name = KBUILD_MODNAME,
	.probe = wland_usb_probe,
	.disconnect = wland_usb_disconnect,
	.id_table = wland_usb_devid_table,
	.suspend = wland_usb_suspend,
	.resume = wland_usb_resume,
	.reset_resume = wland_usb_reset_resume,
	.supports_autosuspend = 1,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	.disable_hub_initiated_lpm = 1,
#endif
	.drvwrap = {
		.driver = {
			.shutdown = &wland_ops_usb_shutdown,
		},
	},
};

static int wland_usb_reset_device(struct device *dev, void *notused)
{
	/*
	 * device past is the usb interface so we need to use parent here.
	 */
	struct wland_bus *bus_if = dev_get_drvdata(dev->parent);
	struct wland_private *drvr;
	//u8 val = 1;

	if (bus_if == NULL)
		return 0;

	drvr = bus_if->drvr;
	if (drvr == NULL)
		return 0;

	WLAND_DBG(USB, INFO, "Enter\n");

	if (drvr->iflist[0])
		wland_stop_chip(drvr->iflist[0]->ndev);
		//wland_fil_iovar_data_set(drvr->iflist[0], "TERMINATED", &val,
			//sizeof(u8));

	return 0;
}

static void wland_ops_usb_shutdown(struct device *dev)
{
	struct device_driver *drv = &wland_usbdrvr.drvwrap.driver;
	int ret;

	WLAND_DBG(USB, INFO, "Enter\n");

	ret = driver_for_each_device(drv, NULL, NULL, wland_usb_reset_device);
}

void wland_usb_exit(void)
{
	struct device_driver *drv = &wland_usbdrvr.drvwrap.driver;
	int ret;

	WLAND_DBG(USB, INFO, "Enter\n");

	ret = driver_for_each_device(drv, NULL, NULL, wland_usb_reset_device);

	usb_deregister(&wland_usbdrvr);

	WLAND_DBG(USB, INFO, "Exit\n");
}

void wland_usb_register(void)
{
	WLAND_DBG(USB, INFO, "Enter\n");

	if (usb_register(&wland_usbdrvr) < 0) {
		wland_registration_sem_up(false);
	}

	WLAND_DBG(USB, INFO, "Exit\n");
}

