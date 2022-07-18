
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
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/wireless.h>
#include <linux/ieee80211.h>
#include <linux/debugfs.h>
#include <net/cfg80211.h>
#include <net/rtnetlink.h>
#include <linux/firmware.h>

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
#include "wland_usb.h"
#include "wland_rf.h"
#include "wland_rx.h"

#ifdef WLAND_AP_RESET
bool ap_reseting = false;
struct wland_cfg80211_profile ap_profile;
u8 ap_gtk_len = 0;
struct wland_bus *ap_bus_if = NULL;

#ifdef WLAND_SDIO_SUPPORT
extern void wland_sdio_exit(void);
extern void wland_sdio_register(void);
#endif
void wland_chip_reset(struct work_struct *work)
{
	WLAND_DBG(DEFAULT, INFO, "Enter ap_reseting:%d.\n", ap_reseting);
	if (ap_reseting) {
#ifdef WLAND_SDIO_SUPPORT
		wland_sdio_exit();
		wland_sdio_register();
#endif
	}
	WLAND_DBG(DEFAULT, INFO, "Done.\n");
}
DECLARE_WORK(wland_chip_reset_work, wland_chip_reset);
void wland_reconfig_ap_inreseting(struct wland_if *ifp)
{
	int err = 0;
	WLAND_DBG(DEFAULT, INFO,"reconig ap\n");
	err = wland_preinit_cmds_91h(ifp);
	if (err < 0) {
		WLAND_ERR("preinit cmds failed!\n");
	}
	err = wland_start_ap_set(ifp, &ap_profile, false);
	if (err) {
		WLAND_ERR("failed to reconfig ap!\n");
		err = 0;
	}
	wland_config_and_efuse(ifp);
}
#endif

/* retries to retrieve matching dcmd response */
#define RETRIES                             2

static inline void put_le16(u8 *p, u16 v)
{
	p[0] = (u8)(v&0x000000ff);
	p[1] = (u8)((v >> 8)&0x000000ff);
}

static inline u16 get_le16(const u8 *p)
{
	return p[0] | (p[1] << 8);
}

static inline u32 get_le32(const u8 *p)
{
	return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
}

static inline void put_le32(u8 *p, u32 v)
{
	p[0] = (u8)(v&0x000000ff);
	p[1] = (u8)((v >> 8)&0x000000ff);
	p[2] = (u8)((v >> 16)&0x000000ff);
	p[3] = (u8)((v >> 24)&0x000000ff);
}

static inline u32 get_be32(const u8 *p)
{
	return p[3] | (p[2] << 8) | (p[1] << 16) | (p[0] << 24);
}
static inline void put_be32(u8 *p, u32 v)
{
	p[3] = (u8)(v&0x000000ff);
	p[2] = (u8)((v >> 8)&0x000000ff);
	p[1] = (u8)((v >> 16)&0x000000ff);
	p[0] = (u8)((v >> 24)&0x000000ff);
}

/*
 * fill wid struct
 * return the length filled or -1
 *@buf buf to fill
 *@WID WID
 *@data the data of @WID, couldn't be NULL. WID_CHAR(&(u8 a)), WID_INT(&(u32 a)), WID_BIN(u8 *data)
 *@data_len length of the WID. WID_CHAR(1), WID_SHORT(2),  WID_INT(4),  WID_STR/BIN(n)
 *@is_query true:query_wid; query_wid @data @data_len could be NULL
 */
s32 wland_push_wid(u8 *buf, u16 WID, const void *data, u16 data_len, bool is_query)
{
	u8* offset = buf;
	enum wid_type type = wland_get_wid_type(WID);
	u16 wid_length = wland_get_wid_size(type, data_len);

	u8 checksum = 0;

	if (buf==NULL || (!is_query && data==NULL)) {
		WLAND_ERR("buf%p or data:%p NULL\n", buf, data);
		return -1;
	}

	if (wid_length<0 || (!is_query && wid_length!=data_len)) {
		WLAND_ERR("WID(0x%04x type:%d) data_len error. wid_length:%d data_len:%d\n",
			WID, type, wid_length, data_len);
		return -1;
	}

	WLAND_DBG(DCMD, TRACE, "WID:0x%04x type:%d wid_length:%d\n",
		WID, type, wid_length);

	put_le16(buf, WID);
	buf += 2;

	//query wid doesn't have length and data
	if (is_query)
		return buf-offset;

	switch (type) {
	case WID_CHAR:
		*buf = (u8)wid_length;
		*(buf+1) = *(u8 *)data;
		buf += 2;
		break;
	case WID_SHORT:
		*buf = (u8)wid_length;
		put_le16(buf+1, *(u16 *)data);//*(u16 *)(buf+1) = (u16)value;
		buf += 3;
		break;
	case WID_INT:
		*buf = (u8)wid_length;
		put_le32(buf+1, *(u32 *)data);//*(u32 *)(buf+1) = (u32)value;
		buf += 5;
		break;
	case WID_STR:
		*buf = (u8)wid_length;
		memcpy(buf+1, data, wid_length);
		buf += (1+wid_length);
		break;
	case WID_BIN:
		put_le16(buf, wid_length);
		memcpy(buf+2, data, wid_length);
		while(data_len--)
			checksum += *(buf+2+data_len);
		*(buf+2+wid_length) = checksum;
		buf += (2+1+wid_length);
		break;
	case WID_UNKNOW:
	default:
		return -1;
	}
	WLAND_DBG(DCMD, TRACE, "Done:%zu\n", buf - offset);
	return buf - offset;
}

/*
 * analysis wid struct
 * return the length analysised or -1
 *@buf buf to analysis
 *@WID return WID, must be !NULL
 *@data buf to return data. must be !NULL
 *@data_len return data_len. must be !NULL
 */
s32 wland_pull_wid(const u8 *buf, u16 buf_len, u16 *WID, const u8 **data, u16 *data_len)
{
	const u8 *offset = buf;
	enum wid_type type;
	u16 wid_length;
	u8 checksum = 0;

	if (buf==NULL || WID==NULL || data==NULL || data_len==NULL) {
		WLAND_ERR("input paramters error\n");
		return -1;
	}
	*WID = *data_len = 0;
	*data = NULL;

	*WID = get_le16(buf);
	buf += 2;
	type = wland_get_wid_type(*WID);

	if (buf > offset + buf_len) {
		WLAND_ERR("data outof buf_len\n");
		return (offset+buf_len) - buf;
	} else if (buf == offset + buf_len)
		return buf_len;

	WLAND_DBG(DCMD, TRACE, "WID:0x%04x type:%d\n",
		*WID, type);

	switch (type) {
	case WID_CHAR:
		wid_length = (u16)(*buf);
 		if (wid_length != 1) {
			WLAND_ERR("WID(0x%04x) data_length(%d) error\n",	*WID, wid_length);
			return -1;
		}
		*data_len = wid_length;
		*data = buf + 1;
		buf += 2;
		break;
	case WID_SHORT:
		wid_length = (u16)(*buf);
 		if (wid_length != 1) {
			WLAND_ERR("WID(0x%04x) data_length(%d) error\n",	*WID, wid_length);
			return -1;
		}
		*data_len = wid_length;
		*data = buf + 1;
		buf += 3;
		break;
	case WID_INT:
		wid_length = (u16)(*buf);
		*data_len = wid_length;
 		if (wid_length != 4) {
			WLAND_ERR("WID(0x%04x) data_length(%d) error\n",	*WID, wid_length);
			return -1;
		}
		*data = buf + 1;
		buf += 5;
		break;
	case WID_STR:
		wid_length = (u16)(*buf);
		*data_len = wid_length;
		*data = buf+1;
		//memcpy(data, buf+1, wid_length);
		buf += (1+wid_length);
		break;
	case WID_BIN:
		//buf += 2;//only for binary_wid. word alignment
		//wid_length = get_le16(buf);
		wid_length = get_le16(buf) & 0x3fff;
		*data_len = wid_length;
		*data = buf+2;
		WLAND_DBG(DCMD, TRACE, "%zu:%d\n", buf-offset+2+1+wid_length, buf_len);
		if (buf-offset+2+1+wid_length > buf_len) {
			WLAND_ERR("data outof buf_len\n");
			return (buf_len - (buf-offset+2+1+wid_length));
		}

		while(wid_length--)
			checksum += *(buf+2+wid_length);
		wid_length = *data_len;
		if ( *(buf+2+wid_length) != checksum)  {
			WLAND_ERR("BINARY WID(0x%04x) checksum error. fw ret(%u) driver ret(%u)\n",
				*WID, *(buf+2+wid_length), checksum);
			return -1;
		}
		buf += (2+1+wid_length);
		break;
	case WID_UNKNOW:
	default:
		return -1;
	}

	if (buf > offset + buf_len) {
		WLAND_ERR("data outof buf_len\n");
		return (offset+buf_len) - buf;
	} else
		return buf - offset;
}

/*
 * hdrpush wid.
 * only used by wland_fil_set_cmd_data | wland_fil_get_cmd_data
 */
static int wland_wid_hdrpush(struct wland_private *drvr, u16 wid, bool rw,
	const u8 * val, u16 val_len)
{
	enum wid_type type = wland_get_wid_type(wid);
	u16 size = wland_get_wid_size(type, val_len);
	u16 wid_msg_len = FMW_HEADER_LEN, wid_pkt_len = 0;
	struct wland_proto *prot = drvr->prot;
	u8 *wid_msg = prot->buf;

	if (drvr->bus_if->state != WLAND_BUS_DATA) {
		WLAND_ERR("bus is down. we have nothing to do.\n");
		return -EINVAL;
	}

	prot->cmd = wid;
	prot->offset = 0;
	prot->rsplen = 0;

	/*
	 * Fill MsgID
	 */
	prot->msg.wid_msg_id = wland_get_seqidx(drvr);

	if (rw) {
		prot->msg.wid_msg_type = WLAND_WID_MSG_WRITE;

		wid_msg[0] = (u8) wid;
		wid_msg[1] = (u8) (wid >> 8);
		if (type == WID_BIN) {
			wid_msg[2] = size & 0xff;
			wid_msg[3] = (size & 0xff00) >> 8;
			memcpy(&wid_msg[4], val, size);
			wid_msg_len += (size + 4);
			wid_msg += (size + 4);
			wid_msg_len += 1;
		} else {
			wid_msg[2] = (u8)(size);
			memcpy(&wid_msg[3], val, size);
			wid_msg_len += (size + 3);
			wid_msg += (size + 3);
		}
	} else {
		prot->msg.wid_msg_type = WLAND_WID_MSG_QUERY;

		wid_msg[0] = (u8) wid;
		wid_msg[1] = (u8) (wid >> 8);
		wid_msg_len += 2;
		wid_msg += 2;
	}

	wid_pkt_len = wid_msg_len + WID_HEADER_LEN;

	prot->msg.wid_msg_length = cpu_to_le16(wid_msg_len);
	prot->msg.wid_pkg_length =
		cpu_to_le16((wid_pkt_len & CDC_DCMD_LEN_MASK) |
		(PKT_TYPE_CFG_REQ << CDC_DCMD_LEN_SHIFT));

	WLAND_DBG(DCMD, TRACE,
		"Done(wid:0x%x,type:%d,size:%d,wid_msg_len:%d,wid_pkt_len:%d)\n",
		wid, type, size, wid_msg_len, wid_pkt_len);

	return (wid_msg_len - FMW_HEADER_LEN);
}

static int wland_wid_hdrpull(struct wland_private *drvr, u8 *val, u16 val_len)
{
	int ret = -EBADE;
	u8 flag = 0;
	struct wland_proto *prot = drvr->prot;
	u8 *wid = prot->buf;
	enum wid_type type = WID_UNKNOW;

	if ((drvr->bus_if->state != WLAND_BUS_DATA)
		|| (val_len < FMWID_HEADER_LEN)) {
		WLAND_ERR("invalid. we have nothing to do.\n");
		return -EINVAL;
	}

	prot->rsplen = 0;
	prot->offset = 0;
	prot->msg.wid_pkg_length = cpu_to_le16(prot->msg.wid_pkg_length);
	prot->msg.wid_msg_length = cpu_to_le16(prot->msg.wid_msg_length);

	flag = (prot->msg.wid_pkg_length & ~CDC_DCMD_LEN_MASK)
		>> CDC_DCMD_LEN_SHIFT;

	if (PKT_TYPE_CFG_RSP == flag) {
		u16 rsp = (u16) (wid[0] | (wid[1] << 8));
		type = wland_get_wid_type(rsp);

		if (WLAND_WID_MSG_RESP == prot->msg.wid_msg_type) {
			if (rsp == WID_STATUS) {
				ret = (wid[3] != STATUS_SUCCESS) ? -EINVAL : 0;
			} else {
				ret = 0;
				if (type == WID_BIN) {
					prot->rsplen = wid[2] | wid[3] << 8;

					prot->offset =
						FMWID_HEADER_LEN - FMW_HEADER_LEN + 1;
				}else{
					prot->rsplen = wid[2];

					prot->offset =
						FMWID_HEADER_LEN - FMW_HEADER_LEN;
				}
			}
		}

		WLAND_DBG(EVENT, TRACE,
			"cfgrsp_len:0x%x,cmd:0x%x,rsp:0x%x,rsplen:0x%x,status:0x%x,prot->rsplen:%d,prot->offset:%d\n",
			val_len, prot->cmd, rsp, wid[2], wid[3], prot->rsplen,
			prot->offset);
	} else if (PKT_TYPE_IND == flag) {
		WLAND_DBG(EVENT, TRACE, "data indication val_len:%d\n",
			val_len);
	} else if (PKT_TYPE_ASYNC == flag) {
		WLAND_DBG(EVENT, TRACE, "sync frame indication val_len:%d\n",
			val_len);
	}

	return ret;
}

static int wland_proto_cdc_msg(struct wland_private *drvr)
{
	struct wland_proto *prot = drvr->prot;
	uint len = le16_to_cpu(prot->msg.wid_pkg_length) & CDC_DCMD_LEN_MASK;
	struct wland_bus *bus = drvr->bus_if;
	u8 *payload = (u8 *)&prot->msg;

	WLAND_DBG(DCMD, TRACE, "Enter(real_pkt_len:%d)\n", len);

	/*
	 * NOTE : cdc->msg.len holds the desired length of the buffer to be
	 * *        returned. Only up to CDC_MAX_MSG_SIZE of this buffer area
	 * *        is actually sent to the dongle
	 */
	if (len > CDC_MAX_MSG_SIZE) {
		WLAND_ERR("pkg_len > CDC_MAX_MSG_SIZE(%d:%d)\n", len, CDC_MAX_MSG_SIZE);
		len = CDC_MAX_MSG_SIZE;
	}

	return wland_bus_txctl(bus, payload, len);
}

static int wland_proto_cdc_cmplt(struct wland_private *drvr, u8 id, u16 len)
{
	int ret;
	struct wland_proto *prot = drvr->prot;

#if 0
	if (wland_check_test_mode()) {
		WLAND_DBG(SDIO, INFO, "In Test Mode and do not send msg!\n");
		return 0;
	}
#endif

	do {
		ret = wland_bus_rxctl(drvr->bus_if, (u8 *) & prot->msg, len);
		if (ret < 0) {
			WLAND_ERR("***response failed, ret:%d***\n",ret);
			break;
		}
	} while (prot->msg.wid_msg_id != id);

	WLAND_DBG(EVENT, TRACE,
		"Done(SendMsgId:%d, ReceivedMsgId:%d, RespLen:%d)\n", id,
		prot->msg.wid_msg_id, ret);
	return ret;
}

/*
 * @wid_msg_len length include msg_information
 * WLAND_WID_MSG_WRITE & PKT_TYPE_CFG_REQ
 */
int wland_proto_cdc_data(struct wland_private *drvr, u16 wid_msg_len)
{
	struct wland_proto *prot = drvr->prot;
	int err, retries = 0;
	u16 wid_pkg_len = 0;
	u8 wid_msg_id = wland_get_seqidx(drvr);

	if (drvr->bus_if->state != WLAND_BUS_DATA) {
		WLAND_ERR("bus is down. we have nothing to do.\n");
		return -EINVAL;
	}

	WLAND_DBG(DCMD, TRACE, "Enter(wid_msg_len:%d)\n", wid_msg_len);

	prot->msg.wid_msg_type = WLAND_WID_MSG_WRITE;
	prot->msg.wid_msg_id = wid_msg_id;

	wid_pkg_len = wid_msg_len + WID_HEADER_LEN;
	prot->msg.wid_msg_length = cpu_to_le16(wid_msg_len);
	prot->msg.wid_pkg_length =
		cpu_to_le16((wid_pkg_len & CDC_DCMD_LEN_MASK) |
		(PKT_TYPE_CFG_REQ << CDC_DCMD_LEN_SHIFT));

	err = wland_proto_cdc_msg(drvr);
	if (err < 0) {
		WLAND_ERR("set_dcmd failed status: %d\n", err);
		goto done;
	}

retry:
	/*
	 * wait for interrupt and get first fragment
	 */
	err = wland_proto_cdc_cmplt(drvr, wid_msg_id, WLAND_DCMD_MEDLEN);
	if (err < 0) {
		WLAND_ERR("cdc_cmplt fail.\n");
		goto done;
	}

	if ((prot->msg.wid_msg_id < wid_msg_id) && (++retries < RETRIES))
		goto retry;

	if (prot->msg.wid_msg_id != wid_msg_id) {
		WLAND_ERR("unexpected request id %d (expected %d)\n",
			prot->msg.wid_msg_id, wid_msg_id);
		err = -EINVAL;
	}

	if (err > 0)
		err = wland_wid_hdrpull(drvr, (u8 *) & prot->msg, (u16) err);

	WLAND_DBG(DCMD, TRACE, "Write_MsgIdx:%d, Read_MsgIdx:%d.\n", wid_msg_id,
		prot->msg.wid_msg_id);
done:
	WLAND_DBG(DCMD, TRACE, "Done(err:%d)\n", err);
	return err;
}

/*
 * this function could only send one wid each time
 * WLAND_WID_MSG_WRITE & PKT_TYPE_CFG_REQ and do not
 * wait for the rsp.
 */
int wland_fil_set_cmd_data_without_rsp(struct wland_if *ifp,
	u16 cmd, const void *data, u16 len)
{
	int err;
	u8 wid_msg_id = 0;
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = NULL;

	if (!drvr) {
		WLAND_ERR("drvr == NULL.\n");
		return -EIO;
	}

	prot = drvr->prot;
	if (!prot) {
		WLAND_ERR("prot == NULL.\n");
		return -EIO;
	}

	if (drvr->bus_if->state != WLAND_BUS_DATA) {
		WLAND_ERR("bus is down. we have nothing to do.\n");
		return -EIO;
	}

	mutex_lock(&drvr->proto_block);

	memset(prot->buf, '\0', sizeof(prot->buf));

	err = wland_wid_hdrpush(drvr, cmd, true, data, len);
	if (err < 0) {
		WLAND_ERR("set_dcmd failed status: %d\n", err);
		goto done;
	}

	wid_msg_id = prot->msg.wid_msg_id;

	err = wland_proto_cdc_msg(drvr);
	if (err < 0) {
		WLAND_ERR("set_dcmd failed status: %d\n", err);
		goto done;
	}

done:
	mutex_unlock(&drvr->proto_block);

	WLAND_DBG(DCMD, TRACE,
		"Done(cmd:0x%x,len:%d,rsplen:%d,widx:%d,ridx:%d)\n", cmd, len,
		err, wid_msg_id, prot->msg.wid_msg_id);

	return (err >= 0) ? 0 : err;
}


/*
 * this function could only send one wid each time
 * WLAND_WID_MSG_WRITE & PKT_TYPE_CFG_REQ
 */
int wland_fil_set_cmd_data(struct wland_if *ifp, u16 cmd, const void *data, u16 len)
{
	int err, retries = 0;
	u8 wid_msg_id = 0;
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = NULL;

	if (!drvr) {
		WLAND_ERR("drvr == NULL.\n");
		return -EIO;
	}

	prot = drvr->prot;
	if (!prot) {
		WLAND_ERR("prot == NULL.\n");
		return -EIO;
	}

	if (drvr->bus_if->state != WLAND_BUS_DATA) {
		WLAND_ERR("bus is down. we have nothing to do.\n");
		return -EIO;
	}

	mutex_lock(&drvr->proto_block);

	memset(prot->buf, '\0', sizeof(prot->buf));

	err = wland_wid_hdrpush(drvr, cmd, true, data, len);
	if (err < 0) {
		WLAND_ERR("set_dcmd failed status: %d\n", err);
		goto done;
	}

	wid_msg_id = prot->msg.wid_msg_id;

	err = wland_proto_cdc_msg(drvr);
	if (err < 0) {
		WLAND_ERR("set_dcmd failed status: %d\n", err);
		goto done;
	}

retry:
	/*
	 * wait for interrupt and get first fragment
	 */
	err = wland_proto_cdc_cmplt(drvr, wid_msg_id, WLAND_DCMD_MEDLEN);
	if (err < 0) {
		WLAND_ERR("cdc_cmplt fail.\n");
		goto done;
	}

	if ((prot->msg.wid_msg_id < wid_msg_id) && (++retries < RETRIES)) {
		WLAND_ERR("MisMatch(Write_MsgIdx:%d,Read_MsgIdx:%d)\n",
			wid_msg_id, prot->msg.wid_msg_id);
		goto retry;
	}

	if (prot->msg.wid_msg_id != wid_msg_id) {
		WLAND_ERR("unexpected request id:%d (expected:%d)\n",
			prot->msg.wid_msg_id, wid_msg_id);
		err = -EINVAL;
	}

	if (err >= 0)
		err = wland_wid_hdrpull(drvr, (u8 *) &prot->msg, (u16)err);

	WLAND_DBG(DCMD, TRACE, "Write_MsgIdx:%d, Read_MsgIdx:%d.\n", wid_msg_id,
		prot->msg.wid_msg_id);
done:
	mutex_unlock(&drvr->proto_block);

	WLAND_DBG(DCMD, TRACE,
		"Done(cmd:0x%x,len:%d,rsplen:%d,widx:%d,ridx:%d)\n", cmd, len,
		err, wid_msg_id, prot->msg.wid_msg_id);

	return (err >= 0) ? 0 : err;
}


/*
 * one query wid each time
 * WLAND_WID_MSG_WRITE & PKT_TYPE_CFG_REQ
 */
int wland_fil_get_cmd_data(struct wland_if *ifp, u16 cmd, void *data, u16 len)
{
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = NULL;
	int err = 0, retries = 0;
	u8 wid_msg_id = 0;

	if (!drvr) {
		WLAND_ERR("drvr == NULL.\n");
		return -EIO;
	}

	prot = drvr->prot;
	if (!prot) {
		WLAND_ERR("prot == NULL.\n");
		return -EIO;
	}

	if (data == NULL) {
		WLAND_ERR("data is NULL while query message\n");
		return -EIO;
	}
	if (drvr->bus_if->state != WLAND_BUS_DATA) {
		WLAND_ERR("bus is down. we have nothing to do.\n");
		return -EIO;
	}

	WLAND_DBG(DCMD, TRACE, "(cmd:0x%x,len:%d),Enter\n", cmd, len);

	mutex_lock(&drvr->proto_block);
	memset(prot->buf, '\0', sizeof(prot->buf));
	err = wland_wid_hdrpush(drvr, cmd, false, data, len);
	if (err < 0) {
		WLAND_ERR("set_dcmd failed status: %d\n", err);
		goto done;
	}

	wid_msg_id = prot->msg.wid_msg_id;

	/*
	 * send msg to chip
	 */

	err = wland_proto_cdc_msg(drvr);
	if (err < 0) {
		WLAND_ERR("query_dcmd failed w/status %d\n", err);
		goto done;
	}

retry:
	/*
	 * wait for interrupt and get first fragment
	 */
	err = wland_proto_cdc_cmplt(drvr, wid_msg_id, WLAND_DCMD_MEDLEN);
	if (err < 0) {
		WLAND_ERR("query_dcmd failed.\n");
		goto done;
	}

	if ((prot->msg.wid_msg_id < wid_msg_id) && (++retries < RETRIES))
		goto retry;

	if (prot->msg.wid_msg_id != wid_msg_id) {
		WLAND_ERR("%s: unexpected request id:%d(expected:%d)\n",
			wland_ifname(drvr, ifp->ifidx), prot->msg.wid_msg_id,
			wid_msg_id);
		err = -EINVAL;
		goto done;
	}

	/*
	 * Copy info buffer
	 */
	if (data) {
		if (err > 0)
			err = wland_wid_hdrpull(drvr, (u8 *) & prot->msg,
				(u16)err);

		if (err >= 0) {
			len = (prot->rsplen > len) ? len : prot->rsplen;
			memcpy(data, &prot->buf[prot->offset], len);
		}
	}
	WLAND_DBG(DCMD, TRACE, "Write_MsgIdx:%d, Read_MsgIdx:%d.\n", wid_msg_id,
		prot->msg.wid_msg_id);
done:
	mutex_unlock(&drvr->proto_block);

	WLAND_DBG(DCMD, TRACE, "(cmd:0x%x,len:%d),Done.\n", cmd, len);

	return (err >= 0) ? len : err;
}

s32 wland_fil_iovar_data_set(struct wland_if * ifp, char *name, void *data,
	u16 len)
{
	s32 err = 0;

#if 0
	struct wland_private *drvr = ifp->drvr;

	mutex_lock(&drvr->proto_block);

	WLAND_DBG(DCMD, TRACE, "name=%s, len=%d\n", name, len);

	memcpy(drvr->proto_buf, data, len);
	err = wland_proto_cdc_set_dcmd(drvr, ifp->ifidx, drvr->proto_buf, len);
	mutex_unlock(&drvr->proto_block);
#endif
	return err;
}

s32 wland_fil_iovar_data_get(struct wland_if * ifp, char *name, void *data,
	u16 len)
{
	s32 err = 0;

#if 0
	struct wland_private *drvr = ifp->drvr;

	mutex_lock(&drvr->proto_block);

	memcpy(drvr->proto_buf, data, len);

	err = wland_proto_cdc_query_dcmd(drvr, ifp->ifidx, drvr->proto_buf,
		len);
	if (err == 0)
		memcpy(data, drvr->proto_buf, len);

	WLAND_DBG(DCMD, TRACE, "name=%s, len=%d\n", name, len);

	mutex_unlock(&drvr->proto_block);
#endif
	return err;
}

void wland_config_and_efuse(struct wland_if *ifp)
{
	int err = 0;
#ifdef WLAND_POWER_CONFIG
	err = wland_set_power_config(ifp);
	if (err < 0) {
		WLAND_DBG(DEFAULT, WARNING, "wland_set_power_config failed!\n");
	}
#endif
#ifdef WLAND_POWER_EFUSE
	err = wland_set_power_efuse(ifp);
	if (err < 0) {
		WLAND_DBG(DEFAULT, WARNING, "wland_set_power_efuse failed!\n");
	}
#endif
#ifdef WLAND_CRYSTAL_CALIBRATION
	err = wland_set_crystal_cal_val(ifp);
	if (err < 0) {
		WLAND_DBG(DEFAULT, WARNING, "wland_set_crystal_cal_val failed!\n");
	}
#endif
#ifdef WLAND_SET_POWER_BY_RATE
	err = wland_set_power_by_rate(ifp);
	if (err < 0) {
		WLAND_DBG(DEFAULT, WARNING, "wland_set_power_by_rate failed!");
	}
#endif
}

s32 wland_set_scan_timeout(struct wland_if * ifp)
{
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;
	s32 ret = 0;
	u16 wid_msg_len = FMW_HEADER_LEN;
	enum wland_firmw_wid wid;

	mutex_lock(&drvr->proto_block);

	memset(prot->buf, '\0', sizeof(prot->buf));

	wid = WID_SITE_SURVEY_SCAN_TIME;
	buf[0] = (u8) (wid & 0x00FF);
	buf[1] = (u8) ((wid & 0xFF00) >> 8);
	buf[2] = 2;
	buf[3] = SCAN_CHANNEL_TIME;
	buf[4] = 0;
	buf += 5;
	wid_msg_len += 5;

	wid = WID_ACTIVE_SCAN_TIME;
	buf[0] = (u8) (wid & 0x00FF);
	buf[1] = (u8) ((wid & 0xFF00) >> 8);
	buf[2] = 2;
	buf[3] = SCAN_ACTIVE_TIME;
	buf[4] = 0;
	buf += 5;
	wid_msg_len += 5;

	wid = WID_PASSIVE_SCAN_TIME;
	buf[0] = (u8) (wid & 0x00FF);
	buf[1] = (u8) ((wid & 0xFF00) >> 8);
	buf[2] = 2;
	buf[3] = SCAN_PASSIVE_TIME;
	buf[4] = 0;
	buf += 5;
	wid_msg_len += 5;

	ret = wland_proto_cdc_data(drvr, wid_msg_len);

	mutex_unlock(&drvr->proto_block);

	WLAND_DBG(DCMD, TRACE, "Done(ret:%d,wid_pkg_len:%d,wid_msg_len:%d)\n",
		ret, (wid_msg_len + WID_HEADER_LEN), wid_msg_len);

	return ret;
}

s32 wland_p2p_start_go_set(struct wland_if * ifp,
	struct wland_cfg80211_profile * profile, bool is_p2p)
{
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;
	s32 ret = 0;
	u8 u8_value;
	u16 u16_value;

	WLAND_DBG(DCMD, DEBUG, "Enter\n");
	mutex_lock(&drvr->proto_block);

	memset(prot->buf, '\0', sizeof(prot->buf));

	u8_value = 1;
	ret = wland_push_wid(buf, WID_QOS_ENABLE, &u8_value, sizeof(u8_value), false);
	if (ret < 0) {
		mutex_unlock(&drvr->proto_block);
		WLAND_ERR("put wid error\n");
		return -1;
	}
	buf += ret;

	ret = wland_push_wid(buf, WID_P2P_11I_MODE_PAIRWISE, &profile->sec.security, sizeof(u8), false);
	if (ret < 0) {
		mutex_unlock(&drvr->proto_block);
		WLAND_ERR("put wid error\n");
		return -1;
	}
	buf += ret;

	ret = wland_push_wid(buf, WID_P2P_11I_MODE_GROUPWISE, &profile->sec.security_group, sizeof(u8), false);
	if (ret < 0) {
		mutex_unlock(&drvr->proto_block);
		WLAND_ERR("put wid error\n");
		return -1;
	}
	buf += ret;

	ret = wland_push_wid(buf, WID_P2P_AUTH_TYPE, &profile->sec.firmware_autype, sizeof(u8), false);
	if (ret < 0) {
		mutex_unlock(&drvr->proto_block);
		WLAND_ERR("put wid error\n");
		return -1;
	}
	buf += ret;

	u16_value = profile->beacon;
	ret = wland_push_wid(buf, WID_BACON_INTERVAL_GO, &u16_value, sizeof(u16), false);
	if (ret < 0) {
		mutex_unlock(&drvr->proto_block);
		WLAND_ERR("put wid error\n");
		return -1;
	}
	buf += ret;

	profile->dtim = 1;
	u8_value = profile->dtim;
	ret = wland_push_wid(buf, WID_P2P_DTIM_PERIOD, &u8_value, sizeof(u8), false);
	if (ret < 0) {
		mutex_unlock(&drvr->proto_block);
		WLAND_ERR("put wid error\n");
		return -1;
	}
	buf += ret;

	ret = wland_push_wid(buf, WID_P2P_WID_SSID, &profile->ssid.SSID, profile->ssid.SSID_len, false);
	if (ret < 0) {
		mutex_unlock(&drvr->proto_block);
		WLAND_ERR("put wid error\n");
		return -1;
	}
	buf += ret;

	u8_value = profile->channel;
	ret = wland_push_wid(buf, WID_P2P_OPER_CHAN, &u8_value, sizeof(u8), false);
	if (ret < 0) {
		mutex_unlock(&drvr->proto_block);
		WLAND_ERR("put wid error\n");
		return -1;
	}
	buf += ret;

	u8_value = 1;
	ret = wland_push_wid(buf, WID_P2P_GO_START_REQ, &u8_value, sizeof(u8), false);
	if (ret < 0) {
		mutex_unlock(&drvr->proto_block);
		WLAND_ERR("put wid error\n");
		return -1;
	}
	buf += ret;

	WLAND_DBG(DCMD, DEBUG, "Start SoftAp(SSID:%s, SSIDlen:%d)\n",
		profile->ssid.SSID, profile->ssid.SSID_len);

	ret = wland_proto_cdc_data(ifp->drvr, buf-(prot->buf) + FMW_HEADER_LEN);

	mutex_unlock(&drvr->proto_block);
	WLAND_DBG(DCMD, DEBUG, "Done(ret=%d).\n", ret);

	return ret;
}

s32 wland_start_ap_set(struct wland_if * ifp,
	struct wland_cfg80211_profile * profile, bool is_p2p)
{
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;
	s32 ret = 0;
	u16 wid_msg_len = FMW_HEADER_LEN;
	enum wid_type type;
	enum wland_firmw_wid wid;
	u8 size;

	WLAND_DBG(DEFAULT, ERROR,
		"Enter mode:%d,wmm_enable:%d,band_width:%d\n",
		profile->mode, profile->wmm_enable, profile->band_width);
#ifdef WLAND_AP_RESET
	memcpy(&ap_profile, profile, sizeof(struct wland_cfg80211_profile));
#endif
	mutex_lock(&drvr->proto_block);
	memset(prot->buf, '\0', sizeof(prot->buf));

	if (profile->mode != WLAND_N_MODE) {
		wid = WID_11N_ENABLE;
		type = wland_get_wid_type(wid);
		size = wland_get_wid_size(type, 1);
		buf[0] = (u8) (wid & 0x00FF);
		buf[1] = (u8) ((wid & 0xFF00) >> 8);
		buf[2] = size;		/* size */
		buf[3] = 0;
		buf += (size + 3);
		wid_msg_len += (size + 3);
	}

#ifndef WLAND_SOFTAP_40M
	profile->band_width = 0;
#endif

//#ifndef WLAND_SOFTAP_40M
	if ((profile->mode == WLAND_N_MODE) &&
			(profile->band_width == 0)) { // close 40m
		//disable 40M
		wid = WID_2040_ENABLE;
		type = wland_get_wid_type(wid);
		size = wland_get_wid_size(type, 1);
		buf[0] = (u8) (wid & 0x00FF);
		buf[1] = (u8) ((wid & 0xFF00) >> 8);
		buf[2] = size;		/* size */
		buf[3] = 0;
		buf += (size + 3);
		wid_msg_len += (size + 3);
	}
//#endif

#if 1
	if (profile->wmm_enable == 0) { // close qos
		wid = WID_QOS_ENABLE;
		type = wland_get_wid_type(wid);
		size = wland_get_wid_size(type, 1);
		buf[0] = (u8) (wid & 0x00FF);
		buf[1] = (u8) ((wid & 0xFF00) >> 8);
		buf[2] = size;		/* size */
		buf[3] = 0;
		buf += (size + 3);
		wid_msg_len += (size + 3);
	}
#endif

	wid = WID_802_11I_MODE;
	type = wland_get_wid_type(wid);
	size = wland_get_wid_size(type, 1);
	buf[0] = (u8) (wid & 0x00FF);
	buf[1] = (u8) ((wid & 0xFF00) >> 8);
	buf[2] = size;		/* size */
	buf[3] = profile->sec.security;
	WLAND_DBG(DCMD, TRACE, "profile->sec.security=0x%x\n",
		profile->sec.security);
	buf += (size + 3);
	wid_msg_len += (size + 3);

	wid = WID_AUTH_TYPE;
	type = wland_get_wid_type(wid);
	size = wland_get_wid_size(type, 1);
	buf[0] = (u8) (wid & 0x00FF);
	buf[1] = (u8) ((wid & 0xFF00) >> 8);
	buf[2] = size;		/* size */
	buf[3] = profile->sec.firmware_autype;
	WLAND_DBG(DCMD, TRACE, "profile->sec.firmware_autype=%d\n",
		profile->sec.firmware_autype);
	buf += (size + 3);
	wid_msg_len += (size + 3);

	wid = WID_BEACON_INTERVAL;
	type = wland_get_wid_type(wid);
	size = wland_get_wid_size(type, 1);
	WLAND_DBG(DCMD, TRACE, "WID_BEACON_INTERVAL size:%d, value:0x%x\n",
		size, profile->beacon);
	buf[0] = (u8) (wid & 0x00FF);
	buf[1] = (u8) ((wid & 0xFF00) >> 8);
	buf[2] = size;
	buf[3] = (u8) (profile->beacon & 0x00FF);
	buf[4] = (u8) ((profile->beacon & 0xFF00) >> 8);
	buf += (size + 3);
	wid_msg_len += (size + 3);

	if (profile->dtim == 0)
		profile->dtim = 1;
	wid = WID_DTIM_PERIOD;
	type = wland_get_wid_type(wid);
	size = wland_get_wid_size(type, 1);
	buf[0] = (u8) (wid & 0x00FF);
	buf[1] = (u8) ((wid & 0xFF00) >> 8);
	buf[2] = size;
	buf[3] = (u8) (profile->dtim & 0xFF);
	buf += (size + 3);
	wid_msg_len += (size + 3);

	wid = WID_SSID;
	type = wland_get_wid_type(wid);
	size = wland_get_wid_size(type, profile->ssid.SSID_len);
	buf[0] = (u8) (wid & 0x00FF);
	buf[1] = (u8) ((wid & 0xFF00) >> 8);
	buf[2] = size;
	memcpy(buf + 3, profile->ssid.SSID, size);
	wid_msg_len += (size + 3);
	buf += (size + 3);

	wid = WID_HIDDEN_SSID;
	type = wland_get_wid_type(wid);
	size = wland_get_wid_size(type, 1);
	buf[0] = (u8) (wid & 0x00FF);
	buf[1] = (u8) ((wid & 0xFF00) >> 8);
	buf[2] = size;
	buf[3] = profile->hidden_ssid;
	wid_msg_len += (size + 3);
	buf += (size + 3);

	wid = WID_CURRENT_CHANNEL;
	type = wland_get_wid_type(wid);
	size = wland_get_wid_size(type, 1);
	buf[0] = (u8) (wid & 0x00FF);
	buf[1] = (u8) ((wid & 0xFF00) >> 8);
	buf[2] = size;
	buf[3] = profile->channel;
	wid_msg_len += (size + 3);
	buf += (size + 3);

//#ifdef WLAND_SOFTAP_40M
	if ((profile->mode == WLAND_N_MODE) && (profile->band_width == 1)) {
		wid = WID_USER_PREF_CHANNEL;
		type = wland_get_wid_type(wid);
		size = wland_get_wid_size(type, 2);
		buf[0] = (u8) (wid & 0x00FF);
		buf[1] = (u8) ((wid & 0xFF00) >> 8);
		buf[2] = size;
		buf[3] = profile->channel;
		buf[4] = ((profile->channel<=9)?1:3) | (0<<7);
		wid_msg_len += (size + 3);
		buf += (size + 3);
	}
//#endif

	wid = WID_AP_START_REQ;
	type = wland_get_wid_type(wid);
	size = wland_get_wid_size(type, 1);
	buf[0] = (u8) (wid & 0x00FF);
	buf[1] = (u8) ((wid & 0xFF00) >> 8);
	buf[2] = size;
	buf[3] = 1;
	wid_msg_len += (size + 3);
	buf += (size + 3);

	WLAND_DBG(DCMD, DEBUG, "Start SoftAp(SSID:%s, SSIDlen:%d)\n",
		profile->ssid.SSID, profile->ssid.SSID_len);

	ret = wland_proto_cdc_data(drvr, wid_msg_len);

	mutex_unlock(&drvr->proto_block);
	WLAND_DBG(DCMD, DEBUG, "Done(ret=%d).\n", ret);

	return ret;
}

#ifdef WLAND_WLAN0_NOSCAN_WHEN_P2P0_DATAINCOMING
extern struct pkt_recv_statistics prs;
#endif
s32 wland_start_scan_set(struct wland_if *ifp,
	struct wland_ssid_le *scan_ssid, bool enable)
{
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;
	s32 ret = 0;
	u16 wid_msg_len = FMW_HEADER_LEN;
	enum wland_firmw_wid wid;
	enum wid_type type;
	u8 size;
	u8 country_code;
	u8 scan_channel_time = 20;
	u8 scan_active_time = 20;
	u8 scan_passive_time = 20;

	WLAND_DBG(DCMD, TRACE, "Enter %s scan\n", enable ? "start" : "stop");
	mutex_lock(&drvr->proto_block);

	memset(prot->buf, '\0', sizeof(prot->buf));
	if ((!test_bit(VIF_STATUS_CONNECTED, &ifp->vif->sme_state))
#ifdef WLAND_WLAN0_NOSCAN_WHEN_P2P0_DATAINCOMING
		&& (!wland_p2p_pkt_recv_statistics(&prs, RECV_CNT, RECV_TIME))
#else
		&& (!test_bit(VIF_STATUS_P2P, &(ifp->vif->sme_state)))
#endif
	) {
		scan_channel_time = 150;
		scan_active_time = 150;
		scan_passive_time = 150;
	}
	wid = WID_SITE_SURVEY_SCAN_TIME;
	buf[0] = (u8) (wid & 0x00FF);
	buf[1] = (u8) ((wid & 0xFF00) >> 8);
	buf[2] = 2;
	buf[3] = scan_channel_time;
	buf[4] = 0;
	buf += 5;
	wid_msg_len += 5;

	wid = WID_ACTIVE_SCAN_TIME;
	buf[0] = (u8) (wid & 0x00FF);
	buf[1] = (u8) ((wid & 0xFF00) >> 8);
	buf[2] = 2;
	buf[3] = scan_active_time;
	buf[4] = 0;
	buf += 5;
	wid_msg_len += 5;

	wid = WID_PASSIVE_SCAN_TIME;
	buf[0] = (u8) (wid & 0x00FF);
	buf[1] = (u8) ((wid & 0xFF00) >> 8);
	buf[2] = 2;
	buf[3] = scan_passive_time;
	buf[4] = 0;
	buf += 5;
	wid_msg_len += 5;

	country_code = WLAND_DEFAULT_COUNTRY_CODE;
	if (drvr->country_code != 0)
		country_code = drvr->country_code;
	wid = WID_SITE_SURVEY;
	type = wland_get_wid_type(wid);
	size = wland_get_wid_size(type, 1);
	buf[0] = (u8) (wid & 0x00FF);
	buf[1] = (u8) ((wid & 0xFF00) >> 8);
	buf[2] = size;
	buf[3] = country_code;
	buf += (size + 3);
	wid_msg_len += (size + 3);


	wid = WID_START_SCAN_REQ;
	type = wland_get_wid_type(wid);
	size = wland_get_wid_size(type, 1);
	buf[0] = (u8) (wid & 0x00FF);
	buf[1] = (u8) ((wid & 0xFF00) >> 8);
	buf[2] = size;
	buf[3] = DEFAULT_SCAN;
	buf += (size + 3);
	wid_msg_len += (size + 3);

	if (scan_ssid) {
		if (scan_ssid->SSID_len == 0) {
			size = 0;
			ret = wland_push_wid(buf, WID_SSID, &size, 1, false);
		} else
			ret = wland_push_wid(buf, WID_SSID, scan_ssid->SSID, scan_ssid->SSID_len, false);
		if (ret < 0) {
			mutex_unlock(&drvr->proto_block);
			WLAND_ERR("put wid error\n");
			return -1;
		}
		buf += ret;
		wid_msg_len += ret;
	}

	//WLAND_DUMP(DCMD, prot->buf, wid_msg_len, "Start Scan(SSID: %s,SSID_len:%d)widlen: %Zu\n", scan_ssid->SSID, scan_ssid->SSID_len, wid_msg_len);

	ret = wland_proto_cdc_data(drvr, wid_msg_len);

	mutex_unlock(&drvr->proto_block);
	WLAND_DBG(DCMD, DEBUG, "Done %s scan\n", enable ? "start" : "stop");

	if (ret < 0)
		WLAND_ERR("WID Result Failed\n");

	return ret;
}

#ifdef WLAND_P2P_SUPPORT
s32 wland_p2p_start_scan_set(struct wland_if * ifp,
		struct wland_scan_params_le *sparams)
{
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;
	s32 ret = 0;
	//u16 wid_msg_len = FMW_HEADER_LEN;
	//enum wland_firmw_wid wid;
	//enum wid_type type;
	//u8 size;
	u8 data;

	WLAND_DBG(DCMD, TRACE, "Enter scan\n");
	mutex_lock(&drvr->proto_block);

	memset(prot->buf, '\0', sizeof(prot->buf));

	WLAND_DBG(DCMD,TRACE,"channel num:%d\n", sparams->channel_num);
	if (sparams->channel_num == SOCIAL_CHAN_CNT)
		data = P2P_SITE_SURVEY_SOCIAL;
	else if (sparams->channel_num == P2P_FULL_CHAN_CNT || sparams->channel_num == P2P_FULL_CHAN_CNT_11)
		data = SITE_SURVEY_ALL_CH;
	else {
		WLAND_ERR("error channel number:%d\n", sparams->channel_num);
		data = P2P_SITE_SURVEY_SOCIAL;
	}
	ret = wland_push_wid(buf, WID_SITE_SURVEY, &data, sizeof(data), false);
	if (ret < 0) {
		mutex_unlock(&drvr->proto_block);
		WLAND_ERR("put wid error\n");
		return -1;
	}
	buf += ret;

	data = 1;
	ret = wland_push_wid(buf, WID_P2P_START_SCAN_SEARCH_REQ, &data, sizeof(data), false);
	if (ret < 0) {
		mutex_unlock(&drvr->proto_block);
		WLAND_ERR("put wid error\n");
		return -1;
	}
	buf += ret;

	ret = wland_proto_cdc_data(ifp->drvr, buf-(prot->buf) + FMW_HEADER_LEN);
	if (ret < 0)
		WLAND_ERR("WID Result Failed\n");
	mutex_unlock(&drvr->proto_block);
	WLAND_DBG(DCMD, DEBUG, "Done scan\n");
	return ret;
}
#endif

s32 wland_p2p_af_scan_set(struct wland_if * ifp,
	struct wland_scan_params_le *sparams)
{
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;
	s32 ret = 0;
	u8 data;

	WLAND_DBG(DCMD, TRACE, "Enter scan\n");
	mutex_lock(&drvr->proto_block);

	memset(prot->buf, '\0', sizeof(prot->buf));

	data = P2P_SITE_SURVEY_SOCIAL;
	ret = wland_push_wid(buf, WID_SITE_SURVEY, &data, sizeof(data), false);
	if (ret < 0) {
		mutex_unlock(&drvr->proto_block);
		WLAND_ERR("put wid error\n");
		return -1;
	}
	buf += ret;
/*
	ret = wland_push_wid(buf, WID_P2P_ONE_CHAN, &oper_channel, sizeof(oper_channel), false);
	if (ret < 0) {
		mutex_unlock(&drvr->proto_block);
		WLAND_ERR("put wid error\n");
		return -1;
	}
	buf += ret;
*/
	data = 1;
	ret = wland_push_wid(buf, WID_P2P_START_AF_SCAN_REQ, &data, sizeof(data), false);
	if (ret < 0) {
		mutex_unlock(&drvr->proto_block);
		WLAND_ERR("put wid error\n");
		return -1;
	}
	buf += ret;

	ret = wland_proto_cdc_data(ifp->drvr, buf-(prot->buf) + FMW_HEADER_LEN);
	if (ret < 0)
		WLAND_ERR("WID Result Failed\n");

	mutex_unlock(&drvr->proto_block);
	WLAND_DBG(DCMD, DEBUG, "Done scan\n");

	return ret;
}

s32 wland_p2p_connect_scan(struct wland_if * ifp,
	struct wland_scan_params_le *sparams)
{
	struct wland_ssid_le *scan_ssid = &sparams->ssid_le;
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;
	s32 ret = 0;
	u8 data;

	WLAND_DBG(DCMD, TRACE, "Enter scan\n");
	mutex_lock(&drvr->proto_block);

	memset(prot->buf, '\0', sizeof(prot->buf));

	if (sparams->channel_num == 1) {
		data = SITE_SURVEY_1CH;
		ret = wland_push_wid(buf, WID_SITE_SURVEY, &data, sizeof(data), false);
		if (ret < 0) {
			mutex_unlock(&drvr->proto_block);
			WLAND_ERR("put wid error\n");
			return -1;
		}
		buf += ret;

		data = sparams->channel_list[0]&0xff;
		ret = wland_push_wid(buf, WID_P2P_ONE_CHAN, &data, sizeof(data), false);
		if (ret < 0) {
			mutex_unlock(&drvr->proto_block);
			WLAND_ERR("put wid error\n");
			return -1;
		}
		buf += ret;
	} else {
		data = SITE_SURVEY_ALL_CH;
		ret = wland_push_wid(buf, WID_SITE_SURVEY, &data, sizeof(data), false);
		if (ret < 0) {
			mutex_unlock(&drvr->proto_block);
			WLAND_ERR("put wid error\n");
			return -1;
		}
		buf += ret;
	}

	if (scan_ssid->SSID_len == 0) {
		ret = wland_push_wid(buf, WID_P2P_WID_SSID, P2P_WILDCARD_SSID, P2P_WILDCARD_SSID_LEN, false);
	} else
		ret = wland_push_wid(buf, WID_P2P_WID_SSID, scan_ssid->SSID, scan_ssid->SSID_len, false);
	if (ret < 0) {
		mutex_unlock(&drvr->proto_block);
		WLAND_ERR("put wid error\n");
		return -1;
	}
	buf += ret;

	data = 1;
	ret = wland_push_wid(buf, WID_P2P_CONNECT_SCAN_REQ, &data, sizeof(data), false);
	if (ret < 0) {
		mutex_unlock(&drvr->proto_block);
		WLAND_ERR("put wid error\n");
		return -1;
	}
	buf += ret;

	ret = wland_proto_cdc_data(ifp->drvr, buf-(prot->buf) + FMW_HEADER_LEN);
	if (ret < 0)
		WLAND_ERR("WID Result Failed\n");

	mutex_unlock(&drvr->proto_block);
	WLAND_DBG(DCMD, DEBUG, "Done scan\n");

	return ret;
}

s32 wland_enable_arp_offload(struct wland_if *ifp,
		char *ipv4_addr)
{
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;
	s32 ret = 0;
	u16 wid_msg_len = FMW_HEADER_LEN;
	enum wland_firmw_wid wid;

	WLAND_DBG(DCMD, INFO, "arp offload:%d.%d.%d.%d\n",
		ipv4_addr[0], ipv4_addr[1], ipv4_addr[2], ipv4_addr[3]);

	mutex_lock(&drvr->proto_block);
	memset(prot->buf, '\0', sizeof(prot->buf));

	if (drvr->bus_if->chip == WLAND_VER_91_H) {
		wid = WID_ARP_OFFLOAD_91H;
		buf[0] = (u8) (wid & 0x00FF);
		buf[1] = (u8) ((wid & 0xFF00) >> 8);
		buf[2] = 5;
		buf[3] = 1;//enable
		memcpy(buf+4, ipv4_addr, 4);
		buf += (5 + 3);
		wid_msg_len += (5 + 3);
	}

	ret = wland_proto_cdc_data(drvr, wid_msg_len);

	mutex_unlock(&drvr->proto_block);

	return ret;
}

s32 wland_start_join(struct wland_if *ifp,
	struct wland_cfg80211_profile *profile)
{
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;
	s32 ret = 0;
	u16 wid_msg_len = FMW_HEADER_LEN;
	enum wland_firmw_wid wid;
	enum wid_type type;
	u8 size;
	u8 char_val;

	WLAND_DBG(DCMD, TRACE,
		"imode:0x%x, authtype:%d, ssid:%s, SSID_len:%d\n",
		profile->sec.security, profile->sec.firmware_autype,
		profile->ssid.SSID, profile->ssid.SSID_len);
	WLAND_DBG(DCMD, INFO, "Connecting to %pM\n", profile->bssid);
	mutex_lock(&drvr->proto_block);

	memset(prot->buf, '\0', sizeof(prot->buf));

#if 1
	wid = WID_QOS_ENABLE;
	type = wland_get_wid_type(wid);
	size = wland_get_wid_size(type, 1);
	char_val = profile->wmm_enable;
	buf[0] = (u8) (wid & 0x00FF);
	buf[1] = (u8) ((wid & 0xFF00) >> 8);
	buf[2] = size;
	buf[3] = char_val;
	buf += (size + 3);
	wid_msg_len += (size + 3);
#endif

	wid = WID_802_11I_MODE;
	type = wland_get_wid_type(wid);
	size = wland_get_wid_size(type, 1);
	if (profile->sec.security == (ENCRYPT_ENABLED | WPA)
		&& 0) {//for 91e/f/g
		//huanglei add for wps
		char_val = ENCRYPT_ENABLED | WPA | TKIP;
	} else {
		//for wep104 need set imode 0x07 firmware problem

		char_val =
			(profile->sec.security == (ENCRYPT_ENABLED | WEP_EXTENDED)) ?
				(ENCRYPT_ENABLED | WEP | WEP_EXTENDED) : profile->sec.security;
	}
	buf[0] = (u8) (wid & 0x00FF);
	buf[1] = (u8) ((wid & 0xFF00) >> 8);
	buf[2] = size;
	buf[3] = char_val;
	buf += (size + 3);
	wid_msg_len += (size + 3);

	wid = WID_AUTH_TYPE;
	type = wland_get_wid_type(wid);
	size = wland_get_wid_size(type, 1);
	char_val = profile->sec.firmware_autype;
	buf[0] = (u8) (wid & 0x00FF);
	buf[1] = (u8) ((wid & 0xFF00) >> 8);
	buf[2] = size;
	buf[3] = char_val;
	buf += (size + 3);
	wid_msg_len += (size + 3);

#ifdef WLAND_CONNECT_WITH_1M
	wid = WID_CURRENT_TX_RATE;
	type = wland_get_wid_type(wid);
	size = wland_get_wid_size(type, 1);
	char_val = 1;
	buf[0] = (u8) (wid & 0x00FF);
	buf[1] = (u8) ((wid & 0xFF00) >> 8);
	buf[2] = size;
	buf[3] = char_val;
	buf += (size + 3);
	wid_msg_len += (size + 3);

	wid = WID_11N_CURRENT_TX_MCS;
	type = wland_get_wid_type(wid);
	size = wland_get_wid_size(type, 1);
	char_val = 255;
	buf[0] = (u8) (wid & 0x00FF);
	buf[1] = (u8) ((wid & 0xFF00) >> 8);
	buf[2] = size;
	buf[3] = char_val;
	buf += (size + 3);
	wid_msg_len += (size + 3);
#endif /*WLAND_CONNECT_WITH_1M*/

#if 1
	wid = WID_11N_SHORT_GI_ENABLE;
	type = wland_get_wid_type(wid);
	size = wland_get_wid_size(type, 1);
	char_val = 1;
	buf[0] = (u8) (wid & 0x00FF);
	buf[1] = (u8) ((wid & 0xFF00) >> 8);
	buf[2] = size;
	buf[3] = char_val;
	buf += (size + 3);
	wid_msg_len += (size + 3);
#endif

	wid = WID_BSSID;
	type = wland_get_wid_type(wid);
	size = wland_get_wid_size(type, sizeof(profile->bssid));
	buf[0] = (u8) (wid & 0x00FF);
	buf[1] = (u8) ((wid & 0xFF00) >> 8);
	buf[2] = size;
	memcpy(buf + 3, profile->bssid, size);
	wid_msg_len += (size + 3);
	buf += (size + 3);

	wid = WID_SSID;
	type = wland_get_wid_type(wid);
	size = wland_get_wid_size(type, profile->ssid.SSID_len);
	buf[0] = (u8) (wid & 0x00FF);
	buf[1] = (u8) ((wid & 0xFF00) >> 8);
	buf[2] = size;
	memcpy(buf + 3, profile->ssid.SSID, size);
	wid_msg_len += (size + 3);
	buf += (size + 3);

	if (drvr->bus_if->chip == WLAND_VER_91_H) {
		wid = WID_CURRENT_CHANNEL;
		type = wland_get_wid_type(wid);
		size = wland_get_wid_size(type, 1);
		buf[0] = (u8) (wid & 0x00FF);
		buf[1] = (u8) ((wid & 0xFF00) >> 8);
		buf[2] = size;
		buf[3] = profile->channel;
		wid_msg_len += (size + 3);
		buf += (size + 3);

		wid = WID_JOIN_REQ;
	 	type = wland_get_wid_type(wid);
		size = wland_get_wid_size(type, 1);
		buf[0] = (u8) (wid & 0x00FF);
		buf[1] = (u8) ((wid & 0xFF00) >> 8);
		buf[2] = size;
		buf[3] = 1;//drvr->config->scan_results.count;//no reset version: 1
		wid_msg_len += (size + 3);
		buf += (size + 3);

		wid = WID_SITE_SURVEY;
		type = wland_get_wid_type(wid);
		size = wland_get_wid_size(type, 1);
		buf[0] = (u8) (wid & 0x00FF);
		buf[1] = (u8) ((wid & 0xFF00) >> 8);
		buf[2] = size;
		buf[3] = SITE_SURVEY_OFF;
		buf += (size + 3);
		wid_msg_len += (size + 3);

	}

#if 0 //91h doesn't have this wid
	wid = WID_WEP_KEY_VALUE0;
	type = wland_get_wid_type(wid);

	//write wep key
	if (profile->sec.security == 3 || profile->sec.security == 5) {
		s32 i;
		u8 *key, key_str_len, key_str[WLAN_MAX_KEY_LEN];

		for (i = 0; i < MAX_WSEC_KEY; i++) {
			key = profile->wepkeys[i].data;

			if (profile->wepkeys[i].len == 0)
				continue;

			if (profile->wepkeys[i].len == KEY_LEN_WEP_40) {
				sprintf(key_str, "%02x%02x%02x%02x%02x\n",
					key[0], key[1], key[2], key[3], key[4]);
				key_str_len = 10;
				key_str[key_str_len] = '\0';
			} else if (profile->wepkeys[i].len == KEY_LEN_WEP_104) {
				sprintf(key_str,
					"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
					key[0], key[1], key[2], key[3], key[4],
					key[5], key[6], key[7], key[8], key[9],
					key[10], key[11], key[12]);
				key_str_len = 26;
				key_str[key_str_len] = '\0';
			} else {
				continue;
			}
			size = wland_get_wid_size(type, key_str_len);
			buf[0] = (u8) ((wid + i) & 0x00FF);
			buf[1] = (u8) (((wid + i) & 0xFF00) >> 8);
			buf[2] = size;

			memcpy(buf + 3, key_str, size);
			buf += (size + 3);
			wid_msg_len += (size + 3);
		}
	}
#endif
	//WLAND_DUMP(DCMD, prot->buf, wid_msg_len, "Start Join:%Zu\n", wid_msg_len);

	ret = wland_proto_cdc_data(drvr, wid_msg_len);

	mutex_unlock(&drvr->proto_block);

	return ret;
}

s32 wland_p2p_start_join(struct wland_if * ifp,
	struct wland_cfg80211_profile * profile)
{
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;
	s32 ret = 0;
	u8 char_val;
	u8 *buf1;
	int buf1_len = 0, count = 0;
	gfp_t alloc_flag = GFP_KERNEL;

	WLAND_DBG(DCMD, TRACE,
		"imode:0x%x, authtype:%d, ssid:%s, SSID_len:%d\n",
		profile->sec.security, profile->sec.firmware_autype,
		profile->ssid.SSID, profile->ssid.SSID_len);
	WLAND_DBG(DCMD, INFO, "Connecting to %pM\n", profile->bssid);

	mutex_lock(&drvr->proto_block);

	memset(prot->buf, '\0', sizeof(prot->buf));

	char_val = profile->wmm_enable;
	ret = wland_push_wid(buf, WID_QOS_ENABLE, &char_val, sizeof(char_val), false);
	if (ret < 0) {
		mutex_unlock(&drvr->proto_block);
		WLAND_ERR("put wid error\n");
		return -1;
	}
	buf += ret;

	if (in_interrupt())
		alloc_flag = GFP_ATOMIC;
	buf1 = kmalloc(100, alloc_flag);
	if (!buf1) {
		mutex_unlock(&drvr->proto_block);
		WLAND_ERR("alloc buf fail\n");
		return -1;
	}
/*
	u8 wpa_versions;
	u8 cipher_group;
	u8 n_ciphers_pairwise;
	u8 ciphers_pairwise[n_ciphers_pairwise];
	u8 n_akm_suites;
	u8 akm_suites[n_akm_suites];
*/
	buf1[buf1_len++] = (u8)(profile->sec.wpa_versions);
	buf1[buf1_len++] = (u8)(profile->sec.cipher_group);
	buf1[buf1_len++] = (u8)(profile->sec.n_ciphers_pairwise);
	for (count = 0; count < profile->sec.n_ciphers_pairwise; ++count)
		buf1[buf1_len++] = (u8)(profile->sec.ciphers_pairwise[count] & 0xff);
	buf1[buf1_len++] = (u8)(profile->sec.n_akm_suites);
	for (count = 0; count < profile->sec.n_akm_suites; ++count)
		buf1[buf1_len++] = (u8)(profile->sec.akm_suites[count] & 0xff);

	ret = wland_push_wid(buf, WID_P2P_RSN_INFO, buf1, buf1_len, false);
	if (ret < 0) {
		mutex_unlock(&drvr->proto_block);
		WLAND_ERR("put wid error\n");
		return -1;
	}
	buf += ret;


	char_val = profile->sec.security;
	ret = wland_push_wid(buf, WID_P2P_11I_MODE_PAIRWISE, &char_val, sizeof(char_val), false);
	if (ret < 0) {
		mutex_unlock(&drvr->proto_block);
		WLAND_ERR("put wid error\n");
		return -1;
	}
	buf += ret;

	char_val = profile->sec.security_group;
	ret = wland_push_wid(buf, WID_P2P_11I_MODE_GROUPWISE, &char_val, sizeof(char_val), false);
	if (ret < 0) {
		mutex_unlock(&drvr->proto_block);
		WLAND_ERR("put wid error\n");
		return -1;
	}
	buf += ret;

	char_val = profile->sec.firmware_autype;
	ret = wland_push_wid(buf, WID_P2P_AUTH_TYPE, &char_val, sizeof(char_val), false);
	if (ret < 0) {
		mutex_unlock(&drvr->proto_block);
		WLAND_ERR("put wid error\n");
		return -1;
	}
	buf += ret;

#ifdef WLAND_CONNECT_WITH_1M
	char_val = 1;
	ret = wland_push_wid(buf, WID_CURRENT_TX_RATE, &char_val, sizeof(char_val), false);
	if (ret < 0) {
		mutex_unlock(&drvr->proto_block);
		WLAND_ERR("put wid error\n");
		return -1;
	}
	buf += ret;

	char_val = 255;
	ret = wland_push_wid(buf, WID_11N_CURRENT_TX_MCS, &char_val, sizeof(char_val), false);
	if (ret < 0) {
		mutex_unlock(&drvr->proto_block);
		WLAND_ERR("put wid error\n");
		return -1;
	}
	buf += ret;
#endif /*WLAND_CONNECT_WITH_1M*/

	ret = wland_push_wid(buf, WID_P2P_WID_BSSID, profile->bssid, ETH_ALEN, false);
	if (ret < 0) {
		mutex_unlock(&drvr->proto_block);
		WLAND_ERR("put wid error\n");
		return -1;
	}
	buf += ret;

	ret = wland_push_wid(buf, WID_P2P_WID_SSID, profile->ssid.SSID, profile->ssid.SSID_len, false);
	if (ret < 0) {
		mutex_unlock(&drvr->proto_block);
		WLAND_ERR("put wid error\n");
		return -1;
	}
	buf += ret;

	char_val = profile->channel;
	ret = wland_push_wid(buf, WID_P2P_ONE_CHAN, &char_val, sizeof(char_val), false);
	if (ret < 0) {
		mutex_unlock(&drvr->proto_block);
		WLAND_ERR("put wid error\n");
		return -1;
	}
	buf += ret;

	char_val = 0;
	ret = wland_push_wid(buf, WID_P2P_JOIN_REQ, &char_val, sizeof(char_val), false);
	if (ret < 0) {
		mutex_unlock(&drvr->proto_block);
		WLAND_ERR("put wid error\n");
		return -1;
	}
	buf += ret;

#if 0 //p2p connect doesn't need wep, , possibly
	wid = WID_WEP_KEY_VALUE0;
	type = wland_get_wid_type(wid);

	//write wep key
	if (profile->sec.security == 3 || profile->sec.security == 5) {
		s32 i;
		u8 *key, key_str_len, key_str[WLAN_MAX_KEY_LEN];

		for (i = 0; i < MAX_WSEC_KEY; i++) {
			key = profile->wepkeys[i].data;

			if (profile->wepkeys[i].len == 0)
				continue;

			if (profile->wepkeys[i].len == KEY_LEN_WEP_40) {
				sprintf(key_str, "%02x%02x%02x%02x%02x\n",
					key[0], key[1], key[2], key[3], key[4]);
				key_str_len = 10;
				key_str[key_str_len] = '\0';
			} else if (profile->wepkeys[i].len == KEY_LEN_WEP_104) {
				sprintf(key_str,
					"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
					key[0], key[1], key[2], key[3], key[4],
					key[5], key[6], key[7], key[8], key[9],
					key[10], key[11], key[12]);
				key_str_len = 26;
				key_str[key_str_len] = '\0';
			} else {
				continue;
			}
			size = wland_get_wid_size(type, key_str_len);
			buf[0] = (u8) ((wid + i) & 0x00FF);
			buf[1] = (u8) (((wid + i) & 0xFF00) >> 8);
			buf[2] = size;

			memcpy(buf + 3, key_str, size);

			buf += (size + 3);
			wid_msg_len += (size + 3);
		}
	}
#endif

	//WLAND_DUMP(DCMD, prot->buf, wid_msg_len, "Start Join:%Zu\n", wid_msg_len);

	ret = wland_proto_cdc_data(drvr, buf-(prot->buf) + FMW_HEADER_LEN);

	mutex_unlock(&drvr->proto_block);

	return ret;
}

s32 wland_disconnect_bss(struct wland_if *ifp,
	struct wland_scb_val_le *scbval)
{
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;
	s32 ret = 0;
	u16 wid_msg_len = FMW_HEADER_LEN;
	enum wland_firmw_wid wid;

	WLAND_DBG(DCMD, TRACE, "Enter(%pM)\n", scbval->ea);
	mutex_lock(&drvr->proto_block);
	memset(prot->buf, '\0', sizeof(prot->buf));

	wid = WID_DISCONNECT_REASON;
	buf[0] = (u8) (wid & 0x00FF);
	buf[1] = (u8) ((wid & 0xFF00) >> 8);
	buf[2] = 4;
	buf[3] = (u8) scbval->val & 0x00FF;
	buf[4] = (u8) ((scbval->val & 0xFF00) >> 8);
	wid_msg_len += 7;
	buf += 7;

	wid = WID_DISCONNECT;
	buf[0] = (u8) (wid & 0x00FF);
	buf[1] = (u8) ((wid & 0xFF00) >> 8);
	buf[2] = 1;
	buf[3] = 0;
	wid_msg_len += 4;
	buf += 4;

	ret = wland_proto_cdc_data(drvr, wid_msg_len);
	mutex_unlock(&drvr->proto_block);
	WLAND_DBG(DCMD, TRACE, "Done(disconnect reason:%d).\n", scbval->val);

	return ret;
}

#ifdef WLAND_P2P_SUPPORT
s32 wland_p2p_disconnect_bss(struct wland_if * ifp,
	struct wland_scb_val_le * scbval)
{
	s32 ret = 0;
	u16 index = 0;
	u8 *buf = kzalloc(100, GFP_KERNEL);
	WLAND_DBG(DCMD, INFO, "Enter( %pM )\n", scbval->ea);

	if (buf == NULL) {
		WLAND_ERR("No Memory.\n");
		return -ENOMEM;
	}

	/* MAC address of Station for Disconnection */
	memcpy(&buf[index], scbval->ea, ETH_ALEN);
	index += ETH_ALEN;

	/* Disconnect Reason Code */
	buf[index++] = (u8)(scbval->val & 0x00ff);
	buf[index++] = (u8)((scbval->val & 0xff00) >> 8);

	/* aid */
	buf[index++] = 0;

	WLAND_DBG(DCMD, INFO, "index=%d\n", index);

	ret = wland_fil_set_cmd_data(ifp, WID_P2P_DISCONNECT_REQ, buf, index);
	if (ret < 0) {
		WLAND_ERR("Set WID_P2P_DISCONNECT_REQ failed \n");
	}

	kfree(buf);

	WLAND_DBG(DCMD, TRACE, "Done(disconnect reason:%d).\n", scbval->val);

	return ret;
}

s32 wland_p2p_go_del_sta(struct wland_if * ifp, struct wland_scb_val_le * scbval)
{

	s32 ret = 0;
	u16 index = 0;
	u8 *buf = kzalloc(100, GFP_KERNEL);

	WLAND_DBG(DCMD, INFO, "Enter wland_disconnect_bss_p2p\n");

	if (buf == NULL) {
		WLAND_ERR("No Memory.\n");
		return -ENOMEM;
	}

	/* MAC address of Station for Disconnection */
	memcpy(&buf[index], scbval->ea, ETH_ALEN);
	index += ETH_ALEN;

	/* Disconnect Reason Code */
	buf[index++] = (u8)(scbval->val & 0x00ff);
	buf[index++] = (u8)((scbval->val & 0xff00) >> 8);

	/* aid */
	buf[index++] = scbval->aid;

	WLAND_DBG(DCMD, INFO, "index=%d\n", index);

	ret = wland_fil_set_cmd_data(ifp, WID_P2P_DISCONNECT_REQ, buf, index);
	if (ret < 0) {
		WLAND_ERR("Set WID_P2P_DISCONNECT_REQ failed \n");
	}

	kfree(buf);

	WLAND_DBG(DCMD, TRACE, "Done(disconnect reason:%d).\n", scbval->val);

	return ret;

}
#endif

s32 wland_ap_del_sta(struct wland_if * ifp, u8 aid)
{
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;
	s32 ret = 0;
	u16 wid_msg_len = FMW_HEADER_LEN;
	enum wland_firmw_wid wid;
	enum wid_type type;
	u8 size;
	u8 char_val;

	WLAND_DBG(DCMD, TRACE, "del sta, aid=%d\n", aid);

	if (aid == 0) {
		WLAND_ERR("del sta, aid=0, invalid aid!\n");
		return -1;
	}

	if (drvr->bus_if->chip == WLAND_VER_91_H) {
		mutex_lock(&drvr->proto_block);

		memset(prot->buf, '\0', sizeof(prot->buf));

		/* wid body */
		wid = WID_DISCONNECT;
		type = wland_get_wid_type(wid);
		size = wland_get_wid_size(type, 1);
		char_val = aid;
		buf[0] = (u8) (wid & 0x00FF);
		buf[1] = (u8) ((wid & 0xFF00) >> 8);
		buf[2] = size;
		buf[3] = char_val;
		/* offset */
		buf += (size + 3);
		wid_msg_len += (size + 3);

		ret = wland_proto_cdc_data(drvr, wid_msg_len);

		mutex_unlock(&drvr->proto_block);
	}

	WLAND_DBG(DCMD, TRACE, "Done\n");

	return ret;
}


s32 wland_add_wep_key_bss_sta(struct wland_if *ifp, u8 *key, u8 wep_len,
	u8 key_id)
{
	s32 err = 0;
	u8 *buf = kzalloc(wep_len + 2, GFP_KERNEL);
	if (buf == NULL) {
		WLAND_ERR("No Memory.\n");
		return -ENOMEM;
	}

	buf[0] = key_id;
	buf[1] = wep_len;
	memcpy(buf + 2, key, wep_len);
	err = wland_fil_set_cmd_data(ifp, WID_ADD_WEP_KEY, buf, (wep_len + 2));
	kfree(buf);

	WLAND_DBG(DCMD, TRACE, "Done(err:%d)\n", err);

	return err;
}

s32 wland_fil_set_mgmt_ie(struct wland_if *ifp, const u8 *vndr_ie_buf,
	u16 vndr_ie_len)
{
	s32 ret = 0;
	//struct wland_private *drvr = ifp->drvr;

	vndr_ie_len = vndr_ie_buf[1] + 2;
	WLAND_DBG(DCMD, TRACE,"Enter vndr_ie_len=%d, vndr_ie_buf=%p\n", vndr_ie_len, vndr_ie_buf);
	WLAND_DUMP(TX_CTRL, vndr_ie_buf, vndr_ie_len, "mgmt_le_len:%u\n", vndr_ie_len);

	/*
	 * wapi ies
	 */
	if (vndr_ie_buf[0] == 0x44)
		ret = wland_fil_set_cmd_data(ifp, WID_WAPI_ASSOC_IE,
			vndr_ie_buf, vndr_ie_len);

	WLAND_DBG(DCMD, TRACE, "Enter(vndr_ie_buf:0x%x,ret:%d)\n",
		vndr_ie_buf[0], ret);

	return ret;
}

int wland_get_reg_for_channels(struct wland_if *ifp, u16 reg, u16 *value)
{
	int ret = 0;
	u16 comp[WLAND_CHANNEL_NUM] = {0};
	u16 reg_value_16[WLAND_CHANNEL_NUM] = {0};


	WLAND_DBG(DCMD, DEBUG, "Enter");

	ret = wland_fil_set_cmd_data(ifp, WID_RF_SET_CHANNEL_ACTIVE_REG, &reg, 2);
	if(ret < 0) {
		WLAND_ERR("fil set cmd data failed!\n");
		return ret;
	}

	ret = wland_fil_get_cmd_data(ifp, WID_RF_SET_CHANNEL_ACTIVE_VAL,
		reg_value_16, sizeof(reg_value_16));
	if(ret < 0) {
		WLAND_ERR("fil get cmd data failed!\n");
		return ret;
	}

	if(memcmp(comp, reg_value_16, WLAND_CHANNEL_NUM*2) == 0) {
		WLAND_ERR("read reg:%x value all zero.\n", reg);
		return -1;
	}

	memcpy(value, reg_value_16, WLAND_CHANNEL_NUM*2);

	return 0;
}

//set reg value for 14 channels
int wland_set_reg_for_channels(struct wland_if *ifp, u16 reg, u16 *value)
{
	int ret = 0;
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;

	WLAND_DBG(DCMD, DEBUG, "Enter");

	mutex_lock(&drvr->proto_block);
	memset(prot->buf, '\0', sizeof(prot->buf));

	ret = wland_push_wid(buf, WID_RF_SET_CHANNEL_ACTIVE_REG, &reg, 2, false);
	if (ret < 0) {
		WLAND_ERR("put wid error\n");
		goto done;
	}
	buf += ret;

	ret = wland_push_wid(buf, WID_RF_SET_CHANNEL_ACTIVE_VAL, (u8 *)value,
		WLAND_CHANNEL_NUM*2, false);
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

int wland_set_reg_8AH(struct wland_if *ifp)
{
	u16 reg = 0x008A;
	u16 value[WLAND_CHANNEL_NUM] = {
			0x69a0,
			0x69a0,
			0x69a0,
			0x69a0,
			0x69a0,
			0x6920,
			0x6920,
			0x6920,
			0x68a0,
			0x6820,
			0x6820,
			0x6820,
			0x6820,
			0x6820};

	WLAND_DBG(DCMD, DEBUG, "Enter");

	return wland_set_reg_for_channels(ifp, reg, value);
}

#ifdef WLAND_CRYSTAL_CALIBRATION
int wland_set_crystal_cal_val(struct wland_if *ifp) {
	u8 cal_val = 0;
	int ret = 0;

	ret = wland_read_efuse_xtal_cal_val(ifp->ndev, NULL, 0, &cal_val);
	if ((ret < 0) || (cal_val == 0)) {
		WLAND_DBG(DCMD, WARNING, "read crystal_cal value from efuse failed\n");
		return -1;
	}
	ret = wland_set_hardware_param(ifp->ndev, NULL, 0, 0, cal_val);
	if (ret < 0) {
		WLAND_ERR("read crystal_cal value from efuse failed\n");
		return -1;
	}
	return ret;
}
#endif

#ifdef WLAND_POWER_EFUSE
s32 wland_set_power_efuse(struct wland_if *ifp) {
	u8 power_efuse[WLAND_TXP_NUM] = {0};
	//ssu8 power_set[42] = {0};
	u8 b_v = 0, g_v = 0, n_v = 0;
	int ret = 0;

	WLAND_DBG(DCMD, INFO, "Enter\n");

	ret = wland_read_txpower_from_efuse(ifp->ndev, NULL, 0, power_efuse);
	if ((ret < 0) || (power_efuse[0] < WLAND_TXP_11F_BASE)
		|| (power_efuse[0] > WLAND_TXP_11F_END)
		|| (power_efuse[1] < WLAND_TXP_120_BASE)
		|| (power_efuse[1] > WLAND_TXP_120_END)) {
		WLAND_DBG(RFTEST, WARNING, "read tx power value from efuse failed\n");
		return -1;
	}

	n_v = power_efuse[0];
	g_v = n_v + ifp->drvr->power_g_n_offset;
	b_v = power_efuse[1];
	ifp->drvr->power_11f = power_efuse[0];
	ifp->drvr->power_120 = power_efuse[1];

	//WLAND_ERR("get tx power form efuse: b-%02x g-%02x n-%02x\n", b_v, g_v, n_v);

	ret = wland_set_hardware_param(ifp->ndev, NULL, 0, 1, n_v);
	if (ret < 0) {
		WLAND_ERR("set 11f failed\n");
		return ret;
	}

	ret = wland_set_hardware_param(ifp->ndev, NULL, 0, 2, b_v);
	if (ret < 0) {
		WLAND_ERR("set 120 failed\n");
		return ret;
	}

	WLAND_DBG(DCMD, TRACE, "Done.\n");

	return ret;
}
#endif

#ifdef WLAND_POWER_CONFIG
/*
 *----------------------------------------------------------------------------
 *| 11b-ch1 | 11n-ch1 | ... | 11b-ch14 | 11n-ch14 | 11g-ch1 | ... | 11g-ch14 |
 *----------------------------------------------------------------------------
 *|1        | 1       | ... | 1        | 1        | 1       | ... | 1        |
 *----------------------------------------------------------------------------
 */

//#define WLAND_POWER_CONFIG_FILE_SIZE	560//367
#if 0
static void wland_calculate_txpower_efuse_config(u8 *power_efuse, u8 *power_config)
{
	return;
}
#endif

#ifdef WLAND_SET_POWER_BY_RATE
static bool wland_check_power_by_rate(u8 i, u8 gain,
	struct wland_if *ifp, u8 *return_val)
{
	struct wland_private *drvr = ifp->drvr;

	if(gain > WLAND_BGN_MAX_POWER_GAIN) {
		WLAND_ERR("invaild gain: i:%d gain:%x\n", i, gain);
		return false;
	}

	if (i>=0 && i< B_RATE_NUM)
	{
		*return_val = drvr->power_120 + gain;
	}
	else if (i>=B_RATE_NUM && i < (B_RATE_NUM+G_RATE_NUM))
	{
		*return_val = drvr->power_11f + drvr->power_g_n_offset + gain;
	}
	else if (i>=(B_RATE_NUM+G_RATE_NUM) && i < (ALL_RATE_NUM))
	{
		*return_val = drvr->power_11f + gain;
	} else {
		WLAND_ERR("invalid i:%d\n", i);
		return false;
	}

	if(*return_val > WLAND_MAX_POWER_REG_VAL)
		*return_val = WLAND_MAX_POWER_REG_VAL;

	return true;
}
int wland_set_power_by_rate(struct wland_if *ifp)
{
	struct wland_private *drvr = ifp->drvr;
	u8 *rates_gain = drvr->power_rates_gain;
	u8 *rates_value = drvr->power_rates_value;
	int ret = 0;
	int i = 0;
	u8 cal_val = 0;

	if(drvr->power_by_rate == 0) {
		WLAND_DBG(DEFAULT, WARNING, "do not set_power_by_rate 1\n");
		return -1;
	}

	for(i=0; i<ALL_RATE_NUM; i++) {
		if(!wland_check_power_by_rate(i, rates_gain[i], ifp, &cal_val)) {
			WLAND_ERR("do not set_power_by_rate 2\n"
				"i:%d gain:%x g_n_offset:%x val_11f:%x val_120:%x\n",
				i, rates_gain[i], drvr->power_g_n_offset,
				drvr->power_11f, drvr->power_120);
			return -1;
		} else {
			rates_value[i] = cal_val;
		}
	}

	if(!wland_check_test_mode()) {
		ret = wland_fil_set_cmd_data(ifp, WID_SET_POWER_BY_RATE,
			rates_value, ALL_RATE_NUM);
		if (ret < 0) {
			WLAND_ERR("failed to set power by rate\n");
			return -1;
		}
	}
	drvr->power_by_rate = 2;

	WLAND_DBG(DEFAULT, INFO, "power_by_rate:%d\n",drvr->power_by_rate);
	return 0;
}
#endif

#ifdef WLAND_DOWNLOAD_FIRMWARE_FROM_HEX
#define power_config_hexcode "power_config.txt.hex"
static unsigned char power_config_hex_buf[] = {
#include power_config_hexcode
};
#define POWER_CONFIG_HEX_SIZE sizeof(power_config_hex_buf)
#endif
s32 wland_set_power_config(struct wland_if *ifp)
{
#ifdef WLAND_FIRMWARE_PATH
	struct kstat config_stat;
	mm_segment_t fs;
	char filename[256];
#elif defined WLAND_DOWNLOAD_FIRMWARE_FROM_HEX
	/*no need value*/
#else /*WLAND_FIRMWARE_PATH*/
	const struct firmware *config_firmware;
	struct wland_private *drvr = ifp->drvr;
#endif /*WLAND_FIRMWARE_PATH*/

	s32 ret = 0;
	u8 *buf = NULL;
	char *buf_end;
	int i = 0;
	//u8 power_config[42] = {0};
	char comp[5];
	char *cc = NULL;
	u8 val = 0;
	u16 val_1 = 0;
	u16 value_8a[WLAND_CHANNEL_NUM] = {0};
	u8 val_11f = 0;
	u8 val_120 = 0;
	char *str_11f = "11f(n_mode):";
	char *str_120 = "120(b_mode):";
	char *g_n_offset = "g_n_offset:";
	char *str_1da = "1da:";
	char *rfregw = "rfregw";
	char *phyregw = "phyregw";
	char *mw = "mw";
	char *reg_set = "reg:";
	int config_size = 0;
	u32 reg_32 = 0;
	u32 reg_val_32 = 0;
	char *pos = NULL;
	u8 num = -1;
#ifdef WLAND_SET_POWER_BY_RATE
	char *power_strings[ALL_RATE_NUM] = {
		"1Mbps", "2Mbps", "5Mbps", "11Mbps",//11b
		"6Mbps", "9Mbps", "12Mbps", "18Mbps",//11g
		"24Mbps", "36Mbps", "48Mbps", "54Mbps",
		"mcs0", "mcs1", "mcs2", "mcs3",//11n
		"mcs4", "mcs5", "mcs6", "mcs7"
	};
#endif
#ifdef WLAND_FIRMWARE_PATH
	fs = get_fs();
	set_fs(KERNEL_DS);
	snprintf(filename, 256, "%s/%s", WLAND_FIRMWARE_PATH, WIFI_POWER_SAVR_FILE_NAME);
	ret = vfs_stat(filename, &config_stat);
	if (ret) {
		WLAND_ERR("can not get config file status :%d\n",ret);
		return ret;
	} else {
		config_size = (int)config_stat.size;
	}
	buf = kzalloc(config_size+1, GFP_KERNEL);
	if(!buf) {
		WLAND_ERR("no more space!\n");
		return -1;
	}
	buf_end = buf + config_size;

	ret = wland_nvram_read(filename, buf, config_size, 0);
	if (ret < 0) {
		WLAND_DBG(DEFAULT, WARNING, "read power save config file failed!\n");
		goto out;
	}
	buf[config_size+1] = '\0';

#elif defined WLAND_DOWNLOAD_FIRMWARE_FROM_HEX
	config_size = POWER_CONFIG_HEX_SIZE;
	if (config_size == 0) {
		WLAND_ERR("config_size == 0!!!\n");
		return -1;
	}
	buf = kzalloc(config_size+1, GFP_KERNEL);
	if(!buf) {
		WLAND_ERR("no more space!\n");
		return -1;
	}
	memcpy(buf, power_config_hex_buf, config_size);
	buf[config_size] = '\0';
	buf_end = buf + config_size;

#else /*WLAND_FIRMWARE_PATH*/
	ret = request_firmware(&config_firmware, WIFI_POWER_SAVR_FILE_NAME, drvr->bus_if->dev);
	if (ret) {
		WLAND_DBG(DEFAULT, WARNING, "Request power config: %s failed, ret = %d\n",
			WIFI_POWER_SAVR_FILE_NAME, ret);
		return ret;
	} else {
		config_size = config_firmware->size;
		buf = kmalloc(config_size+1, GFP_KERNEL);
		if(!buf) {
			WLAND_ERR("no more space!\n");
			return -1;
		}
		memcpy(buf, config_firmware->data, config_size);
		buf[config_size+1] = '\0';
		buf_end = buf + config_size;
		release_firmware(config_firmware);
	}

#endif /*WLAND_FIRMWARE_PATH*/

#if 0
	printk("%s", buf);
#endif
	cc = strstr(buf, "%%");
	if (cc == NULL) {
		WLAND_ERR("/////bad power config file!\n");
		ret = -1;
		goto out;
	}

//11f
	cc = strstr(buf, str_11f);
	if (cc==NULL || cc>=buf_end) {
		WLAND_DBG(DEFAULT, WARNING,
			"can not find 11f reg in power config file!\n");
		ret = -1;
	} else {
		val_11f = simple_strtol(cc+strlen(str_11f), &cc, 16);
		if ((val_11f < WLAND_TXP_11F_BASE) || (val_11f > WLAND_TXP_11F_END)) {
			WLAND_ERR("val_11f invalid!\n");
		} else {
			ifp->drvr->power_11f = val_11f;
			ret = wland_set_hardware_param(ifp->ndev, NULL, 0, 1, val_11f);
			if (ret < 0) {
				WLAND_ERR("set 11f failed\n");
			}
		}
	}

//120
	cc = strstr(buf, str_120);
	if (cc==NULL || cc>=buf_end) {
		WLAND_DBG(DEFAULT, WARNING,
			"can not find 120 reg in power config file!\n");
		ret = -1;
	} else {
		val_120 = simple_strtol(cc+strlen(str_120), &cc, 16);
		if ((val_120 <= WLAND_TXP_120_BASE) || (val_120 >= WLAND_TXP_120_END)) {
			WLAND_ERR("val_120 invalid!\n");
		} else {
			ifp->drvr->power_120 = val_120;
			ret = wland_set_hardware_param(ifp->ndev, NULL, 0, 2, val_120);
			if (ret < 0) {
				WLAND_ERR("set 120 failed\n");
			}
		}
	}

//power g-n offset
	cc = strstr(buf, g_n_offset);
	if (cc==NULL || cc>=buf_end) {
		WLAND_DBG(DEFAULT, WARNING,
			"can not find g-n offset in power config file!\n");
	} else {
		val = simple_strtol(cc+strlen(g_n_offset), &cc, 16);
		if ((val < 0) || (val > WLAND_G_N_MAX_OFFSET)) {
			WLAND_ERR("offset invalid\n");
		} else
			ifp->drvr->power_g_n_offset = val;
	}


//8a (6820~6FA0: 6820 68A0 6920 69A0 ... 6F20 6FA0)
	for (i=1; i<=14; i++) {
		ret = snprintf(comp, 5, "8a%d", i);
		if (ret <= 0) {
			WLAND_ERR("snprintf failed\n");
			ret = -1;
			goto set_1da;
		}
		cc = strstr(buf, comp);
		if (cc==NULL || cc>=buf_end) {
			WLAND_DBG(DEFAULT, WARNING,"can not find 8a reg!\n");
			ret = -1;
			goto set_1da;
		} else {
			if (i <= 9)
				val_1 = simple_strtol(cc+4, &cc, 16);
			else
				val_1 = simple_strtol(cc+5, &cc, 16);
			if ((val_1 < 0x6820)
				|| (val_1 > 0x6FA0)
				|| (((val_1 & 0x00FF) != 0x0020)
				&& ((val_1 & 0x00FF) != 0x00a0))) {
				WLAND_ERR("bad power config file!\n");
				ret = -1;
				goto set_1da;
			} else
				value_8a[i-1] = val_1;
		}

		comp[0] = '\0';
		val_1 = 0;
		cc = NULL;
	}

#if 0
	WLAND_ERR("power config-8a:\n");
	dump_buf((u8*)value_8a, sizeof(value_8a));
#endif

	ret = wland_set_reg_for_channels(ifp, 0x8A, value_8a);
	if (ret<0) {
		WLAND_ERR("Set 8A failed \n");
	}

//1da
set_1da:
	cc = strstr(buf, str_1da);
	if (cc==NULL || cc>=buf_end) {
		WLAND_DBG(DEFAULT, WARNING,
			"can not find 1da value in power config file!\n");
	} else {
		val = simple_strtol(cc+strlen(str_1da), &cc, 16);
		if (val >= 0xFF) {
			WLAND_ERR("1da value invalid:0x%x\n",val);
		} else {
			//printk("%x\n",val);
			ret = wland_set_hardware_param(ifp->ndev, NULL, 0, 0, val);
			if (ret<0) {
				WLAND_ERR("Set 1da failed \n");
			}
		}
	}

//rfregw phyregw mw
	pos = buf;
	while(pos <= buf_end) {
		cc = strstr(pos, reg_set);
		if (cc==NULL) {
			break;
		} else {
			pos = cc + strlen(reg_set);
			if (strncasecmp(pos, rfregw, strlen(rfregw)) == 0) {
				pos += strlen(rfregw);
				num = 0;
			} else if (strncasecmp(pos, phyregw, strlen(phyregw)) == 0) {
				pos += strlen(phyregw);
				num = 1;
			} else if (strncasecmp(pos, mw, strlen(mw)) == 0) {
				pos += strlen(mw);
				num = 2;
			} else {
				WLAND_ERR("invalid reg param, bad powerconfig\n");
				goto out;
			}
			pos ++;

			reg_32 = simple_strtol(pos, &pos, 16);
			if (reg_32 == 0) {
				WLAND_ERR("reg is 0, bad power config file!\n");
				goto out;
			}
			reg_val_32 = simple_strtol(pos+1, &pos, 16);

			switch (num) {
				case 0:
					WLAND_DBG(DEFAULT, INFO, "rfregw %02x %02x\n", reg_32, reg_val_32);
					ret = wland_rf_phy_reg_write(ifp->ndev, NULL, 0, 0, reg_32, reg_val_32);
					if (ret<0) {
						WLAND_ERR("rfregw failed!\n");
					}
					break;
				case 1:
					WLAND_DBG(DEFAULT, INFO, "phyregw %02x %02x\n", reg_32, reg_val_32);
					ret = wland_rf_phy_reg_write(ifp->ndev, NULL, 0, 1, reg_32, reg_val_32);
					if (ret<0) {
						WLAND_ERR("Set phy reg failed \n");
					}
					break;
				case 2:
					WLAND_DBG(DEFAULT, INFO, "mw %02x %02x\n", reg_32, reg_val_32);
					ret = wland_mw(ifp->ndev, NULL, 0, reg_32, reg_val_32);
					if (ret<0) {
						WLAND_ERR("mw failed!\n");
					}
					break;
				default:
					WLAND_ERR("bad param!\n");
			}
		}
	}

#ifdef WLAND_SET_POWER_BY_RATE
//get power by rate
	for(i=0; i<ALL_RATE_NUM; i++) {
		cc = strstr(buf, power_strings[i]);
		if (cc==NULL || cc>=buf_end) {
			WLAND_DBG(DEFAULT, WARNING, "can not find %s in power config\n",
				power_strings[i]);
			goto end_power_by_rate;
		} else {
			val = simple_strtol(cc+strlen(power_strings[i])+1, &cc, 16);
			if ((val < 0) || (val > WLAND_BGN_MAX_POWER_GAIN)) {
				WLAND_ERR("power_rate gain invalid: i:%d val:0x%x\n", i, val);
				goto end_power_by_rate;
			} else
				ifp->drvr->power_rates_gain[i] = val;
		}
	}
	drvr->power_by_rate = 1;
	WLAND_DBG(DEFAULT, INFO, "power_by_rate:%d\n",drvr->power_by_rate);
end_power_by_rate:
#endif

	WLAND_DBG(DCMD, TRACE, "Done.\n");
out:
	kfree(buf);
	return ret>=0 ? 0 : ret;
}
#endif /*WLAND_POWER_CONFIG*/

s32 wland_set_11n_action(struct wland_if * ifp, u8 *mac, u8 tid, u8 add)
{
	s32 ret = 0;
	//struct wland_private *drvr = ifp->drvr;
	struct wland_11n_action action;

	WLAND_DBG(DCMD, INFO, "Enter\n");

	action.category = 0x07;
	action.action = 0x02;
	memcpy(action.bssid, mac, ETH_ALEN);
	action.tid = tid;
	action.max_msdu = 0x10;
	action.ack_policy = 0x00;
	action.ba_policy = 0x01;
	action.buff_size = cpu_to_le16(0x10);
	action.ba_timeout = cpu_to_le16(0x00);
	action.add_ba_timeout = cpu_to_le16(1500);

	if (ifp->bssidx == P2PAPI_BSSCFG_PRIMARY)
		ret = wland_fil_set_cmd_data(ifp, WID_11N_P_ACTION_REQ, &action,
			sizeof(action));
	else
		ret = wland_fil_set_cmd_data(ifp, WID_P2P_P_ACTION_TX, &action,
			sizeof(action));

	if (ret) {
		WLAND_ERR("Set 11n action failed (%pM)\n", mac);
	}

	WLAND_DBG(DCMD, TRACE, "Done.\n");

	return ret;
}

s32 wland_set_txrate(struct wland_if *ifp, u8 mbps)
{
	s32 ret = 0;

	WLAND_DBG(DCMD, TRACE, "Enter\n");
	if (wland_fil_set_cmd_data(ifp, WID_CURRENT_TX_RATE, &mbps,
			sizeof(mbps))) {
		WLAND_ERR("Set WID_CURRENT_TX_RATE value=%d failed \n", mbps);
		goto out;
	}
	WLAND_DBG(DCMD, TRACE, "Done.\n");

out:

	return ret;
}

int wland_dev_get_rssi(struct net_device *ndev, s16 *pRssi)
{
	struct wland_if *ifp = netdev_priv(ndev);
	u8 rssi = 0;
	int error = 0;
	static int count = 0;
	static u8 pre_val = 0;
	int mod = 2;

	if (!pRssi)
		return -EINVAL;
	if ((pre_val == 0) || !((count++) % mod)) {
		WLAND_DBG(DCMD, TRACE, "Get RSSI!\n");
		error = wland_fil_get_cmd_data(ifp, WID_RSSI, &rssi,
			sizeof(rssi));

		if (error < 0) {
			WLAND_ERR("Get RSSI failed!\n");
			return error;
		}

		pre_val = rssi;
#ifdef WLAND_RSSIOFFSET_SUPPORT
		if (rssi < WLAND_RSSI_MAXVAL_FOR_OFFSET)
			*pRssi = (signed char)(rssi + WLAND_RSSI_OFFSET);
		else
			*pRssi = (signed char)(rssi);
#else
		*pRssi = (signed char)(rssi);
#endif
	} else {
#ifdef WLAND_RSSIOFFSET_SUPPORT
		if (pre_val < WLAND_RSSI_MAXVAL_FOR_OFFSET)
			*pRssi = (signed char)(pre_val + WLAND_RSSI_OFFSET);
		else
			*pRssi = (signed char)(pre_val);
#else
		*pRssi = (signed char)(pre_val);
#endif
	}
	WLAND_DBG(DCMD, TRACE, "*pRssi =%d\n", *pRssi);
	return error;
}

int wland_set_memory_32bit(struct wland_if *ifp, u32 addr, u32 val)
{
	int ret;
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;

	mutex_lock(&drvr->proto_block);
	memset(prot->buf, '\0', sizeof(prot->buf));

	ret = wland_push_wid(buf, WID_MEMORY_ADDRESS, &addr, 4, false);
	if (ret < 0) {
		WLAND_ERR("put wid error\n");
		goto done;
	}
	buf += ret;

	ret = wland_push_wid(buf, WID_MEMORY_ACCESS_32BIT, &val, 4, false);
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
	WLAND_DBG(DCMD, DEBUG, "Done(err:%d)\n", ret);
	return ret;

}

int wland_get_memory_32bit(struct wland_if *ifp, u32 addr, u32 *val)
{
	int ret;

	ret = wland_fil_set_cmd_data(ifp, WID_MEMORY_ADDRESS, &addr, 4);
	if (ret < 0) {
		WLAND_ERR("fil set cmd data failed!\n");
		return ret;
	}

	ret = wland_fil_get_cmd_data(ifp, WID_MEMORY_ACCESS_32BIT, val, 4);
	if (ret < 0) {
		WLAND_ERR("fil set cmd data failed!\n");
		return ret;
	}

	return 0;

}

int wland_proto_attach(struct wland_private *drvr)
{
	struct wland_proto *cdc =
		kzalloc(sizeof(struct wland_proto), GFP_KERNEL);
	if (!cdc) {
		WLAND_ERR("no memory for cdc!\n");
		return -ENOMEM;
	}

	memset(cdc, '\0', sizeof(struct wland_proto));

	/*
	 * ensure that the msg buf directly follows the cdc msg struct
	 */
	if ((ulong) (&cdc->msg + 1) != (ulong) cdc->buf) {
		WLAND_ERR("struct wland_proto is not correctly defined\n");
		if (cdc)
			kfree(cdc);
		return -ENOMEM;
	}

	drvr->prot = cdc;
	drvr->hdrlen += WID_HEADER_LEN;
	drvr->maxctl =
		WLAND_DCMD_MEDLEN + sizeof(struct wland_dcmd) + ROUND_UP_MARGIN;

	WLAND_DBG(DCMD, TRACE, "Done(drvr->hdrlen:%d,drvr->maxctl:%d)\n",
		drvr->hdrlen, drvr->maxctl);

	return 0;
}

void wland_proto_detach(struct wland_private *drvr)
{
	if (drvr) {
		kfree(drvr->prot);
		drvr->prot = NULL;
	}
	WLAND_DBG(DCMD, TRACE, "Done\n");
}

#ifdef WLAND_SMART_CONFIG_SUPPORT
int wland_set_channel(struct wland_if *ifp, u8 channel)
{
	int ret = 0;

	WLAND_DBG(DEFAULT, INFO, "set channel %d\n", channel);

	ret = wland_fil_set_cmd_data(ifp, WID_CURRENT_CHANNEL, &channel, 1);
	if (ret < 0) {
		WLAND_ERR("set channel failed 1!\n");
		return ret;
	}

	ret = wland_fil_set_cmd_data(ifp, WID_RAW_PKT_CHANNEL_RF, &channel, 1);
	if (ret < 0) {
		WLAND_ERR("set channel failed 2!\n");
	}
	return ret;
}

int wland_sniffer_set_filter(struct wland_if *ifp,
	u8 to_ds, u8 from_ds, u32 mgm_filter)
{
	int ret = 0;
	struct wland_private *drvr = ifp->drvr;
	//different form 5981: no ldpc
	/*ACK CTS RTS BEACON ATIM CF_END QCF_POLL NSIFS_RESP_BA SIFS_RESP_BA ND_CONTROL*/
	u32 unsupport_filter = BIT0 | BIT1 | BIT2 | BIT4 | BIT5 | BIT6 | BIT12 | BIT13 | BIT17;
	u16 phy_rx_filter = /*BIT0 | */BIT1 | BIT3; // LDPC | SOUNDING  | BCC;
	u16 val = 0;
	u32 val32 = 0;

	WLAND_DBG(DEFAULT, INFO, "Enter\n");

	if (from_ds == 0 && to_ds == 0) {
		WLAND_ERR("both fromds and tods is 0\n");
		return -1;
	} else if (from_ds && to_ds) {
		if (drvr->bus_if->chip_version <= 2) {
			WLAND_ERR("chip version %d doesn't support both fromds and tods\n",
				drvr->bus_if->chip_version);
			val = phy_rx_filter | BIT8; //to ds
		} else
			val = phy_rx_filter | BIT9; //u04 support both from and to ds
	} else if (to_ds) {
		val = phy_rx_filter | BIT8; //to ds
	} else if (from_ds) {
		val = phy_rx_filter & (~BIT8); //from ds
	}
	ret = wland_fil_set_cmd_data(ifp, WID_MON_PHY_RX_FILTER, &val, sizeof(val));
	if (ret < 0) {
		WLAND_ERR("phy rx filter set failed!\n");
		return -1;
	}

	//mgm_filter : 0xe7fff=11100111111111111111
	//addr:0x40020080
	//bit 15 BC/MC data other bss
	//bit 16 non-direct data
	val32 = mgm_filter | unsupport_filter;
	ret = wland_fil_set_cmd_data(ifp, WID_RX_FRAME_FILTER, &val32, sizeof(val32));
	if (ret < 0) {
		WLAND_ERR("rx frame filter set failed!\n");
		return -1;
	}

	ret = wland_get_memory_32bit(ifp, 0x40020080, &val32);
	if(ret < 0) {
		WLAND_ERR("read 0x40020080 failed!\n");
		return -1;
	} else
		WLAND_DBG(DEFAULT, INFO, "0x40020080:%08x\n", val32);
	//addr:0x400250a4
	//bit 12=1 both from ds and to ds
	//bit 18 =0 from ds =1 to ds
	ret = wland_get_memory_32bit(ifp, 0x400250a4, &val32);
	if(ret < 0) {
		WLAND_ERR("read 0x400250a4 failed!\n");
		return -1;
	} else
		WLAND_DBG(DEFAULT, INFO, "0x400250a4:%08x\n", val32);

	return 0;
}

int wland_sniffer_en_dis_able(struct net_device * ndev, bool enable)
{
	struct wland_if *ifp = netdev_priv(ndev);
	struct wland_cfg80211_info *cfg = ifp->drvr->config;
	struct wiphy *wiphy = cfg_to_wiphy(cfg);
	int ret = 0;
	u32 frame_rx_filter = 0;
	u8 val = 0;

	WLAND_DBG(DEFAULT, INFO, "Enter enable:%d\n", enable);

	if (enable) {
//deauth if connected
		if ((test_bit(VIF_STATUS_CONNECTING, &ifp->vif->sme_state)) ||
			(test_bit(VIF_STATUS_CONNECTED, &ifp->vif->sme_state))) {
			WLAND_DBG(DEFAULT, INFO, "conneted or connecting deauth first\n");
			wland_cfg80211_disconnect(wiphy, ndev, 3);
		}

//usr control rx filter
		val = 1;
		ret = wland_fil_set_cmd_data(ifp, WID_USRCTL_RX_FRAME_FILTER, &val, sizeof(val));
		if (ret < 0) {
			WLAND_ERR("set user control filter failed!\n");
			return -1;
		}
//read rx filter
		ret = wland_fil_get_cmd_data(ifp, WID_RX_FRAME_FILTER, &frame_rx_filter, sizeof(frame_rx_filter));
		if (ret < 0) {
			WLAND_ERR("read filter failed\n");
			return -1;
		} else
			WLAND_DBG(DEFAULT, INFO, "init filter:%x", frame_rx_filter);
//set rx filter only get data pkt
		ret = wland_sniffer_set_filter(ifp, 1, 1, 0xe7fff);//just bit 15 and 16 is 0 /*5981:0x27e77*/
		if (ret < 0) {
			WLAND_ERR("set filter 0x27e77 failed\n");
			return -1;
		}
	} else {
		val = 0;
		ret = wland_fil_set_cmd_data(ifp, WID_USRCTL_RX_FRAME_FILTER, &val, sizeof(val));
		if (ret < 0) {
			WLAND_ERR("set user control filter failed!\n");
			return -1;
		}
	}
	return 0;
}
#endif