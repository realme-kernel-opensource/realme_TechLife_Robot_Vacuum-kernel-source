
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
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/vmalloc.h>

#include "ethernet.h"
#include "linux_osl.h"
#include "wland_defs.h"
#include "wland_utils.h"
#include "wland_fweh.h"
#include "wland_dbg.h"
#include "wland_wid.h"
#include "wland_bus.h"
#include "wland_sdmmc.h"
#include "wland_amsdu.h"
#include "wland_cfg80211.h"
#include "wland_rx.h"
#include "wland_rf.h"
#ifdef WLAND_SMART_CONFIG_SUPPORT
#include <net/ieee80211_radiotap.h>
#endif

#ifdef WLAND_RX_SOFT_MAC
static u8 SNAP_ETH_TYPE_IPX[2] = {0x81, 0x37};
static u8 SNAP_ETH_TYPE_APPLETALK_AARP[2] = {0x80, 0xf3};

static u8 wland_rfc1042_header[] =
	{0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00 };
/* Bridge-Tunnel header (for EtherTypes ETH_P_AARP and ETH_P_IPX) */
static u8 wland_bridge_tunnel_header[] =
	{0xaa, 0xaa, 0x03, 0x00, 0x00, 0xf8 };
#endif /*WLAND_RX_SOFT_MAC*/

void wland_dhd_os_sdlock_rxq(struct wland_rx_info *rx_info, unsigned long *flags)
{
	if (rx_info)
		spin_lock_irqsave(&rx_info->rxqlock, *flags);
}

void wland_dhd_os_sdunlock_rxq(struct wland_rx_info *rx_info, unsigned long *flags)
{
	if (rx_info)
		spin_unlock_irqrestore(&rx_info->rxqlock, *flags);
}

#ifdef WLAND_TX_SOFT_MAC
/* This function checks if the given frame information element is the WMM    */
/* parameter or WMM information element.                                               */
static bool is_wmm_info_param_elem(u8 *ie)
{
    /* -------------------------------------------------------------- */
    /* WMM Information/Parameter Element Format                                             */
    /* ---------------------------------------------------------------*/
    /* | OUI | OUIType | OUISubtype | Version | QoSInfo | OUISubtype based |   */
    /* ---------------------------------------------------------------*/
    /* |3    | 1       | 1          | 1       | 1       | ---------------- |                   */
    /* ---------------------------------------------------------------*/
	if((ie[0] == IWMM) && /* WMM Element ID */
		(ie[2] == 0x00) && (ie[3] == 0x50) && (ie[4] == 0xF2) && /* OUI */
		(ie[5] == 0x02) && /* OUI Type     */
		((ie[6] == 0x00) || (ie[6] == 0x01)) && /* OUI Sub Type */
		(ie[7] == 0x01)) /* Version field */
		return true;
	else
		return false;
}
/* This function checks if WMM is supported by parsing the given frame to    */
/* check the presence of WMM information/parameter element.                  */
static bool is_wmm_supported(u8 *resp_ie, u16 resp_ie_len)
{
	u16 ie_offset = 0;

	/* Check for WMM information/parameter element */
	while(ie_offset < resp_ie_len) {
		if(is_wmm_info_param_elem(resp_ie + ie_offset) == true) {
			return true;
		}

		ie_offset += (2 + resp_ie[ie_offset + 1]);
	}

	return false;
}

static unsigned int wland_analysis_assoc_ies(struct wland_if *ifp)
{
	struct wland_cfg80211_connect_info *conn_info = &ifp->vif->conn_info;
	struct Assoc_ie *assocrsp_ie = &conn_info->assocrsp_ie;
	u16 resp_ie_len = conn_info->resp_ie_len;
	u8 *resp_ie = conn_info->resp_ie;

	assocrsp_ie->WMM_enable = is_wmm_supported(resp_ie, resp_ie_len);

	return 0;
}
#endif


static s32 wland_handle_mac_status(struct wland_private *drvr,
	struct wland_event_msg *event_packet, u8 *buffer)
{
	u8 msg_type = 0, wid_len = 0, mac_status, msg_id = 0;
	u16 msg_len = 0, wid_id = WID_NIL;

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

	if (wid_id != WID_STATUS) {
		WLAND_ERR("Received Message wid incorrect.\n");
		return -EBADE;
	}

	/*
	 * Extract WID Length [expected to be = 1]
	 */
	wid_len = buffer[6];

	/*
	 * get the WID value [expected to be one of two values: either MAC_CONNECTED = (1) or MAC_DISCONNECTED = (0)]
	 */
	mac_status = buffer[7];

	WLAND_DBG(RX, INFO,
		"Received(msg_id:0x%x,msg_len:0x%x,wid_id:0x%x,wid_len:0x%x,mac_status:0x%x)\n",
		msg_id, msg_len, wid_id, wid_len, mac_status);

	event_packet->status = STATUS_SUCCESS;

	if (mac_status == MAC_CONNECTED) {
		event_packet->event_code = WLAND_E_CONNECT_IND;
		WLAND_DBG(RX, INFO, "MAC CONNECTED\n");
	} else if (mac_status == MAC_DISCONNECTED) {
		WLAND_DBG(RX, INFO, "MAC_DISCONNECTED\n");
		event_packet->event_code = WLAND_E_DISCONNECT_IND;
	} else if (mac_status == P2P_MAC_CONNECTED) {
		WLAND_DBG(RX, INFO, "P2P MAC CONNECTED\n");
		event_packet->event_code = WLAND_E_CONNECT_IND;
		event_packet->bsscfgidx = P2PAPI_BSSCFG_DEVICE;
	} else if (mac_status == P2P_MAC_DISCONNECTED) {
		WLAND_DBG(RX, INFO, "P2P MAC DISCONNECTED\n");
		event_packet->event_code = WLAND_E_DISCONNECT_IND;
		event_packet->bsscfgidx = P2PAPI_BSSCFG_DEVICE;
	} else {
		WLAND_ERR("Invalid MAC Status 0x%02x\n", mac_status);
		return -EBADE;
	}

	wland_fweh_push_event(drvr, event_packet, buffer);

	return 0;
}

static s32 wland_handle_network_link_event(struct wland_private *drvr,
	struct wland_event_msg *event_packet, u8 *buffer)
{
	struct wland_addba_msg addba_msg;
	struct wland_cfg80211_info *cfg = drvr->config;
	struct wland_cfg80211_vif_event *event = &cfg->vif_event;
	u8 msg_type = 0, event_type = 0;
	u16 event_len = 0;
	s32 ret = 0;
	int i;
	/*
	 * parse type
	 */
	msg_type = buffer[0];

	/*
	 * Check whether the received message type is 'I'
	 */
	if (WLAND_WID_MSG_EVENT != msg_type) {
		WLAND_ERR("Received Message type incorrect.\n");
		return -EBADE;
	}

	/*
	 * Extract event Type
	 */
	event_type = buffer[1];

	/*
	 * Extract event Length
	 */
	event_len = MAKE_WORD16(buffer[2], buffer[3]);

	WLAND_DBG(RX, DEBUG,
		"Received(msg_type:0x%x, event_type:%d, event_len:%d \n",
		msg_type, event_type, event_len);

	event_packet->action = event_type;
	WLAND_DBG(RX, DEBUG, "event_type=%d\n", event_type);
	switch (event_type) {
	case EVENT_AUTH_IND:
		WLAND_DBG(RX, DEBUG, "EVENT_AUTH_IND\n");
		event_packet->event_code = WLAND_E_CONNECT_IND;
		event_packet->status = STATUS_SUCCESS;
		break;
	case EVENT_DEAUTH_IND:
		WLAND_DBG(RX, DEBUG, "EVENT_DEAUTH_IND\n");
		event_packet->event_code = WLAND_E_DISCONNECT_IND;
		break;
	case EVENT_ASSOC_IND:
		WLAND_DBG(RX, DEBUG, "EVENT_ASSOC_IND\n");
		event_packet->event_code = WLAND_E_CONNECT_IND;
		event_packet->status = STATUS_SUCCESS;
		memcpy(event_packet->addr, &buffer[16], ETH_ALEN);
		break;
	case EVENT_REASSOC_IND:
		WLAND_DBG(RX, DEBUG, "EVENT_REASSOC_IND\n");
		event_packet->event_code = WLAND_E_CONNECT_IND;
		event_packet->status = STATUS_SUCCESS;
		break;
	case EVENT_DISASSOC_IND:
		WLAND_DBG(RX, DEBUG, "EVENT_DISASSOC_IND\n");
		event_packet->event_code = WLAND_E_DISCONNECT_IND;
		break;
	case EVENT_P2P_LISTEN_COMP_IND:
		WLAND_DBG(RX, DEBUG, "EVENT_P2P_LISTEN_COMP_IND\n");
		event_packet->event_code = WLAND_E_P2P_DISC_LISTEN_COMPLETE;
		event_packet->bsscfgidx = P2PAPI_BSSCFG_DEVICE;
		if (event_len != ETH_ALEN)
			WLAND_ERR("event WLAND_E_P2P_DISC_LISTEN_COMPLETE len error:%d\n", event_len);
		for (i = 0; i < WLAND_MAX_IFS; ++i) {
			if (drvr->iflist[i]) {
				if (!memcmp(drvr->iflist[i]->mac_addr, buffer+4, ETH_ALEN)) {
					event_packet->bsscfgidx = drvr->iflist[i]->bssidx;
					break;
				}
			}
		}
		if (i == WLAND_MAX_IFS)
			WLAND_ERR("event WLAND_E_P2P_DISC_LISTEN_COMPLETE mac_add error:%pM", buffer+4);
		break;

	case EVENT_ADD_P2P_IF_EVENT:
		WLAND_DBG(RX, DEBUG, "EVENT_ADD_P2P_IF_EVENT\n");
		event_packet->event_code = WLAND_E_IF_ADD;
		event_packet->action = WLAND_ACTION_IF_ADD;
		event_packet->bsscfgidx = P2PAPI_BSSCFG_CONNECTION;
		event_packet->bsscfgidx = buffer[4];
		memcpy(event_packet->addr, buffer+5, ETH_ALEN);
		break;

	case EVENT_P2P_SCAN_COMP_EVENT:
		WLAND_DBG(RX, DEBUG, "EVENT_P2P_SCAN_COMP_EVENT\n");
		event_packet->event_code = WLAND_E_ESCAN_RESULT;
		event_packet->status = STATUS_TIMEOUT;
		memcpy(event_packet->addr, buffer+4, ETH_ALEN);
		break;
	case EVENT_P2P_IF_CHANGE_COMP_EVENT:
		WLAND_DBG(RX, DEBUG, "EVENT_P2P_IF_CHANGE_COMP_EVENT\n");
		event_packet->event_code = WLAND_E_IF_CHANGE;
		event_packet->action = WLAND_ACTION_IF_CHANGE;
		event_packet->bsscfgidx = P2PAPI_BSSCFG_DEVICE;
		event_packet->bsscfgidx = buffer[4];
		memcpy(event_packet->addr, buffer+5, ETH_ALEN);
		break;
	case EVENT_P2P_ACTION_TX_COMP_EVENT:
		WLAND_DBG(RX, DEBUG, "EVENT_P2P_ACTION_TX_COMP_EVENT\n");
		event_packet->event_code = WLAND_E_ACT_FRAME_COMPLETE;
		event_packet->status = buffer[4];
		event_packet->bsscfgidx = P2PAPI_BSSCFG_DEVICE;
		memcpy(event_packet->addr, buffer+5, ETH_ALEN);
		break;
	case EVENT_MICHAEL_MIC_FAILURE:
		event_packet->event_code = WLAND_E_MIC_ERROR;
		event_packet->status = buffer[2];
		WLAND_DBG(RX, DEBUG, "EVENT_MICHAEL_MIC_FAILURE:%x\n",
			buffer[2]);
		break;
	case EVENT_ADDBA:
		WLAND_DBG(RX, DEBUG, "EVENT_ADDBA\n");
		//printk("#####EVENT_ADDBA:index:%d,mac%pM,tid:%d,state%x,amsdu:%x\n",
			//buffer[4], buffer+5, buffer[11], buffer[12], buffer[13]);
		event_packet->event_code = WLAND_E_ADDBA;
		event_packet->bsscfgidx = buffer[4];
		addba_msg.tid = buffer[11];
		if (buffer[12]) {
			if (event->vif == NULL) {
				WLAND_ERR("event->vif == NULL\n");
			}
			mutex_lock(&event->vif_event_lock);
			event->action = WLAND_ACTION_ADDBA_DONE;
			mutex_unlock(&event->vif_event_lock);
			wake_up(&event->vif_wq);
#ifdef WLAND_AMSDU_TX
            wland_amsdu_tx_conf(event->vif->ifp,
                                buffer[11],
                                ((event_len > 13) ? buffer[13] : 0));
#endif
			return 0;
		} else {
#ifdef WLAND_AMSDU_TX
            wland_amsdu_tx_conf(event->vif->ifp, buffer[11], 0);
#endif
			event_packet->action= WLAND_ACTION_DELBA;
		}
		memcpy(addba_msg.mac_addr, buffer+5, ETH_ALEN);
		event_packet->datalen = sizeof(addba_msg);
		wland_fweh_push_event(drvr, event_packet, &addba_msg);
		return 0;
	case EVENT_SOFTWARE_RESET:
		WLAND_DBG(RX, WARNING, "EVENT_SOFTWARE_RESET:%x\n", buffer[4]);
		printk("#####EVENT_SOFTWARE:%x\n", buffer[4]);
		if (buffer[4]) {
			atomic_set(&drvr->bus_if->software_reset, 1);
		} else {
			atomic_set(&drvr->bus_if->software_reset, 0);
		}
		return 0;
	case EVENT_HOST_RESET_COMPLATE:
		WLAND_DBG(RX, DEBUG, "EVENT_HOST_RESET_COMPLATE\n");
		printk("#####EVENT_HOST_RESET_COMPLATE\n");
		if (atomic_read(&drvr->bus_if->software_reset) == 2) {
			event_packet->event_code = WLAND_E_RESET_FW;
			event_packet->status = STATUS_SUCCESS;
			wland_fweh_push_event(drvr, event_packet, buffer);
			atomic_set(&drvr->bus_if->software_reset, 0);
		}
		return 0;
	default: {
		ret = -EBADE;
		WLAND_ERR("Receive invalid event type!\n");
		break;
	}
	}

	wland_fweh_push_event(drvr, event_packet, buffer);

	return ret;
}

#ifdef WLAND_SMART_CONFIG_SUPPORT
void wland_process_raw_data(struct sk_buff *skb, s8 rssi)
{
#ifdef CONFIG_PLATFORM_HIPAD
	u8 *data = NULL;
	u16 len = 0;
#endif
#ifndef CONFIG_PLATFORM_HIPAD
//1.fill radiotap_header
	u8 hdr_buf[64] = {0};
	struct ieee80211_radiotap_header *rtap_hdr =
		(struct ieee80211_radiotap_header *)&hdr_buf[0];
	u16 rt_len = 8;
	u8 *ptr = NULL;

	rtap_hdr->it_version = PKTHDR_RADIOTAP_VERSION;

	/* dBm Antenna Signal */
	rtap_hdr->it_present |= (1 << IEEE80211_RADIOTAP_DBM_ANTSIGNAL);
	hdr_buf[rt_len] = rssi;
	rt_len += 1;

	/* push to skb */

	if (skb_headroom(skb) < rt_len) {
		struct sk_buff *skb2;
		WLAND_ERR("headroom(%d) < rt_len(%d)\n", skb_headroom(skb), rt_len);

		skb2 = skb_realloc_headroom(skb, rt_len);
		dev_kfree_skb(skb);
		skb = skb2;
		if (skb == NULL) {
			WLAND_ERR("skb_realloc_headroom failed\n");
			return;
		}
	}

	ptr = skb_push(skb, rt_len);
	if (ptr) {
		rtap_hdr->it_len = cpu_to_le16(rt_len);
		memcpy(ptr, rtap_hdr, rt_len);
	} else {
		WLAND_ERR("skb push failed\n");
		dev_kfree_skb(skb);
		return;
	}
#else
	len = skb->len;
	skb_push(skb, 2);
	data = skb->data;
	data[0] = len&0x00FF;
	data[1] = len&0xFF00 >> 8;
#endif
//2. inform
	skb_reset_mac_header(skb);
	skb->ip_summed = CHECKSUM_NONE;
	skb->pkt_type = PACKET_OTHERHOST;
	skb->protocol = htons(0x0019); /* ETH_P_80211_RAW */
	if (in_interrupt()) {
		netif_rx(skb);
	} else {
		netif_rx_ni(skb);
	}
}

static s32 wland_handle_monitor_info(struct wland_rx_info *rx_info, struct sk_buff *skb)
{
	u16 wid_id = 0, frame_len = 0;
	u8 *p_frame;
	u8 *p_buffer = skb->data + 2;
	s8 rssi = 0;
	/*skb->data: |2byte host header|4byte msg header| 2byte wid|2byte wid len|1 byte rssi|*/

	wid_id = p_buffer[4] | p_buffer[5]<<8;
	WLAND_DBG(RX, DEBUG, "WID id=%04x\n", wid_id);

	switch (wid_id) {
		case WID_SMARTCONFIG_LDPCBCC_INFO:
			frame_len = (u16) (p_buffer[7] | (p_buffer[8] << 8));
			//u16SNR = (r_u16) (pu8Buffer[9] | (pu8Buffer[10] << 8));
			printk("ldpc len:%d\n", frame_len);
			wland_pkt_buf_free_skb(skb);
			break;
		case WID_NETWORK_INFO:
			p_frame = &p_buffer[9];//initial position of mac_header
			frame_len = (u16) (p_buffer[6] | (p_buffer[7] << 8)) - 1;
			rssi = (signed char)(p_buffer[8]);
			if ((p_frame[0] & 0x0C) == 0x08) {//data
				skb_pull(skb, 9); //skb data point to mac header
				skb_set_tail_pointer(skb, frame_len);
				skb->len = frame_len;
				wland_process_raw_data(skb, rssi);
			} else {
				WLAND_ERR("sniffer mode get none data pkt!\n");
				printk("%02x %02x\n",p_frame[0],p_frame[1]);
				wland_pkt_buf_free_skb(skb);
			}
			break;
		default:
			WLAND_ERR("Receive invalid event type:0x%x!\n", wid_id);
			wland_pkt_buf_free_skb(skb);
			break;
	}

	return 0;
}
#endif
static s32 wland_handle_async_info(struct wland_private *drvr,
	struct wland_event_msg *event_packet, u8 *p_buffer)
{
	s32 ret = 0;
	u16 wid_id = 0, frame_len = 0;
	u8 *p_frame = NULL, sub_type = 0;
	u8 wid_value = 0;
	int i;
	//struct wland_cfg80211_info *config = drvr->config;
	wid_id = p_buffer[4] | p_buffer[5]<<8;
	WLAND_DBG(RX, DEBUG, "WID id=%04x\n", wid_id);
	switch (wid_id) {
		case WID_P2P_ACTION_TO_HOST:
			WLAND_DBG(RX, INFO, "WID_P2P_ACTION_TO_HOST\n");
			event_packet->event_code = WLAND_E_ACTION_FRAME_RX;
			event_packet->status = STATUS_SUCCESS;
			event_packet->bsscfgidx = P2PAPI_BSSCFG_DEVICE;
			wland_fweh_push_event(drvr, event_packet, p_buffer);
			break;
		case WID_NETWORK_INFO:
			p_frame = &p_buffer[9];//initial position of mac_header
			//u8sub_type = wland_get_sub_type(pu8Frame);
			sub_type = p_frame[0] & 0xFC;
			WLAND_DBG(RX, INFO, "WID_NETWORK_INFO, sub_type:0x%02x\n", sub_type);
			switch (sub_type){
			case BEACON:
			case PROBE_RSP:
				event_packet->event_code = WLAND_E_ESCAN_RESULT;
				event_packet->status = STATUS_SUCCESS;
				event_packet->bsscfgidx = P2PAPI_BSSCFG_PRIMARY;
				wland_fweh_push_event(drvr, event_packet, p_buffer);
				break;
			case ASSOC_REQ:
				for (i=0; i<P2PAPI_BSSCFG_MAX; ++i)
					if (drvr->iflist[i])
						if (!memcmp(drvr->iflist[i]->mac_addr, p_frame+4, ETH_ALEN))//for ap,add0
							break;
				if (i!= P2PAPI_BSSCFG_MAX) {
					frame_len = (u16) (p_buffer[6] | (p_buffer[7] << 8)) - 1;//reduce rssi length
					wland_get_assoc_ies_from_frame(drvr->iflist[i], p_frame, frame_len, sub_type);
				}
				break;
			case ASSOC_RSP:
				for (i=0; i<P2PAPI_BSSCFG_MAX; ++i)
					if (drvr->iflist[i])
						if (!memcmp(drvr->iflist[i]->mac_addr, p_frame+4, ETH_ALEN))//for sta,add0
							break;
				if (i!= P2PAPI_BSSCFG_MAX) {
					frame_len = (u16) (p_buffer[6] | (p_buffer[7] << 8)) - 1;//reduce rssi length
					wland_get_assoc_ies_from_frame(drvr->iflist[i], p_frame, frame_len, sub_type);
#ifdef WLAND_TX_SOFT_MAC
					wland_analysis_assoc_ies(drvr->iflist[i]);
#endif
				}
				break;
			default:
				break;
			}
			break;
		case WID_STA_JOIN_INFO_91H:

			/*************************************************************************/
			/* Format of STA JOIN INFO message										 */
			/* ----------------------------------------------------------------------*/
			/* |Last byte| MAC address	| Type of STA	 |	11g info  | Security	 */
			/* | of AID  | of STA		| 11 a/b/g/n	 |	byte	  | byte		 */
			/* ----------------------------------------------------------------------*/
			/* | 1 byte  | 6 bytes		| 1 byte		 |	1 byte	  |  1 byte 	 */
			/*************************************************************************/

			if (drvr->bus_if->chip == WLAND_VER_91_H) {
				WLAND_DBG(RX, INFO, "WID_STA_JOIN_INFO_91H\n");
				frame_len = (u16) (p_buffer[6] | ((u16)p_buffer[7] << 8));
				p_frame = &p_buffer[8];
				memcpy(event_packet->addr, p_frame+1, ETH_ALEN);

				event_packet->bsscfgidx = P2PAPI_BSSCFG_PRIMARY;

				sub_type = p_frame[7];
				if (sub_type) {//ap mac_connected
					event_packet->event_code = WLAND_E_CONNECT_IND;
					event_packet->action = WLAND_ACTION_AP_CONNECTED;
				} else {//ap disconnected
					event_packet->event_code = WLAND_E_DISCONNECT_IND;
					event_packet->action = WLAND_ACTION_AP_DISCONNECTED;
				}
				wland_fweh_push_event(drvr, event_packet, p_buffer);
			}
			break;
		case WID_GO_JOIN_INFO:
				if (drvr->bus_if->chip == WLAND_VER_91_H) {
					WLAND_DBG(RX, INFO, "WID_STA_JOIN_INFO_91H\n");
					frame_len = (u16) (p_buffer[6] | ((u16)p_buffer[7] << 8));
					p_frame = &p_buffer[8];
					memcpy(event_packet->addr, p_frame+1, ETH_ALEN);

					event_packet->bsscfgidx = P2PAPI_BSSCFG_DEVICE;

					sub_type = p_frame[7];
					if (sub_type) {//ap mac_connected
						event_packet->event_code = WLAND_E_CONNECT_IND;
						event_packet->action = WLAND_ACTION_AP_CONNECTED;
					} else {//ap disconnected
						event_packet->event_code = WLAND_E_DISCONNECT_IND;
						event_packet->action = WLAND_ACTION_AP_DISCONNECTED;
					}
					wland_fweh_push_event(drvr, event_packet, p_buffer);
				}
				break;
		case WID_SCAN_CONNECT_RESULT:
			if (drvr->bus_if->chip == WLAND_VER_91_H) {
				wid_value = p_buffer[7];
				switch (wid_value) {
					case RESULT_SCAN_COMP:
						event_packet->event_code = WLAND_E_ESCAN_RESULT;
						event_packet->status = STATUS_TIMEOUT;
						event_packet->bsscfgidx = P2PAPI_BSSCFG_PRIMARY;
						wland_fweh_push_event(drvr, event_packet, NULL);
						break;
					case RESULT_CONN_FAIL:
						event_packet->event_code = WLAND_E_CONNECT_IND;
						event_packet->status = STATUS_TIMEOUT;
						wland_fweh_push_event(drvr, event_packet, NULL);
						break;
					case RESULT_P2P_CONN_FAIL:
						event_packet->event_code = WLAND_E_CONNECT_IND;
						event_packet->status = STATUS_TIMEOUT;
						event_packet->bsscfgidx = P2PAPI_BSSCFG_DEVICE;
						wland_fweh_push_event(drvr, event_packet, NULL);
						break;
					default:
						break;
				}
			}
			break;

		default: {
			//ret = -EBADE;
			WLAND_ERR("Receive invalid event type:0x%x!\n", wid_id);
			break;
		}
	}

	return ret;
}

/* The format of the message is:                                         */

/* +-------------------------------------------------------------------+ */

/* | pkt Type  | Message Type |  Message body according type           | */

/* +-------------------------------------------------------------------+ */

/* |  1 Byte   |   1 Byte     |                                        | */

/* +-------------------------------------------------------------------+ */

void wland_netif_rx(struct wland_if *ifp, struct sk_buff *skb)
{
	struct wland_event_msg event_packet;
	memset(&event_packet, 0, sizeof(event_packet));

	skb->dev = ifp->ndev;
	skb->protocol = eth_type_trans(skb, skb->dev);
	skb->ip_summed = CHECKSUM_NONE;

	if (skb->pkt_type == PACKET_MULTICAST)
		ifp->stats.multicast++;

	/*
	 * free skb
	 */
	if (!(ifp->ndev->flags & IFF_UP)) {
		WLAND_ERR("netdev not up\n");
		wland_pkt_buf_free_skb(skb);
		return;
	}

	if (ifp->bssidx == P2PAPI_BSSCFG_PRIMARY) {
		if(skb->pkt_type != PACKET_OTHERHOST && skb->protocol == htons(ETH_P_IP)) { // IP
			struct iphdr *iph = (struct iphdr *)(skb->data);
			if(iph->protocol == IPPROTO_UDP) { // UDP
				struct udphdr *udph = (struct udphdr *)((u8 *)iph + (iph->ihl << 2));
				if((udph->source == __constant_htons(SERVER_PORT))
					&& (udph->dest == __constant_htons(CLIENT_PORT))) { // DHCP offset/ack
					struct dhcpMessage *dhcph =
						(struct dhcpMessage *)((u8 *)udph + sizeof(struct udphdr));
					if(dhcph->cookie == htonl(DHCP_MAGIC) && dhcph->op == 2 &&
						!memcmp(dhcph->chaddr, ifp->mac_addr, ETH_ALEN)) { // match magic word
						u32 length = ntohs(udph->len) - sizeof(struct udphdr) - offsetof(struct dhcpMessage, options);
						u16 offset = 0;
						u8 *option = dhcph->options;
						while (offset<length && option[offset]!=DHCP_OPTION_END) {
							if (option[offset] == DHCP_OPTION_MESSAGE_TYPE) {
								if (option[offset+2] == DHCP_ACK) {
									//wland_enable_arp_offload(ifp, (char *)(&dhcph->yiaddr));
									event_packet.event_code = WLAND_E_ARP_OFFLOAD;
									event_packet.datalen = 4;
									wland_fweh_push_event(ifp->drvr, &event_packet, (void *)(&dhcph->yiaddr));
									memcpy(ifp->vif->profile.dhcp_server_bssid, eth_hdr(skb)->h_source, ETH_ALEN);
								}
								//break;
							} else if (option[offset] == DHCP_OPTION_ROUTERS) {
								memcpy(ifp->vif->profile.dhcp_server_ip, option+offset+2, 4);
							}
							offset += 2+option[offset+1];
						}
					}
				}
			}
		}

	}

	//ifp->ndev->last_rx = jiffies;
	ifp->stats.rx_bytes += skb->len;
	ifp->stats.rx_packets++;

	WLAND_DBG(RX, DEBUG, "rx proto:0x%X,pkt_len:%d\n",
		ntohs(skb->protocol), skb->len);

	if (in_interrupt()) {
		netif_rx(skb);
	} else {
		/*
		 * If the receive is not processed inside an ISR, the softirqd must be woken explicitly to service the NET_RX_SOFTIRQ.
		 * * In 2.6 kernels, this is handledby netif_rx_ni(), but in earlier kernels, we need to do it manually.
		 */
		netif_rx_ni(skb);
	}
}

/* Receive frame for delivery to OS.  Callee disposes of rxp. */
void wland_process_8023_pkt(struct wland_bus *bus_if, struct sk_buff *skb)
{
	s32 ifidx = 0;
	int ret;
	struct wland_private *drvr = bus_if->drvr;
	struct wland_if *ifp;

	WLAND_DBG(RX, DEBUG, "Enter,%s,count:%u,dev:%p\n", dev_name(bus_if->dev), skb->len, skb->dev);

	ret = wland_proto_hdrpull(drvr, &ifidx, skb);
#ifndef WLAND_5991H_MAC1_SUPPORT
	WLAND_DBG(RX, TRACE, "rx data ifidx:%d\n", ifidx);
	ifp = drvr->iflist[ifidx];
#else
	ifp = netdev_priv(skb->dev);
#endif

	if (ret || !ifp || !ifp->ndev) {
		if ((ret != -ENODATA) && ifp)
			ifp->stats.rx_errors++;
		WLAND_ERR("RX error!\n");
		wland_pkt_buf_free_skb(skb);
	} else {
		WLAND_DBG(RX, DEBUG, "rx data ifidx:%d\n", ifp->bssidx);
		wland_netif_rx(ifp, skb);
	}

	WLAND_DBG(RX, TRACE, "Done,%s: count:%u\n", dev_name(bus_if->dev), skb->len);
}

#if defined WLAND_RX_SOFT_MAC || defined WLAND_RX_8023_REORDER
#if 0
static void wland_analysis_mac_header(struct wland_bus *bus_if, struct sk_buff *skb)
{
	struct wland_private* drvr = bus_if->drvr;
	struct wland_if *ifp = drvr->iflist[0];
	struct net_device *ndev = ifp->ndev;
	struct wland_cfg80211_profile *profile = ndev_to_prof(ndev);
	u8 *da;
	u8 *sa;
	u8 msdu_offset;
	u8 snap_hdr_len;
	u8 mac_hdr_len;
	u8 sec_hdr_len;
	//u8 sec_mic_icv_len;
	u8 ct;
	u8 *mac_hdr_ptr;

	mac_hdr_ptr = skb->data + WID_HEADER_LEN;

	if(wland_get_wep(mac_hdr_ptr))
		ct = profile->sec.security;
	else
		ct = 0;

	mac_hdr_len = wland_get_mac_hdr_len(mac_hdr_ptr);
	sec_hdr_len = wland_get_sec_header_len(ct) ;
	//sec_mic_icv_len = wland_get_sec_mic_icv_len(ct);

	msdu_offset = WID_HEADER_LEN + mac_hdr_len + sec_hdr_len;
	if(wland_is_snap_header_present(skb->data + msdu_offset))
		snap_hdr_len = DOT11_LLC_SNAP_HDR_LEN;
	else
		snap_hdr_len = 0;
	msdu_offset += snap_hdr_len;

	da = skb->data + msdu_offset - ETHER_HDR_LEN;
	sa = skb->data + msdu_offset - ETHER_HDR_LEN + ETHER_ADDR_LEN;
	wland_set_host_eth_addr(mac_hdr_ptr, da, sa);

	//skb->len -= sec_mic_icv_len;

	skb_pull(skb, msdu_offset - ETHER_HDR_LEN);
}
#endif
static struct recv_frame *wland_free_recv_queue_init(struct list_head *q, int qsize)
{
	int i;
	struct recv_frame *req, *reqs;

	reqs = vmalloc(qsize*sizeof(struct recv_frame));

	if (reqs == NULL)
		return NULL;

	req = reqs;

	for (i = 0; i < qsize; i++) {

		INIT_LIST_HEAD(&req->list2);
		list_add(&req->list2, q);

		req->len = 0;
		req++;
	}
	return reqs;
}

static void wland_recvframe_free_q(struct list_head *q)
{
	struct recv_frame *req, *next;

	list_for_each_entry_safe(req, next, q, list2) {
		list_del_init(&req->list2);
	}
}

void wland_recvframe_enq(spinlock_t *lock,
	struct list_head *q, struct list_head *list, u8 *counter)
{
	unsigned long flags;

	spin_lock_irqsave(lock, flags);
	list_add_tail(list, q);
	if (counter)
		(*counter)++;
	spin_unlock_irqrestore(lock, flags);
}

static struct recv_frame *wland_recvframe_deq(spinlock_t *lock,
	struct list_head *q, u8 list_count, u8 *counter)
{
	unsigned long flags;
	struct recv_frame *req;

	spin_lock_irqsave(lock, flags);
	if (list_empty(q)) {
		spin_unlock_irqrestore(lock, flags);
		return NULL;
	}
	if (list_count == 1) //for uc_pending_queue
		req = list_entry(q->next, struct recv_frame, list);
	else if (list_count == 2) //for free_recv_queue
		req = list_entry(q->next, struct recv_frame, list2);
	else {
		spin_unlock_irqrestore(lock, flags);
		return NULL;
	}
	list_del_init(q->next);
	if (counter)
		(*counter)--;

#ifdef WLAND_DEAMSDU_RX
    INIT_LIST_HEAD(&req->deamsdu_list);
    req->deamsdu_cnt = 0;
#endif

	spin_unlock_irqrestore(lock, flags);
	return req;
}

static int wland_is_mcast(unsigned char *da)
{
	if ((*da) & 0x01)
		return 1;
	else
		return 0;
}

void wland_recv_indicatepkts_pkt_loss_cnt(struct wland_rx_info *rx_info, u64 prev_seq, u64 current_seq)
{
	if(current_seq < prev_seq)
		rx_info->dbg_rx_ampdu_loss_count+= (4096 + current_seq - prev_seq);
	else
		rx_info->dbg_rx_ampdu_loss_count+= (current_seq - prev_seq);
}

int wland_recv_indicatepkt(struct wland_rx_info *rx_info, struct recv_frame *precv_frame)
{
	struct list_head *pfree_recv_queue = NULL;
	struct sk_buff *skb = NULL;
#ifdef WLAND_SDIO_SUPPORT
	struct device* dev = rx_info->bus->sdiodev->dev;
#else
	struct device* dev = rx_info->devinfo->dev;
#endif
	struct wland_bus *bus_if = dev_get_drvdata(dev);

	WLAND_DBG(RX, DEBUG, "ENTER:%d\n", precv_frame->attrib.seq_num);

#ifdef WLAND_DEAMSDU_RX
    /* this is a AMSDU includes some MSDUs */
    if (!list_empty(&precv_frame->deamsdu_list))
        return wland_deamsdu_rx_indicatepkt(precv_frame, bus_if);
#endif

	pfree_recv_queue = &rx_info->free_recv_queue;

	skb = precv_frame->pkt;
	if (skb == NULL) {
		WLAND_ERR("skb is NULL\n");
        goto fail;
	}

	skb->data = precv_frame->rx_data;

	skb_set_tail_pointer(skb, precv_frame->len);

	skb->len = precv_frame->len;

	wland_process_8023_pkt(bus_if, skb);

	precv_frame->pkt = NULL;

fail:
	wland_recvframe_enq(&rx_info->free_recv_lock, pfree_recv_queue,
		&precv_frame->list2, &rx_info->free_recv_cnt);

	return 0;
}

bool wland_recv_indicatepkts_in_order(struct wland_rx_info *rx_info,
	struct recv_reorder_ctrl *preorder_ctrl, int bforced)
{
	struct list_head *phead, *plist;
	struct recv_frame *prframe;
	struct rx_pkt_attrib *pattrib;
	bool bPktInBuf = false;
	//struct list_head *ppending_recvframe_queue = &preorder_ctrl->pending_recvframe_queue;
	unsigned long flags;

	WLAND_DBG(RX, DEBUG, "ENTER\n");

	spin_lock_irqsave(&preorder_ctrl->pending_recvframe_queue_lock, flags);
	if (bforced == true) {
		phead = &preorder_ctrl->pending_recvframe_queue;
		if (list_empty(phead)) {
			spin_unlock_irqrestore(&preorder_ctrl->pending_recvframe_queue_lock, flags);
			return false;
		}

		plist = phead->next;

		prframe = list_entry(plist, struct recv_frame, list);
		pattrib = &prframe->attrib;

		WLAND_DBG(RX, ERROR, "#####IndicateSeq: %d, NewSeq: %d\n",
			preorder_ctrl->indicate_seq, pattrib->seq_num);

		wland_recv_indicatepkts_pkt_loss_cnt(rx_info, preorder_ctrl->indicate_seq, pattrib->seq_num);
		preorder_ctrl->indicate_seq = pattrib->seq_num;
	}


	//spin_lock_irqsave(&preorder_ctrl->pending_recvframe_queue_lock, flags);
	phead = &preorder_ctrl->pending_recvframe_queue;
	while (1) {
		if (list_empty(phead)) {
			break;
		}

		plist = phead->next;

		prframe = list_entry(plist, struct recv_frame, list);
		pattrib = &prframe->attrib;

		if (!SN_LESS(preorder_ctrl->indicate_seq, pattrib->seq_num)) {
			WLAND_DBG(RX, DEBUG,
				 "report skb: indicate=%d seq=%d amsdu=%d\n",
				  preorder_ctrl->indicate_seq, pattrib->seq_num, pattrib->amsdu);

			//plist = plist->next;

			list_del_init(&(prframe->list));

			if (SN_EQUAL(preorder_ctrl->indicate_seq, pattrib->seq_num)) {
				preorder_ctrl->indicate_seq = (preorder_ctrl->indicate_seq + 1) & 0xFFF;
				WLAND_DBG(RX, DEBUG, "new IndicateSeq: %d, NewSeq: %d\n",
					preorder_ctrl->indicate_seq, pattrib->seq_num);
			}

			if(!pattrib->amsdu) {
				//spin_unlock_irqrestore(&preorder_ctrl->pending_recvframe_queue_lock, flags);
				wland_recv_indicatepkt(rx_info, prframe);//indicate this recv_frame
				//spin_lock_irqsave(&preorder_ctrl->pending_recvframe_queue_lock, flags);
			}
#if 0
			else if(pattrib->amsdu==1) {
				if(amsdu_to_msdu(padapter, prframe) != 0) {
					wland_free_recvframe(prframe, &precvpriv->free_recv_queue);
				}
			}
#endif
			else {
				WLAND_DBG(RX, ERROR, "new IndicateSeq: %d, NewSeq: %d\n",
					preorder_ctrl->indicate_seq, pattrib->seq_num);
				//error condition;
			}

		} else {
			bPktInBuf = true;
			break;
		}

	}
	spin_unlock_irqrestore(&preorder_ctrl->pending_recvframe_queue_lock, flags);

	WLAND_DBG(RX, DEBUG, "DONE inbuf:%d\n",bPktInBuf?1:0);
	return bPktInBuf;
}

static void wland_reordering_ctrl_timeout_worker(struct work_struct *work)
{
	struct recv_reorder_ctrl *preorder_ctrl =
		container_of(work, struct recv_reorder_ctrl,
		reordering_ctrl_timer_work);
	struct wland_rx_info *rx_info = preorder_ctrl->rx_info;

	WLAND_DBG(RX, INFO, "Enter\n");

	if (wland_recv_indicatepkts_in_order(rx_info, preorder_ctrl, true)==true) {
		mod_timer(&preorder_ctrl->reordering_ctrl_timer,
			jiffies + msecs_to_jiffies(REORDER_WAIT_TIME));
	}

	return ;
}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
static void wland_reordering_ctrl_timeout_handler(struct timer_list *t)
{
	struct recv_reorder_ctrl *preorder_ctrl =
		from_timer(preorder_ctrl, t, reordering_ctrl_timer);
#else
static void wland_reordering_ctrl_timeout_handler (ulong data)
{
	//unsigned long flags;
	struct recv_reorder_ctrl *preorder_ctrl = (struct recv_reorder_ctrl *)data;
#endif
	WLAND_DBG(RX, DEBUG, "wland_reordering_ctrl_timeout_handler\n");

	schedule_work(&preorder_ctrl->reordering_ctrl_timer_work);

}

static inline u8 *wland_recvframe_put(struct recv_frame *precvframe, int sz)
{

	unsigned char * prev_rx_tail;

	if(precvframe==NULL)
		return NULL;

	prev_rx_tail = precvframe->rx_tail;

	precvframe->rx_tail += sz;

	if(precvframe->rx_tail > precvframe->rx_end) {
		WLAND_ERR("Pkt len larger than mtu!\n");
		precvframe->rx_tail -= sz;
		return NULL;
	}

	precvframe->len +=sz;

	return precvframe->rx_tail;
}

int wland_check_indicate_seq(struct recv_reorder_ctrl *preorder_ctrl, u16 seq_num)
{
	u8 wsize = preorder_ctrl->wsize_b;
	u16 wend = (preorder_ctrl->indicate_seq + wsize -1) & 0xFFF;//% 4096;

	if (preorder_ctrl->indicate_seq == 0xFFFF) {
		preorder_ctrl->indicate_seq = seq_num;
		WLAND_DBG(RX, INFO, "init IndicateSeq: %d, NewSeq: %d\n",preorder_ctrl->indicate_seq, seq_num);
	}

	if( SN_LESS(seq_num, preorder_ctrl->indicate_seq)) {

		WLAND_DBG(RX, DEBUG, "IndicateSeq: %d > NewSeq: %d Drop it!\n", preorder_ctrl->indicate_seq, seq_num);
		return -1;
	}

	if (SN_EQUAL(seq_num, preorder_ctrl->indicate_seq)) {
		preorder_ctrl->indicate_seq = (preorder_ctrl->indicate_seq + 1) & 0xFFF;

		WLAND_DBG(RX, DEBUG, "new indicateSeq: %d\n", preorder_ctrl->indicate_seq);

	} else if (SN_LESS(wend, seq_num)) {
		WLAND_DBG(RX, WARNING, "#####new indicateSeq: %d. indicate:%d, wend%d, new indicate:%d\n", seq_num,
			preorder_ctrl->indicate_seq, wend,
			(seq_num >= (wsize-1)) ? (seq_num-(wsize-1)) : (0xFFF - (wsize - (seq_num + 1)) + 1));

		if (seq_num >= (wsize-1))
			preorder_ctrl->indicate_seq = seq_num-(wsize-1);
		else
			preorder_ctrl->indicate_seq = 0xFFF - (wsize - (seq_num + 1)) + 1;

	}

	return 0;
}

static int wland_enqueue_reorder_recvframe(struct recv_reorder_ctrl *preorder_ctrl, struct recv_frame *prframe)
{
	struct rx_pkt_attrib *pattrib = &prframe->attrib;
	struct list_head *ppending_recvframe_queue = &preorder_ctrl->pending_recvframe_queue;
	struct list_head	*phead, *plist;
	struct recv_frame *pnextrframe;
	struct rx_pkt_attrib *pnextattrib;
	unsigned long flags;

	WLAND_DBG(RX, DEBUG, "ENTER\n");

	phead = ppending_recvframe_queue;

	spin_lock_irqsave(&preorder_ctrl->pending_recvframe_queue_lock, flags);

	plist = phead->next;

	while(phead != plist) {
		pnextrframe = list_entry(plist, struct recv_frame, list);
		pnextattrib = &pnextrframe->attrib;

		if(SN_LESS(pnextattrib->seq_num, pattrib->seq_num))	{
			plist = plist->next;
			WLAND_DBG(RX, DEBUG, "< num = %d\n",pnextattrib->seq_num);
			continue;

		} else if(SN_EQUAL(pnextattrib->seq_num, pattrib->seq_num)) {
			spin_unlock_irqrestore(&preorder_ctrl->pending_recvframe_queue_lock, flags);
			WLAND_DBG(RX, DEBUG, "= num = %d\n",pnextattrib->seq_num);
			return -1;

		} else {
			WLAND_DBG(RX, DEBUG, "> num = %d\n",pnextattrib->seq_num);
			break;
		}
	}

	//list_del_init(&(prframe->list));
	list_add_tail(&(prframe->list), plist);
	spin_unlock_irqrestore(&preorder_ctrl->pending_recvframe_queue_lock, flags);

	WLAND_DBG(RX, DEBUG, "DONE\n");
	return 0;
}

struct rx_reorder_msg *wland_rx_reorder_msg_init(
	struct wland_rx_info* rx_info, const u8 *mac_addr)
{
	u8 i = 0;
	struct recv_reorder_ctrl *preorder_ctrl = NULL;
	u16 wRxSeqInitialValue = 0xffff;
	struct wland_bus *bus_if = NULL;
	struct rx_reorder_msg *reorder_msg;

	if (rx_info == NULL) {
		WLAND_ERR("bad rx_info!\n");
		return NULL;
	}

#ifdef WLAND_SDIO_SUPPORT
	bus_if = rx_info->bus->sdiodev->bus_if;
#else
	bus_if = rx_info->devinfo->bus_pub.bus;
#endif
	if(bus_if->state == WLAND_BUS_DOWN){
		WLAND_ERR("Bus is down!\n");
		return NULL;
	}

#if 0//close for multi mac
#ifdef WLAND_USE_RXQ
	cancel_work_sync(&rx_info->RxWork);
	wland_pktq_flush(&rx_info->rxq, true, NULL, NULL);
	atomic_set(&rx_info->rx_dpc_tskcnt, 0);
#endif
#endif

	reorder_msg = kmalloc(sizeof(struct rx_reorder_msg), GFP_ATOMIC);
	if (!reorder_msg) {
		WLAND_ERR("malloc reorder_msg fail\n");
		return NULL;
	}

	memcpy(reorder_msg->mac_addr, mac_addr, ETH_ALEN);

	for (i=0; i < 16; i++) {
		preorder_ctrl = &reorder_msg->preorder_ctrl[i];

		preorder_ctrl->enable = true;

		preorder_ctrl->indicate_seq = 0xffff;
		preorder_ctrl->wend_b= 0xffff;
		preorder_ctrl->wsize_b = WLAND_REORDER_WINSIZE;
		preorder_ctrl->rx_info= rx_info;

		preorder_ctrl->tid_rxseq = wRxSeqInitialValue;

		INIT_LIST_HEAD(&preorder_ctrl->pending_recvframe_queue);
		spin_lock_init(&preorder_ctrl->pending_recvframe_queue_lock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
		timer_setup(&preorder_ctrl->reordering_ctrl_timer,
			wland_reordering_ctrl_timeout_handler, 0);
#else
		init_timer(&preorder_ctrl->reordering_ctrl_timer);
		preorder_ctrl->reordering_ctrl_timer.data = (ulong) preorder_ctrl;
		preorder_ctrl->reordering_ctrl_timer.function = wland_reordering_ctrl_timeout_handler;
#endif
		INIT_WORK(&preorder_ctrl->reordering_ctrl_timer_work,
			wland_reordering_ctrl_timeout_worker);

#ifdef WLAND_DEAMSDU_RX
        preorder_ctrl->wait_deamsdu_state = DEAMSDU_STATE_COMPLETE;
        preorder_ctrl->wait_deamsdu_seq = 0xffff;
        preorder_ctrl->curr_deamsdu = NULL;
#endif
	}
	return reorder_msg;
}

void wland_rx_reorder_msg_deinit(struct wland_rx_info* rx_info,
	struct rx_reorder_msg *reorder_msg)
{
	u8 i = 0;
	unsigned long flags;
	struct recv_reorder_ctrl *preorder_ctrl = NULL;

	if (rx_info == NULL) {
		WLAND_ERR("bad rx_info!\n");
		return;
	}

#if 0//close for multi mac
#ifdef WLAND_USE_RXQ
	cancel_work_sync(&rx_info->RxWork);
	wland_pktq_flush(&rx_info->rxq, true, NULL, NULL);
	atomic_set(&rx_info->rx_dpc_tskcnt, 0);
#endif
#endif

    list_del(&reorder_msg->list);
	for (i=0; i < 16; i++) {
		struct recv_frame *req, *next;
		preorder_ctrl = &reorder_msg->preorder_ctrl[i];
		spin_lock_irqsave(&preorder_ctrl->pending_recvframe_queue_lock, flags);
        preorder_ctrl->enable = false;
		list_for_each_entry_safe(req, next, &preorder_ctrl->pending_recvframe_queue, list) {
			list_del_init(&req->list);
#ifdef WLAND_DEAMSDU_RX
            wland_deamsdu_rx_free((void *)req);
#else
			if(req->pkt != NULL)
				dev_kfree_skb(req->pkt);
			req->pkt = NULL;
			wland_recvframe_enq(&rx_info->free_recv_lock, &rx_info->free_recv_queue,
				&req->list2, &rx_info->free_recv_cnt);
#endif
		}
#ifdef WLAND_DEAMSDU_RX
        if (preorder_ctrl->curr_deamsdu)
            wland_deamsdu_rx_free((void *)(preorder_ctrl->curr_deamsdu));
#endif
		spin_unlock_irqrestore(&preorder_ctrl->pending_recvframe_queue_lock, flags);

		cancel_work_sync(&preorder_ctrl->reordering_ctrl_timer_work);

		if (timer_pending(&preorder_ctrl->reordering_ctrl_timer))
			del_timer_sync(&preorder_ctrl->reordering_ctrl_timer);
	}
	kfree(reorder_msg);
}

#endif

#ifdef WLAND_RX_SOFT_MAC
static inline u8 *wland_get_recvframe_data(struct recv_frame *precvframe)
{
	if(precvframe==NULL)
		return NULL;

	return precvframe->rx_data;
}

static inline u8 *wland_recvframe_pull_tail(struct recv_frame *precvframe, int sz)
{

	if(precvframe==NULL)
		return NULL;

	precvframe->rx_tail -= sz;

	if(precvframe->rx_tail < precvframe->rx_data) {
		precvframe->rx_tail += sz;
		return NULL;
	}

	precvframe->len -= sz;

	return precvframe->rx_tail;

}

static inline u8 *wland_recvframe_pull(struct recv_frame *precvframe, int sz)
{

	if(precvframe==NULL)
		return NULL;

	precvframe->rx_data += sz;

	if(precvframe->rx_data > precvframe->rx_tail) {
		precvframe->rx_data -= sz;
		return NULL;
	}

	precvframe->len -=sz;

	return precvframe->rx_data;

}

int wland_hdr_to_ethhdr ( struct recv_frame *precvframe)
{
	int rmv_len;
	u16 len;
	u8 bsnaphdr;
	u8 *psnap_type;
	int ret=0;

	struct ieee80211_snap_hdr *psnap;
	struct rx_pkt_attrib *pattrib = &precvframe->attrib;
	u8 *ptr = wland_get_recvframe_data(precvframe); // point to frame_ctrl field
	if (ptr==NULL) {
		WLAND_ERR("wland_hdr_to_ethhdr precvframe is NULL\n");
		return -1;
	}

	if (pattrib->encrypt) {
		if(wland_recvframe_pull_tail(precvframe, pattrib->icv_len) == NULL)
			return -1;
	}

	psnap=(struct ieee80211_snap_hdr*)(ptr+pattrib->hdrlen + pattrib->iv_len);
	psnap_type = ptr+pattrib->hdrlen + pattrib->iv_len + SNAP_SIZE;

	if ((!memcmp(psnap, wland_rfc1042_header, SNAP_SIZE) &&
		(memcmp(psnap_type, SNAP_ETH_TYPE_IPX, 2)) &&
		(memcmp(psnap_type, SNAP_ETH_TYPE_APPLETALK_AARP, 2)))||
		//eth_type != ETH_P_AARP && eth_type != ETH_P_IPX) ||
		 !memcmp(psnap, wland_bridge_tunnel_header, SNAP_SIZE)) {
		/* remove RFC1042 or Bridge-Tunnel encapsulation and replace EtherType */
		bsnaphdr = true;
	} else {
		/* Leave Ethernet header part of hdr and full payload */
		bsnaphdr = false;
	}

	rmv_len = pattrib->hdrlen + pattrib->iv_len +(bsnaphdr?SNAP_SIZE:0);
	len = precvframe->len - rmv_len;

	pattrib->eth_type = ptr[rmv_len]<<8 | ptr[rmv_len+1];

	ptr = wland_recvframe_pull(precvframe, (rmv_len-sizeof(struct ethhdr)+ (bsnaphdr?2:0)));

	memcpy(ptr, pattrib->dst, ETH_ALEN);
	memcpy(ptr+ETH_ALEN, pattrib->src, ETH_ALEN);

	if (!bsnaphdr) {
		len = cpu_to_le16(len);
		memcpy(ptr+12, &len, 2);
	}

	return ret;
}

int wland_recv_indicatepkt_reorder(struct wland_rx_info *rx_info, struct recv_frame *prframe)
{
	struct rx_pkt_attrib *pattrib = &prframe->attrib;
	struct recv_reorder_ctrl *preorder_ctrl = prframe->preorder_ctrl;

	if (!pattrib->amsdu) {

		wland_hdr_to_ethhdr(prframe);

		if ((pattrib->qos!=1) || (pattrib->eth_type == 0x888E)
			|| wland_is_mcast(pattrib->ra))	{
			if(pattrib->qos!=1)
				WLAND_DBG(RX, DEBUG, "qos != 1 indicate it!\n");
			if(pattrib->eth_type == 0x888E)
				WLAND_DBG(RX, DEBUG, "eapol pkt indicate it!\n");

			wland_recv_indicatepkt(rx_info, prframe);
			return 0;
		}

		if (preorder_ctrl->enable == false) {

			preorder_ctrl->indicate_seq = pattrib->seq_num;

			wland_recv_indicatepkt(rx_info, prframe);

			preorder_ctrl->indicate_seq = (preorder_ctrl->indicate_seq + 1)%4096;

			return 0;
		}
	}


	WLAND_DBG(RX, TRACE,
		"wland_recv_indicatepkt_reorder: indicate=%d seq=%d\n",
		preorder_ctrl->indicate_seq, pattrib->seq_num);


	spin_lock_irqsave(&preorder_ctrl->pending_recvframe_queue_lock, flags);

	if (wland_check_indicate_seq(preorder_ctrl, pattrib->seq_num)) {
		spin_unlock_irqrestore(&preorder_ctrl->pending_recvframe_queue_lock, flags);
		goto fail;
	}
	spin_unlock_irqrestore(&preorder_ctrl->pending_recvframe_queue_lock, flags);


	if (wland_enqueue_reorder_recvframe(preorder_ctrl, prframe)) {
		goto fail;
	}

	if (wland_recv_indicatepkts_in_order(rx_info, preorder_ctrl, false) == true) {
		mod_timer(&preorder_ctrl->reordering_ctrl_timer,
			jiffies + msecs_to_jiffies(REORDER_WAIT_TIME));
		//spin_unlock_irqrestore(&preorder_ctrl->pending_recvframe_queue_lock, flags);

	} else {
		//spin_unlock_irqrestore(&preorder_ctrl->pending_recvframe_queue_lock, flags);
		if (timer_pending(&preorder_ctrl->reordering_ctrl_timer))
			del_timer_sync(&preorder_ctrl->reordering_ctrl_timer);
	}

	return 0;

fail:
	//spin_unlock_irqrestore(&preorder_ctrl->pending_recvframe_queue_lock, flags);
	return -1;
}

int wland_recv_decache(struct recv_frame *precv_frame, u8 bretry)
{
	int tid = precv_frame->attrib.priority;
	u16 seq_ctrl = ((precv_frame->attrib.seq_num&0xffff) << 4) |
		(precv_frame->attrib.frag_num & 0xf);

	//printk("seq=%d tid=%d :seq_ctrl = %04x\n", precv_frame->attrib.seq_num, precv_frame->attrib.priority, seq_ctrl);
	if (tid>15) {
		WLAND_ERR("tid>15!\n");
		return -1;
	}

	if (1) {
		if(seq_ctrl == precv_frame->preorder_ctrl->tid_rxseq) {
			WLAND_DBG(RX, DEBUG, "same seq, drop\n");
			return -1;
		}
	}

	if (!wland_is_mcast(precv_frame->attrib.ra))
		precv_frame->preorder_ctrl->tid_rxseq = seq_ctrl;

	return 0;
}
int wland_parse_recv_data_frame(struct wland_rx_info *rx_info, struct recv_frame *precv_frame, struct wland_if *ifp)
{
	u8 bretry;
	u8 *psa, *pda, *pbssid;
	u8 *ptr = precv_frame->rx_data;
	struct rx_pkt_attrib *pattrib = & precv_frame->attrib;
	struct net_device *ndev = ifp->ndev;
	struct wland_cfg80211_profile *profile = ndev_to_prof(ndev);
	struct rx_reorder_msg *reorder_msg;
	unsigned long flags;
	u8 *mac;
	int ret = 0;

	bretry = GetRetry(ptr);
	pda = wland_get_da(ptr);
	psa = wland_get_sa(ptr);
	pbssid = wland_get_hdr_bssid(ptr);

	if ((pbssid == NULL) ||(memcmp(profile->bssid, pbssid, ETH_ALEN))) {
		if(pbssid == NULL)
			WLAND_ERR("pbssid == NULL!\n");
		else
			WLAND_ERR("another bsssid!\n");
		ret= -1;
		goto exit;
	}
	if ((psa == NULL) ||(!memcmp(ifp->mac_addr, psa, ETH_ALEN))) {
		WLAND_ERR("the same source address to 91H!\n");
		ret= -1;
		goto exit;
	}

	memcpy(pattrib->dst, pda, ETH_ALEN);
	memcpy(pattrib->src, psa, ETH_ALEN);

	memcpy(pattrib->bssid, pbssid, ETH_ALEN);

	switch(pattrib->to_fr_ds) {
		case 0:
			memcpy(pattrib->ra, pda, ETH_ALEN);
			memcpy(pattrib->ta, psa, ETH_ALEN);
			//ret = sta2sta_data_frame(adapter, precv_frame, &psta);
			break;

		case 1:
			memcpy(pattrib->ra, pda, ETH_ALEN);
			memcpy(pattrib->ta, pbssid, ETH_ALEN);
			//ret = ap2sta_data_frame(adapter, precv_frame, &psta);
			break;

		case 2:
			memcpy(pattrib->ra, pbssid, ETH_ALEN);
			memcpy(pattrib->ta, psa, ETH_ALEN);
			//ret = sta2ap_data_frame(adapter, precv_frame, &psta);
			break;

		case 3:
			memcpy(pattrib->ra, GetAddr1Ptr(ptr), ETH_ALEN);
			memcpy(pattrib->ta, GetAddr2Ptr(ptr), ETH_ALEN);
			ret = -1;
			break;

		default:
			ret = -1;
			break;

	}

	if (ret == -1) {
		WLAND_ERR("memcpy == -1!\n");
		goto exit;
	}

	pattrib->amsdu=0;
	pattrib->ack_policy = 0;
	//parsing QC field
	if (pattrib->qos == 1) {
		pattrib->priority = GetPriority((ptr + 24));
		pattrib->ack_policy = GetAckpolicy((ptr + 24));
		pattrib->amsdu = GetAMsdu((ptr + 24));
		pattrib->hdrlen = pattrib->to_fr_ds==3 ? 32 : 26;

		if (pattrib->priority!=0 && pattrib->priority!=3) {
			WLAND_DBG(RX, TRACE, "Receive packet priority error\n");
		}
	} else {
		pattrib->priority=0;
		pattrib->hdrlen = pattrib->to_fr_ds==3 ? 30 : 24;
	}

	if (pattrib->order) {//HT-CTRL 11n
		pattrib->hdrlen += 4;
	}

	if (pattrib->hdrlen&3)
		pattrib->hdrlen  +=2;
	//printk("priority=%d\n",pattrib->priority);


	if (ifp->vif->mode == WL_MODE_BSS)
		mac = pattrib->dst;
	else if (ifp->vif->mode == WL_MODE_AP)
		mac = pattrib->src;
	else {
		WLAND_ERR("error mode:%d!\n", ifp->vif->mode);
		return -1;
	}

	spin_lock_irqsave(&rx_info->rx_reorder_msg_lock, flags);

	list_for_each_entry(reorder_msg, &rx_info->rx_reorder_msg_list, list) {
		if (!memcmp(mac, reorder_msg->mac_addr, ETH_ALEN)) {
			precv_frame->preorder_ctrl = &reorder_msg->preorder_ctrl[pattrib->priority];
			break;
		}
	}
	if (&reorder_msg->list == &rx_info->rx_reorder_msg_list) {
		WLAND_ERR("add new rx_preorder_msg member:ifx:%d, mode:%d, %pM -> %pM\n",
			ifp->bssidx, ifp->vif->mode, pattrib->src, pattrib->dst);
		reorder_msg = wland_rx_reorder_msg_init(rx_info, mac);
		if (!reorder_msg) {
			WLAND_ERR("malloc reorder_msg fail\n");
			spin_unlock_irqrestore(&rx_info->rx_reorder_msg_lock, flags);
			return -1;
		}
		precv_frame->preorder_ctrl = &reorder_msg->preorder_ctrl[pattrib->priority];
	}
	spin_unlock_irqrestore(&rx_info->rx_reorder_msg_lock, flags);

	//precv_frame->preorder_ctrl = &rx_info->recvreorder_ctrl[pattrib->priority];

	// decache, drop duplicate recv packets
	if (wland_recv_decache(precv_frame, bretry) == -1) {
		WLAND_DBG(RX, INFO, "wland_recv_decache failed\n");
		ret= -1;
		goto exit;
	}

	if (pattrib->privacy) {
		SET_ICE_IV_LEN(pattrib->iv_len, pattrib->icv_len, pattrib->encrypt);

	} else {
		pattrib->encrypt = 0;
		pattrib->iv_len = pattrib->icv_len = 0;
	}

exit:

	return ret;
}
int wland_parse_recv_frame(struct wland_rx_info *rx_info, struct recv_frame *precv_frame)
{
	//shall check frame subtype, to / from ds, da, bssid

	//then call check if rx seq/frag. duplicated.
#ifdef WLAND_SDIO_SUPPORT
	struct wland_sdio* bus = rx_info->bus;
	struct device* dev = bus->sdiodev->dev;
#else
	struct wland_usbdev_info* devinfo = rx_info->devinfo;
	struct device* dev = devinfo->dev;
#endif

	struct wland_bus *bus_if = dev_get_drvdata(dev);
	struct wland_private* drvr = bus_if->drvr;
	struct wland_if *ifp = drvr->iflist[0];
	struct net_device *ndev = ifp->ndev;
	struct wland_cfg80211_profile *profile = ndev_to_prof(ndev);

	u8 type;
	u8 subtype;
	u32 retval = 0;

	struct rx_pkt_attrib *pattrib = & precv_frame->attrib;

	u8 *ptr = precv_frame->rx_data;
	u8 ver =(unsigned char) (*ptr)&0x3 ;

	if (ver !=PROTOCOL_VERSION)
		return -1;

	pattrib->encrypt = profile->sec.security;
	type =  wland_get_type(ptr);
	subtype = wland_get_sub_type(ptr); //bit(7)~bit(2)

	pattrib->to_fr_ds = get_tofr_ds(ptr);

	pattrib->frag_num = GetFragNum(ptr);
	pattrib->seq_num = GetSequence(ptr);//printk("seq_num=%d\n",pattrib->seq_num);

	pattrib->pw_save = GetPwrMgt(ptr);
	pattrib->mdata = GetMData(ptr);
	pattrib->privacy = GetPrivacy(ptr);
	pattrib->order = GetOrder(ptr);

	switch (type) {
	case WIFI_MGT_TYPE: //mgnt
		break;
	case WIFI_CTRL_TYPE: //ctrl
		break;
	case WIFI_DATA_TYPE: //data
		pattrib->qos = (subtype & BIT7)? 1:0;
		retval = wland_parse_recv_data_frame(rx_info, precv_frame, ifp);
		if (!retval)
			//WLAND_ERR("retval = %d\n",retval);

		break;
	default:

		break;
	}

	return retval;
}

int wland_frames_prehandle(struct wland_rx_info *rx_info, struct recv_frame *rframe)
{
	int ret = 0;
	WLAND_DBG(RX, INFO, "ENTER\n");

	ret = wland_parse_recv_frame(rx_info, rframe);

	WLAND_DBG(RX, INFO, "DONE ret=%d\n",ret);
	return ret;
}

int wland_process_recv_indicatepkts(struct wland_rx_info *rx_info, struct recv_frame *prframe)
{
	int retval = 0;

	if (1) {
		if(wland_recv_indicatepkt_reorder(rx_info, prframe))// including perform A-MPDU Rx Ordering Buffer Control
			return -1;
	} else { //B/G mode
		retval = wland_hdr_to_ethhdr(prframe);
		if(retval != 0) {
			return retval;
		}

		if(1) {
			wland_recv_indicatepkt(rx_info, prframe);
		} else {
			retval = -1;
			return retval;
		}

	}

	return retval;

}

int wland_frames_posthandle(struct wland_rx_info *rx_info, struct recv_frame *prframe)
{
	int ret = 0;

	WLAND_DBG(RX, INFO, "ENTER\n");

	ret = wland_process_recv_indicatepkts(rx_info, prframe);

	WLAND_DBG(RX, INFO, "DONE ret=%d\n",ret);
	return ret;
}
int wland_handle_frames(struct wland_rx_info *rx_info, struct recv_frame *rframe)
{
	int ret = 0;

	ret = wland_frames_prehandle(rx_info, rframe);
	if (ret) {
		WLAND_DBG(RX, INFO, "Pre_handle failed, ret=%d",ret);
		return -1;
	}
	ret = wland_frames_posthandle(rx_info, rframe);
	if (ret) {
		WLAND_DBG(RX, INFO, "Post_handle failed, ret=%d\n",ret);
		return -1;
	}
	return ret;
}

static int wland_process_80211_pkt(struct wland_rx_info *rx_info, struct sk_buff *skb)
{
	u8 *buf; int ret = 0;
	struct rx_pkt_attrib *pattrib = NULL;
	struct recv_frame *precvframe = NULL;
	struct list_head *pfree_recv_queue = &rx_info->free_recv_queue;
	u32 mtu;

	mtu = USB_MAX_PKT_SIZE;

	precvframe = wland_recvframe_deq(&rx_info->free_recv_lock,
		pfree_recv_queue, 2, &rx_info->free_recv_cnt);

	if (precvframe==NULL) {
		WLAND_ERR("No recv_frame to use!\n");
		dev_kfree_skb(skb);
		return -1;
	}

	INIT_LIST_HEAD(&precvframe->list);
	pattrib = &precvframe->attrib;

	buf = skb->data;
	// pull hdr from the skb
	pattrib->pkt_len = (u16) (buf[0] | ((buf[1] & 0x0F) << 8)) - HOST_MSG_HEADER_LEN;
	skb_pull(skb, HOST_MSG_HEADER_LEN);

	precvframe->rx_data = precvframe->rx_tail = skb->data;
	precvframe->rx_end = skb->data + mtu;
	precvframe->pkt = skb;
	precvframe->len = 0;

	if (wland_recvframe_put(precvframe, pattrib->pkt_len) == NULL) {
		WLAND_ERR("Move rx_tail failed, pkt_len=%d, mtu=%d!\n",
			pattrib->pkt_len, mtu);
		goto fail;
	}

	ret = wland_handle_frames(rx_info, precvframe);
	if (ret)
		goto fail;
	return ret;

fail:
	if (precvframe->pkt){
		dev_kfree_skb(precvframe->pkt);
		precvframe->pkt = NULL;
	}
	wland_recvframe_enq(&rx_info->free_recv_lock, &rx_info->free_recv_queue,
		&precvframe->list2, &rx_info->free_recv_cnt);
	return ret;
}
#endif

#ifdef WLAND_RX_8023_REORDER
static int wland_process_8023_pkt_reorder(struct wland_rx_info *rx_info,
	struct sk_buff *skb)
{
	u8 *buf; int ret = 0;
	struct rx_pkt_attrib *pattrib = NULL;
	struct recv_frame *precvframe = NULL;
	struct list_head *pfree_recv_queue = &rx_info->free_recv_queue;
	struct wland_if *ifp = netdev_priv(skb->dev);
	u8 *mac;

	u32 mtu;
	unsigned long flags;
	struct ethhdr *eh = (struct ethhdr *) (skb->data + WID_HEADER_LEN_RX);
	struct rx_reorder_msg *reorder_msg;
#ifdef WLAND_DEAMSDU_RX
    enum deamsdu_proc_e deamsdu_proc;
#endif

	WLAND_DBG(RX, TRACE, "Enter\n");
#ifdef WLAND_DMA_RX1536_BLOCKS
	mtu = 1536*12;
#else
	mtu = 1536;
#endif

	if (ifp == NULL) {
		WLAND_ERR("ifp is NULL\n");
		if (skb)
			dev_kfree_skb(skb);
		return -1;
	}
	if (skb->len <= 14) {
		WLAND_ERR("skb len error:%d\n", skb->len);
		if (skb)
			dev_kfree_skb(skb);
		return -1;
	}

	mtu = USB_MAX_PKT_SIZE;

	precvframe = wland_recvframe_deq(&rx_info->free_recv_lock,
		pfree_recv_queue, 2, &rx_info->free_recv_cnt);

	if (precvframe==NULL) {
		WLAND_ERR("No recv_frame to use!\n");
		dev_kfree_skb(skb);
		return -1;
	}

	INIT_LIST_HEAD(&precvframe->list);
	pattrib = &precvframe->attrib;

	buf = skb->data;
	// pull hdr from the skb

	pattrib->seq_num = (buf[5]<<4) | ((buf[4] & 0xF0) >> 4);
	pattrib->qos = (wland_get_sub_type(buf+2) & BIT7)? 1:0;
	pattrib->eth_type = ntohs(eh->h_proto);
	pattrib->priority = buf[4] & 0x0F;
	pattrib->pkt_len = (u16) (buf[0] | ((buf[1] & 0x0F) << 8)) - WID_HEADER_LEN_RX;
	skb_pull(skb, WID_HEADER_LEN_RX);

	precvframe->rx_data = precvframe->rx_tail = skb->data;
	precvframe->rx_end = skb->data + mtu;
	precvframe->pkt = skb;
	precvframe->len = 0;
#ifdef WLAND_DEAMSDU_RX
    precvframe->deamsdu_order = wland_get_deamsdu_order(buf + 2);
#endif
	//TODO analyze amsdu bit.
	pattrib->amsdu = 0;

	if (wland_recvframe_put(precvframe, pattrib->pkt_len) == NULL) {
		WLAND_ERR("Move rx_tail failed, pkt_len=%d, mtu=%d!\n",
			pattrib->pkt_len, mtu);
		goto fail;
	}

	if (!pattrib->amsdu) {
		if ((pattrib->qos!=1) || (pattrib->eth_type == ETH_P_PAE) ||
			(wland_is_mcast(eh->h_dest))) {
			return wland_recv_indicatepkt(rx_info, precvframe);
		}
	}

	if (ifp->vif->mode == WL_MODE_BSS)
		mac = eh->h_dest;
	else if (ifp->vif->mode == WL_MODE_AP)
		mac = eh->h_source;
	else {
		WLAND_ERR("error mode:%d!\n", ifp->vif->mode);
		ret = -1;
        goto fail;
	}

	spin_lock_irqsave(&rx_info->rx_reorder_msg_lock, flags);

	list_for_each_entry(reorder_msg, &rx_info->rx_reorder_msg_list, list) {
		if (!memcmp(mac, reorder_msg->mac_addr, ETH_ALEN)) {
			precvframe->preorder_ctrl = &reorder_msg->preorder_ctrl[pattrib->priority];
			break;
		}
	}
	if (&reorder_msg->list == &rx_info->rx_reorder_msg_list) {
		WLAND_DBG(CFG80211, INFO, "add new rx_preorder_msg member:ifx:%d, mode:%d, %pM -> %pM\n",
			ifp->bssidx, ifp->vif->mode, eh->h_source, eh->h_dest);
		reorder_msg = wland_rx_reorder_msg_init(rx_info, mac);
		if (!reorder_msg) {
			spin_unlock_irqrestore(&rx_info->rx_reorder_msg_lock, flags);
			WLAND_ERR("malloc reorder_msg fail\n");
			ret =  -1;
            goto fail;
		}
		list_add_tail(&reorder_msg->list, &rx_info->rx_reorder_msg_list);
		precvframe->preorder_ctrl = &reorder_msg->preorder_ctrl[pattrib->priority];
	}

#ifdef WLAND_DEAMSDU_RX
    /* all frame contexts are ready and now check whether to do rx-reorder */
    deamsdu_proc = wland_deamsdu_rx_process((void *)precvframe, pattrib->seq_num);
    if (deamsdu_proc == DEAMSDU_PROC_WAIT_NEXT) {
    	spin_unlock_irqrestore(&rx_info->rx_reorder_msg_lock, flags);
        return 0;
    } else if (deamsdu_proc == DEAMSDU_PROC_MSDUS_DONE) {
        /* all MSDUs in AMSDU are ready for rx-reorder */
        precvframe = (struct recv_frame *)(precvframe->preorder_ctrl->curr_deamsdu);
        pattrib = &precvframe->attrib;
    } else if (deamsdu_proc == DEAMSDU_PROC_ERROR) {
    	spin_unlock_irqrestore(&rx_info->rx_reorder_msg_lock, flags);
        ret = -1;

        goto fail;
    }
#endif
	spin_unlock_irqrestore(&rx_info->rx_reorder_msg_lock, flags);

	if (!pattrib->amsdu) {
		//wland_hdr_to_ethhdr(prframe);
		if (precvframe->preorder_ctrl->enable == false) {

			precvframe->preorder_ctrl->indicate_seq = pattrib->seq_num;

			wland_recv_indicatepkt(rx_info, precvframe);

			precvframe->preorder_ctrl->indicate_seq =
				(precvframe->preorder_ctrl->indicate_seq + 1)%4096;

			return 0;
		}
	}


	WLAND_DBG(RX, DEBUG,
		"priority:%d indicate=%d seq=%d\n", pattrib->priority,
		precvframe->preorder_ctrl->indicate_seq, pattrib->seq_num);

	spin_lock_irqsave(&precvframe->preorder_ctrl->pending_recvframe_queue_lock, flags);

	if (wland_check_indicate_seq(precvframe->preorder_ctrl, pattrib->seq_num)) {
		spin_unlock_irqrestore(&precvframe->preorder_ctrl->pending_recvframe_queue_lock, flags);
		WLAND_DBG(RX, DEBUG, "check_indicate_seq fail\n");
		goto reorder_fail;
	}
	spin_unlock_irqrestore(&precvframe->preorder_ctrl->pending_recvframe_queue_lock, flags);

	if (wland_enqueue_reorder_recvframe(precvframe->preorder_ctrl, precvframe)) {
		WLAND_DBG(RX, DEBUG, "enqueue_reorder_recvframe fail\n");
		goto reorder_fail;
	}

	if (wland_recv_indicatepkts_in_order(rx_info, precvframe->preorder_ctrl, false) == true) {
		if (!timer_pending(&precvframe->preorder_ctrl->reordering_ctrl_timer))
			mod_timer(&precvframe->preorder_ctrl->reordering_ctrl_timer,
				jiffies + msecs_to_jiffies(REORDER_WAIT_TIME));

	} else {
		if (timer_pending(&precvframe->preorder_ctrl->reordering_ctrl_timer))
			del_timer_sync(&precvframe->preorder_ctrl->reordering_ctrl_timer);
	}

	return 0;

#ifndef WLAND_DEAMSDU_RX
reorder_fail:
#endif
fail:
	if (precvframe->pkt){
		dev_kfree_skb(precvframe->pkt);
		precvframe->pkt = NULL;
	}
	wland_recvframe_enq(&rx_info->free_recv_lock, &rx_info->free_recv_queue,
		&precvframe->list2, &rx_info->free_recv_cnt);
	return ret;

#ifdef WLAND_DEAMSDU_RX
reorder_fail:
    wland_deamsdu_rx_free((void *)precvframe);

    return ret;
#endif
}

#endif

#ifdef WLAND_WLAN0_NOSCAN_WHEN_P2P0_DATAINCOMING
struct pkt_recv_statistics prs;
/* whether recved RECV_CNT pkts in last RECV_TIME ms?*/
int wland_p2p_pkt_recv_statistics(struct pkt_recv_statistics *p, int cnt, int ms) {
	u8 i = 0;
	unsigned long pkt_time[cnt];
	memcpy(pkt_time, p->time, sizeof(p->time));

	for(i=0;i<cnt;i++) {
		if((jiffies - pkt_time[i]) >= msecs_to_jiffies(ms)) {
			WLAND_DBG(DEFAULT, INFO, "jiff:%ld %d pkt? no \n", msecs_to_jiffies(ms), cnt);
			return 0;
		}
	}
	WLAND_DBG(DEFAULT, INFO, "%d pkt? yes\n", cnt);
	return 1;
}

static void wland_p2p_recv_pkt_inc(struct pkt_recv_statistics *p, int cnt) {
	p->time[p->index] = jiffies;
	p->index++;
	p->index = p->index % cnt;
}
#endif

static void wland_process_rx_datapkt(struct wland_bus *bus_if,
	struct wland_rx_info *rx_info, struct sk_buff *pkt)
{
	struct wland_if *ifp = netdev_priv(pkt->dev);
	struct wland_cfg80211_vif *vif = ifp->vif;
	struct wland_cfg80211_connect_info *conn_info = &ifp->vif->conn_info;
	//u8 *dhcp_server_ip = vif->profile.dhcp_server_ip;

#ifdef WLAND_RX_SOFT_MAC
	wland_process_80211_pkt(rx_info, pkt);
#elif defined WLAND_RX_8023_REORDER
	if ((vif->wdev.iftype == NL80211_IFTYPE_STATION) && conn_info->wmm_enable && conn_info->n_enable
		&& (!timer_pending(&conn_info->connect_restorework_timeout)))
		wland_process_8023_pkt_reorder(rx_info, pkt);
	else if (vif->wdev.iftype == NL80211_IFTYPE_P2P_CLIENT || vif->wdev.iftype == NL80211_IFTYPE_P2P_GO) {
#ifdef WLAND_WLAN0_NOSCAN_WHEN_P2P0_DATAINCOMING
		wland_p2p_recv_pkt_inc(&prs, RECV_CNT);
#endif
		wland_process_8023_pkt_reorder(rx_info, pkt);
	} else {
		//wland_process_8023_pkt_reorder(rx_info, pkt);
		skb_pull(pkt, WID_HEADER_LEN_RX);
		wland_process_8023_pkt(bus_if, pkt);
	}
#else
	skb_pull(pkt, WID_HEADER_LEN);
	wland_process_8023_pkt(bus_if, pkt);
#endif

}

#ifdef WLAND_USE_RXQ
static int wland_process_rxframes(struct wland_rx_info *rx_info)
#else
int wland_process_rxframes(struct wland_rx_info *rx_info, struct sk_buff *pkt)
#endif
{
#ifdef WLAND_SDIO_SUPPORT
	struct wland_sdio* bus = rx_info->bus;
	struct device* dev = bus->sdiodev->dev;

#else
	struct wland_usbdev_info* devinfo = rx_info->devinfo;
	struct device* dev = devinfo->dev;
#endif
	int ret = 0;
	u8 rx_type, msg_type, *buf;
	u16 size = 0, rx_len = 0, wid = 0;
#ifdef WLAND_USE_RXQ
	unsigned long flags = 0;
	struct sk_buff *skb = NULL;	/* Packet for event or data frames */
#else
	struct sk_buff *skb = pkt;
#endif

	struct wland_event_msg event_packet;
	struct wland_bus *bus_if = dev_get_drvdata(dev);
	struct wland_private *drvr = bus_if->drvr;
#ifdef WLAND_SMART_CONFIG_SUPPORT
	struct wland_if *ifp = drvr->iflist[0];
#endif
	WLAND_DBG(RX, TRACE, "Enter\n");
	if (bus_if->state == WLAND_BUS_DOWN) {
		WLAND_ERR("Bus down 3, ret\n");
		return ret;
	}

#ifdef WLAND_USE_RXQ
	while (wland_pktq_mlen(&rx_info->rxq, ~rx_info->flowcontrol)) {
		wland_dhd_os_sdlock_rxq(rx_info, &flags);
		skb = wland_pktq_mdeq(&rx_info->rxq);
		wland_dhd_os_sdunlock_rxq(rx_info, &flags);
		atomic_dec(&rx_info->rx_dpc_tskcnt);
		if (skb == NULL) {
			break;
		}
		//printk("mdeq, pri:%d, num:%d, %02x %02x, skblen:%d\n", rx_info->rxq.hi_prec, rx_info->rxq.len,
			//skb->data[0], skb->data[1], skb->len);
#else
		if (skb== NULL) {
			WLAND_ERR("pkt is null, ret\n");
			return ret;
		} else {
			atomic_dec(&rx_info->rx_dpc_tskcnt);
#endif
		/*
		 * process and remove protocol-specific header
		 */

		//WLAND_DBG(BUS, TRACE, "Enter,%s,count:%u\n", dev_name(dev), skb->len);


		buf = skb->data;
		// pull hdr from the skb
		size = skb->len;
		rx_len = (u16) (buf[0] | ((buf[1] & 0x0F) << 8));

		//printk("size=%d, rx_len=%d, addr:%x\n", size, rx_len, (unsigned int)buf);
		if (rx_len > size) {
			WLAND_ERR("read payload_len invalid! rx_len:%d size:%d\n"
				, rx_len, size);
			wland_pkt_buf_free_skb(skb);
			return -EIO;
		}
		rx_type = (u8) buf[1] >> 4;
		//skb->len = rx_len;

		WLAND_DBG(RX, DEBUG, "rx type:%d\n", rx_type);

		if (rx_type == PKT_TYPE_IND || rx_type == PKT_TYPE_DATA_MAC1) {
			WLAND_DBG(RX, DEBUG, "MSDU data in 1.\n");
			WLAND_DUMP(RX_MSDU, skb->data, skb->len,
				"RX Data (BIN DATA), len:%u\n", skb->len);

#ifdef WLAND_SDIO_SUPPORT
			wland_sdio_clkctl(bus, CLK_AVAIL);
#endif

#ifdef WLAND_5991H_MAC1_SUPPORT
			if ((rx_type == PKT_TYPE_IND) || (rx_type == PKT_TYPE_AGGR_MAC0))
				skb->dev = drvr->iflist[0]->ndev;
			else if ((rx_type == PKT_TYPE_DATA_MAC1) || (rx_type == PKT_TYPE_AGGR_MAC1)) {
#ifdef WLAND_P2P_SUPPORT
				skb->dev = drvr->iflist[1]->ndev;
#else
				WLAND_ERR("p2p is not supported but we get data pkt from interface 1\n");
				wland_pkt_buf_free_skb(skb);
				return 0;
#endif
			}
#endif

			wland_process_rx_datapkt(bus_if, rx_info, skb);

		} else if ((rx_type == PKT_TYPE_AGGR_MAC0) || (rx_type == PKT_TYPE_AGGR_MAC1)) {
#ifdef WLAND_RX_AGGRPKTS
			struct sk_buff *skb_inblock = NULL;

#ifdef WLAND_SDIO_SUPPORT
			wland_sdio_clkctl(bus, CLK_AVAIL);
#endif
			WLAND_DBG(RX, DEBUG, "MSDU data in 2.\n");

			while(!((buf[rx_len] == 0) && (buf[rx_len+1] == 0))) {

				skb_inblock = __dev_alloc_skb((rx_len+NET_IP_ALIGN+3), GFP_KERNEL);
				if(skb_inblock == NULL){
					WLAND_ERR("no more space!\n");
					wland_pkt_buf_free_skb(skb);
					return -EBADE;
				}
				skb_reserve(skb_inblock, NET_IP_ALIGN);
				//4byte align
				wland_pkt_word_align(skb_inblock);

				skb_put(skb_inblock, rx_len);
				memcpy(skb_inblock->data, buf, rx_len);
				WLAND_DUMP(RX_MSDU, skb_inblock->data,  min(64u, skb_inblock->len),
					"RX Data (BIN DATA), len:%u\n", skb_inblock->len);

#ifdef WLAND_5991H_MAC1_SUPPORT
				if ((rx_type == PKT_TYPE_IND) || (rx_type == PKT_TYPE_AGGR_MAC0))
					skb_inblock->dev = drvr->iflist[0]->ndev;
				else if ((rx_type == PKT_TYPE_DATA_MAC1) || (rx_type == PKT_TYPE_AGGR_MAC1)) {
#ifdef WLAND_P2P_SUPPORT
					skb_inblock->dev = drvr->iflist[1]->ndev;
#else
					WLAND_ERR("p2p is not supported but we get data pkt from interface 1\n");
					wland_pkt_buf_free_skb(skb);
					return 0;
#endif
				}
#endif

				wland_process_rx_datapkt(bus_if, rx_info, skb_inblock);

				skb_pull(skb, rx_len);
				buf = skb->data;

				rx_len = (u16) (buf[0] | ((buf[1] & 0x0F) << 8));

				if (skb->len < rx_len) {
					WLAND_ERR("read payload_len invalid! rx_len:%d skb->len:%d\n"
						, rx_len, skb->len);
					break;
				}

				rx_type = (u8) buf[1] >> 4;
				if((rx_type != PKT_TYPE_AGGR_MAC0) && (rx_type != PKT_TYPE_AGGR_MAC1)) {
					//WLAND_ERR("Bad aggr pkts!\n");
					wland_pkt_buf_free_skb(skb);
					return 0;
				}

			}

			if (skb->len < rx_len) {
				//WLAND_ERR("Too short pkt!\n");
				wland_pkt_buf_free_skb(skb);
				return 0;
			} else {
#ifdef WLAND_5991H_MAC1_SUPPORT
				if ((rx_type == PKT_TYPE_IND) || (rx_type == PKT_TYPE_AGGR_MAC0))
					skb->dev = drvr->iflist[0]->ndev;
				else if ((rx_type == PKT_TYPE_DATA_MAC1) || (rx_type == PKT_TYPE_AGGR_MAC1)) {
#ifdef WLAND_P2P_SUPPORT
					skb->dev = drvr->iflist[1]->ndev;
#else
					WLAND_ERR("p2p is not supported but we get data pkt from interface 1\n");
					wland_pkt_buf_free_skb(skb);
					return 0;
#endif
				}
#endif
				skb_trim(skb, rx_len);
				WLAND_DUMP(RX_MSDU, skb->data, min(64u, skb->len),
					"RX Data (BIN DATA), len:%u\n", skb->len);

				wland_process_rx_datapkt(bus_if, rx_info, skb);

			}
#else
			WLAND_ERR("WLAND_RX_AGGRPKTS is not defined!\n");
			wland_pkt_buf_free_skb(skb);
			ret = -EBADE;
#endif

		} else if ((rx_type == PKT_TYPE_CFG_RSP) || (rx_type == PKT_TYPE_CFG_MAC1)){

			msg_type = buf[2];
			memset(&event_packet, 0, sizeof(event_packet));

			/* offset frame hdr */
			event_packet.datalen = rx_len - WID_HEADER_LEN;
			buf += WID_HEADER_LEN;

			switch (msg_type) {
			case WLAND_WID_MSG_RESP:
				WLAND_DBG(RX, TRACE,
					"Receive response(%s:total_len:%u,rx_len:%u,rx_type:%u)\n",
					dev_name(dev),
					skb->len, rx_len, rx_type);
				WLAND_DUMP(RX_WIDRSP, skb->data, skb->len,
					"RX Data (WID_MSG_RESP), len:%u\n", skb->len);
				spin_lock_bh(&rx_info->rxctl_lock);
				rx_info->rxctl = rx_info->rxbuf;
				rx_info->rxlen = rx_len;
				memcpy(rx_info->rxctl, skb->data, rx_len);
				spin_unlock_bh(&rx_info->rxctl_lock);
#ifdef WLAND_SDIO_SUPPORT
				wland_dhd_os_ioctl_resp_wake(bus);
#else
				wland_usb_data_resp_wake(devinfo);
#endif
				wland_pkt_buf_free_skb(skb);
				break;
			case WLAND_WID_MSG_NETINFO:
				WLAND_DBG(RX, TRACE,
					"Receive info notify(%s:total_len:%u,rx_len:%u,rx_type:%u)\n",
					dev_name(dev),
					skb->len, rx_len, rx_type);
				WLAND_DUMP(RX_NETINFO, skb->data, skb->len,
					"RX Data (WID_MSG_NETINFO), len:%u\n",
					skb->len);
#ifdef WLAND_SMART_CONFIG_SUPPORT
				if (ifp->sniffer_enable) {
					skb->dev = ifp->ndev;
					wland_handle_monitor_info(rx_info, skb);
				} else {
#endif
					wland_handle_async_info(bus_if->drvr, &event_packet, buf);
					wland_pkt_buf_free_skb(skb);
#ifdef WLAND_SMART_CONFIG_SUPPORT
				}
#endif
				break;
			case WLAND_WID_MSG_EVENT:
				WLAND_DBG(RX, DEBUG,
					"Receive Network event(%s:total_len:%u,rx_len:%u,rx_type:%u)\n",
					dev_name(dev),
					skb->len, rx_len, rx_type);
				WLAND_DUMP(RX_NETEVENT, skb->data, skb->len,
					"RX Data (WID_MSG_NETEVENT), len:%u\n",
					skb->len);
				wland_handle_network_link_event
					(bus_if->drvr, &event_packet,buf);
				wland_pkt_buf_free_skb(skb);
				break;
			case WLAND_WID_MSG_MAC_STATUS:
				WLAND_DBG(RX, TRACE,
					"Receive mac status notify(%s:total_len:%u,rx_len:%u,rx_type:%u)\n",
					dev_name(dev),
					skb->len, rx_len, rx_type);
				WLAND_DUMP(RX_MACSTAT, skb->data, skb->len,
					"RX Data (WID_MSG_MAC_STATUS), len:%u\n",
					skb->len);
				wid = MAKE_WORD16(buf[4], buf[5]);
				if(wid == WID_STATUS)
					wland_handle_mac_status(bus_if->drvr, &event_packet, buf);
				else if(wid == WID_HUT_LOG_STATS)
					wland_update_rf_rxtest_result(bus_if->drvr, buf);
				else
					WLAND_ERR("Received Message wid incorrect.\n");
				wland_pkt_buf_free_skb(skb);
				break;
			default:
				WLAND_ERR("receive invalid frames!\n");
				wland_pkt_buf_free_skb(skb);
				ret = -EBADE;
				break;
			}
		} else {
			WLAND_ERR("receive invalid type!\n");
			wland_pkt_buf_free_skb(skb);
			ret = -EBADE;
		}

		WLAND_DBG(RX, TRACE,
			"Process rxframes, rx_info->rx_dpc_tskcnt=%d\n",
			atomic_read(&rx_info->rx_dpc_tskcnt));
	}
	return ret;

}

#ifdef WLAND_USE_RXQ
static void wland_rx_dpc(struct wland_rx_info *rx_info)
{
#ifdef WLAND_SDIO_SUPPORT
	struct wland_bus *bus_if = rx_info->bus->sdiodev->bus_if;
#else
	struct wland_bus *bus_if = rx_info->devinfo->bus_pub.bus;
#endif

	WLAND_DBG(RX, TRACE, "Enter\n");

	if (bus_if->state == WLAND_BUS_DOWN) {
		WLAND_ERR("Bus is down and go out.\n");
		goto done;
	}

	wland_process_rxframes(rx_info);

done:
	WLAND_DBG(RX, TRACE, "Done\n");
}

static void wland_RxWorker(struct work_struct *work)
{
	struct wland_rx_info *rx_info = container_of(work, struct wland_rx_info, RxWork);
	if (rx_info) {
		if (atomic_read(&rx_info->rx_dpc_tskcnt) > 0) {
			wland_rx_dpc(rx_info);
		}
	}
}
#endif

struct wland_rx_info* wland_rx_init(void *arg)
{
	struct wland_rx_info* rx_info;

	WLAND_DBG(RX, TRACE, "Enter\n");

	rx_info = kzalloc(sizeof(struct wland_rx_info), GFP_KERNEL);
	if (!rx_info) {
		WLAND_ERR("no enough buffer for rx_info!\n");
		return NULL;
	}

	rx_info->flowcontrol = 0;

#ifdef WLAND_SDIO_SUPPORT
	rx_info->bus = (struct wland_sdio *)arg;
#else
	rx_info->devinfo = (struct wland_usbdev_info *)arg;
#endif

#ifdef WLAND_USE_RXQ
	wland_pktq_init(&rx_info->rxq, (PRIOMASK + 1), RXQLEN);

	INIT_WORK(&rx_info->RxWork, wland_RxWorker);
	rx_info->wland_rxwq = create_singlethread_workqueue("wland_rxwq");
	if (!rx_info->wland_rxwq) {
		WLAND_ERR("insufficient memory to create rxworkqueue.\n");
		kfree(rx_info);
		return NULL;
	}
#endif

	spin_lock_init(&rx_info->rxqlock);
	spin_lock_init(&rx_info->rxctl_lock);
	atomic_set(&rx_info->rx_dpc_tskcnt, 0);

#if defined WLAND_RX_SOFT_MAC || defined WLAND_RX_8023_REORDER
	INIT_LIST_HEAD(&rx_info->free_recv_queue);
	spin_lock_init(&rx_info->free_recv_lock);

	rx_info->recv_frames =
		wland_free_recv_queue_init(&rx_info->free_recv_queue, NR_RECVFRAME);

	if (!rx_info->recv_frames) {
		WLAND_ERR("no enough buffer for free recv frame queue!\n");
#ifdef WLAND_USE_RXQ
		destroy_workqueue(rx_info->wland_rxwq);
#endif
		kfree(rx_info);
		return NULL;
	}
	rx_info->free_recv_cnt = NR_RECVFRAME;

	spin_lock_init(&rx_info->rx_reorder_msg_lock);
	INIT_LIST_HEAD(&rx_info->rx_reorder_msg_list);
#endif

	WLAND_DBG(RX, TRACE, "Done\n");
	return rx_info;
}

void wland_rx_uinit(struct wland_rx_info* rx_info)
{
#if defined WLAND_RX_SOFT_MAC || defined WLAND_RX_8023_REORDER
	unsigned long flags;
	struct rx_reorder_msg *reorder_msg, *reorder_msg1;

	spin_lock_irqsave(&rx_info->rx_reorder_msg_lock, flags);
	list_for_each_entry_safe(reorder_msg, reorder_msg1,
		&rx_info->rx_reorder_msg_list, list) {
		wland_rx_reorder_msg_deinit(rx_info, reorder_msg);
	}
	spin_unlock_irqrestore(&rx_info->rx_reorder_msg_lock, flags);
#endif

#ifdef WLAND_USE_RXQ
	cancel_work_sync(&rx_info->RxWork);
	if (rx_info->wland_rxwq)
		destroy_workqueue(rx_info->wland_rxwq);

	wland_pktq_flush(&rx_info->rxq, true, NULL, NULL);
#endif
	spin_lock_bh(&rx_info->rxctl_lock);
	rx_info->rxlen = 0;
	spin_unlock_bh(&rx_info->rxctl_lock);

#if defined WLAND_RX_SOFT_MAC || defined WLAND_RX_8023_REORDER

	wland_recvframe_free_q(&rx_info->free_recv_queue);

	if (rx_info->recv_frames)
		vfree(rx_info->recv_frames);
#endif

	if (rx_info->rxbuf) {
		kfree(rx_info->rxbuf);
		rx_info->rxctl = rx_info->rxbuf = NULL;
		rx_info->rxlen = 0;
	}

	kfree(rx_info);
	rx_info = NULL;
}
