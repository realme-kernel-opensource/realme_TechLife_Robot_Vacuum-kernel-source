
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
#include <linux/random.h>
#include <net/cfg80211.h>
#include <net/rtnetlink.h>
#include <net/netlink.h>

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

#ifdef WLAND_P2P_SUPPORT

/* parameters used for p2p escan */
#define P2PAPI_SCAN_NPROBES                     1
#define P2PAPI_SCAN_DWELL_TIME_MS               80
#define P2PAPI_SCAN_SOCIAL_DWELL_TIME_MS        40
#define P2PAPI_SCAN_HOME_TIME_MS                60
#define P2PAPI_SCAN_NPROBS_TIME_MS              30
#define P2PAPI_SCAN_AF_SEARCH_DWELL_TIME_MS     100

/* scan connect timeout */
#define WL_SCAN_CONNECT_DWELL_TIME_MS           200
#define WL_SCAN_JOIN_PROBE_INTERVAL_MS          20

#define WLAND_SCB_TIMEOUT_VALUE	                20

/* p2p const */
#define P2P_VER			                        9	/* P2P version: 9=WiFi P2P v1.0 */
#define P2P_PUB_AF_CATEGORY	                    0x04
#define P2P_PUB_AF_ACTION	                    0x09
#define P2P_AF_CATEGORY		                    0x7F
#define P2P_OUI			                        "\x50\x6F\x9A"	/* P2P OUI */
#define P2P_OUI_LEN		                        3	/* P2P OUI length */

/* Action Frame Constants */
#define DOT11_ACTION_HDR_LEN	                2	/* action frame category + action */
#define DOT11_ACTION_CAT_OFF	                0	/* category offset */
#define DOT11_ACTION_ACT_OFF	                1	/* action offset */

#define P2P_AF_DWELL_TIME		                200
#define P2P_AF_MIN_DWELL_TIME		            100
#define P2P_AF_MED_DWELL_TIME		            400
#define P2P_AF_LONG_DWELL_TIME		            1000
#define P2P_AF_TX_MAX_RETRY		                2
#define P2P_AF_MAX_WAIT_TIME		            2000
#define P2P_INVALID_CHANNEL		                -1
#define P2P_CHANNEL_SYNC_RETRY		            3

#define P2P_AF_FRM_SCAN_MAX_WAIT	            1500
#define P2P_DEFAULT_SLEEP_TIME_VSDB	            200

/* WiFi P2P Public Action Frame OUI Subtypes */
#define P2P_PAF_GON_REQ		                    0	/* Group Owner Negotiation Req */
#define P2P_PAF_GON_RSP		                    1	/* Group Owner Negotiation Rsp */
#define P2P_PAF_GON_CONF	                    2	/* Group Owner Negotiation Confirm */
#define P2P_PAF_INVITE_REQ	                    3	/* P2P Invitation Request */
#define P2P_PAF_INVITE_RSP	                    4	/* P2P Invitation Response */
#define P2P_PAF_DEVDIS_REQ	                    5	/* Device Discoverability Request */
#define P2P_PAF_DEVDIS_RSP	                    6	/* Device Discoverability Response */
#define P2P_PAF_PROVDIS_REQ	                    7	/* Provision Discovery Request */
#define P2P_PAF_PROVDIS_RSP	                    8	/* Provision Discovery Response */
#define P2P_PAF_SUBTYPE_INVALID	                255	/* Invalid Subtype */

/* WiFi P2P Action Frame OUI Subtypes */
#define P2P_AF_NOTICE_OF_ABSENCE	            0	/* Notice of Absence */
#define P2P_AF_PRESENCE_REQ		                1	/* P2P Presence Request */
#define P2P_AF_PRESENCE_RSP		                2	/* P2P Presence Response */
#define P2P_AF_GO_DISC_REQ		                3	/* GO Discoverability Request */

/* P2P Service Discovery related */
#define P2PSD_ACTION_CATEGORY		            0x04	/* Public action frame */
#define P2PSD_ACTION_ID_GAS_IREQ	            0x0A	/* GAS Initial Request AF */
#define P2PSD_ACTION_ID_GAS_IRESP	            0x0B	/* GAS Initial Response AF */
#define P2PSD_ACTION_ID_GAS_CREQ	            0x0C	/* GAS Comback Request AF */
#define P2PSD_ACTION_ID_GAS_CRESP	            0x0D	/* GAS Comback Response AF */

/*
 * struct wland_p2p_disc_st_le - set discovery state in firmware.
 *
 * @state   : requested discovery state (see enum wland_p2p_disc_state).
 * @chspec  : channel parameter for %WL_P2P_DISC_ST_LISTEN state.
 * @dwell   : dwell time in ms for %WL_P2P_DISC_ST_LISTEN state.
 */
struct wland_p2p_disc_st_le {
	u8 state;
	__le16 chspec;
	__le16 dwell;
};

/*
 * enum wland_p2p_disc_state - P2P discovery state values
 *
 * @WL_P2P_DISC_ST_SCAN     :   P2P discovery with wildcard SSID and P2P IE.
 * @WL_P2P_DISC_ST_LISTEN   : P2P discovery off-channel for specified time.
 * @WL_P2P_DISC_ST_SEARCH   : P2P discovery with P2P wildcard SSID and P2P IE.
 */
enum wland_p2p_disc_state {
	WL_P2P_DISC_ST_SCAN,
	WL_P2P_DISC_ST_LISTEN,
	WL_P2P_DISC_ST_SEARCH,
	WL_P2P_CONNECT_SCAN_RDA
};



/*
 * struct wland_p2p_pub_act_frame - WiFi P2P Public Action Frame
 *
 * @category    : P2P_PUB_AF_CATEGORY
 * @action      : P2P_PUB_AF_ACTION
 * @oui[3]      : P2P_OUI
 * @oui_type    : OUI type - P2P_VER
 * @subtype     : OUI subtype - P2P_TYPE_*
 * @dialog_token: nonzero, identifies req/rsp transaction
 * @elts[1]     : Variable length information elements.
 */
struct wland_p2p_pub_act_frame {
	u8 category;
	u8 action;
	u8 oui[3];
	u8 oui_type;
	u8 subtype;
	u8 dialog_token;
	u8 elts[1];
};

/**
 * struct wland_p2p_action_frame - WiFi P2P Action Frame
 *
 * @category: P2P_AF_CATEGORY
 * @OUI[3]  : OUI - P2P_OUI
 * @type    : OUI Type - P2P_VER
 * @subtype : OUI Subtype - P2P_AF_*
 * @dialog_token: nonzero, identifies req/resp tranaction
 * @elts[1] : Variable length information elements.
 */
struct wland_p2p_action_frame {
	u8 category;
	u8 oui[3];
	u8 type;
	u8 subtype;
	u8 dialog_token;
	u8 elts[1];
};

/*
 * struct wland_p2psd_gas_pub_act_frame - Wi-Fi GAS Public Action Frame
 *
 * @category        : 0x04 Public Action Frame
 * @action          : 0x6c Advertisement Protocol
 * @dialog_token    : nonzero, identifies req/rsp transaction
 * @query_data[1]   : Query Data. SD gas ireq SD gas iresp
 */
struct wland_p2psd_gas_pub_act_frame {
	u8 category;
	u8 action;
	u8 dialog_token;
	u8 query_data[1];
};

/*
 * struct wland_config_af_params - Action Frame Parameters for tx.
 *
 * @search_channel  : 1: search peer's channel to send af
 * @extra_listen    : keep the dwell time to get af response frame.
 */
struct wland_config_af_params {
	bool search_channel;
	bool extra_listen;
};

/*
 * wland_p2p_is_pub_action() - true if p2p public type frame.
 *
 * @frame       : action frame data.
 * @frame_len   : length of action frame data.
 *
 * Determine if action frame is p2p public action type
 */
static bool wland_p2p_is_pub_action(void *frame, u32 frame_len)
{
	struct wland_p2p_pub_act_frame *pact_frm =
		(struct wland_p2p_pub_act_frame *) frame;

	if (frame == NULL) {
		WLAND_DBG(CFG80211, TRACE, "P2P: frame = NULL\n");
		return false;
	}

	if (frame_len < sizeof(struct wland_p2p_pub_act_frame) - 1) {
		WLAND_DBG(CFG80211, TRACE, "P2P: frame_len error\n");
		return false;
	}

	if (pact_frm->category == P2P_PUB_AF_CATEGORY &&
		pact_frm->action == P2P_PUB_AF_ACTION &&
		pact_frm->oui_type == P2P_VER &&
		memcmp(pact_frm->oui, P2P_OUI, P2P_OUI_LEN) == 0) {
		WLAND_DBG(CFG80211, TRACE, "P2P: is pub action \n");
		return true;
	}

	WLAND_DBG(CFG80211, TRACE, "P2P: not pub action\n");
	return false;
}

/*
 * wland_p2p_is_p2p_action() - true if p2p action type frame.
 *
 * @frame       : action frame data.
 * @frame_len   : length of action frame data.
 *
 * Determine if action frame is p2p action type
 */
static bool wland_p2p_is_p2p_action(void *frame, u32 frame_len)
{
	struct wland_p2p_action_frame *act_frm =
		(struct wland_p2p_action_frame *) frame;

	if (frame == NULL)
		return false;

	if (frame_len < sizeof(struct wland_p2p_action_frame) - 1)
		return false;

	if (act_frm->category == P2P_AF_CATEGORY &&
		act_frm->type == P2P_VER &&
		memcmp(act_frm->oui, P2P_OUI, P2P_OUI_LEN) == 0)
		return true;

	return false;
}

/*
 * wland_p2p_is_gas_action() - true if p2p gas action type frame.
 *
 * @frame: action frame data.
 * @frame_len: length of action frame data.
 *
 * Determine if action frame is p2p gas action type
 */
static bool wland_p2p_is_gas_action(void *frame, u32 frame_len)
{
	struct wland_p2psd_gas_pub_act_frame *sd_act_frm;

	if (frame == NULL)
		return false;

	sd_act_frm = (struct wland_p2psd_gas_pub_act_frame *) frame;
	if (frame_len < sizeof(struct wland_p2psd_gas_pub_act_frame) - 1)
		return false;

	if (sd_act_frm->category != P2PSD_ACTION_CATEGORY)
		return false;

	if (sd_act_frm->action == P2PSD_ACTION_ID_GAS_IREQ ||
		sd_act_frm->action == P2PSD_ACTION_ID_GAS_IRESP ||
		sd_act_frm->action == P2PSD_ACTION_ID_GAS_CREQ ||
		sd_act_frm->action == P2PSD_ACTION_ID_GAS_CRESP)
		return true;

	return false;
}

/*
 * wland_p2p_set_firmware() - prepare firmware for peer-to-peer operation.
 *
 * @ifp     : ifp to use for iovars (primary).
 * @p2p_mac : mac address to configure for p2p_da_override
 */
static int wland_p2p_set_firmware(struct wland_if *ifp, u8 * p2p_mac)
{
	s32 ret = 0;
	u8 val = 1;

	wland_fil_iovar_data_set(ifp, "apsta", &val, sizeof(u8));

	/*
	 * In case of COB type, firmware has default mac address
	 * * After Initializing firmware, we have to set current mac address to
	 * * firmware for P2P device address
	 */
//	ret = wland_fil_iovar_data_set(ifp, "p2p_da_override", p2p_mac,
//		ETH_ALEN);
//	ret = wland_fil_set_cmd_data(ifp, WID_P2P_SET_DEV_ADDR, p2p_mac, ETH_ALEN);
 //       if(ret < 0)
//		WLAND_ERR("failed to update device address ret %d\n", ret);

	return ret;
}

/*
 * wland_p2p_generate_bss_mac() - derive mac addresses for P2P.
 *
 * @p2p     : P2P specific data.
 * @dev_addr: optional device address.
 *
 * P2P needs mac addresses for P2P device and interface. If no device
 * address it specified, these are derived from the primary net device, ie.
 * the permanent ethernet address of the device.
 */
void wland_p2p_generate_bss_mac(struct wland_p2p_info *p2p,
	u8 * dev_addr)
{
	struct wland_if *pri_ifp = p2p->bss_idx[P2PAPI_BSSCFG_PRIMARY].vif->ifp;
	bool local_admin = false;

	if (!dev_addr || is_zero_ether_addr(dev_addr)) {
		dev_addr = pri_ifp->mac_addr;
		local_admin = true;
	}

	/*
	 * Generate the P2P Device Address.  This consists of the device's
	 * * primary MAC address with the locally administered bit set.
	 */
	if (dev_addr)
		memcpy(p2p->dev_addr, dev_addr, ETH_ALEN);

	if (local_admin) {
		p2p->dev_addr[0] ^= 0x04;
		//p2p->dev_addr[0] |= 0x02;
	}
	/*
	 * Generate the P2P Interface Address.  If the discovery and connection
	 * * BSSCFGs need to simultaneously co-exist, then this address must be
	 * * different from the P2P Device Address, but also locally administered.
	 */
	memcpy(p2p->int_addr, p2p->dev_addr, ETH_ALEN);

	//p2p->int_addr[0] |= 0x02;
	p2p->int_addr[4] ^= 0x80;
}

/*
 * wland_p2p_scan_is_p2p_request() - is cfg80211 scan request a P2P scan.
 *
 * @request: the scan request as received from cfg80211.
 *
 * returns true if one of the ssids in the request matches the
 * P2P wildcard ssid; otherwise returns false.
 */

bool wland_p2p_scan_is_p2p_request(struct cfg80211_scan_request *request,
	struct wland_cfg80211_vif *vif)
{
	struct cfg80211_ssid *ssids = request->ssids;
	int i;

	if (vif->ifp->bssidx != P2PAPI_BSSCFG_PRIMARY)
		return true;

	for (i = 0; i < request->n_ssids; i++) {
		WLAND_DBG(CFG80211, TRACE, "comparing ssid \"%s\"",
			ssids[i].ssid);

		if (!memcmp(P2P_WILDCARD_SSID, ssids[i].ssid,
				P2P_WILDCARD_SSID_LEN))
			return true;
	}
	return false;
}

/*
 * wland_p2p_set_discover_state - set discover state in firmware.
 *
 * @ifp         : low-level interface object.
 * @state       : discover state to set.
 * @chanspec    : channel parameters (for state @WL_P2P_DISC_ST_LISTEN only).
 * @listen_ms   : duration to listen (for state @WL_P2P_DISC_ST_LISTEN only).
 */
static s32 wland_p2p_set_discover_state(struct wland_if *ifp, u8 state,
	u16 chanspec, u16 listen_ms)
{
	struct wland_p2p_disc_st_le discover_state;

	WLAND_DBG(CFG80211, TRACE, "enter\n");

	discover_state.state = state;
	discover_state.chspec = cpu_to_le16(chanspec);
	discover_state.dwell = cpu_to_le16(listen_ms);

	return wland_fil_iovar_data_set(ifp, "p2p_state", &discover_state,
		sizeof(discover_state));
}

/*
 * wland_p2p_deinit_discovery() - disable P2P device discovery.
 *
 * @p2p: P2P specific data.
 *
 * Resets the discovery state and disables it in firmware.
 */
static s32 wland_p2p_deinit_discovery(struct wland_p2p_info *p2p)
{
	u8 enable = 0;
	struct wland_cfg80211_vif *vif = p2p->bss_idx[P2PAPI_BSSCFG_DEVICE].vif;

	WLAND_DBG(CFG80211, TRACE, "enter\n");

	/*
	 * Set the discovery state to SCAN
	 */
	wland_p2p_set_discover_state(vif->ifp, WL_P2P_DISC_ST_SCAN, 0, 0);

	/*
	 * Disable P2P discovery in the firmware
	 */
	vif = p2p->bss_idx[P2PAPI_BSSCFG_PRIMARY].vif;

	return wland_fil_iovar_data_set(vif->ifp, "p2p_disc", &enable,
		sizeof(u8));
}

/*
 * wland_p2p_enable_discovery() - initialize and configure discovery.
 *
 * @p2p: P2P specific data.
 *
 * Initializes the discovery device and configure the virtual interface.
 */
static s32 wland_p2p_enable_discovery(struct wland_p2p_info *p2p)
{
	struct wland_cfg80211_vif *vif = p2p->bss_idx[P2PAPI_BSSCFG_DEVICE].vif;
	s32 ret = 0;
	u8 enable = 1;

	WLAND_DBG(CFG80211, TRACE, "Enter\n");

	if (!vif) {
		WLAND_ERR("P2P config device not available\n");
		ret = -EPERM;
		goto exit;
	}

	if (test_bit(P2P_STATUS_ENABLED, &p2p->status)) {
		WLAND_DBG(CFG80211, TRACE,
			"P2P config device already configured\n");
		goto exit;
	}

	/*
	 * Re-initialize P2P Discovery in the firmware
	 */
	vif = p2p->bss_idx[P2PAPI_BSSCFG_PRIMARY].vif;

	ret = wland_fil_iovar_data_set(vif->ifp, "p2p_disc", &enable,
		sizeof(u8));
	if (ret < 0) {
		WLAND_ERR("set p2p_disc error\n");
		goto exit;
	}
	vif = p2p->bss_idx[P2PAPI_BSSCFG_DEVICE].vif;

	ret = wland_p2p_set_discover_state(vif->ifp, WL_P2P_DISC_ST_SCAN, 0, 0);
	if (ret < 0) {
		WLAND_ERR("unable to set WL_P2P_DISC_ST_SCAN\n");
		goto exit;
	}

	/*
	 * Set wsec to any non-zero value in the discovery bsscfg
	 * to ensure our P2P probe responses have the privacy bit
	 * set in the 802.11 WPA IE. Some peer devices may not
	 * initiate WPS with us if this bit is not set.
	 */
	enable = AES_ENABLED;
	ret = wland_fil_iovar_data_set(vif->ifp, "wsec", &enable, sizeof(u8));
	if (ret < 0) {
		WLAND_ERR("wsec error %d\n", ret);
		goto exit;
	}

	set_bit(P2P_STATUS_ENABLED, &p2p->status);

exit:
	WLAND_DBG(CFG80211, TRACE, "Done\n");
	return ret;
}

/*
 * wland_p2p_escan() - initiate a P2P scan.
 *
 * @p2p         : P2P specific data.
 * @num_chans   : number of channels to scan.
 * @chanspecs   : channel parameters for @num_chans channels.
 * @search_state: P2P discover state to use.
 * @action      : scan action to pass to firmware.
 * @bss_type    : type of P2P bss.
 */
static s32 wland_p2p_escan(struct wland_p2p_info *p2p, u32 num_chans,
	u16 chanspecs[], s32 search_state, u16 action)
{
	s32 ret = 0;
	u32 i;
	struct wland_cfg80211_vif *vif;
	//struct wland_p2p_scan_le *p2p_params;
	//struct wland_scan_params_le *sparams;

	struct wland_scan_params_le sparams;
	struct wland_ssid_le *scan_ssid = &sparams.ssid_le;

	//struct wland_ssid ssid;


	vif = p2p->bss_idx[P2PAPI_BSSCFG_DEVICE].vif;
	if (vif == NULL) {
		WLAND_ERR("no vif for bss type %d\n", P2PAPI_BSSCFG_DEVICE);
		ret = -EINVAL;
		goto exit;
	}

	switch (search_state) {
	case WL_P2P_DISC_ST_SEARCH:
		scan_ssid->SSID_len = P2P_WILDCARD_SSID_LEN;
		memcpy(scan_ssid->SSID, P2P_WILDCARD_SSID, P2P_WILDCARD_SSID_LEN);
		break;
	case WL_P2P_DISC_ST_SCAN:
		/*
		 * wpa_supplicant has p2p_find command with type social or
		 * progressive. For progressive, we need to set the ssid to
		 * P2P WILDCARD because we just do broadcast scan unless setting SSID.
		 */
		scan_ssid->SSID_len = P2P_WILDCARD_SSID_LEN;
		memcpy(scan_ssid->SSID, P2P_WILDCARD_SSID, P2P_WILDCARD_SSID_LEN);
		break;
	case WL_P2P_CONNECT_SCAN_RDA:
		scan_ssid->SSID_len = p2p->ssid.SSID_len;
		memcpy(scan_ssid->SSID, p2p->ssid.SSID, p2p->ssid.SSID_len);
		WLAND_DBG(CFG80211, TRACE, "connect scan ssid:%s, ssid len = %d\n",
			scan_ssid->SSID, scan_ssid->SSID_len);
		break;
	default:
		WLAND_ERR(" invalid search state %d\n", search_state);
		ret = -EINVAL;
		goto exit;
	}

	wland_p2p_set_discover_state(vif->ifp, search_state, 0, 0);

#if 0
	if (p2p->cfg->active_scan)
		sparams->scan_type = 1;
	else
		sparams->scan_type = 0;

	memset(&sparams->bssid, 0xFF, ETH_ALEN);

	sparams->home_time = cpu_to_le32(P2PAPI_SCAN_HOME_TIME_MS);

	/*
	 * SOCIAL_CHAN_CNT + 1 takes care of the Progressive scan supported by the supplicant.
	 */
	if (num_chans == SOCIAL_CHAN_CNT || num_chans == (SOCIAL_CHAN_CNT + 1))
		active = P2PAPI_SCAN_SOCIAL_DWELL_TIME_MS;
	else if (num_chans == AF_PEER_SEARCH_CNT)
		active = P2PAPI_SCAN_AF_SEARCH_DWELL_TIME_MS;
	else if (wland_vif_get_state_all(p2p->cfg, VIF_STATUS_CONNECTED))
		active = -1;
	else
		active = P2PAPI_SCAN_DWELL_TIME_MS;

	/*
	 * Override scan params to find a peer for a connection
	 */
	if (num_chans == 1) {
		active = WL_SCAN_CONNECT_DWELL_TIME_MS;
		/*
		 * WAR to sync with presence period of VSDB GO.
		 * * send probe request more frequently
		 */
		nprobes = active / WL_SCAN_JOIN_PROBE_INTERVAL_MS;
	} else {
		nprobes = active / P2PAPI_SCAN_NPROBS_TIME_MS;
	}

	if (nprobes <= 0)
		nprobes = 1;

	WLAND_DBG(CFG80211, TRACE, "num_chans= %d , nprobes # %d, active_time %d\n",
		num_chans, nprobes,
		active);

	sparams->active_time = active;
	sparams->nprobes = nprobes;
	sparams->passive_time = -1;
#endif

	sparams.channel_num = num_chans;

	for (i = 0; i < num_chans; i++){
		sparams.channel_list[i] = chanspecs[i];
		WLAND_DBG(CFG80211, TRACE, "scan chanspecs[%d] = 0x%x\n",i,chanspecs[i]);
	}

	if (search_state == WL_P2P_CONNECT_SCAN_RDA) {
		ret = wland_p2p_connect_scan(vif->ifp, &sparams);
	} else if(num_chans == AF_PEER_SEARCH_CNT) {
		ret = wland_p2p_af_scan_set(vif->ifp, &sparams);
	} else {
		ret = wland_p2p_start_scan_set(vif->ifp, &sparams);
		if (!ret)
			set_bit(SCAN_STATUS_BUSY, &p2p->cfg->scan_status);
	}

exit:
	return ret;
}

/*
 * wland_p2p_run_escan() - escan callback for peer-to-peer.
 *
 * @cfg     : driver private data for cfg80211 interface.
 * @ndev    : net device for which scan is requested.
 * @request : scan request from cfg80211.
 * @action  : scan action.
 *
 * Determines the P2P discovery state based to scan request parameters and
 * validates the channels in the request.
 */
s32 wland_p2p_run_escan(struct wland_cfg80211_info *cfg,
	struct wland_if *ifp, struct cfg80211_scan_request *request, u16 action)
{
	struct wland_p2p_info *p2p = &cfg->p2p;
	s32 err = 0;
	s32 search_state = WL_P2P_DISC_ST_SCAN;
	struct wland_cfg80211_vif *vif;
	struct net_device *dev = NULL;
	int i, num_nodfs = 0;
	u16 *chanspecs;

	WLAND_DBG(CFG80211, DEBUG, "enter\n");

	if (!request) {
		err = -EINVAL;
		goto exit;
	}
	if ((request->n_channels == 1) || (request->n_channels == 2))
		mod_timer(&cfg->scan_timeout, jiffies + msecs_to_jiffies(400));
	else
		mod_timer(&cfg->scan_timeout, jiffies + msecs_to_jiffies(3000));

	if (request->n_channels) {
		chanspecs =
			kcalloc(request->n_channels, sizeof(*chanspecs), GFP_KERNEL);
		if (!chanspecs) {
			err = -ENOMEM;
			goto exit;
		}
		vif = p2p->bss_idx[P2PAPI_BSSCFG_DEVICE].vif;

		if (vif)
			dev = vif->wdev.netdev;

		if (request->n_channels == 3 &&
			request->channels[0]->hw_value == SOCIAL_CHAN_1 &&
			request->channels[1]->hw_value == SOCIAL_CHAN_2 &&
			request->channels[2]->hw_value == SOCIAL_CHAN_3) {
			/*
			 * SOCIAL CHANNELS 1, 6, 11
			 */
			search_state = WL_P2P_DISC_ST_SEARCH;
			WLAND_DBG(CFG80211, INFO, "P2P SEARCH PHASE START\n");
		} else if (dev != NULL && vif->mode == WL_MODE_AP) {
			/*
			 * If you are already a GO, then do SEARCH only
			 */
			WLAND_DBG(CFG80211, INFO,
				"Already a GO. Do SEARCH Only\n");
			search_state = WL_P2P_DISC_ST_SEARCH;
		} else if (request->n_ssids==1 &&
				!memcmp(request->ssids->ssid, P2P_WILDCARD_SSID, P2P_WILDCARD_SSID_LEN) &&
				request->ssids->ssid_len != P2P_WILDCARD_SSID_LEN) {
			WLAND_DBG(CFG80211, INFO, "Do CLIENT Connect scan, channel num:%d\n", request->n_channels);
			search_state = WL_P2P_CONNECT_SCAN_RDA;
		} else if (request->n_channels==1 &&
				request->n_ssids == 0) {
			WLAND_DBG(CFG80211, INFO, "Do CLIENT Connect scan, channel num:%d\n", request->n_channels);
			search_state = WL_P2P_CONNECT_SCAN_RDA;
		} else {
			WLAND_DBG(CFG80211, INFO, "P2P SCAN STATE START\n");
		}

		/*
		 * no P2P scanning on passive or DFS channels.
		 */
		for (i = 0; i < request->n_channels; i++) {
			struct ieee80211_channel *chan = request->channels[i];

			if (chan->flags & (IEEE80211_CHAN_RADAR |
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
				IEEE80211_CHAN_NO_IR))
#else /*LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)*/
				IEEE80211_CHAN_PASSIVE_SCAN))
#endif /*LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)*/
				continue;

			chanspecs[num_nodfs] =
				wland_channel_to_chanspec(&p2p->cfg->d11inf, chan);
			WLAND_DBG(CFG80211, INFO,
				"%d: chan=%d, channel spec=%x\n", num_nodfs,
				chan->hw_value, chanspecs[i]);
			num_nodfs++;
		}
		err = wland_p2p_escan(p2p, num_nodfs, chanspecs, search_state,
			action);
		kfree(chanspecs);
	}
exit:
	if (err)
		WLAND_ERR("error (%d)\n", err);
	return err;
}

/*
 * wland_p2p_find_listen_channel() - find listen channel in ie string.
 *
 * @ie     : string of information elements.
 * @ie_len : length of string.
 *
 * Scan ie for p2p ie and look for attribute 6 channel.
 * If available determine channel and return it.
 */
static s32 wland_p2p_find_listen_channel(const u8 * ie, u32 ie_len)
{
	u8 channel_ie[5]={0};
	s32 listen_channel;

#if 1
	s32 err;

	err = cfg80211_get_p2p_attr(ie, ie_len,
		IEEE80211_P2P_ATTR_LISTEN_CHANNEL, channel_ie,
		sizeof(channel_ie));
	if (err < 0)
		return err;
#endif
	/*
	 * listen channel subel length format:
	 */
	/*
	 * 3(country) + 1(op. class) + 1(chan num)
	 */
	listen_channel = (s32) channel_ie[3 + 1];

	if (listen_channel == SOCIAL_CHAN_1 ||
		listen_channel == SOCIAL_CHAN_2 ||
		listen_channel == SOCIAL_CHAN_3) {
		WLAND_DBG(CFG80211, TRACE, "Found my Listen Channel %d\n",
			listen_channel);
		return listen_channel;
	} else {
		WLAND_ERR("Doesn't find my listen channel\n");
	}

	return -EPERM;
}

static s32 wland_p2p_enable(struct wland_cfg80211_info *cfg, int re_enable)
{
	s32 err = 0;
	struct wland_p2p_info *p2p = &cfg->p2p;
	struct wland_cfg80211_vif * vif = p2p->bss_idx[P2PAPI_BSSCFG_DEVICE].vif;
	struct wland_private *drvr;
	u8 *buf;
	u8 val;

	WLAND_DBG(CFG80211, INFO, "Enter, %d\n", re_enable);

	atomic_set(&p2p->p2p_state, 1);
	drvr = vif->ifp->drvr;
	buf = drvr->prot->buf;

	mutex_lock(&drvr->proto_block);

	if (re_enable == 0) {
		val = NO_POWERSAVE;
		err = wland_push_wid(buf, WID_POWER_MANAGEMENT, &val, sizeof(val), false);
		if (err < 0) {
			WLAND_ERR("put wid error\n");
			mutex_unlock(&drvr->proto_block);
			return -1;
		}
		buf += err;

		err = wland_push_wid(buf, WID_P2P_SET_DEV_ADDR, p2p->dev_addr, ETH_ALEN, false);
		if (err < 0) {
			WLAND_ERR("put wid error\n");
			mutex_unlock(&drvr->proto_block);
			return -1;
		}
		buf += err;

		val = (u8)(p2p->afx_hdl.my_listen_chan);
		if (val != 0) {
			err = wland_push_wid(buf, WID_P2P_LISTEN_CHAN, &val, sizeof(val), false);
			if (err < 0) {
				WLAND_ERR("put wid error\n");
				mutex_unlock(&drvr->proto_block);
				return -1;
			}
			buf += err;
		}
	}

	val = 1;
	err = wland_push_wid(buf, WID_P2P_ENABLE, &val, sizeof(val), false);
	if (err < 0) {
		WLAND_ERR("put wid error\n");
		mutex_unlock(&drvr->proto_block);
		return -1;
	}
	buf += err;

	err = wland_proto_cdc_data(drvr, buf-(drvr->prot->buf) + FMW_HEADER_LEN);
	if (err < 0)
		WLAND_ERR("Failed to init p2p\n");

	mutex_unlock(&drvr->proto_block);
	return err;

}


/*
 * wland_p2p_scan_prep() - prepare scan based on request.
 *
 * @wiphy   : wiphy device.
 * @request : scan request from cfg80211.
 * @vif     : vif on which scan request is to be executed.
 *
 * Prepare the scan appropriately for type of scan requested. Overrides the
 * escan .run() callback for peer-to-peer scanning.
 */
s32 wland_p2p_scan_prep(struct wiphy * wiphy,
	struct cfg80211_scan_request * request, struct wland_cfg80211_vif * vif)
{
	struct wland_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct wland_p2p_info *p2p = &cfg->p2p;
	s32 err = 0;
	///TODO: find way enable, disable p2p.
	//static u8 p2p_on = 0;

	/*
	 * find my listen channel
	 */
	if (request->ssids) {
		p2p->ssid.SSID_len = request->ssids->ssid_len;
		memcpy(p2p->ssid.SSID, request->ssids->ssid, request->ssids->ssid_len);
	} else
		p2p->ssid.SSID_len = 0;
	err = wland_p2p_find_listen_channel(request->ie,
		request->ie_len);
	if (err < 0) {
		WLAND_ERR("Could not find listen channel\n");
		return err;
	}

	p2p->afx_hdl.my_listen_chan = err;

	clear_bit(P2P_STATUS_GO_NEG_PHASE, &p2p->status);
	WLAND_DBG(CFG80211, INFO, "P2P: GO_NEG_PHASE status cleared\n");

	err = wland_p2p_enable_discovery(p2p);
	if (err < 0)
		return err;

	vif = p2p->bss_idx[P2PAPI_BSSCFG_DEVICE].vif;

	cancel_work_sync(&p2p->p2p_alive_timeout_work);
	mod_timer(&p2p->p2p_alive_timer,
		jiffies + msecs_to_jiffies(P2P_ALIVE_TIME_MS));
	atomic_set(&p2p->p2p_alive_timer_count, 0);

	/*
	 * override .run_escan() callback.
	 */
	cfg->scan_info.run = wland_p2p_run_escan;
	if (atomic_read(&p2p->p2p_state) == 0) {
		wland_p2p_enable(cfg, 0);
	} else if (atomic_read(&p2p->p2p_state) == 2) {
		wland_p2p_enable(cfg, 1);
	}
	WLAND_DBG(CFG80211, INFO,
		"P2P: request_ie_len = %zu \n", request->ie_len);

	return wland_vif_set_mgmt_ie(vif, WLAND_VNDR_IE_PRBREQ_FLAG,
		request->ie, request->ie_len);
}

#pragma pack (push)
#pragma pack(1)
struct wland_remain_on_channel_para {
	u8 chnum;
	u32 duration;
};
#pragma pack (pop)

/*
 * wland_p2p_discover_listen() - set firmware to discover listen state.
 *
 * @p2p: p2p device.
 * @channel: channel nr for discover listen.
 * @duration: time in ms to stay on channel.
 *
 */
static s32 wland_p2p_discover_listen(struct wland_p2p_info *p2p, u8 channel,
	u32 duration)
{
	struct wland_cfg80211_vif *vif;
	struct wland_chan ch;
	struct wland_remain_on_channel_para ch_para;
	s32 err = 0;
	WLAND_DBG(CFG80211, INFO, "wland_p2p_discover_listen: Duration:%d, Channel: %d\n", duration, channel);

	vif = p2p->bss_idx[P2PAPI_BSSCFG_DEVICE].vif;
	if (!vif) {
		WLAND_ERR("Discovery is not set, so we have nothing to do\n");
		err = -EPERM;
		goto exit;
	}

	if (test_bit(P2P_STATUS_DISCOVER_LISTEN, &p2p->status)) {
		WLAND_ERR("Previous LISTEN is not completed yet\n");
		/*
		 * WAR: prevent cookie mismatch in wpa_supplicant return OK
		 */
		goto exit;
	}

	ch.chnum = channel;
	ch.bw = CHAN_BW_20;

	p2p->cfg->d11inf.encchspec(&ch);

	//err = wland_p2p_set_discover_state(vif->ifp, WL_P2P_DISC_ST_LISTEN,
	//	ch.chspec, (u16) duration);

	ch_para.chnum = channel;
	ch_para.duration = cpu_to_le32(duration);

	err = wland_fil_set_cmd_data(vif->ifp, WID_P2P_START_LISTEN_REQ,
		&ch_para, sizeof(struct wland_remain_on_channel_para));

	if (!err) {
		set_bit(P2P_STATUS_DISCOVER_LISTEN, &p2p->status);
		p2p->remain_on_channel_cookie++;
	}
exit:
	return err;
}

/*
 * wland_cfg80211_p2p_remain_on_channel() - put device on channel and stay there.
 *
 * @wiphy   : wiphy device.
 * @channel : channel to stay on.
 * @duration: time in ms to remain on channel.
 *
 */

int wland_cfg80211_p2p_remain_on_channel(struct wiphy *wiphy,
#if    LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
	struct wireless_dev *wdev, struct ieee80211_channel *channel,
	unsigned int duration, u64 * cookie)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
	struct wireless_dev *wdev, struct ieee80211_channel *channel,
	enum nl80211_channel_type channel_type,
	unsigned int duration, u64 * cookie)
#else
	struct net_device *dev, struct ieee80211_channel *channel,
	enum nl80211_channel_type channel_type,
	unsigned int duration, u64 * cookie)
#endif
{
	struct wland_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct wland_p2p_info *p2p = &cfg->p2p;
	s32 err = 0;
	u8 channel_nr = ieee80211_frequency_to_channel(channel->center_freq);
	//struct wland_cfg80211_vif *vif =
	//	container_of(wdev, struct wland_cfg80211_vif, wdev);

	set_bit(SCAN_STATUS_BUSY, &cfg->scan_status);

	atomic_set(&p2p->p2p_alive_timer_count, 0);

	if (timer_pending(&cfg->pub->iflist[0]->vif->conn_info.connect_restorework_timeout) ||
		timer_pending(&cfg->pub->iflist[1]->vif->conn_info.connect_restorework_timeout) ||
		(test_bit(VIF_STATUS_CONNECTING, &cfg->pub->iflist[0]->vif->sme_state)) ||
		(test_bit(VIF_STATUS_CONNECTING, &cfg->pub->iflist[1]->vif->sme_state))) {
		WLAND_DBG(CFG80211, INFO, "getting ip, delay scan\n");
		p2p->remain_on_channel_cookie ++;
		*cookie = p2p->remain_on_channel_cookie;
		memcpy(&p2p->remain_on_channel, channel, sizeof(*channel));
		schedule_delayed_work(&p2p->delay_remain_onchannel_work, msecs_to_jiffies(duration));
	} else {

		WLAND_DBG(CFG80211, INFO, "Enter, channel: %d, duration ms (%d)\n",
			channel_nr, duration);

		if (p2p->afx_hdl.my_listen_chan == 0)
			p2p->afx_hdl.my_listen_chan = channel_nr;
		else if (p2p->afx_hdl.my_listen_chan != channel_nr) {
			WLAND_ERR("listen channel not match:%d, %d(use this)\n",
				p2p->afx_hdl.my_listen_chan, channel_nr);
			p2p->afx_hdl.my_listen_chan = channel_nr;
		}

		if (atomic_read(&p2p->p2p_state) == 0) {
			wland_p2p_enable(cfg, 0);
		} else if (atomic_read(&p2p->p2p_state) == 2) {
			wland_p2p_enable(cfg, 1);
		}

		err = wland_p2p_enable_discovery(p2p);
		if (err) {
			WLAND_DBG(CFG80211, INFO, "wland_p2p_enable_discovery fail\n");
			goto exit;
		}
		//set_bit(P2P_STATUS_DISCOVER_LISTEN, &p2p->status);

		//duration = duration * 3;
		err = wland_p2p_discover_listen(p2p, channel_nr, duration);
		if (err) {
			WLAND_DBG(CFG80211, INFO, "wland_p2p_discover_listen fail\n");
			goto exit;
		}


		memcpy(&p2p->remain_on_channel, channel, sizeof(*channel));
		*cookie = p2p->remain_on_channel_cookie;
	}

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 7, 2)
	cfg80211_ready_on_channel(wdev, *cookie, channel, duration, GFP_KERNEL);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
	cfg80211_ready_on_channel(wdev, *cookie, channel, channel_type, duration,
		GFP_KERNEL);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
	cfg80211_ready_on_channel(dev, *cookie, channel, channel_type, duration,
		GFP_KERNEL);
#endif

exit:
	return err;
}

/*
 * wland_notify_p2p_listen_complete() - p2p listen has completed.
 *
 * @ifp             : interfac control.
 * @e: event message. Not used, to make it usable for fweh event dispatcher.
 * @data            : payload of message. Not used.
 *
 */
s32 wland_notify_p2p_listen_complete(struct wland_if * ifp,
	const struct wland_event_msg * e, void *data)
{
	struct wland_cfg80211_info *cfg = ifp->drvr->config;
	struct wland_p2p_info *p2p = &cfg->p2p;

	WLAND_DBG(CFG80211, INFO, "Enter\n");

	if (test_and_clear_bit(P2P_STATUS_DISCOVER_LISTEN, &p2p->status)) {
		if (test_and_clear_bit(P2P_STATUS_WAITING_NEXT_AF_LISTEN,
				&p2p->status)) {
			clear_bit(P2P_STATUS_WAITING_NEXT_ACT_FRAME,
				&p2p->status);
			WLAND_DBG(CFG80211, INFO,
				"Listen DONE, wake up wait_next_af\n");
			complete(&p2p->wait_next_af);
		}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
		cfg80211_remain_on_channel_expired(&ifp->vif->wdev,
			p2p->remain_on_channel_cookie, &p2p->remain_on_channel,
			GFP_KERNEL);
#else /* LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0) */
		cfg80211_remain_on_channel_expired(ifp->ndev,
			p2p->remain_on_channel_cookie, &p2p->remain_on_channel,
			p2p->remain_on_chan_type, GFP_KERNEL);
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0) */
	}
	clear_bit(SCAN_STATUS_BUSY, &cfg->scan_status);

	WLAND_DBG(CFG80211, TRACE, "Done\n");
	return 0;
}

/*
 * wland_p2p_cancel_remain_on_channel() - cancel p2p listen state.
 *
 * @ifp: interfac control.
 *
 */
void wland_p2p_cancel_remain_on_channel(struct wland_if *ifp)
{
	struct wland_cfg80211_info *cfg;
	if (!ifp)
		return;
	cfg = ifp->drvr->config;
	wland_p2p_set_discover_state(ifp, WL_P2P_DISC_ST_SCAN, 0, 0);

	wland_notify_p2p_listen_complete(ifp, NULL, NULL);
	clear_bit(SCAN_STATUS_BUSY, &cfg->scan_status);
}

/*
 * wland_p2p_act_frm_search() - search function for action frame.
 *
 * @p2p: p2p device.
 * channel: channel on which action frame is to be trasmitted.
 *
 * search function to reach at common channel to send action frame. When
 * channel is 0 then all social channels will be used to send af
 */
static s32 wland_p2p_act_frm_search(struct wland_p2p_info *p2p, u16 channel)
{
	s32 err;
	u32 channel_cnt, i;
	u16 *default_chan_list;
	struct wland_chan ch;

	WLAND_DBG(CFG80211, INFO, "Enter, channel = %d \n", channel);

	if (channel)
		channel_cnt = AF_PEER_SEARCH_CNT;
	else
		channel_cnt = SOCIAL_CHAN_CNT;

	default_chan_list =
		kzalloc(channel_cnt * sizeof(*default_chan_list), GFP_KERNEL);

	if (default_chan_list == NULL) {
		WLAND_ERR("channel list allocation failed\n");
		err = -ENOMEM;
		goto exit;
	}
	ch.bw = CHAN_BW_20;

	if (channel) {
		ch.chnum = channel;
		p2p->cfg->d11inf.encchspec(&ch);
		/*
		 * insert same channel to the chan_list
		 */
		for (i = 0; i < channel_cnt; i++)
			default_chan_list[i] = ch.chspec;
	} else {
		ch.chnum = SOCIAL_CHAN_1;
		p2p->cfg->d11inf.encchspec(&ch);
		default_chan_list[0] = ch.chspec;
		ch.chnum = SOCIAL_CHAN_2;
		p2p->cfg->d11inf.encchspec(&ch);
		default_chan_list[1] = ch.chspec;
		ch.chnum = SOCIAL_CHAN_3;
		p2p->cfg->d11inf.encchspec(&ch);
		default_chan_list[2] = ch.chspec;
	}
	err = wland_p2p_escan(p2p,
		channel_cnt,
		default_chan_list,
		WL_P2P_DISC_ST_SEARCH, SCAN_ACTION_START);
	kfree(default_chan_list);
exit:
	return err;
}

/*
 * wland_p2p_afx_handler() - afx worker thread.
 *
 * @work:
 *
 */
static void wland_p2p_afx_handler(struct work_struct *work)
{
	struct afx_hdl *afx_hdl = container_of(work, struct afx_hdl, afx_work);
	struct wland_p2p_info *p2p =
		container_of(afx_hdl, struct wland_p2p_info, afx_hdl);
	s32 err;

	if (!afx_hdl->is_active)
		return;

	WLAND_DBG(CFG80211, INFO, "!!! afx_hdl->is_listen = %d, afx_hdl->my_listen_chan = %d\n",
			afx_hdl->is_listen, afx_hdl->my_listen_chan);

	if (afx_hdl->is_listen && afx_hdl->my_listen_chan)
		/*
		 * 100ms ~ 300ms
		 */
		err = wland_p2p_discover_listen(p2p, afx_hdl->my_listen_chan,
			100 * (1 + RANDOM32() % 3));
	else
		err = wland_p2p_act_frm_search(p2p, afx_hdl->peer_listen_chan);

	if (err) {
		WLAND_ERR("occurred! value is (%d)\n", err);

		if (test_bit(P2P_STATUS_FINDING_COMMON_CHANNEL, &p2p->status))
			complete(&afx_hdl->act_frm_scan);
	}
}

/*
 * wland_p2p_af_searching_channel() - search channel.
 *
 * @p2p: p2p device info struct.
 *
 */
static s32 wland_p2p_af_searching_channel(struct wland_p2p_info *p2p)
{
	struct afx_hdl *afx_hdl = &p2p->afx_hdl;
	struct wland_cfg80211_vif *pri_vif =
		p2p->bss_idx[P2PAPI_BSSCFG_PRIMARY].vif;
	ulong duration;
	s32 retry = 0;

	WLAND_DBG(CFG80211, TRACE, "Enter wland_p2p_af_searching_channel\n");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
		reinit_completion(&afx_hdl->act_frm_scan);
#else /*LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)*/
		INIT_COMPLETION(afx_hdl->act_frm_scan);
#endif /*LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)*/

	set_bit(P2P_STATUS_FINDING_COMMON_CHANNEL, &p2p->status);

	afx_hdl->is_active = true;
	afx_hdl->peer_chan = P2P_INVALID_CHANNEL;

	/*
	 * Loop to wait until we find a peer's channel or the pending action frame tx is cancelled.
	 */
	duration = msecs_to_jiffies(P2P_AF_FRM_SCAN_MAX_WAIT);

	while ((retry < P2P_CHANNEL_SYNC_RETRY)
		&& (afx_hdl->peer_chan == P2P_INVALID_CHANNEL)) {
		afx_hdl->is_listen = false;
		WLAND_DBG(CFG80211, DEBUG,
			"Scheduling action frame for sending.. (%d)\n", retry);
		/*
		 * search peer on peer's listen channel
		 */
		schedule_work(&afx_hdl->afx_work);
		wait_for_completion_timeout(&afx_hdl->act_frm_scan, duration);

		if ((afx_hdl->peer_chan != P2P_INVALID_CHANNEL) ||
			(!test_bit(P2P_STATUS_FINDING_COMMON_CHANNEL,
					&p2p->status))) {
			break;
		}

#if 0
		if (afx_hdl->my_listen_chan) {
			WLAND_DBG(CFG80211, TRACE,
				"Scheduling listen peer, channel=%d\n",
				afx_hdl->my_listen_chan);
			/*
			 * listen on my listen channel
			 */
			afx_hdl->is_listen = true;
			//schedule_work(&afx_hdl->afx_work);
			wait_for_completion_timeout(&afx_hdl->act_frm_scan,
				duration);
		}
#endif
		if ((afx_hdl->peer_chan != P2P_INVALID_CHANNEL) ||
			(!test_bit(P2P_STATUS_FINDING_COMMON_CHANNEL,
					&p2p->status))) {
			break;
		}
		retry++;

		/*
		 * if sta is connected or connecting, sleep for a while before retry af tx or finding a peer
		 */
		if (test_bit(VIF_STATUS_CONNECTED, &pri_vif->sme_state) ||
			test_bit(VIF_STATUS_CONNECTING, &pri_vif->sme_state)) {
			msleep(P2P_DEFAULT_SLEEP_TIME_VSDB);
		}
	}

	WLAND_DBG(CFG80211, INFO, "Completed search/listen peer_chan=%d\n",
		afx_hdl->peer_chan);
	afx_hdl->is_active = false;

	clear_bit(P2P_STATUS_FINDING_COMMON_CHANNEL, &p2p->status);

	return afx_hdl->peer_chan;
}
/*
 * wland_p2p_scan_finding_common_channel() - was escan used for finding channel
 *
 * @cfg : common configuration struct.
 * @bi  : bss info struct, result from scan.
 *
 */
bool wland_p2p_scan_finding_common_channel(struct wland_cfg80211_info * cfg,
	struct wland_bss_info_le * bi)
{
	struct wland_p2p_info *p2p = &cfg->p2p;
	struct afx_hdl *afx_hdl = &p2p->afx_hdl;
	struct wland_chan ch;
	s32 err = 0;
	u8 p2p_dev_addr[ETH_ALEN];

	if (!test_bit(P2P_STATUS_FINDING_COMMON_CHANNEL, &p2p->status))
		return false;

	if (bi == NULL) {
		WLAND_DBG(CFG80211, DEBUG, "ACTION FRAME SCAN Done\n");
		if (afx_hdl->peer_chan == P2P_INVALID_CHANNEL)
			complete(&afx_hdl->act_frm_scan);
		return true;
	}

	memset(p2p_dev_addr, 0, sizeof(p2p_dev_addr));
#if 1
	err = cfg80211_get_p2p_attr(bi->ie,
		bi->ie_length,
		IEEE80211_P2P_ATTR_DEVICE_INFO,
		p2p_dev_addr, sizeof(p2p_dev_addr));
	if (err < 0)
		err = cfg80211_get_p2p_attr(bi->ie,
			bi->ie_length,
			IEEE80211_P2P_ATTR_DEVICE_ID,
			p2p_dev_addr, sizeof(p2p_dev_addr));
#endif
	if ((err >= 0)
		&& (!memcmp(p2p_dev_addr, afx_hdl->tx_dst_addr, ETH_ALEN))) {
		if (!bi->ctl_ch) {
			ch.chspec = bi->chanspec;
			cfg->d11inf.decchspec(&ch);
			bi->ctl_ch = ch.chnum;
		}
		afx_hdl->peer_chan = bi->ctl_ch;
		WLAND_DBG(CFG80211, INFO,
			"ACTION FRAME SCAN: Peer %pM found, channel : %d\n",
			afx_hdl->tx_dst_addr, afx_hdl->peer_chan);
		complete(&afx_hdl->act_frm_scan);
	}
	return true;
}

/*
 * wland_p2p_stop_wait_next_action_frame() - finish scan if af tx complete.
 *
 * @cfg: common configuration struct.
 */
static void wland_p2p_stop_wait_next_action_frame(struct wland_cfg80211_info
	*cfg)
{
	struct wland_p2p_info *p2p = &cfg->p2p;
	//struct wland_if *ifp = cfg->scan_info.ifp;
	//WLAND_DBG(CFG80211, INFO, "Enter\n");
	if (test_bit(P2P_STATUS_SENDING_ACT_FRAME, &p2p->status) &&
		(test_bit(P2P_STATUS_ACTION_TX_COMPLETED, &p2p->status)
			|| test_bit(P2P_STATUS_ACTION_TX_NOACK, &p2p->status))) {
		WLAND_DBG(CFG80211, INFO,
			"*** Wake UP ** abort actframe iovar\n");
		/*
		 * if channel is not zero, "actfame" uses off channel scan.
		 * * So abort scan for off channel completion.
		 */
		//if (p2p->af_sent_channel)
			//wland_notify_escan_complete(cfg, ifp, true, true);
	} else if (test_bit(P2P_STATUS_WAITING_NEXT_AF_LISTEN, &p2p->status)) {
		//WLAND_DBG(CFG80211, INFO,
			//"*** Wake UP ** abort listen for next af frame\n");
#if 0
		/*
		 * So abort scan to cancel listen
		 */
		wland_notify_escan_complete(cfg, ifp, true, true);
#else
		clear_bit(P2P_STATUS_WAITING_NEXT_ACT_FRAME,
			&p2p->status);
		WLAND_DBG(CFG80211, INFO,
			"RX frame DONE, wake up wait_next_af\n");
		complete(&p2p->wait_next_af);
#endif
	}
}

/*
 * wland_p2p_gon_req_collision() - Check if go negotiaton collission
 *
 * @p2p: p2p device info struct.
 *
 * return true if recevied action frame is to be dropped.
 */
static bool wland_p2p_gon_req_collision(struct wland_p2p_info *p2p, u8 * mac)
{
	struct wland_cfg80211_info *cfg = p2p->cfg;
	struct wland_if *ifp = p2p->bss_idx[P2PAPI_BSSCFG_DEVICE].vif->ifp;

	WLAND_DBG(CFG80211, TRACE, "Enter\n");

	if (!test_bit(P2P_STATUS_WAITING_NEXT_ACT_FRAME, &p2p->status)
		|| !p2p->gon_req_action)
		return false;

	WLAND_DBG(CFG80211, INFO, "GO Negotiation Request COLLISION !!!\n");

	/*
	 * if sa(peer) addr is less than da(my) addr, then this device
	 * * process peer's gon request and block to send gon req.
	 * * if not (sa addr > da addr), this device will process gon request and drop gon req of peer.
	 */
	if (memcmp(mac, ifp->mac_addr, ETH_ALEN) < 0) {
		WLAND_DBG(CFG80211, TRACE, "Block transmit gon req !!!\n");
		p2p->block_gon_req_tx = true;
		/*
		 * if we are finding a common channel for sending af, do not scan more to block to send current gon req
		 */
		if (test_and_clear_bit(P2P_STATUS_FINDING_COMMON_CHANNEL,
				&p2p->status))
			complete(&p2p->afx_hdl.act_frm_scan);
		if (test_and_clear_bit(P2P_STATUS_WAITING_NEXT_ACT_FRAME,
				&p2p->status))
			wland_p2p_stop_wait_next_action_frame(cfg);

		return false;
	}

	/*
	 * drop gon request of peer to process gon request by this device.
	 */
	WLAND_DBG(CFG80211, TRACE, "Drop received gon req !!!\n");

	return true;
}

/*
 * wland_notify_p2p_action_frame_rx() - received action frame.
 *
 * @ifp : interfac control.
 * @e   : event message. Not used, to make it usable for fweh event dispatcher.
 * @data: payload of message, containing action frame data.
 *
 */
s32 wland_notify_p2p_action_frame_rx(struct wland_if * ifp,
	const struct wland_event_msg * e, void *data)
{
	struct wland_cfg80211_info *cfg = ifp->drvr->config;
	struct wland_p2p_info *p2p = &cfg->p2p;
	struct afx_hdl *afx_hdl = &p2p->afx_hdl;
//	struct wireless_dev *wdev;
//	struct wland_rx_async_mgmt_data *rxframe = (struct wland_rx_async_mgmt_data *)data;
	u8 *local_data = (u8 *)data;
//	u16 wid_id = local_data[4] | local_data[5]<<8;
	u16 wid_len = local_data[6] | local_data[7]<<8;
	//u8 rssi = local_data[8];
	u8 channel_num = local_data[9];

	//u8 *frame = (u8 *)(local_data + 10);

	u32 mgmt_frame_len = wid_len;// - 2;

	struct wland_p2p_pub_act_frame *act_frm;
	struct wland_p2psd_gas_pub_act_frame *sd_act_frm;
	struct ieee80211_mgmt *mgmt_frame = (struct ieee80211_mgmt *)(local_data + 10);
	struct wland_cfg80211_vif *vif = ifp->vif;
    s32 freq;
	u16 mgmt_type;
	u8 action;
	WLAND_DBG(CFG80211, TRACE, "mgmt_frame_len is  %04x\n", mgmt_frame_len);
	WLAND_DBG(CFG80211, TRACE, "channel_num is  %04x\n", channel_num);

	/*
	 * Check if wpa_supplicant has registered for this frame
	 */
	WLAND_DBG(CFG80211, TRACE, "ifp->vif->mgmt_rx_reg %04x\n",
		vif->mgmt_rx_reg);

	mgmt_type = (IEEE80211_STYPE_ACTION & IEEE80211_FCTL_STYPE) >> 4;

	if ((vif->mgmt_rx_reg & BIT(mgmt_type)) == 0)
		return 0;

	action = P2P_PAF_SUBTYPE_INVALID;

	if (wland_p2p_is_pub_action((void *)mgmt_frame+offsetof(struct ieee80211_mgmt, u),
			mgmt_frame_len-MAC_HDR_LEN)) {
		act_frm = (struct wland_p2p_pub_act_frame *)
			((void *)mgmt_frame+offsetof(struct ieee80211_mgmt, u));
		action = act_frm->subtype;

		WLAND_DBG(CFG80211, INFO, "public action frame received:%d\n", action);

		if ((action == P2P_PAF_GON_REQ)
			&& wland_p2p_gon_req_collision(p2p, (u8 *) e->addr)) {
			if (test_bit(P2P_STATUS_FINDING_COMMON_CHANNEL, 	&p2p->status)
				&& (memcmp(afx_hdl->tx_dst_addr, e->addr, ETH_ALEN) == 0)) {
				WLAND_DBG(CFG80211, INFO,
					"GON request: Peer found, channel=%d\n",
					channel_num);
				afx_hdl->peer_chan = channel_num;
				complete(&afx_hdl->act_frm_scan);
			}
			return 0;
		}

		if (action == P2P_PAF_GON_CONF) {
			WLAND_DBG(CFG80211, INFO,
				"P2P: GO_NEG_PHASE status cleared\n");
			clear_bit(P2P_STATUS_GO_NEG_PHASE, &p2p->status);
		}
	}
	else if (wland_p2p_is_gas_action((void *)mgmt_frame+offsetof(struct ieee80211_mgmt, u),
			mgmt_frame_len-MAC_HDR_LEN)) {
		sd_act_frm = (struct wland_p2psd_gas_pub_act_frame *)
			((void *)mgmt_frame+offsetof(struct ieee80211_mgmt, u));
		action = sd_act_frm->action;
		WLAND_DBG(CFG80211, TRACE,
				"P2P: wland_p2p_is_gas_action\n");

	}

	if (test_bit(P2P_STATUS_WAITING_NEXT_ACT_FRAME, &p2p->status)
		&& (p2p->next_af_subtype == action)) {
		WLAND_DBG(CFG80211, INFO, "We got a right next frame! (%d)\n",
			action);
		clear_bit(P2P_STATUS_WAITING_NEXT_ACT_FRAME, &p2p->status);
		/*
		 * Stop waiting for next AF.
		 */
		wland_p2p_stop_wait_next_action_frame(cfg);
	}

#if 0

	mgmt_frame =
		kzalloc(offsetof(struct ieee80211_mgmt, u) + mgmt_frame_len,
		GFP_KERNEL);
	if (!mgmt_frame) {
		WLAND_ERR("No memory available for action frame\n");
		return -ENOMEM;
	}

	memcpy(mgmt_frame->da, ifp->mac_addr, ETH_ALEN);

//	wland_fil_iovar_data_get(ifp, "get_bssid", mgmt_frame->bssid, ETH_ALEN);
	//memcpy(mgmt_frame->bssid, frame, ETH_ALEN);
	memcpy(mgmt_frame->bssid, &frame[16], ETH_ALEN);
	//memcpy(mgmt_frame->sa, e->addr, ETH_ALEN);
	memcpy(mgmt_frame->sa, &frame[10], ETH_ALEN);

	mgmt_frame->frame_control = cpu_to_le16(IEEE80211_STYPE_ACTION);
	memcpy(&mgmt_frame->u, frame, mgmt_frame_len);
	mgmt_frame_len += offsetof(struct ieee80211_mgmt, u);

#endif
	WLAND_DUMP(RX_NETEVENT, mgmt_frame->bssid, ETH_ALEN, "mgmt_frame->bssid\n");
	WLAND_DUMP(RX_NETEVENT, ifp->mac_addr, ETH_ALEN, "ifp->mac_addr\n");
	WLAND_DUMP(RX_NETEVENT, mgmt_frame->sa, ETH_ALEN, "mgmt_frame->sa\n");


	freq = ieee80211_channel_to_frequency(channel_num,
		(channel_num <= CH_MAX_2G_CHANNEL) ? NL80211_BAND_2GHZ : NL80211_BAND_5GHZ);

	WLAND_DBG(CFG80211, TRACE, "!!! PASS THE PUB_ACTION FRAME TO WPAS\n");
	WLAND_DUMP(RX_NETEVENT, mgmt_frame, mgmt_frame_len, "RX ACTION FRAME\n");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0)
	cfg80211_rx_mgmt(&vif->wdev, freq, 0, (u8 *)mgmt_frame, mgmt_frame_len, 0);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	cfg80211_rx_mgmt(&vif->wdev, freq, 0, (u8 *)mgmt_frame, mgmt_frame_len, 0,
		GFP_ATOMIC);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
	cfg80211_rx_mgmt(&vif->wdev, freq, 0, (u8 *)mgmt_frame, mgmt_frame_len,
		GFP_ATOMIC);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,4,0)
	cfg80211_rx_mgmt(ifp->ndev, freq, 0, (u8 *)mgmt_frame, mgmt_frame_len,	GFP_ATOMIC);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,37)
	cfg80211_rx_mgmt(ifp->ndev, freq, (u8 *)mgmt_frame, mgmt_frame_len, GFP_ATOMIC);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
	cfg80211_rx_action(ifp->ndev, freq, (u8 *)mgmt_frame, mgmt_frame_len, GFP_ATOMIC);
#endif

	WLAND_DBG(CFG80211, TRACE, "Done\n");
#if 0
	kfree(mgmt_frame);
#endif
	return 0;
}

/*
 * wland_notify_p2p_action_tx_complete() - transmit action frame complete
 *
 * @ifp : interfac control.
 * @e   : event message. Not used, to make it usable for fweh event dispatcher.
 * @data: not used.
 *
 */
s32 wland_notify_p2p_action_tx_complete(struct wland_if * ifp,
	const struct wland_event_msg * e, void *data)
{
	struct wland_cfg80211_info *cfg = ifp->drvr->config;
	struct wland_p2p_info *p2p = &cfg->p2p;

	WLAND_DBG(CFG80211, TRACE, "Enter: event %s, status=%d\n",
		e->event_code ==
		WLAND_E_ACT_FRAME_OFF_CHAN_COMPLETE ?
		"ACTION_FRAME_OFF_CHAN_COMPLETE" : "ACTION_FRAME_COMPLETE",
		e->status);

	if (!test_bit(P2P_STATUS_SENDING_ACT_FRAME, &p2p->status))
		return 0;

	if (e->event_code == WLAND_E_ACT_FRAME_COMPLETE) {
		if (e->status == STATUS_SUCCESS) {
			set_bit(P2P_STATUS_ACTION_TX_COMPLETED, &p2p->status);
		} else {
			set_bit(P2P_STATUS_ACTION_TX_NOACK, &p2p->status);
			/*
			 * If there is no ack, we don't need to wait for WLC_E_ACTION_FRAME_OFFCHAN_COMPLETE event
			 */
			wland_p2p_stop_wait_next_action_frame(cfg);
		}
	}

	complete(&p2p->send_af_done);

	return 0;
}

/*
 * wland_p2p_tx_action_frame() - send action frame over fil.
 *
 * @p2p      : p2p info struct for vif.
 * @af_params: action frame data/info.
 *
 * Send an action frame immediately without doing channel synchronization.
 *
 * This function waits for a completion event before returning.
 * The WLC_E_ACTION_FRAME_COMPLETE event will be received when the action
 * frame is transmitted.
 */
static s32 wland_p2p_tx_action_frame(struct wland_p2p_info *p2p,
	struct wland_fil_af_params_le *af_params)
{
	struct wland_cfg80211_vif *vif;
	s32 err = 0, timeout = 0;

	WLAND_DBG(CFG80211, INFO, "Enter\n");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	reinit_completion(&p2p->send_af_done);
#else /*LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)*/
	INIT_COMPLETION(p2p->send_af_done);
#endif /*LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)*/

	clear_bit(P2P_STATUS_ACTION_TX_COMPLETED, &p2p->status);
	clear_bit(P2P_STATUS_ACTION_TX_NOACK, &p2p->status);

	vif = p2p->bss_idx[P2PAPI_BSSCFG_DEVICE].vif;

//	err = wland_fil_iovar_data_set(vif->ifp, "actframe", af_params,
//		sizeof(*af_params));
//  err =  wland_fil_set_cmd_data(vif->ifp, WID_P2P_ACTION_TX,
//    		&(af_params->action_frame.data),af_params->action_frame.len);

	WLAND_DBG(CFG80211, TRACE, "tx af channel = %x\n", af_params->channel);

    err =  wland_fil_set_cmd_data(vif->ifp, WID_P2P_ACTION_TX, af_params,
    		WLAND_FIL_AF_PARAMS_HDR_LEN +
    		WLAND_FIL_ACTION_FRAME_HDR_LEN +
    		af_params->action_frame.len);

	WLAND_DUMP(RX_NETEVENT, af_params, (WLAND_FIL_AF_PARAMS_HDR_LEN + WLAND_FIL_ACTION_FRAME_HDR_LEN +
			af_params->action_frame.len), "TX ACTION FRAME\n");
	if (err < 0) {
		WLAND_ERR(" sending action frame has failed\n");
		goto exit;
	}
#if 1
	p2p->af_sent_channel = le32_to_cpu(af_params->channel);
	p2p->af_tx_sent_jiffies = jiffies;

	timeout =
		wait_for_completion_timeout(&p2p->send_af_done,
			msecs_to_jiffies(P2P_AF_MAX_WAIT_TIME));

	if (test_bit(P2P_STATUS_ACTION_TX_COMPLETED, &p2p->status)) {
		WLAND_DBG(CFG80211, DEBUG,
			"TX action frame operation is success\n");
	} else {
		err = -EIO;
		WLAND_ERR("TX action frame operation has failed\n");
	}
	/*
	 * clear status bit for action tx
	 */
#else
	msleep(1);
#endif
	clear_bit(P2P_STATUS_ACTION_TX_COMPLETED, &p2p->status);
	clear_bit(P2P_STATUS_ACTION_TX_NOACK, &p2p->status);

exit:
	return err;
}

/*
 * wland_p2p_pub_af_tx() - public action frame tx routine.
 *
 * @cfg             : driver private data for cfg80211 interface.
 * @af_params       : action frame data/info.
 * @config_af_params: configuration data for action frame.
 *
 * routine which transmits ation frame public type.
 */
static s32 wland_p2p_pub_af_tx(struct wland_cfg80211_info *cfg,
	struct wland_fil_af_params_le *af_params,
	struct wland_config_af_params *config_af_params)
{
	struct wland_p2p_info *p2p = &cfg->p2p;
	struct wland_fil_action_frame_le *action_frame =
		&af_params->action_frame;
	struct wland_p2p_pub_act_frame *act_frm =
		(struct wland_p2p_pub_act_frame *) (action_frame->data);
	s32 err = 0;
	u16 ie_len;

	config_af_params->extra_listen = true;

	switch (act_frm->subtype) {
	case P2P_PAF_GON_REQ:
		WLAND_DBG(CFG80211, TRACE, "P2P: GO_NEG_PHASE status set\n");
		set_bit(P2P_STATUS_GO_NEG_PHASE, &p2p->status);
		config_af_params->search_channel = true;

		p2p->next_af_subtype = act_frm->subtype + 1;
		p2p->gon_req_action = true;
		/*
		 * increase dwell time to wait for RESP frame
		 */
		af_params->dwell_time = cpu_to_le32(P2P_AF_MED_DWELL_TIME);
		break;
	case P2P_PAF_GON_RSP:
		p2p->next_af_subtype = act_frm->subtype + 1;
		/*
		 * increase dwell time to wait for CONF frame
		 */
		af_params->dwell_time = cpu_to_le32(P2P_AF_MED_DWELL_TIME);
		WLAND_DBG(CFG80211, TRACE, "!!! send P2P_PAF_GON_RSP\n");
		break;
	case P2P_PAF_GON_CONF:
		//config_af_params->search_channel = true;
		/*
		 * If we reached till GO Neg confirmation reset the filter
		 */
		WLAND_DBG(CFG80211, TRACE, "P2P: GO_NEG_PHASE status cleared\n");
		clear_bit(P2P_STATUS_GO_NEG_PHASE, &p2p->status);
		/*
		 * minimize dwell time
		 */
		af_params->dwell_time = cpu_to_le32(P2P_AF_MIN_DWELL_TIME);
		config_af_params->extra_listen = false;
		break;
	case P2P_PAF_INVITE_REQ:
		config_af_params->search_channel = true;
		p2p->next_af_subtype = act_frm->subtype + 1;
		/*
		 * increase dwell time
		 */
		af_params->dwell_time = cpu_to_le32(P2P_AF_MED_DWELL_TIME);
		break;
	case P2P_PAF_INVITE_RSP:
		/*
		 * minimize dwell time
		 */
		af_params->dwell_time = cpu_to_le32(P2P_AF_MIN_DWELL_TIME);
		config_af_params->extra_listen = false;
		break;
	case P2P_PAF_DEVDIS_REQ:
		config_af_params->search_channel = true;
		p2p->next_af_subtype = act_frm->subtype + 1;
		/*
		 * maximize dwell time to wait for RESP frame
		 */
		af_params->dwell_time = cpu_to_le32(P2P_AF_LONG_DWELL_TIME);
		break;
	case P2P_PAF_DEVDIS_RSP:
		/*
		 * minimize dwell time
		 */
		af_params->dwell_time = cpu_to_le32(P2P_AF_MIN_DWELL_TIME);
		config_af_params->extra_listen = false;
		break;
	case P2P_PAF_PROVDIS_REQ:
		ie_len = le16_to_cpu(action_frame->len) -
			offsetof(struct wland_p2p_pub_act_frame, elts);
#if 1
		if (cfg80211_get_p2p_attr(&act_frm->elts[0], ie_len,
				IEEE80211_P2P_ATTR_GROUP_ID, NULL, 0) < 0)
			config_af_params->search_channel = true;
#endif
		p2p->next_af_subtype = act_frm->subtype + 1;
		/*
		 * increase dwell time to wait for RESP frame
		 */
		af_params->dwell_time = cpu_to_le32(P2P_AF_MED_DWELL_TIME);
		break;
	case P2P_PAF_PROVDIS_RSP:
		/*
		 * wpa_supplicant send go nego req right after prov disc
		 */
		p2p->next_af_subtype = P2P_PAF_GON_REQ;
		/*
		 * increase dwell time to MED level
		 */
		af_params->dwell_time = cpu_to_le32(P2P_AF_MED_DWELL_TIME);
		config_af_params->extra_listen = false;
		WLAND_DBG(CFG80211, TRACE, "!!! send P2P_PAF_PROVDIS_RSP\n");
		break;
	default:
		WLAND_ERR("Unknown p2p pub act frame subtype: %d\n",
			act_frm->subtype);
		err = -EINVAL;
		break;
	}
	return err;
}

/*
 * wland_p2p_send_action_frame() - send action frame .
 *
 * @cfg			: driver private data for cfg80211 interface.
 * @ndev		: net device to transmit on.
 * @af_params	: configuration data for action frame.
 */
bool wland_p2p_send_action_frame(struct wland_cfg80211_info * cfg,
	struct net_device * ndev, struct wland_fil_af_params_le * af_params)
{
	struct wland_p2p_info *p2p = &cfg->p2p;
	struct wland_if *ifp = netdev_priv(ndev);
	struct wland_fil_action_frame_le *action_frame;
	struct wland_config_af_params config_af_params;
	struct afx_hdl *afx_hdl = &p2p->afx_hdl;
	u16 action_frame_len;
	bool ack = false;
	u8 category, action;
	s32 tx_retry, extra_listen_time;
	uint delta_ms;
//	u8 err = 0;

	action_frame = &af_params->action_frame;
	action_frame_len = le16_to_cpu(action_frame->len);

	WLAND_DBG(CFG80211, TRACE, "!!! Enter wland_p2p_send_action_frame\n");

	/*
	 * Add the default dwell time. Dwell time to stay off-channel
	 * to wait for a response action frame after transmitting an
	 * GO Negotiation action frame
	 */
	af_params->dwell_time = cpu_to_le32(P2P_AF_DWELL_TIME);

	category = action_frame->data[DOT11_ACTION_CAT_OFF];
	action = action_frame->data[DOT11_ACTION_ACT_OFF];

	/*
	 * initialize variables
	 */
	p2p->next_af_subtype = P2P_PAF_SUBTYPE_INVALID;
	p2p->gon_req_action = false;

	/*
	 * config parameters
	 */
	config_af_params.search_channel = false;
	config_af_params.extra_listen = false;
//	err =  wland_fil_set_cmd_data(ifp, WID_SET_P2P_TARGET_DEV_ID, af_params->action_frame.da, 6);
//	if (err < 0) {
//		WLAND_ERR(" sending target id has failed\n");
//		}

	if (wland_p2p_is_pub_action(action_frame->data, action_frame_len)) {
		/*
		 * p2p public action frame process
		 */
		if (wland_p2p_pub_af_tx(cfg, af_params, &config_af_params)) {
			/*
			 * Just send unknown subtype frame with
			 */
			/*
			 * default parameters.
			 */
			WLAND_ERR
				("P2P Public action frame, unknown subtype.\n");
		}
	} else if (wland_p2p_is_gas_action(action_frame->data,
			action_frame_len)) {
		/*
		 * service discovery process
		 */
		if (action == P2PSD_ACTION_ID_GAS_IREQ
			|| action == P2PSD_ACTION_ID_GAS_CREQ) {
			/*
			 * configure service discovery query frame
			 */
			config_af_params.search_channel = true;

			/*
			 * save next af suptype to cancel remaining dwell time
			 */
			p2p->next_af_subtype = action + 1;
			af_params->dwell_time =
				cpu_to_le32(P2P_AF_MED_DWELL_TIME);
		} else if (action == P2PSD_ACTION_ID_GAS_IRESP
			|| action == P2PSD_ACTION_ID_GAS_CRESP) {
			/*
			 * configure service discovery response frame
			 */
			af_params->dwell_time =
				cpu_to_le32(P2P_AF_MIN_DWELL_TIME);
		} else {
			WLAND_ERR("Unknown action type: %d\n", action);
			goto exit;
		}
	} else if (wland_p2p_is_p2p_action(action_frame->data,
			action_frame_len)) {
		/*
		 * do not configure anything. it will be sent with a default configuration
		 */
	} else {
		WLAND_ERR("Unknown Frame: category 0x%x, action 0x%x\n",
			category, action);
		return false;
	}

	/*
	 * if connecting on primary iface, sleep for a while before sending af tx for VSDB
	 */
	if (test_bit(VIF_STATUS_CONNECTING,
			&p2p->bss_idx[P2PAPI_BSSCFG_PRIMARY].vif->sme_state))
		msleep(50);

	/*
	 * if scan is ongoing, abort current scan.
	 */
	if (test_bit(SCAN_STATUS_BUSY, &cfg->scan_status))
		wland_abort_scanning(cfg);

	memcpy(afx_hdl->tx_dst_addr, action_frame->da, ETH_ALEN);

	/*
	 * set status and destination address before sending af
	 */
	if (p2p->next_af_subtype != P2P_PAF_SUBTYPE_INVALID) {
		/*
		 * set status to cancel the remained dwell time in rx process
		 */
		set_bit(P2P_STATUS_WAITING_NEXT_ACT_FRAME, &p2p->status);
	}

	p2p->af_sent_channel = 0;

	set_bit(P2P_STATUS_SENDING_ACT_FRAME, &p2p->status);

	/*
	 * validate channel and p2p ies
	 */
#if 1
	WLAND_DBG(CFG80211, INFO, "!!! config_af_params.search_channel = %d\n",config_af_params.search_channel);

	if (config_af_params.search_channel &&
		IS_P2P_SOCIAL_CHANNEL(le32_to_cpu(af_params->channel)) &&
		p2p->bss_idx[P2PAPI_BSSCFG_DEVICE].vif->saved_ie.probe_req_ie_len) {
		afx_hdl = &p2p->afx_hdl;
		afx_hdl->peer_listen_chan = le32_to_cpu(af_params->channel);

		if (wland_p2p_af_searching_channel(p2p) == P2P_INVALID_CHANNEL) {
			WLAND_ERR("Couldn't find peer's channel, use default channel:%d.\n", af_params->channel);
			//goto exit;
		} else {

			/*
			 * Abort scan even for VSDB scenarios. Scan gets aborted in
			 * * firmware but after the check of piggyback algorithm. To take
			 * * care of current piggback algo, lets abort the scan here itself.
			 */
			wland_notify_escan_complete(cfg, ifp, true, true);

			/*
			 * update channel
			 */
			af_params->channel = cpu_to_le32(afx_hdl->peer_chan);
		}
	}
#endif
	tx_retry = 0;

	while (!p2p->block_gon_req_tx && (ack == 0)
		&& (tx_retry < P2P_AF_TX_MAX_RETRY)) {
		ack = !wland_p2p_tx_action_frame(p2p, af_params);
		if (ack == 0) {
			WLAND_ERR("Failed to send Action Frame(retry %d)\n", tx_retry);
			afx_hdl = &p2p->afx_hdl;
			afx_hdl->peer_listen_chan = le32_to_cpu(af_params->channel);
			if (wland_p2p_af_searching_channel(p2p) == P2P_INVALID_CHANNEL) {
				WLAND_ERR("Couldn't find peer's channel, use default channel:%d.\n", af_params->channel);
				//goto exit;
			}
		}
		tx_retry++;
	}

	if (!ack) {
		clear_bit(P2P_STATUS_GO_NEG_PHASE, &p2p->status);
	}

exit:
	clear_bit(P2P_STATUS_SENDING_ACT_FRAME, &p2p->status);

	/*
	 * WAR: sometimes dongle does not keep the dwell time of 'actframe'.
	 * * if we coundn't get the next action response frame and dongle does
	 * * not keep the dwell time, go to listen state again to get next action
	 * * response frame.
	 */
	if (0 && ack && config_af_params.extra_listen && !p2p->block_gon_req_tx &&
		test_bit(P2P_STATUS_WAITING_NEXT_ACT_FRAME, &p2p->status) &&
		p2p->af_sent_channel == afx_hdl->my_listen_chan) {
		delta_ms = jiffies_to_msecs(jiffies - p2p->af_tx_sent_jiffies);

		if (le32_to_cpu(af_params->dwell_time) > delta_ms)
			extra_listen_time =
				le32_to_cpu(af_params->dwell_time) - delta_ms;
		else
			extra_listen_time = 0;

		if (extra_listen_time > 50) {
			set_bit(P2P_STATUS_WAITING_NEXT_AF_LISTEN,
				&p2p->status);
			WLAND_DBG(CFG80211, INFO,
				"Wait more time! actual af time:%d, calculated extra listen:%d\n",
				le32_to_cpu(af_params->dwell_time),
				extra_listen_time);
			extra_listen_time += 100;

			if (!wland_p2p_discover_listen(p2p,
					p2p->af_sent_channel,
					extra_listen_time)) {
				unsigned long duration;

				extra_listen_time += 100;
				duration = msecs_to_jiffies(extra_listen_time);
				wait_for_completion_timeout(&p2p->wait_next_af,
					duration);
			}
			clear_bit(P2P_STATUS_WAITING_NEXT_AF_LISTEN,
				&p2p->status);
		}
	}

	if (p2p->block_gon_req_tx) {
		/*
		 * if ack is true, supplicant will wait more time(100ms).
		 * * so we will return it as a success to get more time .
		 */
		p2p->block_gon_req_tx = false;
		ack = true;
	}

	clear_bit(P2P_STATUS_WAITING_NEXT_ACT_FRAME, &p2p->status);

	return ack;
}

/*
 * wland_notify_p2p_rx_mgmt_probereq() - Event handler for p2p probe req.
 *
 * @ifp : interface pointer for which event was received.
 * @e   : even message.
 * @data: payload of event message (probe request).
 */
s32 wland_notify_p2p_rx_mgmt_probereq(struct wland_if * ifp,
	const struct wland_event_msg * e, void *data)
{
	struct wland_cfg80211_info *cfg = ifp->drvr->config;
	struct wland_p2p_info *p2p = &cfg->p2p;
	struct afx_hdl *afx_hdl = &p2p->afx_hdl;
	struct wland_cfg80211_vif *vif = ifp->vif;
	struct wland_rx_async_mgmt_data *rxframe = (struct wland_rx_async_mgmt_data *)data;
	u8 *frame = (u8 *)(data + rxframe->offset);
	u32 mgmt_frame_len = rxframe->length;
	s32 freq;
	u16 mgmt_type;

	WLAND_DBG(CFG80211, TRACE, "Enter: event %d reason %d\n", e->event_code,
		e->reason);

	if (test_bit(P2P_STATUS_FINDING_COMMON_CHANNEL, &p2p->status)
		&& (memcmp(afx_hdl->tx_dst_addr, e->addr, ETH_ALEN) == 0)) {
		afx_hdl->peer_chan = rxframe->chnum;
		WLAND_DBG(CFG80211, TRACE,
			"PROBE REQUEST: Peer found, channel=%d\n",
			afx_hdl->peer_chan);
		complete(&afx_hdl->act_frm_scan);
	}

	/*
	 * Firmware sends us two proberesponses for each idx one. At the
	 * moment anything but bsscfgidx 0 is passed up to supplicant
	 */
	if (e->bsscfgidx == 0)
		return 0;

	/*
	 * Filter any P2P probe reqs arriving during the GO-NEG Phase
	 */
	if (test_bit(P2P_STATUS_GO_NEG_PHASE, &p2p->status)) {
		WLAND_DBG(CFG80211, TRACE,
			"Filtering P2P probe_req in GO-NEG phase\n");
		return 0;
	}

	/*
	 * Check if wpa_supplicant has registered for this frame
	 */
	WLAND_DBG(CFG80211, TRACE, "vif->mgmt_rx_reg %04x\n", vif->mgmt_rx_reg);

	mgmt_type = (IEEE80211_STYPE_PROBE_REQ & IEEE80211_FCTL_STYPE) >> 4;

	if ((vif->mgmt_rx_reg & BIT(mgmt_type)) == 0)
		return 0;

	freq = ieee80211_channel_to_frequency(rxframe->chnum,
		(rxframe->chnum <= CH_MAX_2G_CHANNEL) ? NL80211_BAND_2GHZ : NL80211_BAND_5GHZ);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0)
	cfg80211_rx_mgmt(&vif->wdev, freq, 0, frame, mgmt_frame_len, 0);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	cfg80211_rx_mgmt(&vif->wdev, freq, 0, frame, mgmt_frame_len, 0,
		GFP_ATOMIC);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
	cfg80211_rx_mgmt(&vif->wdev, freq, 0, frame, mgmt_frame_len,
		GFP_ATOMIC);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,4,0)
	cfg80211_rx_mgmt(ifp->ndev, freq, 0, frame, mgmt_frame_len,	GFP_ATOMIC);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,37)
	cfg80211_rx_mgmt(ifp->ndev, freq, frame, mgmt_frame_len, GFP_ATOMIC);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
	cfg80211_rx_action(ifp->ndev, freq, frame, mgmt_frame_len, GFP_ATOMIC);
#endif

	WLAND_DBG(CFG80211, TRACE,
		"mgmt_frame_len(%d),datalen (%d),chanspec(%04x),freq (%d)\n",
		mgmt_frame_len, e->datalen, 0, freq);

	return 0;
}

/*
 * wland_p2p_get_current_chanspec() - Get current operation channel.
 *
 * @p2p		: P2P specific data.
 * @chanspec: chanspec to be returned.
 */
static void wland_p2p_get_current_chanspec(struct wland_p2p_info *p2p,
	u16 * chanspec)
{
	struct wland_chan ch;
	struct wland_bss_info_le *bi;
	u8 *buf;
	u8 mac_addr[ETH_ALEN];
	struct wland_if *ifp = p2p->bss_idx[P2PAPI_BSSCFG_PRIMARY].vif->ifp;

	if (wland_fil_iovar_data_get(ifp, "get_bssid", mac_addr, ETH_ALEN) > 0) {
		buf = kzalloc(WLAND_BSS_INFO_MAX, GFP_KERNEL);

		if (buf != NULL) {
			*(__le32 *) buf = cpu_to_le32(WLAND_BSS_INFO_MAX);

			if (wland_fil_iovar_data_get(ifp, "get_bss_info", buf,
					WLAND_BSS_INFO_MAX) > 0) {
				bi = (struct wland_bss_info_le *) (buf + 4);
				*chanspec = le16_to_cpu(bi->chanspec);
				kfree(buf);
				return;
			}
			kfree(buf);
		}
	}

	/*
	 * Use default channel for P2P
	 */
	ch.chnum = WLAND_P2P_TEMP_CHAN;
	ch.bw = CHAN_BW_20;
	p2p->cfg->d11inf.encchspec(&ch);
	*chanspec = ch.chspec;
}

/*
 * Change a P2P Role.
 * Parameters:
 * @mac     : MAC address of the BSS to change a role
 * Returns 0 if success.
 */
s32 wland_p2p_ifchange(struct wland_cfg80211_info * cfg,
	enum wland_fil_p2p_if_types if_type)
{
	struct wland_p2p_info *p2p = &cfg->p2p;
	struct wland_cfg80211_vif *vif =
		p2p->bss_idx[P2PAPI_BSSCFG_PRIMARY].vif;
	struct wland_fil_p2p_if_le if_request;
	s32 err, timeout;
	u16 chanspec;

	WLAND_DBG(CFG80211, INFO, "Enter\n");

	if (!vif) {
		WLAND_ERR("vif for P2PAPI_BSSCFG_PRIMARY does not exist\n");
		return -EPERM;
	}

	wland_notify_escan_complete(cfg, vif->ifp, true, true);

	vif = p2p->bss_idx[P2PAPI_BSSCFG_DEVICE].vif;

	if (!vif) {
		WLAND_ERR("vif for P2PAPI_BSSCFG_CONNECTION does not exist\n");
		return -EPERM;
	}
	/*
	 * In concurrency case, STA may be already associated in a particular
	 */
	/*
	 * channel. so retrieve the current channel of primary interface and
	 */
	/*
	 * then start the virtual interface on that.
	 */
	wland_p2p_get_current_chanspec(p2p, &chanspec);

	if_request.type = cpu_to_le16((u16) if_type);
	if_request.channel= cpu_to_le16(chanspec & 0xff);

	memcpy(if_request.addr, vif->ifp->mac_addr, ETH_ALEN);

	wland_cfg80211_arm_vif_event(cfg, vif);

#if 0
	err = wland_fil_iovar_data_set(vif->ifp, "p2p_ifupd", &if_request,
		sizeof(if_request));
	if (err < 0) {
		WLAND_ERR("p2p_ifupd FAILED, err=%d\n", err);
		wland_cfg80211_arm_vif_event(cfg, NULL);
		return err;
	}
#else

	if_request.bsscfgidx = P2PAPI_BSSCFG_DEVICE;
	if_request.ifidx = 0;

	err = wland_fil_set_cmd_data(vif->ifp,
		WID_P2P_CHANGE_INTERFACE, &if_request, sizeof(if_request));
#endif

#if 1
	err = wland_cfg80211_wait_vif_event_timeout(cfg, WLAND_ACTION_IF_CHANGE,
		msecs_to_jiffies(1500));

	wland_cfg80211_arm_vif_event(cfg, NULL);
	if (!err) {
		WLAND_ERR("No WLAND_E_IF_CHANGE event received\n");
		return -EIO;
	}
#endif
	timeout = WLAND_SCB_TIMEOUT_VALUE;

	return err >= 0 ? 0 : -1;
	//return wland_fil_iovar_data_set(vif->ifp, "scb_timeout", &timeout,
	//	sizeof(timeout));
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
s32 wland_cfg80211_p2p_start_device(struct wiphy * wiphy, struct wireless_dev * wdev)
{
	s32 err;
	struct wland_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct wland_p2p_info *p2p = &cfg->p2p;
	struct wland_cfg80211_vif *vif =
		container_of(wdev, struct wland_cfg80211_vif, wdev);

	WLAND_DBG(CFG80211, TRACE, "Enter\n");

	mutex_lock(&cfg->usr_sync);
	err = wland_p2p_enable_discovery(p2p);
	if (!err)
		set_bit(VIF_STATUS_READY, &vif->sme_state);
	mutex_unlock(&cfg->usr_sync);

	return err;
}

void wland_cfg80211_p2p_stop_device(struct wiphy *wiphy, struct wireless_dev *wdev)
{
	struct wland_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct wland_p2p_info *p2p = &cfg->p2p;
	struct wland_cfg80211_vif *vif =
		container_of(wdev, struct wland_cfg80211_vif, wdev);

	WLAND_DBG(CFG80211, TRACE, "Enter\n");

	mutex_lock(&cfg->usr_sync);
	wland_p2p_deinit_discovery(p2p);
	wland_abort_scanning(cfg);
	clear_bit(VIF_STATUS_READY, &vif->sme_state);
	mutex_unlock(&cfg->usr_sync);
}
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0) */

static void wland_cfg80211_delay_remain_on_channel_worker(struct work_struct *work)
{
	struct wland_p2p_info *p2p =
		container_of(work, struct wland_p2p_info, delay_remain_onchannel_work.work);
	struct wland_if *ifp = p2p->bss_idx[P2PAPI_BSSCFG_DEVICE].vif->ifp;
	struct wland_cfg80211_info *cfg = ifp->drvr->config;

	WLAND_DBG(CFG80211, INFO, "Enter\n");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	cfg80211_remain_on_channel_expired(&ifp->vif->wdev,
		p2p->remain_on_channel_cookie, &p2p->remain_on_channel,
		GFP_KERNEL);
#else /* LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0) */
	cfg80211_remain_on_channel_expired(ifp->ndev,
		p2p->remain_on_channel_cookie, &p2p->remain_on_channel,
		p2p->remain_on_chan_type, GFP_KERNEL);
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0) */
	clear_bit(SCAN_STATUS_BUSY, &cfg->scan_status);

}

static void wland_p2p_alive_timeout_worker(struct work_struct *work)
{
	u8 val = 0;
	struct wland_p2p_info *p2p =
		container_of(work, struct wland_p2p_info, p2p_alive_timeout_work);
	struct wland_if *ifp = p2p->cfg->pub->iflist[P2PAPI_BSSCFG_PRIMARY];

	WLAND_DBG(CFG80211, INFO, "Enter\n");
	if (timer_pending(&p2p->p2p_alive_timer)) {
		del_timer_sync(&p2p->p2p_alive_timer);
	}

	wland_fil_set_cmd_data(ifp, WID_P2P_ENABLE, &val, sizeof(val));

	WLAND_DBG(CFG80211, TRACE, "Done.\n");
	return ;
}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
static void wland_p2p_alive_timeout(struct timer_list *t)
{
	struct wland_p2p_info *p2p = from_timer(p2p, t, p2p_alive_timer);
#else
static void wland_p2p_alive_timeout(ulong data)
{
	struct wland_p2p_info *p2p =
		(struct wland_p2p_info *) data;
#endif
	struct wland_if *p2p_ifp = p2p->bss_idx[P2PAPI_BSSCFG_DEVICE].vif->ifp;

	if (!wland_check_vif_up(p2p_ifp->vif)) {
		WLAND_DBG(CFG80211, INFO, "timer return\n");
		return;
	}

	atomic_inc(&p2p->p2p_alive_timer_count);

	if (atomic_read(&p2p->p2p_alive_timer_count) < P2P_ALIVE_TIME_COUNT) {
		mod_timer(&p2p->p2p_alive_timer,
			jiffies + msecs_to_jiffies(P2P_ALIVE_TIME_MS));
		return;
	} else
		atomic_set(&p2p->p2p_alive_timer_count, 0);

	WLAND_DBG(CFG80211, DEBUG, "p2p_alive timer expired state:%d, mode:%d, sme_state:%x\n",
			atomic_read(&p2p->p2p_state), p2p_ifp->vif->mode, (u32)p2p_ifp->vif->sme_state);

	if (atomic_read(&p2p->p2p_state) != 1)
		WLAND_ERR("error p2p state:%d, mode:%d\n",
			atomic_read(&p2p->p2p_state), p2p_ifp->vif->mode);

	if (test_bit(VIF_STATUS_CONNECTED, &p2p_ifp->vif->sme_state) ||
		test_bit(VIF_STATUS_AP_CREATED, &p2p_ifp->vif->sme_state)) {
		mod_timer(&p2p->p2p_alive_timer,
			jiffies + msecs_to_jiffies(P2P_ALIVE_TIME_MS));
	} else {
		WLAND_DBG(CFG80211, INFO, "disable p2p\n");
		atomic_set(&p2p->p2p_state, 2);
		schedule_work(&p2p->p2p_alive_timeout_work);
	}
}

/*
 * cfg80211_p2p_attach() - attach for P2P.
 *
 * @cfg: driver private data for cfg80211 interface.
 */
s32 cfg80211_p2p_attach(struct wland_cfg80211_info *cfg)
{
	struct wland_if *pri_ifp = NULL;
	struct wland_if *p2p_ifp = NULL;
	struct wland_cfg80211_vif *p2p_vif = NULL;
	struct wland_p2p_info *p2p = &cfg->p2p;
	struct wland_private *drvr = cfg->pub;
	s32 err = 0;
	u8 enable = 1;

	p2p->cfg = cfg;

	/*
	 * primary vif same to "wlan0"
	 */
	pri_ifp = drvr->iflist[P2PAPI_BSSCFG_PRIMARY];
	p2p_ifp = drvr->iflist[P2PAPI_BSSCFG_DEVICE];

	p2p->bss_idx[P2PAPI_BSSCFG_PRIMARY].vif = pri_ifp->vif;

	INIT_DELAYED_WORK(&p2p->delay_remain_onchannel_work,
		wland_cfg80211_delay_remain_on_channel_worker);

	WLAND_DBG(CFG80211, TRACE, "Enter(pri_ifp:%p,p2p_ifp:%p)\n", pri_ifp,
		p2p_ifp);

	if (p2p_ifp) {
		p2p_vif = wland_alloc_vif(cfg,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
			NL80211_IFTYPE_STATION,
#else /*LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0) */
			NL80211_IFTYPE_STATION,
#endif /*LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0) */
			false);
		if (IS_ERR(p2p_vif)) {
			WLAND_ERR("could not create discovery vif\n");
			err = -ENOMEM;
			goto exit;
		}
		p2p_vif->mode = WL_MODE_P2P;
		p2p_vif->ifp = p2p_ifp;
		p2p_ifp->vif = p2p_vif;
		p2p_vif->wdev.netdev = p2p_ifp->ndev;
		p2p_ifp->ndev->ieee80211_ptr = &p2p_vif->wdev;

		SET_NETDEV_DEV(p2p_ifp->ndev, wiphy_dev(cfg->wiphy));

		p2p->bss_idx[P2PAPI_BSSCFG_DEVICE].vif = p2p_vif;

		wland_p2p_generate_bss_mac(p2p, NULL);

		memcpy(p2p_ifp->mac_addr, p2p->dev_addr, ETH_ALEN);

		wland_p2p_set_firmware(pri_ifp, p2p->dev_addr);

		/*
		 * Initialize P2P Discovery in the firmware
		 */
		err = wland_fil_iovar_data_set(pri_ifp, "p2p_disc", &enable,
			sizeof(u8));
		if (err < 0) {
			WLAND_ERR("set p2p_disc error\n");
			wland_free_vif(cfg, p2p_vif);
			goto exit;
		}

		init_completion(&p2p->send_af_done);
		INIT_WORK(&p2p->afx_hdl.afx_work, wland_p2p_afx_handler);
		init_completion(&p2p->afx_hdl.act_frm_scan);
		init_completion(&p2p->wait_next_af);

		atomic_set(&p2p->p2p_state, 0);
		atomic_set(&p2p->p2p_alive_timer_count, 0);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
		timer_setup(&p2p->p2p_alive_timer, wland_p2p_alive_timeout, 0);
#else
		init_timer(&p2p->p2p_alive_timer);
		p2p->p2p_alive_timer.data = (unsigned long)p2p;
		p2p->p2p_alive_timer.function =	wland_p2p_alive_timeout;
#endif
		INIT_WORK(&p2p->p2p_alive_timeout_work,
			wland_p2p_alive_timeout_worker);
	}
exit:
	return err;
}

/*
 * cfg80211_p2p_detach() - detach P2P.
 *
 * @p2p: P2P specific data.
 */
void cfg80211_p2p_detach(struct wland_p2p_info *p2p)
{
	struct wland_cfg80211_vif *vif = p2p->bss_idx[P2PAPI_BSSCFG_DEVICE].vif;

	WLAND_DBG(CFG80211, TRACE, "Enter\n");

	cancel_delayed_work_sync(&p2p->delay_remain_onchannel_work);

	if (timer_pending(&p2p->p2p_alive_timer)) {
		del_timer_sync(&p2p->p2p_alive_timer);
	}
	cancel_work_sync(&p2p->p2p_alive_timeout_work);

	if (vif) {
		wland_p2p_cancel_remain_on_channel(vif->ifp);
		wland_p2p_deinit_discovery(p2p);
		/*
		 * remove discovery interface
		 */
		wland_free_vif(p2p->cfg, vif);
		p2p->bss_idx[P2PAPI_BSSCFG_DEVICE].vif = NULL;
	}
	/*
	 * just set it all to zero
	 */
	memset(p2p, '\0', sizeof(*p2p));
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 8, 0)
int cfg80211_get_p2p_attr(const u8 *ies, unsigned int len,
			  enum ieee80211_p2p_attr_id attr,
			  u8 *buf, unsigned int bufsize)
{
	u8 *out = buf;
	u16 attr_remaining = 0;
	bool desired_attr = false;
	u16 desired_len = 0;

	while (len > 0) {
		unsigned int iedatalen;
		unsigned int copy;
		const u8 *iedata;

		if (len < 2)
			return -EILSEQ;
		iedatalen = ies[1];
		if (iedatalen + 2 > len)
			return -EILSEQ;

		if (ies[0] != WLAN_EID_VENDOR_SPECIFIC)
			goto cont;

		if (iedatalen < 4)
			goto cont;

		iedata = ies + 2;

		/* check WFA OUI, P2P subtype */
		if (iedata[0] != 0x50 || iedata[1] != 0x6f ||
		    iedata[2] != 0x9a || iedata[3] != 0x09)
			goto cont;

		iedatalen -= 4;
		iedata += 4;

		/* check attribute continuation into this IE */
		copy = min_t(unsigned int, attr_remaining, iedatalen);
		if (copy && desired_attr) {
			desired_len += copy;
			if (out) {
				memcpy(out, iedata, min(bufsize, copy));
				out += min(bufsize, copy);
				bufsize -= min(bufsize, copy);
			}


			if (copy == attr_remaining)
				return desired_len;
		}

		attr_remaining -= copy;
		if (attr_remaining)
			goto cont;

		iedatalen -= copy;
		iedata += copy;

		while (iedatalen > 0) {
			u16 attr_len;

			/* P2P attribute ID & size must fit */
			if (iedatalen < 3)
				return -EILSEQ;
			desired_attr = iedata[0] == attr;
			attr_len = get_unaligned_le16(iedata + 1);
			iedatalen -= 3;
			iedata += 3;

			copy = min_t(unsigned int, attr_len, iedatalen);

			if (desired_attr) {
				desired_len += copy;
				if (out) {
					memcpy(out, iedata, min(bufsize, copy));
					out += min(bufsize, copy);
					bufsize -= min(bufsize, copy);
				}

				if (copy == attr_len)
					return desired_len;
			}

			iedata += copy;
			iedatalen -= copy;
			attr_remaining = attr_len - copy;
		}

 cont:
		len -= ies[1] + 2;
		ies += ies[1] + 2;
	}

	if (attr_remaining && desired_attr)
		return -EILSEQ;

	return -ENOENT;
}
#endif
#endif /* WLAND_P2P_SUPPORT */
