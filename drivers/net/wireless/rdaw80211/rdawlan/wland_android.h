
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
#ifndef _WLAND_ANDROID_H_
#define _WLAND_ANDROID_H_

/*
 * Android private command strings, PLEASE define new private commands here
 * so they can be updated easily in the future (if needed)
 */

#define CMD_START		        "START"
#define CMD_STOP		        "STOP"
#define	CMD_SCAN_ACTIVE		    "SCAN-ACTIVE"
#define	CMD_SCAN_PASSIVE	    "SCAN-PASSIVE"
#define CMD_RSSI		        "RSSI"
#define CMD_LINKSPEED		    "LINKSPEED"
#define CMD_RXFILTER_START	    "RXFILTER-START"
#define CMD_RXFILTER_STOP	    "RXFILTER-STOP"
#define CMD_RXFILTER_ADD	    "RXFILTER-ADD"
#define CMD_RXFILTER_REMOVE	    "RXFILTER-REMOVE"
#define CMD_BTCOEXSCAN_START	"BTCOEXSCAN-START"
#define CMD_BTCOEXSCAN_STOP	    "BTCOEXSCAN-STOP"
#define CMD_BTCOEXMODE		    "BTCOEXMODE"
#define CMD_SETSUSPENDOPT	    "SETSUSPENDOPT"
#define CMD_SETSUSPENDMODE      "SETSUSPENDMODE"
#define CMD_P2P_DEV_ADDR	    "P2P_DEV_ADDR"
#define CMD_SETFWPATH		    "SETFWPATH"
#define CMD_SETBAND		        "SETBAND"
#define CMD_GETBAND		        "GETBAND"
#define CMD_COUNTRY		        "COUNTRY"
#define CMD_P2P_SET_NOA		    "P2P_SET_NOA"
#if !defined WL_ENABLE_P2P_IF
#define CMD_P2P_GET_NOA		    "P2P_GET_NOA"
#endif
#define CMD_P2P_SD_OFFLOAD		"P2P_SD_"
#define CMD_P2P_SET_PS		    "P2P_SET_PS"
#define CMD_SET_AP_WPS_P2P_IE 	"SET_AP_WPS_P2P_IE"
#define CMD_SETROAMMODE 	    "SETROAMMODE"

/* CCX Private Commands */
#ifdef PNO_SUPPORT
#define CMD_PNOSSIDCLR_SET	    "PNOSSIDCLR"
#define CMD_PNOSETUP_SET	    "PNOSETUP "
#define CMD_PNOENABLE_SET	    "PNOFORCE"
#define CMD_PNODEBUG_SET	    "PNODEBUG"

#define PNO_TLV_PREFIX			'S'
#define PNO_TLV_VERSION			'1'
#define PNO_TLV_SUBVERSION 		'2'
#define PNO_TLV_RESERVED		'0'
#define PNO_TLV_TYPE_SSID_IE	'S'
#define PNO_TLV_TYPE_TIME		'T'
#define PNO_TLV_FREQ_REPEAT		'R'
#define PNO_TLV_FREQ_EXPO_MAX	'M'

struct cmd_tlv {
	char prefix;
	char version;
	char subver;
	char reserved;
};
#endif /* PNO_SUPPORT */

#define CMD_OKC_SET_PMK		    "SET_PMK"
#define CMD_OKC_ENABLE		    "OKC_ENABLE"

struct android_wifi_priv_cmd {
	char *buf;
	int used_len;
	int total_len;
};

#ifdef CONFIG_COMPAT
typedef struct _compat_android_wifi_priv_cmd {
	compat_caddr_t buf;
	int used_len;
	int total_len;
} compat_android_wifi_priv_cmd;
#endif /* CONFIG_COMPAT */

#define RSSI_MAXVAL                 -2
#define RSSI_MINVAL                 -200
#define REPEATED_SCAN_RESULT_CNT	4

#ifdef WLAND_RSSIAVG_SUPPORT
#define RSSIAVG_LEN                 (4*REPEATED_SCAN_RESULT_CNT)
#define RSSICACHE_LEN               (4*REPEATED_SCAN_RESULT_CNT)

struct wland_rssi_cache {
	struct wland_rssi_cache *next;
	int dirty;
	u8 BSSID[ETH_ALEN];
	s16 RSSI[RSSIAVG_LEN];
};

struct wland_rssi_cache_ctrl {
	struct wland_rssi_cache *m_cache_head;
};

void wland_free_rssi_cache(struct wland_rssi_cache_ctrl *rssi_cache_ctrl);
void wland_delete_dirty_rssi_cache(struct wland_rssi_cache_ctrl *rssi_cache_ctrl);
void wland_delete_disconnected_rssi_cache(struct wland_rssi_cache_ctrl
	*rssi_cache_ctrl, u8 * bssid);
void wland_reset_rssi_cache(struct wland_rssi_cache_ctrl *rssi_cache_ctrl);
void wland_update_rssi_cache(struct wland_rssi_cache_ctrl *rssi_cache_ctrl,
	struct wland_bss_info_le *bss);
int wland_update_connected_rssi_cache(struct net_device *net,
	struct wland_rssi_cache_ctrl *rssi_cache_ctrl, s16 * rssi_avg);
s16 wland_get_avg_rssi(struct wland_rssi_cache_ctrl *rssi_cache_ctrl, const u8 *addr);
#endif /* WLAND_RSSIAVG_SUPPORT */


#ifdef WLAND_BSSCACHE_SUPPORT
#define BSSCACHE_LEN	            (REPEATED_SCAN_RESULT_CNT)

struct wland_bss_cache {
	struct wland_bss_cache *next;
	int dirty;
	u32 version;
	struct wland_bss_info_le bss;
};
struct wland_bss_cache_ctrl {
	struct wland_bss_cache *m_cache_head;
};

void wland_free_bss_cache(struct wland_bss_cache_ctrl *bss_cache_ctrl);
void wland_delete_dirty_bss_cache(struct wland_bss_cache_ctrl *bss_cache_ctrl);
void wland_delete_disconnected_bss_cache(struct wland_bss_cache_ctrl
	*bss_cache_ctrl, u8 *bssid);
void wland_reset_bss_cache(struct wland_bss_cache_ctrl *bss_cache_ctrl);
void wland_update_bss_cache(struct wland_bss_cache_ctrl *bss_cache_ctrl,
	struct list_head *scan_results_list);
void wland_release_bss_cache_ctrl(struct wland_bss_cache_ctrl *bss_cache_ctrl);
#endif /* WLAND_BSSCACHE_SUPPORT */

int wland_android_priv_cmd(struct net_device *net, struct ifreq *ifr, int cmd);
#endif /* _WLAND_ANDROID_H_ */
