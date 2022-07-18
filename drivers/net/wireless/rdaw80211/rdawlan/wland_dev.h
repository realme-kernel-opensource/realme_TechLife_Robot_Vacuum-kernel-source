
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
#ifndef _WLAND_DEV_H_
#define _WLAND_DEV_H_

#include <linux/version.h>
#include <linux/wireless.h>
#include <linux/ieee80211.h>
#include <linux/nl80211.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include "wland_usb.h"
#include "wland_fweh.h"

#ifndef FCS_LEN
#define FCS_LEN                         4
#endif

#define PPP_HDR_LEN						8 //include ppp header len and ppp protocol

#define ALIGNMENT                       4

#define WLAN_EID_HT_CAP					45

/* Max valid buffer size that can be sent to the dongle */
#ifdef WLAND_TXLEN_1536
#define CDC_MAX_MSG_SIZE	            1536
#else
#define CDC_MAX_MSG_SIZE				(ETH_FRAME_LEN+ETH_FCS_LEN)
#endif

#ifndef MAX_WPA_IE_LEN
#define MAX_WPA_IE_LEN                  100
#endif

#ifndef MAX_RATES
#define MAX_RATES                       16	/* max # of rates in rateset */
#endif

#define MAX_WSEC_KEY                    4	/* max # of rates in rateset */

#define KEY_LEN_WPA_AES                 16
#define KEY_LEN_WPA_TKIP                32
#define KEY_LEN_WEP_104                 13
#define KEY_LEN_WEP_40                  5

#define ASSOC_FLAG_SSID                 1
#define ASSOC_FLAG_CHANNEL              2
#define ASSOC_FLAG_BAND                 3
#define ASSOC_FLAG_MODE                 4
#define ASSOC_FLAG_BSSID                5
#define ASSOC_FLAG_WEP_KEYS             6
#define ASSOC_FLAG_WEP_TX_KEYIDX        7
#define ASSOC_FLAG_WPA_MCAST_KEY        8
#define ASSOC_FLAG_WPA_UCAST_KEY        9
#define ASSOC_FLAG_SECINFO              10
#define ASSOC_FLAG_WPA_IE               11
#define ASSOC_FLAG_ASSOC_RETRY          12
#define ASSOC_FLAG_ASSOC_START          13
#define ASSOC_FLAG_WLAN_CONNECTING      14

#define WLAN_NF_DEFAULT_SCAN_VALUE      (-96)
#define PERFECT_RSSI                    ((u8)50)
#define WORST_RSSI                      ((u8)0)
#define RSSI_DIFF                       ((u8)(PERFECT_RSSI - WORST_RSSI))

#define WLAN_RTS_MIN_VALUE              0
#define WLAN_RTS_MAX_VALUE              2347
#define WLAN_FRAG_MIN_VALUE             256
#define WLAN_FRAG_MAX_VALUE             2346

#define AUTH_OPEN                       0	/* d11 open authentication   */
#define AUTH_SHARED_KEY                 1	/* d11 shared authentication */
#define AUTH_OPEN_SHARED                2	/* try open, then shared if open failed w/rc 13 */

#define CAPABILITY_ESS                  (1<<0)
#define CAPABILITY_IBSS                 (1<<1)
#define CAPABILITY_CF_POLLABLE          (1<<2)
#define CAPABILITY_CF_POLL_REQUEST      (1<<3)
#define CAPABILITY_PRIVACY              (1<<4)
#define CAPABILITY_SHORT_PREAMBLE       (1<<5)
#define CAPABILITY_PBCC                 (1<<6)
#define CAPABILITY_CHANNEL_AGILITY      (1<<7)

#define IW_AUTH_ALG_WAPI                0x08
#define IW_ENCODE_ALG_WAPI              0x80
#define IW_AUTH_WAPI_ENABLED            0x20
#define IW_ENCODE_ALG_SM4               0x20

#define WAPI_KEY_MGMT_NONE              0
#define WAPI_KEY_MGMT_CERT              BIT2
#define WAPI_KEY_MGMT_PSK               BIT3

#define WLAND_FIL_AF_PARAMS_HDR_LEN		16
#define WLAND_FIL_ACTION_FRAME_HDR_LEN	12
#define WLAND_FIL_ACTION_FRAME_SIZE	    1800

#define MCSSET_LEN	                    16

#define TOE_TX_CSUM_OL		            0x00000001
#define TOE_RX_CSUM_OL		            0x00000002

/* primary (ie tx) key */
#define WL_PRIMARY_KEY	                (1 << 1)

/* For supporting multiple interfaces */
#define WLAND_MAX_IFS	                 4

#define WLAND_STA_ASSOC			         0x10	/* Associated */

/* Enumerate crypto algorithms */
#define	CRYPTO_ALGO_OFF			         0
#define	CRYPTO_ALGO_WEP1		         1
#define	CRYPTO_ALGO_TKIP		         2
#define	CRYPTO_ALGO_WEP128		         3
#define CRYPTO_ALGO_AES_CCM		         4
#define CRYPTO_ALGO_AES_RESERVED1	     5
#define CRYPTO_ALGO_AES_RESERVED2	     6
#define CRYPTO_ALGO_CKIP		         7
#define CRYPTO_ALGO_CKIP_MMH		     8
#define CRYPTO_ALGO_WEP_MMH		         9
#define CRYPTO_ALGO_NALG		         10

#ifdef WLAND_WAPI_SUPPORT
#define CRYPTO_ALGO_SMS4                 11
#endif /* WLAND_WAPI_SUPPORT */
#define CRYPTO_ALGO_PMK			         12	/* for 802.1x supp to set PMK before 4-way */

/* wireless security bitvec */
#define WEP_ENABLED		                0x0001
#define TKIP_ENABLED		            0x0002
#define AES_ENABLED		                0x0004
#define WSEC_SWFLAG		                0x0008

/* to go into transition mode without setting wep */
#define SES_OW_ENABLED		            0x0040
#define SMS4_ENABLED                    0x0100

/* WPA authentication mode bitvec */
#define WPA_AUTH_DISABLED	            0x0000	/* Legacy (i.e., non-WPA) */
#define WPA_AUTH_NONE		            0x0001	/* none (IBSS) */
#define WPA_AUTH_UNSPECIFIED	        0x0002	/* over 802.1x */
#define WPA_AUTH_PSK		            0x0004	/* Pre-shared key */
#define WPA_AUTH_RESERVED1	            0x0008
#define WPA_AUTH_RESERVED2	            0x0010

#define WPA2_AUTH_RESERVED1	            0x0020
#define WPA2_AUTH_UNSPECIFIED	        0x0040	/* over 802.1x */
#define WPA2_AUTH_PSK		            0x0080	/* Pre-shared key */
#define WPA2_AUTH_RESERVED3	            0x0200
#define WPA2_AUTH_RESERVED4	            0x0400
#define WPA2_AUTH_RESERVED5	            0x0800

/* Small, medium and maximum buffer size for dcmd */
#define WLAND_DCMD_SMLEN	            256
#define WLAND_DCMD_MEDLEN	            1536
#define WLAND_DCMD_LARGE	            8192
#define ROUND_UP_MARGIN	                32	/* Biggest SDIO block size possible for round off at the end of buffer */

#define MAKE_WORD16(lsb, msb)           (((u16)(msb) << 8)  & 0xFF00) | (lsb)
#define MAKE_WORD32(lsw, msw)           (((u32)(msw) << 16) & 0xFFFF0000) | (lsw)

enum wland_current_mode {
	WLAND_B_MODE,
	WLAND_G_MODE,
	WLAND_N_MODE,
	WLAND_ERR_MODE,
};

enum WLAN_SCAN_STATUS {
	WLAN_SCAN_IDLE = 0,
	WLAN_SCAN_RUNNING = 1,
	WLAN_SCAN_COMPLET = 2
};

enum WLAN_PACKET_TYPE {
	WLAN_CMD = 1,
	WLAN_DATA = 2
};

/* KEY_TYPE_ID */
enum KEY_TYPE_ID {
	KEY_TYPE_ID_WEP = 0,
	KEY_TYPE_ID_TKIP,
	KEY_TYPE_ID_AES
};

enum PACKET_TYPE {
	WID_REQUEST_PACKET,
	WID_REQUEST_POLLING_PACKET,
	DATA_REQUEST_PACKET
};

/** KEY_INFO_WPA (applies to both TKIP and AES/CCMP) */
enum KEY_INFO_WPA {
	KEY_INFO_WPA_MCAST = 0x01,
	KEY_INFO_WPA_UNICAST = 0x02,
	KEY_INFO_WPA_ENABLED = 0x04
};

/*
 *  @user set ps mode for save power
 */
enum USER_PS_MODE_T {
	NO_POWERSAVE = 0,
	MIN_FAST_PS = 1,
	MAX_FAST_PS = 2,
	MIN_PSPOLL_PS = 3,
	MAX_PSPOLL_PS = 4
};

enum SITE_SURVEY_T {
	SITE_SURVEY_1CH = 0,
	SITE_SURVEY_ALL_CH = 1,//channel 1~14
	SITE_SURVEY_OFF = 2,
	P2P_SITE_SURVEY_SOCIAL = 3,
	SITE_SURVEY_NA_CH = 4,// channel 1~11
	SITE_SURVEY_EU_CH = 5// chanenl 1~13
};

enum DEVICE_MODE_T {
	NOT_CONFIGURED = 0,
	ACCESS_POINT = 1,
	BSS_STA = 2,
	IBSS_STA = 3,
	P2P_GO = 4,
	P2P_DEVICE = 5,
	P2P_CLIENT = 6
};

enum MAC_ROLE_T {
	MAC_ROLE_STA = 0,
	MAC_ROLE_AP = 1
};

/* ERP Protection type*/
typedef enum {
	G_SELF_CTS_PROT,
	G_RTS_CTS_PROT,
	NUM_G_PROTECTION_MODE
} G_PROTECTION_MODE;

typedef enum {
	B_ONLY_MODE        = 0,
	G_ONLY_MODE,
	G_MIXED_11B_1_MODE,
	G_MIXED_11B_2_MODE,
	NUM_G_OPERATING_MODE
} G_OPERATING_MODE_T;

struct wlan_802_11_security {
	u8 WPAenabled;
	u8 WPA2enabled;
	u8 wep_enabled;
	u8 auth_mode;
	u32 key_mgmt;
	u32 cipther_type;
};

/* Generic structure to hold all key types. */
struct enc_key {
	u16 len;
	u16 flags;		/* KEY_INFO_* from defs.h */
	u16 type;		/* KEY_TYPE_* from defs.h */
	u8 key[32];
};

enum wland_fil_p2p_if_types {
	FIL_P2P_IF_CLIENT,
	FIL_P2P_IF_GO,
	FIL_P2P_IF_DYNBCN_GO,
	FIL_P2P_IF_DEV,
};

struct wland_fil_p2p_if_le {
	u8 addr[ETH_ALEN];
	u8 ifidx;
	u8 bsscfgidx;
	__le16 type;
	__le16 channel;
};

struct wland_fil_chan_info_le {
	__le32 hw_channel;
	__le32 target_channel;
	__le32 scan_channel;
};

struct wland_fil_action_frame_le {
	u8 da[ETH_ALEN];
	__le16 len;
	__le32 packet_id;
	u8 data[WLAND_FIL_ACTION_FRAME_SIZE];
};

struct wland_fil_af_params_le {
	__le32 channel;
	__le32 dwell_time;
	u8 bssid[ETH_ALEN];
	u8 pad[2];
	struct wland_fil_action_frame_le action_frame;
};

struct wland_fil_bss_enable_le {
	__le32 bsscfg_idx;
	__le32 enable;
};

#define WLC_CNTRY_BUF_SZ	                    4	/* Country string is 3 bytes + NUL */

struct wland_country {
	char country_abbrev[WLC_CNTRY_BUF_SZ];	/* nul-terminated country code used in the Country IE */
	int rev;		/* revision specifier for ccode on set, -1 indicates unspecified. on get, rev >= 0 */
	char ccode[WLC_CNTRY_BUF_SZ];	/* nul-terminated built-in country code. variable length, but fixed size in
					 * struct allows simple allocation for expected country strings <= 3 chars.
					 */
};

/*
 * struct tdls_iovar - common structure for tdls iovars.
 *
 * @ea: ether address of peer station.
 * @mode: mode value depending on specific tdls iovar.
 * @chanspec: channel specification.
 * @pad: unused (for future use).
 */
struct wland_tdls_iovar_le {
	u8 ea[ETH_ALEN];	/* Station address */
	u8 mode;		/* mode: depends on iovar */
	__le16 chanspec;
	__le32 pad;		/* future */
};

enum wland_tdls_manual_ep_ops {
	TDLS_MANUAL_EP_CREATE = 1,
	TDLS_MANUAL_EP_DELETE = 3,
	TDLS_MANUAL_EP_DISCOVERY = 6
};

/* BSS info structure
 * Applications MUST CHECK ie_offset field and length field to access IEs and
 * next bss_info structure in a vector (in struct wland_scan_results)
 */
struct wland_bss_info_le {
	struct wland_cfg80211_vif *vif;
	u32 length;		/* byte length of data in this record, starting at version and including IEs */
	u8 BSSID[ETH_ALEN];
	u16 beacon_period;	/* units are Kusec          */
	u16 capability;		/* Capability information   */
	u8 SSID_len;
	u8 SSID[32];
	struct {
		u8 count;	/* # rates in this set      */
		u8 rates[MAX_RATES + 2];	/* rates in 500kbps units w/hi bit set if basic */
	} rateset;		/* supported rates          */
	u16 chanspec;		/* chanspec for bss         */
	u16 atim_window;	/* units are Kusec          */
	u8 dtim_period;		/* DTIM period              */
	s8 RSSI;		/* receive signal strength (in dBm) */
	s8 phy_noise;		/* noise (in dBm)           */

	//u8 n_cap;		/* BSS is 802.11N Capable   */
	u8 wmm_enable;		/* BSS is QOS enable*/
	u8 n_enable;
	/*
	 * 802.11N BSS Capabilities (based on HT_CAP_*):
	 */
	u32 nbss_cap;
	u8 ctl_ch;		/* 802.11N BSS control channel number */
	u8 basic_mcs[MCSSET_LEN];	/* 802.11N BSS required MCS set */
	u8 *ie;
	u32 ie_length;		/* byte length of Information Elements */
	s16 SNR;		/* average SNR of during frame reception */
	unsigned long time;
	struct list_head list;
	/*
	 * Add new fields here
	 */
	/*
	 * variable length Information Elements
	 */
};

struct wland_ssid {
	u32 SSID_len;
	u8 SSID[32];
};

struct wland_ssid_le {
	u32 SSID_len;
	u8 SSID[32];
};

#define DOT11_BSSTYPE_ANY		2
#define DOT11_MAX_DEFAULT_KEYS	4

struct wland_scan_params_le {
	struct wland_ssid_le ssid_le;	/* default: {0, ""} */
	u8 bssid[ETH_ALEN];	/* default: bcast */
	s8 bss_type;		/* default: any,
				 * DOT11_BSSTYPE_ANY/INFRASTRUCTURE/INDEPENDENT
				 */
	u8 scan_type;		/* flags, 0 use default */
	__le32 nprobes;		/* -1 use default, number of probes per channel */
	__le32 active_time;	/* -1 use default, dwell time per channel for active scanning */
	__le32 passive_time;	/* -1 use default, dwell time per channel for passive scanning */
	__le32 home_time;	/* -1 use default, dwell time for the home channel between channel scans */
	__le32 channel_num;	/* count of channels and ssids that follow
				 *
				 * low half is count of channels in channel_list, 0 means default (use all available channels)
				 *
				 * high half is entries in struct wland_ssid array that follows channel_list, aligned for
				 * s32 (4 bytes) meaning an odd channel count
				 * implies a 2-byte pad between end of channel_list and first ssid
				 *
				 * if ssid count is zero, single ssid in the fixed parameter portion is assumed, otherwise
				 * ssid in the fixed portion is ignored
				 */
	u16 channel_list[15];	/* list of chanspecs */
};

struct wland_scan_results {
	u32 version;
	u32 count;
	u16 beacon_period;
};


#define P2P_WILDCARD_SSID		                "DIRECT-"
#define P2P_WILDCARD_SSID_LEN	                (sizeof(P2P_WILDCARD_SSID) - 1)

/* wifi direct social channel */
#define SOCIAL_CHAN_1		                    1
#define SOCIAL_CHAN_2		                    6
#define SOCIAL_CHAN_3		                    11

#define IS_P2P_SOCIAL_CHANNEL(channel)         ((channel == SOCIAL_CHAN_1) || \
                            					(channel == SOCIAL_CHAN_2) || \
                            				    (channel == SOCIAL_CHAN_3))
#define WLAND_P2P_TEMP_CHAN	                    SOCIAL_CHAN_3
#define SOCIAL_CHAN_CNT		                    3
#define AF_PEER_SEARCH_CNT	                    2
#define CONNECT_SCAN_CHAN_CNT                   1
#define P2P_FULL_CHAN_CNT		                14
#define P2P_FULL_CHAN_CNT_11		            11

/* used for association with a specific BSSID and chanspec list */
struct wland_assoc_params_le {
	/*
	 * 00:00:00:00:00:00: broadcast scan
	 */
	u8 bssid[ETH_ALEN];
	/*
	 * 0: all available channels, otherwise count of chanspecs in chanspec_list
	 */
	__le32 chanspec_num;
	/*
	 * list of chanspecs
	 */
	__le16 chanspec_list[1];
};

/* used for join with or without a specific bssid and channel list */
struct wland_join_params {
	struct wland_ssid_le ssid_le;
	struct wland_assoc_params_le params_le;
};

struct wland_wsec_key {
	u32 index;		/* key index */
	u32 len;		/* key length */
	u8 data[WLAN_MAX_KEY_LEN];	/* key data */
	u32 algo;		/* CRYPTO_ALGO_AES_CCM, CRYPTO_ALGO_WEP128, etc */
	u32 flags;		/* misc flags */
	u32 iv_initialized;	/* has IV been initialized already? */
	/*
	 * Rx IV
	 */
	struct {
		u32 hi;		/* upper 32 bits of IV */
		u16 lo;		/* lower 16 bits of IV */
	} rxiv;
	u8 ea[ETH_ALEN];	/* per station */
};
struct wland_ptkey {
	u8 ea[ETH_ALEN];	/* per station */
	u8 ken_len;		/* key length */
	u8 key[WLAN_MAX_KEY_LEN];	/* key data */
};
struct wland_rx_gtkey {
	u8 ea[ETH_ALEN];	/* per station */
	u8 keyRSC[8];		/* key seq */
	u8 key_idx;		/* key index */
	u8 ken_len;		/* key length */
	u8 key[WLAN_MAX_KEY_LEN];	/* key data */
};

/* Used to get specific STA parameters */
struct wland_scb_val_le {
	s16 val;
	u8 ea[ETH_ALEN];
	u8 aid;
};

struct wland_11n_action {
	u8 category;
	u8 action;
	u8 bssid[ETH_ALEN];
	u8 tid;
	u8 max_msdu;
	u8 ack_policy;
	u8 ba_policy;
	__le16 buff_size;
	__le16 ba_timeout;
	__le16 add_ba_timeout;
};

/* security information with currently associated ap */
struct wland_cfg80211_security {
	u32 wpa_versions;
	u32 auth_type;
//	u8 rsn_mode;
	int n_ciphers_pairwise;
	u32 ciphers_pairwise[NL80211_MAX_NR_CIPHER_SUITES];
	u32 cipher_pairwise;
    int n_akm_suites;
	u32 akm_suites[NL80211_MAX_NR_AKM_SUITES];
	u8 akm;
	u32 cipher_group;
	u32 wpa_auth;
	u8 security;
	u8 security_group;
	u8 firmware_autype;
};

/*
 * struct wland_cfg80211_profile - profile information.
 *
 * @ssid        : ssid of associated/associating ap.
 * @bssid       : bssid of joined/joining ibss.
 * @sec         : security information.
 * @wepkey_idx  : wep_default_index.
 * @wepkeys     : wep-keys.
 */
struct wland_cfg80211_profile {
    int channel;
	struct wland_ssid ssid;
	u8 bssid[ETH_ALEN];
	u8 hidden_ssid;
	u8 dhcp_server_ip[4];
	u8 dhcp_server_bssid[ETH_ALEN];
	struct wland_cfg80211_security sec;
	u32 wepkey_idx;
	struct wland_wsec_key wepkeys[MAX_WSEC_KEY];
	u32 beacon;		/* beacon interval */
	u32 dtim;		/* dtim period */
	u16 rsn_cap;		/* RSN Capabilities */
	bool valid_bssid;
	bool wmm_enable;
	u8 *wps_ie;
	u16 wps_ie_len;
	u8 mode;
	u8 band_width; //0:20M 1:40M
};

struct wland_sta_info_le {
	__le16 ver;		/* version of this struct */
	__le16 len;		/* length in bytes of this structure */
	__le16 cap;		/* sta's advertised capabilities */
	__le32 flags;		/* flags defined below */
	__le32 idle;		/* time since data pkt rx'd from sta */
	u8 ea[ETH_ALEN];	/* Station address */
	__le32 count;		/* # rates in this set */
	u8 rates[MAX_RATES];	/* rates in 500kbps units */
	/*
	 * w/hi bit set if basic
	 */
	__le32 in;		/* seconds elapsed since associated */
	__le32 listen_interval_inms;	/* Min Listen interval in ms for STA */
	__le32 tx_pkts;		/* # of packets transmitted */
	__le32 tx_failures;	/* # of packets failed */
	__le32 rx_ucast_pkts;	/* # of unicast packets received */
	__le32 rx_mcast_pkts;	/* # of multicast packets received */
	__le32 tx_rate;		/* Rate of last successful tx frame */
	__le32 rx_rate;		/* Rate of last successful rx frame */
	__le32 rx_decrypt_succeeds;	/* # of packet decrypted successfully */
	__le32 rx_decrypt_failures;	/* # of packet decrypted failed */
};

struct wland_chanspec_list {
	__le32 count;		/* # of entries */
	__le32 element[1];	/* variable length u32 list */
};

/*
 * WLC_E_PROBRESP_MSG
 * WLC_E_P2P_PROBREQ_MSG
 * WLC_E_ACTION_FRAME_RX
 */
struct wland_rx_mgmt_data {
	__be16 version;
	__be16 chanspec;
	__be32 rssi;
	__be32 mactime;
	__be32 rate;
};

struct wland_rx_async_mgmt_data {
	u8  offset;
	u16 length;
	u8  rssi;
	u8  chnum;
};
/** Length of the Host Interface specific header */
#define HOST_MSG_HDR_LEN    (2)

/** Length of the Config header */
#define CFG_MSG_HDR_LEN     (4)
/* Bus independent dongle command */
struct wland_dcmd {
	__le16 wid_pkg_length;	/*
				 *  bit[0:11] : store pkg_length
				 *  bit[12:15]: store host_msg_type
				 *         PKT_TYPE_DATAOUT      0x1
				 *         PKT_TYPE_DATAIN       0x2
				 *         PKT_TYPE_CFG_RSP      0x3
				 *         PKT_TYPE_CFG_REQ      0x4
				 *         HOST_MSG_ASYNCEVENT   0x5
				 */
	u8 wid_msg_type;	/*
				 *'Q'  -- request  for wid query
				 *'W'  -- request  for wid write
				 *'R'  -- response for write or query
				 *'I'  -- mac status indication
				 *'N'  -- network info: scan AP list
				 */

	u8 wid_msg_id;		/* message id     */
	__le16 wid_msg_length;	/* message length */
};

/* Forward decls for struct wland_private (see below) */
struct wland_proto {
	u8 reqid;
	u16 rsplen;		/* response length          */
	u32 cmd;		/* dongle command value     */
	u32 offset;		/* response data offset     */
	struct wland_dcmd msg;
	u8 buf[WLAND_DCMD_MEDLEN + ROUND_UP_MARGIN];
};

/* forward declarations */
struct wland_cfg80211_vif;
struct wland_mac_descriptor;
struct wland_fw_info;

/*
 * struct wland_if - interface control information.
 *
 * @drvr:            points to device related information.
 * @vif:             points to cfg80211 specific interface information.
 * @ndev:            associated network device.
 * @stats:           interface specific network statistics.
 * @setmacaddr_work: worker object for setting mac address.
 * @multicast_work:  worker object for multicast provisioning.
 * @fws_desc:        interface specific firmware-signalling descriptor.
 * @ifidx:           interface index in device firmware.
 * @bssidx:          index of bss associated with this interface.
 * @mac_addr:        assigned mac address.
 * @netif_stop:      bitmap indicates reason why netif queues are stopped.
 * @netif_stop_lock: spinlock for update netif_stop from multiple sources.
 * @pend_8021x_cnt:  tracks outstanding number of 802.1x frames.
 * @pend_8021x_wait: used for signalling change in count.
 */
struct wland_if {
	struct wland_private *drvr;
	struct wland_cfg80211_vif *vif;
	struct net_device *ndev;
	struct net_device_stats stats;
	struct work_struct setmacaddr_work;
	struct work_struct multicast_work;
	struct wland_mac_descriptor *fws_desc;
	s32 ifidx;
	s32 bssidx;
	u8 mac_addr[ETH_ALEN];
	u8 netif_stop;
	spinlock_t netif_stop_lock;
	atomic_t pend_8021x_cnt;
	wait_queue_head_t pend_8021x_wait;
	bool tx_flowblock;
#ifdef WLAND_SMART_CONFIG_SUPPORT
	bool sniffer_enable;
#endif
};

/* Common structure for module and instance linkage */
struct wland_private {
	/*
	 * Linkage ponters
	 */
	struct wland_bus *bus_if;
	struct wland_proto *prot;
	struct wland_cfg80211_info *config;

	/*
	 * Internal items
	 */
	uint hdrlen;		/* Total WLAND header length (proto + bus)  */
	uint maxctl;		/* Max size rxctl request from proto to bus */
	u8 wme_dp;		/* wme discard priority                     */
	bool p2p_enable;	/* P2P enable                               */
#ifdef WLAND_POWER_MANAGER
	int sleep_flags;
#endif				/*WLAND_POWER_MANAGER */
	/*
	 * chip media info
	 */
	u32 drv_version;	/* Version of dongle-resident driver        */
	u8 mac[ETH_ALEN];	/* MAC address obtained from dongle         */

	/*
	 * Multicast data packets sent to chip
	 */
	u32 tx_multicast;
	u8 channel;

	struct wland_if *iflist[WLAND_MAX_IFS];

	struct mutex proto_block;

	struct wland_fw_info fweh;	/* process firmware events */
	struct wland_fws_info *fws;

	struct dentry *dbgfs_dir;

	struct mutex rf_result_block;
	unsigned long long pkt_rx_complete;
	unsigned long long pkt_fcs_success;
	u8 power_g_n_offset;
	u8 current_mode;
	u8 country_code;

	u8 power_11f;
	u8 power_120;
#ifdef WLAND_SET_POWER_BY_RATE
	u8 power_by_rate;//default:0 find:1 use:2
	u8 power_rates_gain[ALL_RATE_NUM];
	u8 power_rates_value[ALL_RATE_NUM];
#endif
	u8 rates[ALL_RATE_NUM];
};

/*
 * enum wland_netif_stop_reason - reason for stopping netif queue.
 *
 * @NETIF_STOP_REASON_FWS_FC:	netif stopped due to firmware signalling flow control.
 * @NETIF_STOP_REASON_BLOCK_BUS:netif stopped due to bus blocking.
 */
enum wland_netif_stop_reason {
	NETIF_STOP_REASON_FWS_FC = 1,
	NETIF_STOP_REASON_BLOCK_BUS = 2
};

struct wland_platform_data {
	u16 sd_head_align;
	void (*power_on) (void);
	void (*power_off) (void);
	void (*reset) (void);
};

static inline void pkt_align(struct sk_buff *p, int len, int align)
{
	uint datalign;

	datalign = (ulong) (p->data);
	datalign = roundup(datalign, (align)) - datalign;
	if (datalign)
		skb_pull(p, datalign);
	__skb_trim(p, len);
}

static inline void skb_align(struct sk_buff *p, uint datalign)
{
	uint offset = ((ulong) (p->data) & (datalign - 1));

	if (offset) {
		skb_pull(p, (datalign - offset));
	}
}

extern s32 wland_dhd_net2idx(struct wland_private *dhd, struct net_device *net);
extern struct net_device *wland_dhd_idx2net(void *pub, s32 ifidx);

extern int wland_netdev_wait_pend8021x(struct net_device *ndev);

/* Return pointer to interface name */
extern char *wland_ifname(struct wland_private *drvr, int idx);

/* net attach */
extern int wland_netdev_attach(struct wland_if *ifp);
extern int wland_netdev_p2p_attach(struct wland_if *ifp);

/* wland if */
extern struct wland_if *wland_add_if(struct wland_private *drvr, s32 bssidx,
	s32 ifidx, char *name, u8 * mac_addr);
extern void wland_del_if(struct wland_private *drvr, s32 bssidx);

#ifdef WLAND_SDIO_SUPPORT
#ifdef WLAND_RDAPLATFORM_SUPPORT
extern void rda_mmc_set_sdio_irq(u32 host_id, u8 enable);
extern void rda_mmc_bus_scan(u32 host_id);
#endif /*WLAND_RDAPLATFORM_SUPPORT*/
#endif /*WLAND_SDIO_SUPPORT */

#ifdef WLAND_RDAPLATFORM_SUPPORT
/* get chip id by i2c register */
extern u32 rda_wlan_version(void);
#endif /*WLAND_RDAPLATFORM_SUPPORT*/

extern u8 wland_check_test_mode(void);
extern void wland_set_test_mode(u8 mode);

extern int rda_wifi_power_on(void);
extern int rda_wifi_power_off(void);

extern void wland_registration_sem_up(bool check_flag);

/* read/store mac address by file */
extern int wland_get_mac_address(char *buf);
extern int wland_set_mac_address(char *buf);
int wland_read_mac_from_nvram(char *buf);
int wland_write_mac_to_nvram(const char *buf);
extern int wland_nvram_read(const char *filename, char *data, int size, int offset);
extern int wland_file_write(char *filename, char *data , int size, int offset, u32 mode1, u32 mode2);

#ifdef WLAND_AMLOGIC_PLATFORM_SUPPORT
extern void extern_wifi_set_enable(int is_on);
extern void sdio_reinit(void);
#endif /*WLAND_AMLOGIC_PLATFORM_SUPPORT*/
extern int wland_dev_get_tx_status(struct net_device *ndev, char *data, int len);
#ifdef WLAND_AP_RESET
extern bool ap_reseting;
extern struct wland_cfg80211_profile ap_profile;
extern u8 ap_gtk_len;
extern void wland_reconfig_ap_inreseting(struct wland_if *ifp);
void wland_chip_reset(struct work_struct *work);
extern struct work_struct wland_chip_reset_work;
extern struct wland_bus *ap_bus_if;
#endif
#endif /*_WLAND_DEV_H_*/
