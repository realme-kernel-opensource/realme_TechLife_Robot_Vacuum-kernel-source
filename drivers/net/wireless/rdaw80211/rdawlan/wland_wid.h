
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
#ifndef _WLAND_WID_H_
#define _WLAND_WID_H_

#include "wland_dev.h"
#include "wland_bus.h"
#include "wland_utils.h"

#define MAX_STRING_LEN                          (256)
#define MAX_CMD_LEN                             (MAX_STRING_LEN)
#define WLAN_MAX_WID_LEN                        (MAX_CMD_LEN - 2)

#define FWS_HANGER_MAXITEMS	                    16

#define WLAND_FWS_MAC_DESC_TABLE_SIZE			16

#define WLAND_FWS_PSQ_PREC_COUNT		        ((FWS_FIFO_COUNT + 1) * 2)
#define WLAND_FWS_PSQ_LEN				        256

#define BRCMF_FWS_RET_OK_NOSCHEDULE	            0
#define BRCMF_FWS_RET_OK_SCHEDULE	            1

#define WLAND_CHANNLE_RELATED_REG				4
#define WLAND_CHANNEL_NUM						14


/*******************************************************************************
 * WID message type
 ******************************************************************************/
#define WLAND_WID_MSG_QUERY						'Q'	/* Hex---0x51 */
#define WLAND_WID_MSG_WRITE						'W'	/* Hex---0x57 */
#define WLAND_WID_MSG_RESP						'R'	/* Hex---0x52 */
#define WLAND_WID_MSG_NETINFO					'N'	/* Hex---0x4E */
#define WLAND_WID_MSG_MAC_STATUS				'I'	/* Hex---0x49 */
#define WLAND_WID_MSG_EVENT					    'E'	/* Hex---0x45 */

/**
 * NETWORK_EVENT_TYPE_T - Network Event type
 */
typedef enum {

	/**
	 * EVENT_SCAN_COMPLETE - Scan complete
	 *
	 * This event should be used when host triggered scan complete.
	 */
	EVENT_SCAN_COMPLETE = 0,

	/**
	 * EVENT_SCAN_NOT_FOUND - Scan for join but no BSS found.
	 *
	 * This event should be used when BSS scaned for join not found.
	 */
	EVENT_SCAN_NOT_FOUND,

	/**
	 * EVENT_JOIN - Join the BSS
	 *
	 * This event should be used when join a (I)BSS (Rx Beacon).
	 */
	EVENT_JOIN,

	/**
	 * EVENT_JOIN_TIMED_OUT - Join timed out
	 *
	 * This event should be used when join a (I)BSS timed out.
	 */
	EVENT_JOIN_TIMED_OUT,

	/**
	 * EVENT_AUTH - Authentication
	 *
	 * This event should be used when authentication has been completed.
	 */
	EVENT_AUTH,

	/**
	 * EVENT_AUTH_TIMED_OUT - Authentication timed out
	 */
	EVENT_AUTH_TIMED_OUT,

	/**
	 * EVENT_DEAUTH - Authentication lost
	 *
	 * This event should be called when authentication is lost either due
	 * to receiving deauthenticate frame from the AP or when sending that
	 * frame to the current AP.
	 */
	EVENT_DEAUTH,

	/**
	 * EVENT_ASSOC - Association completed
	 *
	 * This event needs to be delivered when the firmware completes IEEE
	 * 802.11 association or reassociation.
	 */
	EVENT_ASSOC,

	/**
	 * EVENT_ASSOC_TIMED_OUT - Association timed out
	 */
	EVENT_ASSOC_TIMED_OUT,

	/**
	 * EVENT_DISASSOC - Association lost
	 *
	 * This event should be called when association is lost either due to
	 * receiving deauthenticate or disassociate frame from the AP or when
	 * sending either of these frames to the current AP.
	 */
	EVENT_DISASSOC,

	/**
	 * EVENT_MICHAEL_MIC_FAILURE - Michael MIC (TKIP) detected
	 *
	 * This event must be delivered when a Michael MIC error is detected by
	 * the firmware. Additional data for event processing is
	 * provided with network_event_data_t::michael_mic_failure.
	 */
	EVENT_MICHAEL_MIC_FAILURE,

	EVENT_AUTH_IND,
	EVENT_DEAUTH_IND,
	EVENT_ASSOC_IND,
	EVENT_REASSOC_IND,
	EVENT_DISASSOC_IND,
	EVENT_P2P_LISTEN_COMP_IND		= 16,
	EVENT_ADD_P2P_IF_EVENT			= 17,
	EVENT_P2P_SCAN_COMP_EVENT		= 18,
	EVENT_P2P_IF_CHANGE_COMP_EVENT	= 19,
	EVENT_P2P_ACTION_TX_COMP_EVENT	= 20,
	EVENT_ADDBA,
	EVENT_SOFTWARE_RESET			= 22,
	EVENT_HOST_RESET_COMPLATE		= 23,
	NUM_EVENT_TYPE
} NETWORK_EVENT_TYPE_T;

/*******************************************************************************
 * IO codes that are interpreted by dongle firmware
 ******************************************************************************/

/* G_PREAMBLE type */
#define G_SHORT_PREAMBLE                        0
#define G_LONG_PREAMBLE                         1
#define G_AUTO_PREAMBLE                         2

/* WID Data Types */
enum wid_type {
	WID_CHAR = 0,
	WID_SHORT = 1,
	WID_INT = 2,
	WID_STR = 3,
	WID_BIN = 4,
	WID_UNKNOW = 5
};

enum wland_pkt_type {
	PKT_TYPE_REQ = 1,	/* data    to   firmware */
	PKT_TYPE_IND = 2,	/* data    from frimware */
	PKT_TYPE_CFG_RSP = 3,	/* cfg rsp from frimware */
	PKT_TYPE_CFG_REQ = 4,	/* cfg req to   firmware */
	PKT_TYPE_ASYNC = 5,
	PKT_TYPE_DATA_MAC1 = 8, /* data for mac1, in and out */
	PKT_TYPE_CFG_MAC1 = 9,	/* config msg for mac1, in and out */ /*it's not used, now*/
	PKT_TYPE_AGGR_MAC0 = 10, /* aggr data mac0, in and out */
	PKT_TYPE_AGGR_MAC1 = 11, /* aggr data mac1, in and out */
};

/* WLAN Identifiers */
enum wland_firmw_wid {
	WID_NIL								= -1,
	WID_BSS_TYPE						= 0x0000,
	WID_CURRENT_TX_RATE					= 0x0001,
	WID_CURRENT_CHANNEL					= 0x0002,
	WID_PREAMBLE						= 0x0003,
	WID_11G_OPERATING_MODE				= 0x0004,
	WID_STATUS							= 0x0005,
	WID_SCAN_TYPE						= 0x0007,
	WID_PRIVACY_INVOKED					= 0x0008,
	WID_KEY_ID							= 0x0009,
	WID_QOS_ENABLE						= 0x000A,
	WID_POWER_MANAGEMENT				= 0x000B,
	WID_802_11I_MODE					= 0x000C,
	WID_AUTH_TYPE						= 0x000D,
	WID_SITE_SURVEY						= 0x000E,
	WID_LISTEN_INTERVAL					= 0x000F,
	WID_DTIM_PERIOD						= 0x0010,
	WID_ACK_POLICY						= 0x0011,
	WID_RESET							= 0x0012,
	WID_BCAST_SSID						= 0x0015,

	WID_DISCONNECT						= 0x0016,

	WID_READ_ADDR_SDRAM					= 0x0017,
	WID_TX_POWER_LEVEL_11A				= 0x0018,
	WID_REKEY_POLICY					= 0x0019,
	WID_SHORT_SLOT_ALLOWED				= 0x001A,
	WID_PHY_ACTIVE_REG					= 0x001B,
	WID_TX_POWER_LEVEL_11B				= 0x001D,
	WID_START_SCAN_REQ					= 0x001E,
	WID_RSSI							= 0x001F,//rssi is received signal strength indication
	WID_RSSI_SNR_CONFIG				    = 0x2202,
	WID_RSSI_SNR						= 0x2203, //snr is signal/noise
	WID_JOIN_REQ						= 0x0020,
	WID_USER_CONTROL_ON_TX_POWER		= 0x0027,
	WID_MEMORY_ACCESS_8BIT				= 0x0029,
	WID_UAPSD_SUPPORT_AP				= 0x002A,
	WID_CURRENT_MAC_STATUS				= 0x0031,
	WID_AUTO_RX_SENSITIVITY				= 0x0032,
	WID_DATAFLOW_CONTROL				= 0x0033,
	WID_SCAN_FILTER						= 0x0036,
	WID_LINK_LOSS_THRESHOLD				= 0x0037,
	WID_AUTORATE_TYPE					= 0x0038,

	WID_802_11H_DFS_MODE				= 0x003B,
	WID_802_11H_TPC_MODE				= 0x003C,

	WID_WPS_ENABLE						= 0x0041,
	WID_WPS_START						= 0x0043,
	WID_WPS_DEV_MODE					= 0x0044,
	WID_AUTORATE_START_POINT			= 0x0045,
	WID_OOB_RESET_REQ					= 0x0046,
	WID_ENABLE_INT_SUPP					= 0x0047,
	WID_DEVICE_MODE						= 0x0048,


	WID_ENABLE_MULTI_DOMAIN				= 0x0049,
	WID_CURRENT_REG_DOMAIN				= 0x0050,
	WID_CURRENT_REG_CLASS				= 0x0051,

	WID_CPU_SUSPEND					= 0x0052,
	WID_TBTT_SLEEP_CNT				= 0x0053,
	WID_AP_LOW_POWER				= 0x0054,

	/*
	 * NMAC Character WID list
	 */
	WID_11N_PROT_MECH					= 0x0080,
	WID_11N_ERP_PROT_TYPE				= 0x0081,
	WID_11N_ENABLE						= 0x0082,
	WID_11N_OPERATING_TYPE				= 0x0083,
	WID_11N_OBSS_NONHT_DETECTION		= 0x0084,
	WID_11N_HT_PROT_TYPE				= 0x0085,
	WID_11N_RIFS_PROT_ENABLE			= 0x0086,
	WID_11N_SMPS_MODE					= 0x0087,
	WID_11N_CURRENT_TX_MCS				= 0x0088,
	WID_11N_PRINT_STATS					= 0x0089,
	WID_HUT_FCS_CORRUPT_MODE			= 0x008A,
	WID_HUT_RESTART						= 0x008B,
	WID_HUT_TX_FORMAT					= 0x008C,
	WID_11N_SHORT_GI_ENABLE				= 0x008D,
	WID_HUT_BANDWIDTH					= 0x008E,
	WID_HUT_OP_BAND						= 0x008F,
	WID_HUT_STBC						= 0x0090,
	WID_HUT_ESS							= 0x0091,
	WID_HUT_ANTSET						= 0x0092,
	WID_HUT_HT_OP_MODE					= 0x0093,
	WID_RIFS_MODE						= 0x0094,
	WID_HUT_SMOOTHING_REC				= 0x0095,
	WID_HUT_SOUNDING_PKT				= 0x0096,
	WID_HUT_HT_CODING					= 0x0097,
	WID_HUT_TEST_DIR					= 0x0098,
	WID_HUT_CUSTOM_WAVE_PERIOD			= 0x0099,
	WID_HUT_PHY_TEST_MODE				= 0x009A,
	WID_HUT_PHY_TEST_RATE_HI			= 0x009B,
	WID_HUT_PHY_TEST_RATE_LO			= 0x009C,
	WID_HUT_DISABLE_RXQ_REPLENISH		= 0x009D,
	WID_HUT_KEY_ORIGIN					= 0x009E,
	WID_HUT_BCST_PERCENT				= 0x009F,
	WID_HUT_GROUP_CIPHER_TYPE			= 0x00A0,
	WID_TX_ABORT_CONFIG					= 0x00A1,
	WID_HOST_DATA_IF_TYPE				= 0x00A2,
	WID_HOST_CONFIG_IF_TYPE				= 0x00A3,
	WID_HUT_TSF_TEST_MODE				= 0x00A4,
	WID_HUT_PKT_TSSI_VALUE				= 0x00A5,
	WID_REG_TSSI_11B_VALUE				= 0x00A6,
	WID_REG_TSSI_11G_VALUE				= 0x00A7,
	WID_REG_TSSI_11N_VALUE				= 0x00A8,
	WID_TX_CALIBRATION					= 0x00A9,
	WID_DSCR_TSSI_11B_VALUE				= 0x00AA,
	WID_DSCR_TSSI_11G_VALUE				= 0x00AB,
	WID_DSCR_TSSI_11N_VALUE				= 0x00AC,
	WID_HUT_RSSI_EX						= 0x00AD,
	WID_HUT_ADJ_RSSI_EX					= 0x00AE,
	WID_11N_IMMEDIATE_BA_ENABLED		= 0x00AF,
	WID_11N_TXOP_PROT_DISABLE			= 0x00B0,
	WID_TX_POWER_LEVEL_11N				= 0x00B1,
	WID_VSIE_FRAME						= 0x00B4,
	WID_VSIE_INFO_ENABLE				= 0x00B5,
	WID_2040_COEXISTENCE				= 0x00C1,
	WID_HUT_FC_TXOP_MOD					= 0x00C2,
	WID_HUT_FC_PROT_TYPE				= 0x00C3,
	WID_HUT_SEC_CCA_ASSERT				= 0x00C4,
	WID_2040_ENABLE						= 0x00C5,
	WID_2040_40MHZ_INTOLERANT			= 0x00C7,
	WID_11N_CURRENT_TX_BW				= 0x00C8,
	WID_TX_POWER_LEVEL_11N_40MHZ		= 0x00C9,
	WID_SLEEP_NOW						= 0x00CB,
	WID_ENABLE_STBC						= 0x00CD,
	WID_ENABLE_GREENFIELD				= 0x00CE,
	WID_BA_MAX_BUFFER_SIZE				= 0x00CF,
	WID_USRCTL_RX_FRAME_FILTER			= 0x00D0,
	WID_SLEEP_INACT_IND_THRESHOLD		= 0x00D2,
	WID_RAW_PKT_CHANNEL_RF				= 0x00D3,
	WID_STA_ENABLE_CSA					= 0x00D5,
	WID_WAKEUP_HOST						= 0x00D7,

	/*
	 * Custom Character WID list
	 */
	WID_P2P_ENABLE						= 0x0201,
	WID_P2P_DISCOVERABLE				= 0x0202,
	WID_P2P_LISTEN_CHAN					= 0x0203,
	WID_P2P_FIND_TO						= 0x0204,
	WID_P2P_GO_INT_VAL					= 0x0205,
	WID_P2P_PERSIST_GRP					= 0x0206,
	WID_P2P_AUTO_GO						= 0x0207,
	WID_P2P_INTRA_BSS					= 0x0208,
	WID_P2P_CT_WINDOW					= 0x0209,
	WID_P2P_LISTEN_MODE					= 0x020A,
	WID_P2P_OPER_CHAN					= 0x020B,
	WID_ANTENNA_SELECT					= 0x020C,
	WID_AMPDU_RETRY_LIMIT				= 0x020D,
	WID_P2P_START_SCAN_SEARCH_REQ		= 0x020E,
	WID_P2P_START_AF_SCAN_REQ			= 0x020F,

	WID_P2P_ONE_CHAN					= 0x0270,
	WID_P2P_CONNECT_SCAN_REQ			= 0x0271,
	WID_P2P_JOIN_REQ					= 0x0272,
	WID_P2P_11I_MODE_PAIRWISE			= 0x0273,
	WID_P2P_AUTH_TYPE					= 0x0274,
	WID_P2P_DTIM_PERIOD					= 0x0275,
	WID_P2P_GO_START_REQ				= 0x0276,
	WID_P2P_11I_MODE_GROUPWISE			= 0x0277,

	WID_WFD_ENABLE						= 0x0301,
	WID_WFD_DEV_CAP						= 0x0302,
	WID_WFD_DEV_ROLE					= 0x0303,
	WID_WFD_COUPLED_STATUS_BITMAP		= 0x0304,

	WID_BOOTROM_DECRYPT					= 0x0401,

	WID_BOOTROM_START_APP				= 0x0402,
	WID_BOOTROM_DBGA					= 0x0403,

	WID_BOOTROM_DBGL					= 0x0404,
	WID_WDT_TIMEOUT						= 0x0405,
	WID_AP_START_REQ					= 0x0410,
	WID_SCAN_CONNECT_RESULT 			= 0x0411,
	WID_HIDDEN_SSID						= 0x0413,
	WID_SET_TID							= 0x0414,
	WID_CHIP_VERSION					= 0x0416,
	WID_ENHANCE_MODE					= 0x0419,
	WID_HOST_AMSDU_TX                   = 0x0420,
	WID_HOST_DEAMSDU_RX                 = 0x0421,

	WID_MAX_CHAR_ID						= 0x0fff,	//last char id

	/*
	 * EMAC Short WID list
	 */
	WID_RTS_THRESHOLD					= 0x1000,
	WID_FRAG_THRESHOLD					= 0x1001,
	WID_SHORT_RETRY_LIMIT				= 0x1002,
	WID_LONG_RETRY_LIMIT				= 0x1003,
	WID_BEACON_INTERVAL					= 0x1006,
	WID_MEMORY_ACCESS_16BIT				= 0x1008,
	WID_RX_SENSE						= 0x100B,
	WID_ACTIVE_SCAN_TIME				= 0x100C,
	WID_PASSIVE_SCAN_TIME				= 0x100D,
	WID_SITE_SURVEY_SCAN_TIME			= 0x100E,
	WID_JOIN_TIMEOUT					= 0x100F,
	WID_AUTH_TIMEOUT					= 0x1010,
	WID_ASOC_TIMEOUT					= 0x1011,
	WID_11I_PROTOCOL_TIMEOUT			= 0x1012,
	WID_EAPOL_RESPONSE_TIMEOUT			= 0x1013,
	WID_WPS_PASS_ID						= 0x1017,
	WID_WPS_CONFIG_METHOD				= 0x1018,

	WID_USER_PREF_CHANNEL				= 0x1020,
	WID_CURR_OPER_CHANNEL				= 0x1021,
	WID_RF_SET_CHANNEL_ACTIVE_REG		= 0x1022,

	WID_HUT_FRAME_LEN					= 0x1081,
	WID_HUT_TXOP_LIMIT					= 0x1082,
	WID_HUT_SIG_QUAL_AVG				= 0x1083,
	WID_HUT_SIG_QUAL_AVG_CNT			= 0x1084,
	WID_11N_SIG_QUAL_VAL				= 0x1085,
	WID_HUT_RSSI_EX_COUNT				= 0x1086,
	WID_CCA_THRESHOLD					= 0x1087,

	WID_BACON_INTERVAL_GO				= 0x1090,

	WID_WFD_DEV_INFO					= 0x1301,
	WID_WFD_SESS_MGT_CTRL_PORT			= 0x1302,
	WID_WFD_MAX_THROUGHPUT				= 0x1303,
	WID_VENDOR_ID						= 0x1400,
	WID_HUT_AUTO_HW_RX_STATS			= 0x1401,
	WID_EFUSE_XTAL_CAL_VAL				= 0x1402,
	WID_MON_PHY_RX_FILTER				= 0x1405,

	WID_MAX_SHORT_ID					= 0x1fff,	//last short wid

	/*
	 * EMAC Integer WID list
	 */
	WID_FAILED_COUNT					= 0x2000,
	WID_RETRY_COUNT						= 0x2001,
	WID_MULTIPLE_RETRY_COUNT			= 0x2002,
	WID_FRAME_DUPLICATE_COUNT			= 0x2003,
	WID_ACK_FAILURE_COUNT				= 0x2004,
	WID_RECEIVED_FRAGMENT_COUNT			= 0x2005,
	WID_MULTICAST_RECEIVED_FRAME_COUNT	= 0x2006,
	WID_FCS_ERROR_COUNT					= 0x2007,
	WID_SUCCESS_FRAME_COUNT				= 0x2008,
	WID_HUT_TX_COUNT					= 0x200A,
	WID_TX_FRAGMENT_COUNT				= 0x200B,
	WID_TX_MULTICAST_FRAME_COUNT		= 0x200C,
	WID_RTS_SUCCESS_COUNT				= 0x200D,
	WID_RTS_FAILURE_COUNT				= 0x200E,
	WID_WEP_UNDECRYPTABLE_COUNT			= 0x200F,
	WID_REKEY_PERIOD					= 0x2010,
	WID_REKEY_PACKET_COUNT				= 0x2011,

	WID_1X_SERV_ADDR					= 0x2012,

	WID_STACK_IP_ADDR					= 0x2013,
	WID_STACK_NETMASK_ADDR				= 0x2014,
	WID_HW_RX_COUNT						= 0x2015,
	WID_MEMORY_ADDRESS					= 0x201E,
	WID_MEMORY_ACCESS_32BIT				= 0x201F,
	WID_PHY_RF_REG_VAL					= 0x2021,
	WID_DEV_OS_VERSION					= 0x2025,


	WID_MEMORY_LENGTH					= 0x2030,
	WID_CHECKSUM_TYPE					= 0x2031,
	WID_DECRYPT_TYPE					= 0x2032,
	WID_TX_POWER_LEVELS					= 0x2079,
	WID_11N_PHY_ACTIVE_REG_VAL			= 0x2080,
	WID_HUT_NUM_TX_PKTS					= 0x2081,
	WID_HUT_TX_TIME_TAKEN				= 0x2082,
	WID_HUT_TX_TEST_TIME				= 0x2083,

	WID_VSIE_RX_OUI						= 0x2084,
	WID_RX_FRAME_FILTER					= 0x2085,

	WID_DISCONNECT_REASON				= 0x2086,
	WID_NTWK_EXPIRY_TIME_MS				= 0x2087,
	WID_PHY_TEST_MODE_OPTIONS			= 0x2088,
	WID_GET_TX_RATE						= 0x2089,

	WID_WPS_USER_SPEC_CONFIG_METH		= 0x210B,
	WID_SET_EFUSE_ONE_PAGE				= 0x210C,
	WID_SMARTCONFIG_LDPCBCC_INFO		= 0x2200,
	WID_MON_FILTER						= 0x2201,
	WID_MAX_INTEGER_ID					= 0x2fff,	//last int id

	/*
	 * EMAC String WID list
	 */
	WID_SSID							= 0x3000,
	WID_FIRMWARE_VERSION				= 0x3001,
	WID_OPERATIONAL_RATE_SET			= 0x3002,
	WID_BSSID							= 0x3003,
	WID_WEP_KEY_VALUE					= 0x3004,
	WID_11I_PSK							= 0x3008,
	WID_11E_P_ACTION_REQ				= 0x3009,
	WID_1X_KEY							= 0x300A,
	WID_HARDWARE_VERSION				= 0x300B,
	WID_MAC_ADDR						= 0x300C,
	WID_HUT_DEST_ADDR				= 0x300D,
	WID_MISC_TEST_MODES					= 0x300E,
	WID_PHY_VERSION						= 0x300F,
	WID_SUPP_USERNAME					= 0x3010,
	WID_SUPP_PASSWORD					= 0x3011,
	WID_SITE_SURVEY_RESULTS				= 0x3012,
	WID_RX_POWER_LEVEL					= 0x3013,
	WID_ADD_WEP_KEY						= 0x3019,
	WID_REMOVE_WEP_KEY					= 0x301A,
	WID_ADD_PTK							= 0x301B,
	WID_ADD_RX_GTK						= 0x301C,
	WID_ADD_TX_GTK						= 0x301D,
	WID_REMOVE_KEY						= 0x301E,
	WID_ASSOC_REQ_INFO					= 0x301F,
	WID_ASSOC_RES_INFO					= 0x3020,
	WID_WPS_STATUS						= 0x3024,
	WID_WPS_PIN							= 0x3025,
	WID_MANUFACTURER					= 0x3026,
	WID_MODEL_NAME						= 0x3027,
	WID_MODEL_NUM						= 0x3028,
	WID_DEVICE_NAME						= 0x3029,
	WID_11I_PSK_VALUE					= 0x302a,
	WID_SUPP_REG_DOMAIN_INFO			= 0x3030,
	WID_1X_SERV_ETH_ADDR				= 0x3031,
	WID_STA_VNDR_IE 					= 0x3032,


	/* WAPI WID list */
	WID_WAPI_ASSOC_IE					= 0x3050,
	WID_ADD_WAPI_PTK					= 0x3051,
	WID_ADD_WAPI_RX_GTK					= 0x3052,
	WID_ADD_WAPI_TX_GTK					= 0x3053,

	WID_11N_P_ACTION_REQ				= 0x3080,
	WID_HUT_TEST_ID						= 0x3081,
	WID_PMKID_INFO						= 0x3082,
	WID_FIRMWARE_INFO					= 0x3083,

	/* Custom String WID list */
	WID_SERIAL_NUMBER					= 0x3102,

	WID_P2P_TARGET_DEV_ID				= 0x3201,
	WID_P2P_INVIT_DEV_ID				= 0x3202,
	WID_P2P_PERSIST_CRED				= 0x3203,
	WID_P2P_NOA_SCHEDULE				= 0x3204,
	WID_P2P_SET_DEV_ADDR				= 0x3205,

	//WID_P2P_PROBERSP_IE				=0x3302,

	WID_P2P_ACTION_TX					= 0x3206,


	WID_P2P_ADD_IF						= 0x3208,

	WID_P2P_START_LISTEN_REQ			= 0x3209,

	WID_P2P_WID_SSID 					= 0x320A,
	WID_P2P_WID_BSSID					= 0x320B,
	WID_P2P_CHANGE_INTERFACE			= 0x320C,
	WID_P2P_DISCONNECT_REQ				= 0x320D,
	WID_P2P_RSN_INFO 					= 0x320E,
	WID_P2P_P_ACTION_TX					= 0x320F,
	WID_STOP_AP_MAC1					= 0x3210,

	WID_WFD_COUPLED_MAC_ADDR			= 0x3301,

	WID_P2P_RX_GTK						= 0x3310,
	WID_P2P_TX_GTK						= 0x3311,
	WID_ARP_OFFLOAD_91H					= 0x3312,
	WID_RF_SET_CHANNEL_ACTIVE_VAL		= 0x3313,
	WID_MAX_STRING_ID					= 0x3fff,	//last string id

	/*
	 * EMAC Binary WID List
	 */
	WID_UAPSD_CONFIG					= 0x4001,
	WID_UAPSD_STATUS					= 0x4002,
	WID_WMM_AP_AC_PARAMS				= 0x4003,
	WID_WMM_STA_AC_PARAMS				= 0x4004,
	WID_NETWORK_INFO					= 0x4005,
	WID_WPS_CRED_LIST					= 0x4006,
	WID_PRIM_DEV_TYPE				= 0x4007,
	WID_STA_JOIN_INFO_91H				= 0x4008,
	WID_CONNECTED_STA_LIST				= 0x4009,




	WID_MEMORY_ACCESS					= 0x4010,

              /* NMAC Binary WID list */
	WID_11N_AUTORATE_TABLE				= 0x4080,
	WID_HUT_TX_PATTERN					= 0x4081,
	WID_SYSTEM_STATS					= 0x4082,
	WID_HUT_LOG_STATS					= 0x4083,

	WID_VSIE_TX_DATA					= 0x4085,
	WID_VSIE_RX_DATA					= 0x4086,

	WID_P2P_VNDR_IE 					= 0x4087,
              /* Bootrom Binary WID list */
	WID_BOOTROM_CHECKSUM				= 0x4101,

	WID_P2P_ACTION_TO_HOST				= 0x4170,
	WID_GO_JOIN_INFO					= 0x4171,

	/* Custom Binary WID list */
	WID_P2P_REQ_DEV_TYPE				= 0x4201,
	WID_P2P_NETWORK_INFO				= 0x4202,

	WID_WFD_NETWORK_INFO				= 0x4301,
	WID_PHY_TX_POWER_11NB_11G			= 0x4310,
	WID_EFUSE_PHY_TXPOW_VAL				= 0x4311,
	WID_GET_EFUSE_ALL_PAGE				= 0x4312,
	WID_GET_TX_STATUS					= 0x4313,
	WID_SET_POWER_BY_RATE				= 0x4314,
	WID_SET_RATE_MODE					= 0x4315,
	WID_MAX_BINARY_ID					= 0x4fff,	//last string id

	/*
	 * Miscellaneous WIDs
	 */
	WID_ALL								= 0x7FFE,
	WID_MAX								= 0xFFFF
};

/*
 * enum wland_fws_skb_state - indicates processing state of skb.
 *
 * @FWS_SKBSTATE_NEW: sk_buff is newly arrived in the driver.
 * @FWS_SKBSTATE_DELAYED: sk_buff had to wait on queue.
 * @FWS_SKBSTATE_SUPPRESSED: sk_buff has been suppressed by firmware.
 * @FWS_SKBSTATE_TIM: allocated for TIM update info.
 */
enum wland_fws_skb_state {
	FWS_SKBSTATE_NEW,
	FWS_SKBSTATE_DELAYED,
	FWS_SKBSTATE_SUPPRESSED,
	FWS_SKBSTATE_TIM
};

/*
 * struct wland_skbuff_cb - control buffer associated with skbuff.
 *
 * @if_flags: holds interface index and packet related flags.
 * @htod: host to device packet identifier (used in PKTTAG tlv).
 * @state: transmit state of the packet.
 * @mac: descriptor related to destination for this packet.
 *
 * This information is stored in control buffer struct sk_buff::cb, which
 * provides 48 bytes of storage so this structure should not exceed that.
 */
struct wland_skbuff_cb {
	u16 if_flags;
	u32 htod;
	enum wland_fws_skb_state state;
	struct wland_mac_descriptor *mac;
};

/*
 * enum wland_fws_fifo - fifo indices used by dongle firmware.
 *
 * @WLAND_FWS_FIFO_FIRST: first fifo, ie. background.
 * @WLAND_FWS_FIFO_AC_BK: fifo for background traffic.
 * @WLAND_FWS_FIFO_AC_BE: fifo for best-effort traffic.
 * @WLAND_FWS_FIFO_AC_VI: fifo for video traffic.
 * @WLAND_FWS_FIFO_AC_VO: fifo for voice traffic.
 * @WLAND_FWS_FIFO_BCMC : fifo for broadcast/multicast (AP only).
 * @WLAND_FWS_FIFO_ATIM : fifo for ATIM (AP only).
 * @FWS_FIFO_COUNT      : number of fifos.
 */
enum wland_fws_fifo {
	WLAND_FWS_FIFO_FIRST,
	WLAND_FWS_FIFO_AC_BK = WLAND_FWS_FIFO_FIRST,
	WLAND_FWS_FIFO_AC_BE,
	WLAND_FWS_FIFO_AC_VI,
	WLAND_FWS_FIFO_AC_VO,
	WLAND_FWS_FIFO_BCMC,
	WLAND_FWS_FIFO_ATIM,
	FWS_FIFO_COUNT
};

enum wland_fws_mac_desc_state {
	FWS_STATE_OPEN = 1,
	FWS_STATE_CLOSE
};

/*
 * struct wland_mac_descriptor - firmware signalling data per node/interface
 *
 * @occupied:           slot is in use.
 * @mac_handle:         handle for mac entry determined by firmware.
 * @interface_id:       interface index.
 * @state:              current state.
 * @suppressed:         mac entry is suppressed.
 * @generation:         generation bit.
 * @ac_bitmap:          ac queue bitmap.
 * @requested_credit:   credits requested by firmware.
 * @ea:                 ethernet address.
 * @seq:                per-node free-running sequence.
 * @psq:                power-save queue.
 * @transit_count:      packet in transit to firmware.
 */
struct wland_mac_descriptor {
	char name[16];
	u8 occupied;
	u8 mac_handle;
	u8 interface_id;
	u8 state;
	bool suppressed;
	u8 generation;
	u8 ac_bitmap;
	u8 requested_credit;
	u8 requested_packet;
	u8 ea[ETH_ALEN];
	u8 seq[FWS_FIFO_COUNT];
	struct pktq psq;
	int transit_count;
	int suppr_transit_count;
	bool send_tim_signal;
	u8 traffic_pending_bmp;
	u8 traffic_lastreported_bmp;
};

/*
 * enum wland_fws_hanger_item_state - state of hanger item.
 *
 * @FWS_HANGER_ITEM_STATE_FREE  : item is free for use.
 * @FWS_HANGER_ITEM_STATE_INUSE : item is in use.
 * @FWS_HANGER_ITEM_STATE_INUSE_SUPPRESSED: item was suppressed.
 */
enum wland_fws_hanger_item_state {
	FWS_HANGER_ITEM_STATE_FREE = 1,
	FWS_HANGER_ITEM_STATE_INUSE,
	FWS_HANGER_ITEM_STATE_INUSE_SUPPRESSED
};

/*
 * struct wland_fws_hanger_item - single entry for tx pending packet.
 *
 * @state   : entry is either free or occupied.
 * @pkt     : packet itself.
 */
struct wland_fws_hanger_item {
	enum wland_fws_hanger_item_state state;
	struct sk_buff *pkt;
};

/*
 * struct wland_fws_hanger - holds packets awaiting firmware txstatus.
 *
 * @pushed          : packets pushed to await txstatus.
 * @popped          : packets popped upon handling txstatus.
 * @failed_to_push  : packets that could not be pushed.
 * @failed_to_pop   : packets that could not be popped.
 * @failed_slotfind : packets for which failed to find an entry.
 * @slot_pos        : last returned item index for a free entry.
 * @items           : array of hanger items.
 */
struct wland_fws_hanger {
	u32 pushed;
	u32 popped;
	u32 failed_to_push;
	u32 failed_to_pop;
	u32 failed_slotfind;
	u32 slot_pos;
	struct wland_fws_hanger_item items[FWS_HANGER_MAXITEMS];
};

struct wland_fws_macdesc_table {
	struct wland_mac_descriptor nodes[WLAND_FWS_MAC_DESC_TABLE_SIZE];
	struct wland_mac_descriptor iface[WLAND_MAX_IFS];
	struct wland_mac_descriptor other;	/* current mac descriptor */
};

struct wland_fws_info {
	struct wland_private *drvr;
	spinlock_t spinlock;
	struct wland_fws_stats stats;
	struct wland_fws_hanger hanger;
	struct wland_fws_macdesc_table desc;
	u32 fifo_enqpkt[FWS_FIFO_COUNT];
	u32 fifo_delay_map;
};

typedef enum {
	PTA_NONE_PROTECT = 0,
	PTA_NULL_DATA_PROTECT,
	PTA_PS_POLL_PROTECT,
	PTA_SELF_CTS_PROTECT,
	PTA_AUTO_PROTECT
} PTA_PROTECT_MODE_T;

struct pta_param_s {
	u8 prot_mode;
	u8 mac_rate;		// 0: MIN_basic rate
	u8 hw_retry;
	u8 sw_retry;
	u8 cca_bypass;

	u8 restore;

	u16 active_time;	/* Unit is 100us */
	u16 thresh_time;	/* Unit is 100us */

	u16 auto_prot_thresh_time;	/* Unit is 100us */

	/*
	 * BIT0: Check high priority Q NULL before send PS_Poll or NULL frame
	 * BIT1: Check normal priority Q(AC_VO_Q) NULL before send PS_Poll or NULL frame
	 * BIT2: Check AC_VI_Q NULL before send PS_Poll or NULL frame
	 * BIT3: Check AC_BE_Q NULL before send PS_Poll or NULL frame
	 * BIT4: Check AC_BK_Q NULL before send PS_Poll or NULL frame
	 * BIT5: Check g_more_data_expected when send PS_Poll
	 */
	u16 flags;
	u8 listen_interval;
} __packed;

/* return wid type by wid */
static inline enum wid_type wland_get_wid_type(enum wland_firmw_wid firmw_wid)
{
	if (firmw_wid < WID_MAX_CHAR_ID) {
		return WID_CHAR;
	} else if (firmw_wid < WID_MAX_SHORT_ID) {
		return WID_SHORT;
	} else if (firmw_wid < WID_MAX_INTEGER_ID) {
		return WID_INT;
	} else if (firmw_wid < WID_MAX_STRING_ID) {
		return WID_STR;
	} else if (firmw_wid < WID_MAX_BINARY_ID) {
		return WID_BIN;
	} else {
		return WID_UNKNOW;
	}
}

static inline u8 wland_get_seqidx(struct wland_private *drvr)
{
	u8 idx = 0;
	struct wland_proto *prot = drvr->prot;

	/*
	 * Fill MsgIdx
	 */
	if (prot) {
		idx = prot->reqid;
		++prot->reqid;
	}

	return idx;
}

static inline u16 wland_get_wid_size(enum wid_type type, u16 len)
{
	switch (type) {
	case WID_CHAR:
		return sizeof(u8);
	case WID_SHORT:
		return sizeof(u16);
	case WID_INT:
		return sizeof(u32);
	case WID_STR:
	case WID_BIN:
	case WID_UNKNOW:
		break;
	default:
		break;
	}
	return len;
}

/* attach proto module */
extern int wland_proto_attach(struct wland_private *drvr);
extern void wland_proto_detach(struct wland_private *drvr);
extern s32 wland_push_wid(u8 *buf, u16 WID,  const void *data, u16 data_len, bool is_query);
extern s32 wland_pull_wid(const u8 *buf, u16 buf_len, u16 *WID, const u8 **data, u16 *data_len);

/* Add any protocol-specific data header */
extern int wland_proto_hdrpush(struct wland_private *drvr, s32 ifidx,
	struct sk_buff *pktbuf);

/* Remove any protocol-specific data header. */
extern int wland_proto_hdrpull(struct wland_private *drvr, s32 * ifidx,
	struct sk_buff *pktbuf);

/* group cmd set scan parameters */
extern s32 wland_set_scan_timeout(struct wland_if *ifp);

/* config regs from config_file and efuse*/
extern void wland_config_and_efuse(struct wland_if * ifp);

/* enable scan for ap list*/
extern s32 wland_start_scan_set(struct wland_if *ifp,
	struct wland_ssid_le *scan_ssid, bool enable);
extern s32 wland_p2p_start_scan_set(struct wland_if *ifp,
	struct wland_scan_params_le *sparams);

extern s32 wland_p2p_af_scan_set(struct wland_if * ifp,
	struct wland_scan_params_le *sparams);
extern s32 wland_p2p_connect_scan(struct wland_if * ifp,
	struct wland_scan_params_le *sparams);
extern s32 wland_start_ap_set(struct wland_if *ifp,
	struct wland_cfg80211_profile *profile, bool is_p2p);

extern s32 wland_p2p_start_go_set(struct wland_if *ifp,
	struct wland_cfg80211_profile *profile, bool is_p2p);

extern s32 wland_fil_set_mgmt_ie(struct wland_if *ifp, const u8 * vndr_ie_buf,
	u16 vndr_ie_len);
extern s32 wland_set_11n_action(struct wland_if * ifp, u8 *mac, u8 tid, u8 add);
extern s32 wland_set_txrate(struct wland_if *ifp, u8 mbps);
#ifdef WLAND_POWER_CONFIG
extern s32 wland_set_power_config(struct wland_if *ifp);
#endif
#ifdef WLAND_POWER_EFUSE
extern s32 wland_set_power_efuse(struct wland_if *ifp);
#endif
#ifdef WLAND_CRYSTAL_CALIBRATION
extern int wland_set_crystal_cal_val(struct wland_if *ifp);
#endif
#ifdef WLAND_SET_POWER_BY_RATE
extern int wland_set_power_by_rate(struct wland_if * ifp);
#endif
extern int wland_set_reg_for_channels(struct wland_if *ifp, u16 reg, u16 *value);
extern int wland_get_reg_for_channels(struct wland_if *ifp, u16 reg, u16 *value);
extern int wland_set_reg_8AH(struct wland_if *ifp);
extern int wland_dev_get_rssi(struct net_device *ndev, s16 * pRssi);
extern s32 wland_disconnect_bss(struct wland_if *ifp,
	struct wland_scb_val_le *scbval);

#ifdef WLAND_P2P_SUPPORT
extern s32 wland_p2p_disconnect_bss(struct wland_if * ifp,
	struct wland_scb_val_le * scbval);
s32 wland_p2p_go_del_sta(struct wland_if * ifp, struct wland_scb_val_le * scbval);
#endif

extern s32 wland_ap_del_sta(struct wland_if * ifp, u8 aid);
extern s32 wland_set_p2p_wps_done(struct wland_if * ifp, u8 is_wps_done);
extern s32 wland_add_wep_key_bss_sta(struct wland_if *ifp, u8 * key, u8 wep_len,
	u8 key_id);

extern s32 wland_start_join(struct wland_if *ifp,
	struct wland_cfg80211_profile *profile);
extern s32 wland_enable_arp_offload(struct wland_if *ifp,
	char *ipv4_addr);
extern s32 wland_p2p_start_join(struct wland_if *ifp,
	struct wland_cfg80211_profile *profile);

/* set/get cmd */
extern int wland_fil_set_cmd_data(struct wland_if *ifp, u16 cmd, const void *data,
	u16 len);
extern int wland_fil_get_cmd_data(struct wland_if *ifp, u16 cmd, void *data,
	u16 len);

extern s32 wland_fil_iovar_data_set(struct wland_if *ifp, char *name,
	void *data, u16 len);
extern s32 wland_fil_iovar_data_get(struct wland_if *ifp, char *name,
	void *data, u16 len);

/* Sets chip media info (drv_version, mac address). */
extern int wland_start_chip(struct net_device *ndev);
extern int wland_stop_chip(struct net_device *ndev);
#ifdef WLAND_DRIVER_RELOAD_FW
extern struct wland_bus *bus_if_backup;
extern bool wland_repowering_chip;
extern bool first_download_fw;
extern int wland_repower_chip(struct net_device *ndev, enum nl80211_iftype type);
extern void wland_repower_sem_up(bool check_flag);
#endif
/* send the wid command send to chip */
extern int wland_fws_init(struct wland_private *drvr);
extern void wland_fws_deinit(struct wland_private *drvr);
extern void wland_fws_add_interface(struct wland_if *ifp);
extern void wland_fws_del_interface(struct wland_if *ifp);
extern void wland_fws_macdesc_init(struct wland_mac_descriptor *desc, u8 * addr,
	u8 ifidx);
int wland_set_memory_32bit(struct wland_if *ifp, u32 addr, u32 val);
int wland_get_memory_32bit(struct wland_if *ifp, u32 addr, u32 *val);
extern int wland_proto_cdc_data(struct wland_private *drvr, u16 wid_msg_len);
extern int wland_fil_set_cmd_data_without_rsp(struct wland_if *ifp,
	u16 cmd, const void *data, u16 len);
#ifdef WLAND_SMART_CONFIG_SUPPORT
extern int wland_set_channel(struct wland_if *ifp, u8 channel);
extern int wland_sniffer_en_dis_able(struct net_device * ndev, bool enable);
#endif
/* Send packet to dongle via data channel */
extern int wland_sendpkt(struct wland_if *ifp, struct sk_buff *skb);
int wland_preinit_cmds_91h(struct wland_if *ifp);
#endif /* _WLAND_WID_H_ */
