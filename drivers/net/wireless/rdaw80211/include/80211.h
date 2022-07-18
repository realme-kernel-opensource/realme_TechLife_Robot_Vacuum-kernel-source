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
#ifndef _802_11_H_
#define _802_11_H_

#define MAC_HDR_LEN                     24          /* No Address4 - non-ESS         */
#define MAX_SSID_LEN                    33
#define FCS_LEN                         4
#define TIME_STAMP_LEN                  8
#define BEACON_INTERVAL_LEN             2
#define CAP_INFO_LEN                    2
#define LISTEN_INTERVAL_LEN             2
#define STATUS_CODE_LEN                 2
#define AID_LEN                         2
#define IE_HDR_LEN       		        2
#define MAC_HDR_ADDR2_OFFSET			10

#define SNAP_HDR_LEN                8

#define SNAP_HDR_ID_LEN             6

/** Size of the QoS Control Header in MAC Header */
#define QOS_CTRL_HDR_LEN            2

/** Size of the HT/VHT Control Header in MAC Header */
#define HT_CTRL_HDR_LEN             4

/* Macro to used to read Frame Type (BIT3-BIT2) field in Frame control of MAC */
#define FRAME_TYPE_MASK             0x0C

/* Macro to used to read Frame Type & Sub Type (BIT7-BIT2) fields in Frame control of MAC header */
#define FRAME_TYPE_SUBTYPE_MASK     0xFC

/**
*******************************************************************************
* Macro returns BTRUE if HTC field is present in specified Management frame.
*******************************************************************************
*/
#define IS_MGMT_HTC_PRESENT(pu1_msa)     (!!(pu1_msa[1] & BIT7))
#define IS_MGMT_WEP_PROTECTD_PRESENT(pu1_msa)     (!!(pu1_msa[1] & BIT6))

/**
*******************************************************************************
* Macro returns length of MAC header for specified management frame.
*******************************************************************************
*/
#define GET_MGMT_HDR_LEN(pu1_msa) ((IS_MGMT_HTC_PRESENT(pu1_msa))?          \
                                   (MAC_HDR_LEN + HT_CTRL_HDR_LEN) :        \
                                   (MAC_HDR_LEN))

#define DOT11_TU_TO_US			        1024	/* 802.11 Time Unit is 1024 microseconds */

/* Generic 802.11 frame constants */
#define DOT11_A3_HDR_LEN		        24	/* d11 header length with A3 */
#define DOT11_A4_HDR_LEN		        30	/* d11 header length with A4 */
#define DOT11_MAC_HDR_LEN		        DOT11_A3_HDR_LEN	/* MAC header length */
#define DOT11_FCS_LEN			        4	/* d11 FCS length */
#define DOT11_ICV_LEN			        4	/* d11 ICV length */
#define DOT11_ICV_AES_LEN		        8	/* d11 ICV/AES length */
#define DOT11_QOS_LEN			        2	/* d11 QoS length */
#define DOT11_HTC_LEN			        4	/* d11 HT Control field length */

#define DOT11_KEY_INDEX_SHIFT		    6	/* d11 key index shift */
#define DOT11_IV_LEN			        4	/* d11 IV length */
#define DOT11_IV_TKIP_LEN		        8	/* d11 IV TKIP length */
#define DOT11_IV_AES_OCB_LEN		    4	/* d11 IV/AES/OCB length */
#define DOT11_IV_AES_CCM_LEN		    8	/* d11 IV/AES/CCM length */
#define DOT11_IV_MAX_LEN		        8	/* maximum iv len for any encryption */

/* Includes MIC */
#define DOT11_MAX_MPDU_BODY_LEN		    2304	/* max MPDU body length */
/* A4 header + QoS + CCMP + PDU + ICV + FCS = 2352 */
#define DOT11_MAX_MPDU_LEN		        (DOT11_A4_HDR_LEN + \
                    					 DOT11_QOS_LEN + \
                    					 DOT11_IV_AES_CCM_LEN + \
                    					 DOT11_MAX_MPDU_BODY_LEN + \
                    					 DOT11_ICV_LEN + \
                    					 DOT11_FCS_LEN)	/* d11 max MPDU length */

#define DOT11_MAX_SSID_LEN		        32	/* d11 max ssid length */

/* dot11RTSThreshold */
#define DOT11_DEFAULT_RTS_LEN		    2347	/* d11 default RTS length */
#define DOT11_MAX_RTS_LEN		        2347	/* d11 max RTS length */

/* dot11FragmentationThreshold */
#define DOT11_MIN_FRAG_LEN		        256	    /* d11 min fragmentation length */
#define DOT11_MAX_FRAG_LEN		        2346	/* Max frag is also limited by aMPDUMaxLength of the attached PHY */
#define DOT11_DEFAULT_FRAG_LEN		    2346	/* d11 default fragmentation length */

/* dot11BeaconPeriod */
#define DOT11_MIN_BEACON_PERIOD		    1	/* d11 min beacon period */
#define DOT11_MAX_BEACON_PERIOD		    0xFFFF	/* d11 max beacon period */

/* dot11DTIMPeriod */
#define DOT11_MIN_DTIM_PERIOD		    1	/* d11 min DTIM period */
#define DOT11_MAX_DTIM_PERIOD		    0xFF	/* d11 max DTIM period */

/* 802.2 LLC/SNAP header used by 802.11 per 802.1H */
#define DOT11_LLC_SNAP_HDR_LEN		    8	/* d11 LLC/SNAP header length */
#define DOT11_OUI_LEN			        3	/* d11 OUI length */
/* RFC1042 header used by 802.11 per 802.1H */
#define RFC1042_HDR_LEN	                (ETHER_HDR_LEN + DOT11_LLC_SNAP_HDR_LEN)	/* RCF1042 header length */
#define VNDR_IE_HDR_LEN		        2	/* id + len field */
#define VNDR_IE_MIN_LEN		        3	/* size of the oui field */
#define VNDR_IE_FIXED_LEN	        (VNDR_IE_HDR_LEN + VNDR_IE_MIN_LEN)
#define VNDR_IE_MAX_LEN		        256	/* verdor IE max length */

/* ************* HT definitions. ************* */
#define MCSSET_LEN	                16	/* 16-bits per 8-bit set to give 128-bits bitmap of MCS Index */
#define MAX_MCS_NUM	                (128)	/* max mcs number = 128 */



#define HT_PROP_IE_OVERHEAD	            4	/* overhead bytes for prop oui ie */
#define HT_CAP_IE_LEN		            26	/* HT capability len (based on .11n d2.0) */
#define HT_CAP_IE_TYPE		            51

#define HT_CAP_LDPC_CODING	            0x0001	/* Support for rx of LDPC coded pkts */
#define HT_CAP_40MHZ		            0x0002  /* false:20Mhz, true:20/40MHZ supported */
#define HT_CAP_MIMO_PS_MASK	            0x000C  /* Mimo PS mask */
#define HT_CAP_MIMO_PS_SHIFT	        0x0002	/* Mimo PS shift */
#define HT_CAP_MIMO_PS_OFF	            0x0003	/* Mimo PS, no restriction */
#define HT_CAP_MIMO_PS_RTS	            0x0001	/* Mimo PS, send RTS/CTS around MIMO frames */
#define HT_CAP_MIMO_PS_ON	            0x0000	/* Mimo PS, MIMO disallowed */
#define HT_CAP_GF		                0x0010	/* Greenfield preamble support */
#define HT_CAP_SHORT_GI_20	            0x0020	/* 20MHZ short guard interval support */
#define HT_CAP_SHORT_GI_40	            0x0040	/* 40Mhz short guard interval support */
#define HT_CAP_TX_STBC		            0x0080	/* Tx STBC support */
#define HT_CAP_RX_STBC_MASK	            0x0300	/* Rx STBC mask */
#define HT_CAP_RX_STBC_SHIFT	        8	/* Rx STBC shift */
#define HT_CAP_DELAYED_BA	            0x0400	/* delayed BA support */
#define HT_CAP_MAX_AMSDU	            0x0800	/* Max AMSDU size in bytes , 0=3839, 1=7935 */

#define HT_CAP_DSSS_CCK	                0x1000	/* DSSS/CCK supported by the BSS */
#define HT_CAP_PSMP		                0x2000	/* Power Save Multi Poll support */
#define HT_CAP_40MHZ_INTOLERANT         0x4000	/* 40MHz Intolerant */
#define HT_CAP_LSIG_TXOP	            0x8000	/* L-SIG TXOP protection support */

#define HT_CAP_RX_STBC_NO		        0x0	/* no rx STBC support */
#define HT_CAP_RX_STBC_ONE_STREAM	    0x1	/* rx STBC support of 1 spatial stream */
#define HT_CAP_RX_STBC_TWO_STREAM	    0x2	/* rx STBC support of 1-2 spatial streams */
#define HT_CAP_RX_STBC_THREE_STREAM	    0x3	/* rx STBC support of 1-3 spatial streams */

#define VHT_MAX_MPDU		            11454	/* max mpdu size for now (bytes) */
#define VHT_MPDU_MSDU_DELTA	            56		/* Difference in spec - vht mpdu, amsdu len */
/* Max AMSDU len - per spec */
#define VHT_MAX_AMSDU		            (VHT_MAX_MPDU - VHT_MPDU_MSDU_DELTA)

#define HT_MAX_AMSDU		            7935	/* max amsdu size (bytes) per the HT spec */
#define HT_MIN_AMSDU		            3835	/* min amsdu size (bytes) per the HT spec */

#define HT_PARAMS_RX_FACTOR_MASK	    0x03	/* ampdu rcv factor mask */
#define HT_PARAMS_DENSITY_MASK		    0x1C	/* ampdu density mask */
#define HT_PARAMS_DENSITY_SHIFT	        2	/* ampdu density shift */

/* HT/AMPDU specific define */
#define AMPDU_MAX_MPDU_DENSITY          7       /* max mpdu density; in 1/4 usec units */
#define AMPDU_DENSITY_NONE              0       /* No density requirement */
#define AMPDU_DENSITY_1over4_US         1       /* 1/4 us density */
#define AMPDU_DENSITY_1over2_US         2       /* 1/2 us density */
#define AMPDU_DENSITY_1_US              3       /*   1 us density */
#define AMPDU_DENSITY_2_US              4       /*   2 us density */
#define AMPDU_DENSITY_4_US              5       /*   4 us density */
#define AMPDU_DENSITY_8_US              6       /*   8 us density */
#define AMPDU_DENSITY_16_US             7       /*  16 us density */
#define AMPDU_RX_FACTOR_8K              0       /* max rcv ampdu len (8kb) */
#define AMPDU_RX_FACTOR_16K             1       /* max rcv ampdu len (16kb) */
#define AMPDU_RX_FACTOR_32K             2       /* max rcv ampdu len (32kb) */
#define AMPDU_RX_FACTOR_64K             3       /* max rcv ampdu len (64kb) */
#define AMPDU_RX_FACTOR_BASE            8*1024  /* ampdu factor base for rx len */

#define AMPDU_DELIMITER_LEN	            4	/* length of ampdu delimiter */
#define AMPDU_DELIMITER_LEN_MAX	        63	/* max length of ampdu delimiter(enforced in HW) */

#define HT_CAP_EXT_PCO			        0x0001
#define HT_CAP_EXT_PCO_TTIME_MASK	    0x0006
#define HT_CAP_EXT_PCO_TTIME_SHIFT	    1
#define HT_CAP_EXT_MCS_FEEDBACK_MASK	0x0300
#define HT_CAP_EXT_MCS_FEEDBACK_SHIFT	8
#define HT_CAP_EXT_HTC			        0x0400
#define HT_CAP_EXT_RD_RESP		        0x0800


/* ************* WPA definitions. ************* */
#define WPA_OUI			        "\x00\x50\xF2"	/* WPA OUI */
#define WPA_OUI_LEN		        3		        /* WPA OUI length */
#define WPA_OUI_TYPE		    1
#define WPA_VERSION		        1		        /* WPA version */
#define WPA2_OUI		        "\x00\x0F\xAC"	/* WPA2 OUI */
#define WPA2_OUI_LEN		    3		        /* WPA2 OUI length */
#define WPA2_VERSION		    1		        /* WPA2 version */
#define WPA2_VERSION_LEN	    2		        /* WAP2 version length */

/* ************* WPS definitions. ************* */
#define WPS_OUI			        "\x00\x50\xF2"	/* WPS OUI */
#define WPS_OUI_LEN		        3		        /* WPS OUI length */
#define WPS_OUI_TYPE		    4

#define RSN_OUI				    "\x00\x0F\xAC"	/* RSN OUI */


/* ************* WFA definitions. ************* */

#ifdef P2P_IE_OVRD
#define WFA_OUI			        MAC_OUI
#else
#define WFA_OUI			        "\x50\x6F\x9A"	/* WFA OUI */
#endif /* P2P_IE_OVRD */

#define WFA_OUI_LEN		        3		/* WFA OUI length */
#ifdef P2P_IE_OVRD
#define WFA_OUI_TYPE_P2P	    MAC_OUI_TYPE_P2P
#else
#define WFA_OUI_TYPE_P2P	    9
#endif

#define WFA_OUI_TYPE_TPC	    8

#ifdef WLTDLS
#define WFA_OUI_TYPE_WFD	    10
#endif /* WTDLS */

/* RSN authenticated key managment suite */
#define RSN_AKM_NONE		    0	/* None (IBSS) */
#define RSN_AKM_UNSPECIFIED	    1	/* Over 802.1x */
#define RSN_AKM_PSK		        2	/* Pre-shared Key */
#define RSN_AKM_FBT_1X		    3	/* Fast Bss transition using 802.1X */
#define RSN_AKM_FBT_PSK		    4	/* Fast Bss transition using Pre-shared Key */
#define RSN_AKM_MFP_1X		    5	/* SHA256 key derivation, using 802.1X */
#define RSN_AKM_MFP_PSK		    6	/* SHA256 key derivation, using Pre-shared Key */
#define RSN_AKM_TPK			    7	/* TPK(TDLS Peer Key) handshake */

/* Key related defines */
#define DOT11_MAX_DEFAULT_KEYS	4	/* number of default keys */
#define DOT11_MAX_KEY_SIZE	    32	/* max size of any key */
#define DOT11_MAX_IV_SIZE	    16	/* max size of any IV */
#define DOT11_EXT_IV_FLAG	    (1<<5)	/* flag to indicate IV is > 4 bytes */
#define DOT11_WPA_KEY_RSC_LEN   8       /* WPA RSC key len */

#define WEP1_KEY_SIZE		    5	/* max size of any WEP key */
#define WEP1_KEY_HEX_SIZE	    10	/* size of WEP key in hex. */
#define WEP128_KEY_SIZE		    13	/* max size of any WEP key */
#define WEP128_KEY_HEX_SIZE	    26	/* size of WEP key in hex. */
#define TKIP_MIC_SIZE		    8	/* size of TKIP MIC */
#define TKIP_EOM_SIZE		    7	/* max size of TKIP EOM */
#define TKIP_EOM_FLAG		    0x5a	/* TKIP EOM flag byte */
#define TKIP_KEY_SIZE		    32	/* size of any TKIP key */
#define TKIP_MIC_AUTH_TX	    16	/* offset to Authenticator MIC TX key */
#define TKIP_MIC_AUTH_RX	    24	/* offset to Authenticator MIC RX key */
#define TKIP_MIC_SUP_RX		    TKIP_MIC_AUTH_TX	/* offset to Supplicant MIC RX key */
#define TKIP_MIC_SUP_TX		    TKIP_MIC_AUTH_RX	/* offset to Supplicant MIC TX key */
#define AES_KEY_SIZE		    16	/* size of AES key */
#define AES_MIC_SIZE		    8	/* size of AES MIC */
#define BIP_KEY_SIZE		    16	/* size of BIP key */

/* WCN */
#define WCN_OUI			         "\x00\x50\xf2"	/* WCN OUI */
#define WCN_TYPE		        4	/* WCN type */
#ifdef BCMWAPI_WPI
#define SMS4_KEY_LEN            16
#define SMS4_WPI_CBC_MAC_LEN    16
#endif

/* WME Elements */
#define WME_OUI			            "\x00\x50\xf2"	/* WME OUI */
#define WME_OUI_LEN		            3
#define WME_OUI_TYPE		        2	/* WME type */
#define WME_TYPE		            2	/* WME type, deprecated */
#define WME_SUBTYPE_IE		        0	/* Information Element */
#define WME_SUBTYPE_PARAM_IE	    1	/* Parameter Element */
#define WME_SUBTYPE_TSPEC	        2	/* Traffic Specification */
#define WME_VER			            1	/* WME version */

/* Basic Frame Type Codes (2-bit) */
enum BASICTYPE_T
{
    CONTROL         = 0x04,
    DATA_BASICTYPE  = 0x08,
    MANAGEMENT      = 0x00,
    RESERVED        = 0x0C
};

/* Element ID  of various Information Elements */
enum ELEMENTID_T{
    ISSID			= 0,   /* Service Set Identifier		 */
    ISUPRATES		= 1,	 /* Supported Rates 			   */
    IFHPARMS		= 2,	 /* FH parameter set			   */
    IDSPARMS		= 3,	 /* DS parameter set			   */
    ICFPARMS		= 4,	 /* CF parameter set			   */
    ITIM			= 5,	 /* Traffic Information Map 	   */
    IIBPARMS		= 6,	 /* IBSS parameter set			   */
    ICOUNTRY		= 7,	 /* Country element 			   */
    IEDCAPARAMS 	= 12,  /* EDCA parameter set			   */
    ITSPEC			  = 13,  /* Traffic Specification		   */
    ITCLAS			  = 14,  /* Traffic Classification		   */
    ISCHED			  = 15,  /* Schedule					   */
    ICTEXT			  = 16,  /* Challenge Text				   */
    IPOWERCONSTRAINT	  = 32,  /* Power Constraint			   */
    IPOWERCAPABILITY	  = 33,  /* Power Capability			   */
    ITPCREQUEST 	  = 34,  /* TPC Request 				   */
    ITPCREPORT		  = 35,  /* TPC Report					   */
    ISUPCHANNEL 	  = 36,  /* Supported channel list		   */
    ICHSWANNOUNC		  = 37,  /* Channel Switch Announcement    */
    IMEASUREMENTREQUEST = 38,  /* Measurement request		   */
    IMEASUREMENTREPORT	= 39,  /* Measurement report			   */
    IQUIET			  = 40,  /* Quiet element Info			   */
    IIBSSDFS			  = 41,  /* IBSS DFS					   */
    IERPINFO			  = 42,  /* ERP Information 			   */
    ITSDELAY			  = 43,  /* TS Delay					   */
    ITCLASPROCESS	  = 44,  /* TCLAS Processing			   */
    IHTCAP			  = 45,  /* HT Capabilities 			   */
    IQOSCAP 		  = 46,  /* QoS Capability				   */
    IRSNELEMENT 	  = 48,  /* RSN Information Element 	   */
    IEXSUPRATES 	  = 50,  /* Extended Supported Rates	   */
    ISUPOPCLASS 	  = 59,  /* Supported Operating Class	   */
    IEXCHSWANNOUNC	  = 60,  /* Extended Ch Switch Announcement*/
    IHTOPERATION		  = 61,  /* HT Information				   */
    ISECCHOFF		  = 62,  /* Secondary Channel Offeset	   */
#ifdef MAC_RDA_WAPI
    IWAPI			  = 68,  /* WAPI Information			   */
#endif  /* MAC_RDA_WAPI */
    I2040COEX		  = 72,  /* 20/40 Coexistence IE		   */
    I2040INTOLCHREPORT	= 73,  /* 20/40 Intolerant channel report*/
    IOBSSSCAN		  = 74,  /* OBSS Scan parameters		   */
    IEXTCAP 		  = 127, /* Extended capability 		   */
    /* Need to change all to Vendor */
    IWMM				  = 221, /* WMM parameters				   */
    IWPAELEMENT 	  = 221, /* WPA Information Element 	   */
    IP2P				  = 221, /* P2P Information Element 	   */
    IVSIE			  = 221, /* Vendor Specific Element 	   */
    IWFD				  = 221  /* WFD Information Element 	   */
};


/* Frame Type and Subtype Codes (6-bit) */
enum TYPESUBTYPE_T
{
    ASSOC_REQ             = 0x00,
    ASSOC_RSP             = 0x10,
    REASSOC_REQ           = 0x20,
    REASSOC_RSP           = 0x30,
    PROBE_REQ             = 0x40,
    PROBE_RSP             = 0x50,
    BEACON                = 0x80,
    ATIM                  = 0x90,
    DISASOC               = 0xA0,
    AUTH                  = 0xB0,
    DEAUTH                = 0xC0,
    ACTION                = 0xD0,
    PS_POLL               = 0xA4,
    RTS                   = 0xB4,
    CTS                   = 0xC4,
    ACK                   = 0xD4,
    CFEND                 = 0xE4,
    CFEND_ACK             = 0xF4,
    DATA                  = 0x08,
    DATA_ACK              = 0x18,
    DATA_POLL             = 0x28,
    DATA_POLL_ACK         = 0x38,
    NULL_FRAME            = 0x48,
    CFACK                 = 0x58,
    CFPOLL                = 0x68,
    CFPOLL_ACK            = 0x78,
    QOS_DATA              = 0x88,
    QOS_DATA_ACK          = 0x98,
    QOS_DATA_POLL         = 0xA8,
    QOS_DATA_POLL_ACK     = 0xB8,
    QOS_NULL_FRAME        = 0xC8,
    QOS_CFPOLL            = 0xE8,
    QOS_CFPOLL_ACK        = 0xF8,
    BLOCKACK_REQ          = 0x84,
    BLOCKACK              = 0x94
};


#define	DOT11_BCN_PRB_LEN	        12		/* 802.11 beacon/probe frame fixed length */
#define	DOT11_BCN_PRB_FIXED_LEN	    12		/* 802.11 beacon/probe frame fixed length */

#define	DOT11_MGMT_HDR_LEN	        24		/* d11 management header length */


#define WPA_IE_SUITE_COUNT_LEN	2


/* WPA cipher suites */
#define WPA_CIPHER_NONE		            0	/* None */
#define WPA_CIPHER_WEP_40	            1	/* WEP (40-bit) */
#define WPA_CIPHER_TKIP		            2	/* TKIP: default for WPA */
#define WPA_CIPHER_AES_OCB	            3	/* AES (OCB) */
#define WPA_CIPHER_AES_CCM	            4	/* AES (CCM) */
#define WPA_CIPHER_WEP_104	            5	/* WEP (104-bit) */
#define WPA_CIPHER_BIP		            6	/* WEP (104-bit) */
#define WPA_CIPHER_TPK		            7	/* Group addressed traffic not allowed */
#ifdef BCMWAPI_WPI
#define WAPI_CIPHER_NONE	            WPA_CIPHER_NONE
#define WAPI_CIPHER_SMS4	            11
#define WAPI_CSE_WPI_SMS4	            1
#endif /* BCMWAPI_WPI */
#define IS_WPA_CIPHER(cipher)			((cipher) == WPA_CIPHER_NONE || \
										(cipher) == WPA_CIPHER_WEP_40 || \
										(cipher) == WPA_CIPHER_WEP_104 || \
										(cipher) == WPA_CIPHER_TKIP || \
										(cipher) == WPA_CIPHER_AES_OCB || \
										(cipher) == WPA_CIPHER_AES_CCM || \
										(cipher) == WPA_CIPHER_TPK)

	/* WPA TKIP countermeasures parameters */
#define WPA_TKIP_CM_DETECT	            60	/* multiple MIC failure window (seconds) */
#define WPA_TKIP_CM_BLOCK	            60	/* countermeasures active window (seconds) */

	/* RSN IE defines */
#define RSN_CAP_LEN		                2	/* Length of RSN capabilities field (2 octets) */

	/* RSN Capabilities defined in 802.11i */
#define RSN_CAP_PREAUTH			        0x0001
#define RSN_CAP_NOPAIRWISE		        0x0002
#define RSN_CAP_PTK_REPLAY_CNTR_MASK	0x000C
#define RSN_CAP_PTK_REPLAY_CNTR_SHIFT	2
#define RSN_CAP_GTK_REPLAY_CNTR_MASK	0x0030
#define RSN_CAP_GTK_REPLAY_CNTR_SHIFT	4
#define RSN_CAP_1_REPLAY_CNTR		    0
#define RSN_CAP_2_REPLAY_CNTRS		    1
#define RSN_CAP_4_REPLAY_CNTRS		    2
#define RSN_CAP_16_REPLAY_CNTRS		    3
#ifdef MFP
#define RSN_CAP_MFPR			        0x0040
#define RSN_CAP_MFPC			        0x0080
#endif


/* The following macros describe the bitfield map used by the firmware to determine its 11i mode */
#define NO_ENCRYPT			             0
#define ENCRYPT_ENABLED	                (1 << 0)
#define WEP					            (1 << 1)
#define WEP_EXTENDED		            (1 << 2)
#define WPA					            (1 << 3)
#define WPA2				            (1 << 4)
#define AES					            (1 << 5)
#define TKIP					        (1 << 6)

enum SECURITY_T{
	NO_SECURITY   = 0,
	WEP_40        = 0x3,
	WEP_104       = 0x7,
	WPA_AES       = 0x29,
	WPA_TKIP      = 0x49,
	WPA_AES_TKIP  = 0x69,		/* Aes or Tkip */
	WPA2_AES      = 0x31,
	WPA2_TKIP     = 0x51,
	WPA2_AES_TKIP = 0x71,	/* Aes or Tkip */
};

enum AUTHTYPE_T{
	OPEN_SYSTEM   = 1,
	SHARED_KEY    = 2,
	ANY           = 3,
    IEEE8021      = 5
};

#endif /* _802_11_H_ */
