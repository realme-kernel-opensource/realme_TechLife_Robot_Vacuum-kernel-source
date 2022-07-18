
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
#ifndef _WLAND_DEFS_H_
#define _WLAND_DEFS_H_

#include <linux/types.h>
#include <linux/if_ether.h>
#include <linuxver.h>

/****************************************************************************
                        Wlan Const Defines
 ****************************************************************************/

#define WLAND_5991H_MAC1_SUPPORT

/* Driver Version Sync With Source Server */
#define WLAND_VER_MAJ                           1
#define WLAND_VER_MIN                           6
#define WLAND_VER_BLD                           0

/* Packet alignment for most efficient SDIO (can change based on platform) */
#define WLAND_SDALIGN	                (1 << 2)

/* define for chip version */
enum WLAND_CHIP_VERSION {
	WLAND_VER_90_E = 2,
	WLAND_VER_91 = 3,
	WLAND_VER_91_E = 4,
	WLAND_VER_91_F = 5,
	WLAND_VER_91_G = 6,
	WLAND_VER_91_H = 7,
	WLAND_VER_96 = 8,
	WLAND_VER_MAX = 10
};

#define WLAND_DEFAULT_COUNTRY_CODE SITE_SURVEY_EU_CH
//SITE_SURVEY_ALL_CH = 1,//channel 1~14
//SITE_SURVEY_NA_CH = 4,// channel 1~11
//SITE_SURVEY_EU_CH = 5// chanenl 1~13

#define RDA5995_TESTMODE_FILE    "/data/misc/wifi/rda5995_testmode"

#ifdef WLAND_HISI3798MV130_PLATFORM_SUPPORT
#define DHCP_PKT_MEMCOPY_BEFORE_SEND
#define WLAND_FIRMWARE_PATH_FILE "/data/vendor/wifi/firmware_path"
#define WLAND_DRIVER_RELOAD_FW
#else
/*some platform like hisimv130 need a memcopy before send a dhcp pkt*/
//#define DHCP_PKT_MEMCOPY_BEFORE_SEND

//#define WLAND_FIRMWARE_PATH_FILE "/var/Run/wifi/rdaw80211"

/*no firmware_path param when loading rdawfmac.ko, driver will reload fw by mode*/
#define WLAND_DRIVER_RELOAD_FW
#endif

/* if can not up wlan0 before start wpa_supplicant and you want to use MACADDR in efuse
 please open WLAND_MACADDR_FIRST_DYNAMIC_THEN_EFUSE, sta will use a dynamic macaddr
 on first start and use MADADDR from efuse in the future. */
//#define WLAND_MACADDR_FIRST_DYNAMIC_THEN_EFUSE

#ifndef WLAND_LINUX_SUPPORT
#define WLAND_MACADDR_EFUSE
#endif

#define WLAND_FIRMWARE_PATH "/var/Run/wifi/rdaw"
//#define WLAND_DOWNLOAD_FIRMWARE_FROM_HEX

#ifdef WLAND_DOWNLOAD_FIRMWARE_FROM_HEX
#define WLAND_DOWNLOAD_FIRMWARE_FROM_HEX_FOR_RF
struct wland_image_info {
	unsigned char* bin_name;
	unsigned char* buf;
	size_t size;
};
#endif

#define WLAND_CRYSTAL_CALIBRATION
#define WLAND_POWER_EFUSE
#define WLAND_POWER_CONFIG
#ifdef WLAND_POWER_CONFIG
#define WIFI_POWER_SAVR_FILE_NAME "power_config.txt"
#endif /*WLAND_POWER_CONFIG*/

/* 20180904 defaultly using rising edge to wake up host, */
/* unless open the macro WLAND_DESCENT_EDGE_WAKEUP_HOST  */
#define WLAND_DESCENT_EDGE_WAKEUP_HOST
//#define WLAND_AP_LOW_POWER
//#define WLAND_ENHANCE_MODE
//#define WLAND_SET_POWER_BY_RATE
#define B_RATE_NUM	4
#define G_RATE_NUM	8
#define N_RATE_NUM	8
#define ALL_RATE_NUM (B_RATE_NUM+G_RATE_NUM+N_RATE_NUM)

/*find csa ie in a beacon, fw switch to a new channel*/
//#define WLAND_STA_CSA_SUPPORT

//#define WLAND_SOFTAP_40M

//#define WLAND_WLAN0_NOSCAN_WHEN_P2P0_DATAINCOMING

#ifdef CONFIG_RDAWFMAC_SDIO

//#define WLAND_INTPENDING_READ_CLEAN_BIT3

#define WLAND_SDIO_SUPPORT
#elif defined CONFIG_RDAWFMAC_USB
#define WLAND_USB_SUPPORT
#endif /*CONFIG_RDAWFMAC_SDIO*/

#ifdef CONFIG_ARCH_RDA
/* rda platform sdio should 2^n alligen */
#define WLAND_RDAPLATFORM_SUPPORT
#endif /*CONFIG_ARCH_RDA*/

#ifdef WLAND_SDIO_SUPPORT
//#define WLAND_AP_RESET
#define WLAND_NO_TXDATA_SCAN
#define WLAND_CONNECT_WITH_1M

#define WLAND_P2P_SUPPORT

/*define for power manager*/
#define WLAND_POWER_MANAGER

#define WLAND_USE_RXQ
//#define WLAND_RX_SOFT_MAC
//#define WLAND_TX_SOFT_MAC

#ifndef WLAND_RX_SOFT_MAC
#define WLAND_RX_8023_REORDER
#endif

#define WLAND_TX_AGGRPKTS
#define WLAND_RX_AGGRPKTS
#ifdef WLAND_RX_AGGRPKTS
#define WLAND_DMA_RX1536_BLOCKS
#endif
#ifdef WLAND_TX_AGGRPKTS
#define WLAND_DMA_TX1536_BLOCKS
#endif

//#define WLAND_TXLEN_1536
//#define WLAND_RXLEN_1536
#endif /*WLAND_SDIO_SUPPORT*/

#ifdef WLAND_RDAPLATFORM_SUPPORT
#define USE_MAC_FROM_RDA_NVRAM
#endif /*WLAND_RDAPLATFORM_SUPPORT*/

#ifdef WLAND_USB_SUPPORT

#define WLAND_P2P_SUPPORT

#define WLAND_CONNECT_WITH_1M
//#define WLAND_RX_SOFT_MAC
//#define WLAND_TX_SOFT_MAC
#ifndef WLAND_RX_SOFT_MAC
#define WLAND_RX_8023_REORDER
#endif
#define WLAND_USE_RXQ //usb must use rxq
#define WLAND_USE_USB_TXQ
#define WLAND_NO_TXDATA_SCAN
#endif

/* define for use random mac address  */
#define WLAND_MACADDR_DYNAMIC
/* define for use macaddr when insmod ko */
//#define WLAND_MACADDR_FROM_USER

//#define DECRYPT_FIRMWARE_AES
#define DECRYPT_FIRMWARE_RC4

//#define CHECK_FIRMWARE_SHA1
#define CHECK_FIRMWARE_MD5
//#define CHECK_FIRMWARE_CRC32

#define RDA5991H_SDIO_CODE_STA 	"rda5995_sdio_code_sta.bin"
#define RDA5991H_SDIO_DATA_STA 	"rda5995_sdio_data_sta.bin"

#define RDA5991H_SDIO_CODE_P2P 	"rda5995_sdio_code_p2p.bin"
#define RDA5991H_SDIO_DATA_P2P 	"rda5995_sdio_data_p2p.bin"

#define RDA5991H_SDIO_CODE_AP 	"rda5995_sdio_code_ap.bin"
#define RDA5991H_SDIO_DATA_AP 	"rda5995_sdio_data_ap.bin"

#define RDA5991H_SDIO_CODE_RF 	"rda5995_sdio_code_rf.bin"
#define RDA5991H_SDIO_DATA_RF 	"rda5995_sdio_data_rf.bin"

#define RDA5991H_USB_CODE_STA 	"rda5995_usb_code_sta.bin"
#define RDA5991H_USB_DATA_STA 	"rda5995_usb_data_sta.bin"

#define RDA5991H_USB_CODE_AP 	"rda5995_usb_code_ap.bin"
#define RDA5991H_USB_DATA_AP 	"rda5995_usb_data_ap.bin"

#define RDA5991H_USB_CODE_P2P 	"rda5995_usb_code_p2p.bin"
#define RDA5991H_USB_DATA_P2P 	"rda5995_usb_data_p2p.bin"

#define RDA5991H_USB_CODE_RF 	"rda5995_usb_code_rf.bin"
#define RDA5991H_USB_DATA_RF 	"rda5995_usb_data_rf.bin"

#define RDA5991H_CODE_ADDR 0x100000
#define RDA5991H_DATA_ADDR_STA_AP 0x180000

//#define DOWNLOAD_STA_FIRMWARE
#ifndef DOWNLOAD_STA_FIRMWARE
#ifdef RDA5991H_SDIO_CODE_STA
#undef RDA5991H_SDIO_CODE_STA
#define RDA5991H_SDIO_CODE_STA 	"rda5995_sdio_code_p2p.bin"
#endif /*RDA5991H_SDIO_CODE_STA*/

#ifdef RDA5991H_USB_CODE_STA
#undef RDA5991H_USB_CODE_STA
#define RDA5991H_USB_CODE_STA 	"rda5995_usb_code_p2p.bin"
#endif /*RDA5991H_USB_CODE_STA*/

#ifdef RDA5991H_SDIO_DATA_STA
#undef RDA5991H_SDIO_DATA_STA
#define RDA5991H_SDIO_DATA_STA 	"rda5995_sdio_data_p2p.bin"
#endif /*RDA5991H_SDIO_DATA_STA*/

#ifdef RDA5991H_USB_DATA_STA
#undef RDA5991H_USB_DATA_STA
#define RDA5991H_USB_DATA_STA 	"rda5995_usb_data_p2p.bin"
#endif /*RDA5991H_USB_DATA_STA*/

#define RDA5991H_SDIO_CODE1_STA	"rda5995_sdio_code1_p2p.bin"
#define RDA5991H_USB_CODE1_STA 	"rda5995_usb_code1_p2p.bin"

#define RDA5991H_DATA_ADDR_P2P 0x184000
#define RDA5991H_CODE1_ADDR_P2P  0x180000
#endif /*DOWNLOAD_STA_FIRMWARE*/

#define CRC32_DIGEST_SIZE	4
#define SHA1_DIGEST_SIZE    20
#define MD5_DIGEST_LENGTH	16

enum HOST_CHECKSUM_TYPE_T///HCMD_CHECKSUM_TYPE
{
	HOST_CHECKSUM_CRC = 1,
	HOST_CHECKSUM_SHA1,
	HOST_CHECKSUM_MD5
};

enum HOST_DECRYPT_TYPE_T////HCMD_DECRYPT_TYPE
{
	HOST_DECRYPT_RC4 = 1,
	HOST_DECRYPT_AES_CBC
};

#define WLAND_VERSION_STR		                "9.59.95.5"
#define CHIP_ID_MASK                            (0x1F)

/* SDIO Device ID */
#define SDIO_VENDOR_ID_RDAWLAN		            0x5449
#define SDIO_DEVICE_ID_RDA599X      	        0x0145

/* USB  Device ID */
#define USB_VENDOR_ID_RDAMICRO	                0x1E04
#define USB_DEVICE_ID_RDA599X	                0x8888
#define USB_DEVICE_ID_BCMFW	                    0x0BDC

#define WIFI_MAC_ACTIVATED_FLAG    				0x5990

#ifndef TRUE
#define TRUE            (1)
#endif

/*
#ifndef FALSE
#define FALSE           (0)
#endif
*/
#ifndef NULL
#define NULL                                    ((void*)0)
#endif

/* Support BUS TYPE */
#define SDIO_BUS		                        1	/* SDIO target */
#define USB_BUS			                        2	/* USB  target */

/* bit mask */
#define BIT17									(1 << 17)
#define BIT16									(1 << 16)
#define BIT15                                   (1 << 15)
#define BIT14                                   (1 << 14)
#define BIT13                                   (1 << 13)
#define BIT12                                   (1 << 12)
#define BIT11                                   (1 << 11)
#define BIT10                                   (1 << 10)
#define BIT9                                    (1 << 9)
#define BIT8                                    (1 << 8)
#define BIT7                                    (1 << 7)
#define BIT6                                    (1 << 6)
#define BIT5                                    (1 << 5)
#define BIT4                                    (1 << 4)
#define BIT3                                    (1 << 3)
#define BIT2                                    (1 << 2)
#define BIT1                                    (1 << 1)
#define BIT0                                    (1 << 0)

#define CLEAR_BIT(X , Y)                        (X) &= (~(Y))
#define SET_BIT(X , Y)                          (X) |= (Y)

/* Values for PM */
#define	OFF	                                    0
#define	ON	                                    1	/* ON = 1    */
#define	AUTO	                                (-1)	/* Auto = -1 */

#define MIN_SCAN_TIME				            10
#define MAX_SCAN_TIME				            1200
#define DEFAULT_SCAN				            0
#define USER_SCAN					            BIT0

/* Return Results */
#define STATUS_SUCCESS                          (1)
#define STATUS_TIMEOUT			                (2)
#define STATUS_ABORTED      	                (3)
#define STATUS_FAILED                           (4)
#define STATUS_NO_NETWORKS                      (5)

#define MAC_DISCONNECTED                        (0)
#define MAC_CONNECTED                           (1)
#define P2P_MAC_DISCONNECTED                    (2)
#define P2P_MAC_CONNECTED                       (3)
#define RESULT_SCAN_COMP			0x00
#define RESULT_CONN_FAIL			0x10
#define RESULT_P2P_CONN_FAIL		0x20

/* Priority definitions according 802.1D */
#define PRIO_8021D_NONE		                    2
#define PRIO_8021D_BK		                    1
#define PRIO_8021D_BE		                    0
#define PRIO_8021D_EE		                    3
#define PRIO_8021D_CL		                    4
#define PRIO_8021D_VI		                    5
#define PRIO_8021D_VO		                    6
#define PRIO_8021D_NC		                    7

#define AC_BE		                    0
#define AC_BK		                    1
#define AC_VI		                    2
#define AC_VO		                    3

#define	MAXPRIO			                        7
#define NUMPRIO			                        (MAXPRIO + 1)

/* Bit masks for radio disabled status - returned by WL_GET_RADIO */
#define RADIO_SW_DISABLE		                (1<<0)
#define RADIO_HW_DISABLE		                (1<<1)

/* some countries don't support any channel */
#define RADIO_COUNTRY_DISABLE	                (1<<3)

/* Override bit for SET_TXPWR.  if set, ignore other level limits */
#define TXPWR_OVERRIDE	                        (1U<<31)

/* band types */
#define	WLAND_BAND_AUTO		                    0	/* auto-select */
#define	WLAND_BAND_5G		                    1	/* 5 Ghz */
#define	WLAND_BAND_2G		                    2	/* 2.4 Ghz */
#define	WLAND_BAND_ALL		                    3	/* all bands */
/*
#ifndef WLAN_EID_GENERIC
#define WLAN_EID_GENERIC                        0xDD
#endif
*/

/* define for debug information */
#define MAX_HEX_DUMP_LEN	                    64

#define ALL_INTERFACES	                        0xFF

#define IOCTL_RESP_TIMEOUT                      (5*1000)
#define SCAN_CMP_TIMEOUT						(2*1000)

/* scan relation timeout  */
#define SCAN_CHANNEL_TIME		                20	/* ms */
#define SCAN_ACTIVE_TIME		                20	/* ms */
#define SCAN_PASSIVE_TIME		                20	/* ms */

// Low snr agc setting
#define CHINA_VERSION

/* CDC flag definitions */
#define CDC_DCMD_LEN_MASK	                    0x0FFF	/* id an cmd pairing */
#define CDC_DCMD_LEN_SHIFT	                    12	/* ID Mask shift bits */

/****************************************************************************
                        Wlan Features Support
 ****************************************************************************/
#ifndef DEBUG
#define DEBUG
#endif

#define MOD_PARAM_PATHLEN 100
extern char rdawlan_firmware_path[MOD_PARAM_PATHLEN];
extern unsigned char WifiMac[6];
extern int n_WifiMac;

/*
 * WLAND_BSSCACHE_SUPPORT     : Cache bss list
 * WLAND_RSSIAVG_SUPPORT      : Average RSSI of BSS list
 * WLAND_RSSIOFFSET_SUPPORT   : RSSI offset
 */
//#define WLAND_BSSCACHE_SUPPORT
//#define WLAND_RSSIAVG_SUPPORT
//#define WLAND_RSSIOFFSET_SUPPORT

#ifdef WLAND_RSSIOFFSET_SUPPORT
#define WLAND_RSSI_MAXVAL_FOR_OFFSET	236
#define WLAND_RSSI_OFFSET	                12
#endif

/* define support cfg80211 or wext mode */
#define WLAND_CFG80211_SUPPORT

//#define WLAND_TBD_SUPPORT
/* define support wapi sec mode */
//#define WLAND_WAPI_SUPPORT

/*define for flow ctrl*/
#define WLAND_SDIO_FC_SUPPORT

/* define for chip patch */
//#define NORMAL_FIXED
#define WLAN_BIG_CURRENT_90E

/* define for support 5G rf,default 2.4G */
//#define WLAND_5GRF_SUPPORT

#define CARD_ENTER_SLEEP_TIMER                  (200)
#define FLOW_CTRL_INT_SLEEP_RETRY_COUNT_91      (25)
#define FLOW_CTRL_RXCMPL_RETRY_COUNT_91         (200)
#define FLOW_CTRL_RXCMPL_RETRY_COUNT_90         (2000)

#define DEFAULT_MAX_SCAN_AGE                    (15*HZ)

#ifdef WLAND_RX_8023_REORDER
#define WID_HEADER_LEN_RX                       (6)
#endif
#define WID_HEADER_LEN                          (2)
#ifdef WLAND_RX_SOFT_MAC
#define HOST_MSG_HEADER_LEN                     (4)
#endif

#ifdef WLAND_TXLEN_1536
#define WLAND_AGGR_TXPKT_LEN					(1536)
#endif
#ifdef WLAND_DMA_TX1536_BLOCKS
#define WLAND_AGGR_TXPKT_LEN					(1536*6)
#endif

/* Space for header read, limit for data packets */
#ifdef WLAND_SDIO_SUPPORT
#ifdef WLAND_DMA_RX1536_BLOCKS
#define WLAND_MAX_BUFSZ                         (1600*12)//192000	/* Maximum size of a sdio dma buffer */
#else
#define WLAND_MAX_BUFSZ                         2048	/* Maximum size of a sdio dma buffer */
#endif
#else /*WLAND_SDIO_SUPPORT */
#define WLAND_MAX_BUFSZ                         1660	/* Maximum size of a sdio dma buffer */
#endif /*WLAND_SDIO_SUPPORT */

/* Driver Features Config */
#define WLAND_SLEEP_ENABLE                      BIT0
#define WLAND_SLEEP_PREASSO                     BIT1

/* Mac Listen Interval */
#define WIFI_LISTEN_INTERVAL                    0x1

/* Link Loss Threshold */
#define WIFI_LINK_LOSS_THRESHOLD_90                0x20
#define WIFI_LINK_LOSS_THRESHOLD_91                0x40
#define WIFI_LINK_LOSS_THRESHOLD_91H                0x40

/* Link Sleep Threashold,old Value: 0x00A00080 */
#define WIFI_PREASSO_SLEEP                      0x000500FF

/* max sequential rxcntl timeouts to set HANG event */
#ifndef MAX_CNTL_TIMEOUT
#define MAX_CNTL_TIMEOUT                        2
#endif

/*BT WIFI CONEXIST*/
#define BT_COEXIST  SIOCDEVPRIVATE + 2
#define BT_STATE_SCO_ON  0x01
#define BT_STATE_SCO_OFF  0x02
#define BT_STATE_SCO_ONGOING 0x04
#define BT_STATE_A2DP_PLAYING  0x08
#define BT_STATE_A2DP_NO_PLAYING 0x10
#define BT_STATE_CONNECTION_ON 0x20
#define BT_STATE_CONNECTION_OFF 0x40

/*BT WIFI CONEXIST*/

/*get mac from rda nvram*/
struct wlan_mac_info {
	u16 activated;
	u8 mac_addr[ETH_ALEN];
};

#ifdef WLAND_FIBERHOME_SUPPORT
#define WLAND_SET_TID
#endif

#define WLAND_TID_NUM		4

/* Host AMSDU-TX support */
#ifndef WLAND_TX_SOFT_MAC
//#define WLAND_AMSDU_TX
#endif

/* Host DeAMSDU RX-reorder support */
#ifndef WLAND_RX_SOFT_MAC
//#define WLAND_DEAMSDU_RX
#endif

#endif /* _WLAND_DEFS_H_ */
