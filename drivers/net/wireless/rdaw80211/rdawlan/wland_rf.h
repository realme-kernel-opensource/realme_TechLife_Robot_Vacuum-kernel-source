
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

#ifndef _WLAND_RF_H_
#define _WLAND_RF_H_

#include "wland_defs.h"
#include "wland_android.h"
#include "wland_dev.h"

#define WLAND_OLD_EFUSE_COMPATIBLE

/* start tx test
 * TX_TEST channel format bw op_band rate length
 * channel 1-14
 * format: 0:b/g mode; 1:11n green field mode; 2:11n mixed mode
 * bw: 0:20MHz; 1:40MHz;
 * op_band: 0:40M; 1:CH_OFF_20U(bw=1); 2:CH_OFF_NONE(bw=0); 3:CH_OFF_20L(bw=1)
 * rate: rate support by format(11b/g), or mcs value(11n)
 * length: tx length (1-1536)
 * rda_tools success log: printf("Done\n");
 */
#define CMD_TX_TEST		        "TX_TEST"

/* start rx test
 * TX_TEST channel format bw op_band
 * channel 1-14
 * format: 0:b/g mode; 1:11n mode;
 * bw: 0:20MHz; 1:40MHz;
 * op_band: 0:40M or duplicate(bw=1); 1:CH_OFF_20U(bw=1); 2:CH_OFF_NONE(bw=0); 3:CH_OFF_20L(bw=1)
 * rda_tools success log: printf("Done\n");
 */
#define CMD_RX_TEST		        "RX_TEST" //start rx test

/* get rx result
 * return rx complete number and rx fcs correct nubmer
 * rda_tools success log: printf("recv:%d, fcs_passed:%d\n", rx, rx_succ);
 */
#define CMD_RX_RESULT		    "RX_RESULT"


/* stop rx test
 * RX_STOP
 */
#define CMD_RX_STOP				"RX_STOP"


/* set mac addr
 * SET_MACADDR 00:50:c2:5e:10:83
 * rda_tools success log: printf("Done\n");
 */
#define CMD_SET_MACADDR		    "SET_MACADDR"

/* get mac addr
 * rda_tools success log: printf("mac addr:%02x:%02x:%02x:%02x:%02x:%02x\n", ***);
 */
#define CMD_GET_MACADDR		    "GET_MACADDR"

/* set vendor id
 * SET_VENID xxxx
 * vendor id is hexadecimal
 * rda_tools success log: printf("Done\n");
 */
#define CMD_SET_VENDOR_ID		    "SET_VENID"

/* get vendor id
 * GET_VENID
 * rda_tools success log: printf("vendor id:%02x%02x\n", ***);
 */
#define CMD_GET_VENDOR_ID		    "GET_VENID"

/* set hardware parameters
 * SET_PARAM function value
 * function: 0: set crystal frequency offset; 1:set 11g/n mode tx_power for current channel;
 2:set 11b mode tx_power for current channel;
 * rda_tools success log: printf("Done\n");
 */
#define CMD_SET_PARAM					"SET_PARAM"

/* write_f_cal_val
 * write frequency offset calibration value to effuse.
* limit: the lenth of value is 2 bytes and bit[8:0] must be 0x0CF, it can just be used in test mode.
 * rda_tools success log: printf("Done\n");
 */
#define CMD_WRITE_F_CAL_VAL		    "WRITE_F_CAL_VAL"

/* read_f_cal_val
* read frequency offset calibration value from effuse.
* limit: it can just be used in test mode.
* rda_tools success log: printf("frequency offset calibration value:%04x\n", *);
 */
#define CMD_READ_F_CAL_VAL		    "READ_F_CAL_VAL"

/* write_txp
 * write tx_power to effuse.
* limit: the lenth of value is 6 bytes, it can just be used in test mode.
 * rda_tools success log: printf("Done\n");
 */
#define CMD_WRITE_TXPOWER		    "WRITE_TXP"

/* read_txp
* read tx_power from effuse, when get the result, we can calculate with the value from configure file.
* limit: the lenth of results is 6 bytes, it can just be used in test mode.
* rda_tools success log: printf("tx power value: %02x,%02x,%02x,%02x,%02x,%02x \n", ******);
 */
#define CMD_READ_TXPOWER		    "READ_TXP"

/* get_efuse
 * get efuse all data from page 2 to page 15.
*/

#define CMD_GET_EFUSE				"GET_EFUSE"
/*
*get hardware parameters
*/
#define CMD_GET_PARAM				"GET_PARAM"

/*get reg values for all channel*/
#define CMD_GET_REG_CHAN			"GET_REG_CHAN"

/*set reg values for one channel*/
#define CMD_SET_REG_CHAN			"SET_REG_CHAN"

#define CMD_SET_SDIO_PIN			"SET_SDIO_PIN"

/*rssi_snr*/
#define CMD_SET_RSSI_SNR			"SET_RSSI_SNR"
#define CMD_GET_RSSI_SNR			"GET_RSSI_SNR"
#define CMD_MD						"MD"

#define CMD_MW						"MW"

#define CMD_RF_REGR					"RFREGR"

#define CMD_RF_REGW					"RFREGW"

#define CMD_PHY_REGR				"PHYREGR"

#define CMD_PHY_REGW				"PHYREGW"

#define CMD_GET_TX_STATUS			"TX_STATUS"

#define CMD_SET_RATE				"SET_RATE"

#define CMD_SET_TBTT_CNT			"TBTT_CNT"


#ifdef WLAND_SMART_CONFIG_SUPPORT
#define CMD_SET_CHANNEL			"SET_CHANNEL"

#define CMD_SNIFFER_ENABLE			"SNIFFER_ENABLE"
#endif
//#define WLAND_TXP_NUM			4
#define WLAND_TXP_NUM				2

#define WLAND_TXP_11F_BASE	0x25	//n_mode
#define WLAND_TXP_11F_END	0x64	//n_mode
#define WLAND_TXP_120_BASE	0x15
#define WLAND_TXP_120_END	0x54
#define WLAND_G_N_MAX_OFFSET 0x18
#ifdef WLAND_SET_POWER_BY_RATE
#define WLAND_BGN_MAX_POWER_GAIN 0x30
#define WLAND_MAX_POWER_REG_VAL	0x7f
#endif

int wland_rf_phy_reg_write(struct net_device *net,
	char *data, int len, u8 rf_or_phy, u16 addr_p, u32 value_p);
int wland_mw(struct net_device *net, char *data,
	int len, u32 addr_p, u32 value_p);

int wland_rf_test_cmd(struct net_device *net, struct ifreq *ifr, int cmd);
int wland_update_rf_rxtest_result(struct wland_private *drvr, u8* buffer);
int wland_read_txpower_from_efuse(struct net_device *net,
	 char *data, int len, u8 *tx_power);
int wland_read_efuse_xtal_cal_val(struct net_device *net,
	 char *data, int len, u8 *cal_val);
int wland_set_hardware_param(struct net_device *net,
	char *data, int len, int func_num, u16 value_set);
int wland_efuse_get_mac_addr(struct net_device *net,
	char *data, int len, u8* mac_from_efuse);
int wland_get_efuse_data(struct net_device *net, char *data, int len);
int wland_get_hardware_param(struct net_device *net, char *data,
	int len, int func, u16 *value);
int wland_get_reg_for_all_channels(struct net_device *net, char *data, int len);
#endif /* _WLAND_RF_H_ */
