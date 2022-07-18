
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
#include <linux/if_arp.h>
#include <linux/netdevice.h>
#include <linux/module.h>
#include <linux/etherdevice.h>
#include <linux/wireless.h>
#include <linux/ieee80211.h>
#include <linux/debugfs.h>
#include <net/cfg80211.h>

#include "wland_defs.h"
#include "wland_fweh.h"
#include "wland_dev.h"
#include "wland_bus.h"
#include "wland_dbg.h"
#include "wland_utils.h"

struct sk_buff *wland_pkt_buf_get_skb(uint len)
{
	struct sk_buff *skb;

	skb = __dev_alloc_skb(len, GFP_KERNEL);
	if (skb) {
		skb_put(skb, len);
		skb->priority = 0;
		memset(skb->data, 0, len);
	}
	return skb;
}


/* Free the driver packet. Free the tag if present */
void wland_pkt_buf_free_skb(struct sk_buff *skb)
{
	struct sk_buff *nskb;

	WARN_ON(skb == NULL);

	if (!skb)
		return;
	//WARN_ON(skb->next);
	dev_kfree_skb_any(skb);
	return ;
	while (skb) {
		nskb = skb->next;
		skb->next = NULL;
		dev_kfree_skb_any(skb);
		skb = nskb;
	}
}


/*
 * osl multiple-precedence packet queue
 * hi_prec is always >= the number of the highest non-empty precedence
 */
struct sk_buff *wland_pktq_penq(struct pktq *pq, int prec, struct sk_buff *p)
{
	struct sk_buff_head *q;

	if (pktq_full(pq) || pktq_pfull(pq, prec))
		return NULL;

	q = &pq->q[prec].skblist;
	__skb_queue_tail(q, p);
	pq->len++;

	if (pq->hi_prec < prec)
		pq->hi_prec = (u8) prec;

	return p;
}

struct sk_buff *wland_pktq_pdeq(struct pktq *pq, int prec)
{
	struct sk_buff_head *q = &pq->q[prec].skblist;
	struct sk_buff *p = skb_dequeue(q);

	if (p == NULL)
		return NULL;

	pq->len--;
	return p;
}


/*
 * precedence based dequeue with match function. Passing a NULL pointer
 * for the match function parameter is considered to be a wildcard so
 * any packet on the queue is returned. In that case it is no different
 * from wland_pktq_pdeq() above.
 */
struct sk_buff *wland_pktq_pdeq_match(struct pktq *pq, int prec,
	bool(*match_fn) (struct sk_buff * skb, void *arg), void *arg)
{
	struct sk_buff_head *q = &pq->q[prec].skblist;
	struct sk_buff *p, *next;

	skb_queue_walk_safe(q, p, next) {
		if (match_fn == NULL || match_fn(p, arg)) {
			skb_unlink(p, q);
			pq->len--;
			return p;
		}
	}
	return NULL;
}


struct sk_buff *wland_pktq_pdeq_tail(struct pktq *pq, int prec)
{
	struct sk_buff_head *q = &pq->q[prec].skblist;
	struct sk_buff *p = skb_dequeue_tail(q);

	if (p == NULL)
		return NULL;

	pq->len--;
	return p;
}

/* Empty the queue at particular precedence level */
/* callback function fn(pkt, arg) returns true if pkt belongs to if */

static void wland_pktq_pflush(struct pktq *pq, int prec, bool dir,
	bool(*fn) (struct sk_buff *, void *), void *arg)
{
	struct sk_buff_head *q;
	struct sk_buff *p, *next;

	q = &pq->q[prec].skblist;

	skb_queue_walk_safe(q, p, next) {
		if (fn == NULL || (*fn) (p, arg)) {
			skb_unlink(p, q);
			wland_pkt_buf_free_skb(p);
			pq->len--;
		}
	}
}

void wland_pktq_flush(struct pktq *pq, bool dir, bool(*fn) (struct sk_buff *,
		void *), void *arg)
{
	int prec;

	for (prec = 0; prec < pq->num_prec; prec++)
		wland_pktq_pflush(pq, prec, dir, fn, arg);
}


void wland_pktq_init(struct pktq *pq, int num_prec, int max_len)
{
	int prec;

	/*
	 * pq is variable size; only zero out what's requested
	 */
	memset(pq, 0, offsetof(struct pktq,
			q) + (sizeof(struct pktq_prec) * num_prec));

	pq->num_prec = (u16) num_prec;
	pq->max = (u16) max_len;

	for (prec = 0; prec < num_prec; prec++) {
		pq->q[prec].max = pq->max;
		skb_queue_head_init(&pq->q[prec].skblist);
	}
}


struct sk_buff *wland_pktq_peek_tail(struct pktq *pq, int *prec_out)
{
	int prec;

	if (pq->len == 0)
		return NULL;

	for (prec = 0; prec < pq->hi_prec; prec++)
		if (!skb_queue_empty(&pq->q[prec].skblist))
			break;

	if (prec_out)
		*prec_out = prec;

	return skb_peek_tail(&pq->q[prec].skblist);
}


/* Return sum of lengths of a specific set of precedences */
int wland_pktq_mlen(struct pktq *pq, uint prec_bmp)
{
	int prec, len = 0;

	for (prec = 0; prec <= pq->hi_prec; prec++)
		if (prec_bmp & (1 << prec))
			len += pq->q[prec].skblist.qlen;

	return len;
}


/* Priority dequeue from a specific set of precedences */
struct sk_buff *wland_pktq_mdeq(struct pktq *pq)
{
	struct sk_buff_head *q;
	struct sk_buff *p;
	int prec;

	if (pq->len == 0)
		return NULL;

	while ((prec = pq->hi_prec) > 0 &&
		skb_queue_empty(&pq->q[prec].skblist))
		pq->hi_prec--;

	q = &pq->q[prec].skblist;
	p = __skb_dequeue(q);
	if (p == NULL)
		return NULL;

	pq->len--;

	return p;
}

bool wland_prec_enq(struct device * dev, struct pktq * q, struct sk_buff * pkt,
	int prec)
{
	struct sk_buff *p;
	int eprec = -1;		/* precedence to evict from */
	bool discard_oldest = false;

	//WLAND_DUMP(DCMD, pkt->data, pkt->len, "TxData,prec:%d,TxDatalen:%Zu\n", prec, pkt->len);
	//prec = 0;
	/*
	 * Fast case, precedence queue is not full and we are also not exceeding total queue length
	 */
	if (!pktq_pfull(q, prec) && !pktq_full(q)) {
		wland_pktq_penq(q, prec, pkt);
		return true;
	}
	WLAND_ERR("PKT queue is over flow!\n");

	/*
	 * Determine precedence from which to evict packet, if any
	 */
	if (pktq_pfull(q, prec)) {
		eprec = prec;
	} else if (pktq_full(q)) {
		p = wland_pktq_peek_tail(q, &eprec);
		if (eprec > prec)
			return false;
	}

	/*
	 * Evict if needed
	 */
	if (eprec >= 0) {
		/*
		 * refuse newer (incoming) packet
		 */
		if (eprec == prec && !discard_oldest)
			return false;

		/*
		 * Evict packet according to discard policy
		 */
		p = discard_oldest ? wland_pktq_pdeq(q,
			eprec) : wland_pktq_pdeq_tail(q, eprec);

		if (p == NULL)
			WLAND_ERR("failed, oldest %d\n", discard_oldest);

		wland_pkt_buf_free_skb(p);
	}

	p = wland_pktq_penq(q, prec, pkt);
	if (p == NULL)
		WLAND_ERR("failed\n");

	WLAND_DBG(DCMD, TRACE, "Done\n");

	return p != NULL;
}

/* This function extracts the beacon period field from the beacon or probe   */
/* response frame.                                                           */
u16 wland_get_beacon_period(u8 *data)
{
	u16 bcn_per = 0;

	bcn_per = data[0];
	bcn_per |= (data[1] << 8);

	return bcn_per;
}

/* This function extracts the 'frame type' bits from the MAC header of the   */

/* input frame.                                                              */

/* Returns the value in the LSB of the returned value.                       */
u8 wland_get_type(u8 * header)
{
	return ((u8) (header[0] & 0x0C));
}


/* This function extracts the 'frame type and sub type' bits from the MAC    */
/* header of the input frame.                                                */
/* Returns the value in the LSB of the returned value.                       */
u8 wland_get_sub_type(u8 *header)
{
	return ((u8) (header[0] & 0xFC));
}


/* This function extracts the 'to ds' bit from the MAC header of the input   */
/* frame.                                                                    */
/* Returns the value in the LSB of the returned value.                       */
static u8 wland_get_to_ds(u8 *header)
{
	return (header[1] & 0x01);
}


/* This function extracts the 'from ds' bit from the MAC header of the input */
/* frame.                                                                    */
/* Returns the value in the LSB of the returned value.                       */
static u8 wland_get_from_ds(u8 *header)
{
	return ((header[1] & 0x02) >> 1);
}


/* This function extracts the MAC Address in 'address1' field of the MAC     */
/* header and updates the MAC Address in the allocated 'addr' variable.      */
static void wland_get_address1(u8 *data, u8 *addr)
{
	memcpy(addr, data + 4, 6);
}


/* This function extracts the MAC Address in 'address2' field of the MAC     */
/* header and updates the MAC Address in the allocated 'addr' variable.      */
static void wland_get_address2(u8 *data, u8 *addr)
{
	memcpy(addr, data + 10, 6);
}

/* This function extracts the MAC Address in 'address3' field of the MAC     */
/* header and updates the MAC Address in the allocated 'addr' variable.      */
static void wland_get_address3(u8 *data, u8 *addr)
{
	memcpy(addr, data + 16, 6);
}


/* This function extracts the BSSID from the incoming WLAN packet based on   */
/* the 'from ds' bit, and updates the MAC Address in the allocated 'addr'    */
/* variable.                                                                 */
void wland_get_BSSID(u8 *data, u8 *bssid)
{
	if (wland_get_from_ds(data) == 1)
		wland_get_address2(data, bssid);
	else if (wland_get_to_ds(data) == 1)
		wland_get_address1(data, bssid);
	else
		wland_get_address3(data, bssid);
}


/* This function extracts the SSID from a beacon/probe response frame        */
void wland_get_ssid(u8 *data, u8 *ssid, u8 *p_ssid_len)
{
	u8 len = 0;
	u8 i = 0;
	u8 j = 0;

	len = data[MAC_HDR_LEN + TIME_STAMP_LEN + BEACON_INTERVAL_LEN +
		CAP_INFO_LEN + 1];
	j = MAC_HDR_LEN + TIME_STAMP_LEN + BEACON_INTERVAL_LEN + CAP_INFO_LEN +
		2;

	/*
	 * If the SSID length field is set wrongly to a value greater than the
	 * allowed maximum SSID length limit, reset the length to 0
	 */
	if (len >= MAX_SSID_LEN)
		len = 0;

	for (i = 0; i < len; i++, j++)
		ssid[i] = data[j];

	ssid[len] = '\0';

	*p_ssid_len = len;
}


/* This function extracts the capability info field from the beacon or probe */
/* response frame.                                                           */
u16 wland_get_cap_info(u8 *data)
{
	u16 cap_info = 0;
	u16 index = MAC_HDR_LEN;
	u8 st = BEACON;

	st = wland_get_sub_type(data);

	/*
	 * Location of the Capability field is different for Beacon and
	 * Association frames.
	 */
	if ((st == BEACON) || (st == PROBE_RSP))
		index += TIME_STAMP_LEN + BEACON_INTERVAL_LEN;

	cap_info = data[index];
	cap_info |= (data[index + 1] << 8);

	return cap_info;
}

/* This function judge whether the 802.11n mode support from the beacon or probe
 * response frame.
 */
u16 wland_get_n_cap_info(u8 * data, u16 len)
{
	u16 ht_cap_info = 0, l = 0;
	u16 index = MAC_HDR_LEN;
	u8 st = BEACON;
	u8 *p;
	st = wland_get_sub_type(data);

	if ((st == BEACON) || (st == PROBE_RSP)) {
		index += TIME_STAMP_LEN + BEACON_INTERVAL_LEN + CAP_INFO_LEN;
		len -= MAC_HDR_LEN + TIME_STAMP_LEN + BEACON_INTERVAL_LEN + CAP_INFO_LEN;
	}

	p = data+index;
	l = len;
	/* Go through the IEs and find WLAN_EID_HT_CAPABILITY. */
	while (p && l >= 2) {
		len = p[1] + 2;
		if (len > l) {
			//printk(KERN_INFO "Truncated IE in assoc_info\n\r");
			break;
		}
		if (p[0] == WLAN_EID_HT_CAPABILITY ){
			//printk(KERN_INFO "find WLAN_EID_HT_CAPABILITY!!\n\r");
			ht_cap_info = 1;
			break;
		}
		l -= len;
		p += len;
	}

	return ht_cap_info;
}

/* This function extracts the capability info field from the Association */

/* response frame.                                                           		 */
u16 wland_get_assoc_resp_cap_info(u8 * data)
{
	u16 cap_info = 0;

	cap_info = data[0];
	cap_info |= (data[1] << 8);

	return cap_info;
}



/* This funcion extracts the association status code from the incoming       */

/* association response frame and returns association status code            */
u16 wland_get_asoc_status(u8 * data)
{
	u16 asoc_status = 0;

	asoc_status = data[3];
	asoc_status = (asoc_status << 8) | data[2];

	return asoc_status;
}



/* This function extracts association ID from the incoming association       */

/* response frame							                                     */
u16 wland_get_asoc_id(u8 * data)
{
	u16 asoc_id = 0;

	asoc_id = data[4];
	asoc_id |= (data[5] << 8);

	return asoc_id;
}

u8 *wland_get_tim_elm(u8 *data, u16 rx_len, u16 tag_param_offset)
{
	u16 index = tag_param_offset;

	/************************************************************************
	 * Beacon Frame - Frame Body
	 * ---------------------------------------------------------------------
	 * |Timestamp |BeaconInt |CapInfo |SSID |SupRates |DSParSet |TIM elm   |
	 * ---------------------------------------------------------------------
	 * |8         |2         |2       |2-34 |3-10     |3        |4-256     |
	 * ---------------------------------------------------------------------
	 *************************************************************************/

	/*
	 * Search for the TIM Element Field and return if the element is found
	 */
	while (index < (rx_len - FCS_LEN)) {
		if (data[index] == ITIM) {
			return (&data[index]);
		} else {
			index += (IE_HDR_LEN + data[index + 1]);
		}
	}

	return NULL;
}


u8 wland_get_current_channel(u8 *data, u16 rx_len)
{
	u16 index =
		MAC_HDR_LEN + TIME_STAMP_LEN + BEACON_INTERVAL_LEN +
		CAP_INFO_LEN;

	while (index < (rx_len - FCS_LEN)) {
		if (data[index] == IDSPARMS)
			return (data[index + 2]);
		else
			/*
			 * Increment index by length information and header
			 */
			index += data[index + 1] + IE_HDR_LEN;
	}

	/*
	 * Return current channel information from the MIB, if beacon/probe
	 * response frame does not contain the DS parameter set IE
	 */
	return 0;		/* no MIB here */
}


u8 *wland_get_data_rate(u8 *data, u16 rx_len, u8 type, u8 *rate_size)
{
	u16 index =
		MAC_HDR_LEN + TIME_STAMP_LEN + BEACON_INTERVAL_LEN +
		CAP_INFO_LEN;

	while (index < (rx_len - FCS_LEN)) {
		if (data[index] == type) {
			if (rate_size)
				*rate_size = data[index + 1];
			return (&data[index + 2]);
		} else {
			/*
			 * Increment index by length information and header
			 */
			index += data[index + 1] + IE_HDR_LEN;
		}
	}

	/*
	 * Return current channel information from the MIB, if beacon/probe
	 * response frame does not contain the DS parameter set IE
	 */
	return NULL; /* no MIB here */
}
#if defined WLAND_RX_SOFT_MAC || defined WLAND_TX_SOFT_MAC
u8 g_snap_header[SNAP_HDR_ID_LEN] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00};
#endif
#ifdef WLAND_RX_SOFT_MAC
u8 *wland_get_da(unsigned char *pframe)
{
	unsigned char 	*da;
	unsigned int	to_fr_ds	= (GetToDs(pframe) << 1) | GetFrDs(pframe);

	switch (to_fr_ds) {
		case 0x00:	// ToDs=0, FromDs=0
			da = GetAddr1Ptr(pframe);
			break;
		case 0x01:	// ToDs=0, FromDs=1
			da = GetAddr1Ptr(pframe);
			break;
		case 0x02:	// ToDs=1, FromDs=0
			da = GetAddr3Ptr(pframe);
			break;
		default:	// ToDs=1, FromDs=1
			da = GetAddr3Ptr(pframe);
			break;
	}

	return da;
}

u8 *wland_get_sa(unsigned char *pframe)
{
	unsigned char 	*sa;
	unsigned int	to_fr_ds	= (GetToDs(pframe) << 1) | GetFrDs(pframe);

	switch (to_fr_ds) {
		case 0x00:	// ToDs=0, FromDs=0
			sa = GetAddr2Ptr(pframe);
			break;
		case 0x01:	// ToDs=0, FromDs=1
			sa = GetAddr3Ptr(pframe);
			break;
		case 0x02:	// ToDs=1, FromDs=0
			sa = GetAddr2Ptr(pframe);
			break;
		default:	// ToDs=1, FromDs=1
			sa = GetAddr4Ptr(pframe);
			break;
	}

	return sa;
}

u8 *wland_get_hdr_bssid(unsigned char *pframe)
{
	unsigned char 	*sa = NULL;
	unsigned int	to_fr_ds	= (GetToDs(pframe) << 1) | GetFrDs(pframe);

	switch (to_fr_ds) {
		case 0x00:	// ToDs=0, FromDs=0
			sa = GetAddr3Ptr(pframe);
			break;
		case 0x01:	// ToDs=0, FromDs=1
			sa = GetAddr2Ptr(pframe);
			break;
		case 0x02:	// ToDs=1, FromDs=0
			sa = GetAddr1Ptr(pframe);
			break;
		case 0x03:	// ToDs=1, FromDs=1
			sa = GetAddr1Ptr(pframe);
			break;
	}

	return sa;
}

u8 wland_get_protocol_version(u8 * header)
{
	return ((u8) (header[0] & 0x03));
}
/* This function checks if QoS bit is set in the given QoS frame */
bool wland_is_qos_bit_set(u8* msa)
{
	return ((msa[0] & BIT7) && (msa[0] & BIT3))? true:false;
}
u8 wland_get_order_bit(u8 *header)
{
	return ((header[1] & 0x80) >> 7);

}
/* This function check whether the MAC header contains HT control field */
bool wland_is_ht_frame(u8 *header)
{
	if((true == wland_is_qos_bit_set(header)) && (1 == wland_get_order_bit(header)))
		return true;

	return false;
}
u16 wland_get_mac_hdr_len(u8 * msa)
{
	u8 mac_hdr_len = MAC_HDR_LEN;

	/* The MAC Header len is 26 only when in QOD Data frames */
	if((wland_is_qos_bit_set(msa) == true) && (wland_get_type(msa) == DATA_BASICTYPE))
		mac_hdr_len += QOS_CTRL_HDR_LEN;

	if(true == wland_is_ht_frame(msa))
	mac_hdr_len += HT_CTRL_HDR_LEN;

	if(mac_hdr_len&3)
		mac_hdr_len +=2;

	return mac_hdr_len;
}

/* This function returns the length of the security header for each cipher   */
/* type.                                                                     */
u8 wland_get_sec_header_len(u8 ct)
{
	switch(ct) {

	case WEP_40:
	case WEP_104:
		return DOT11_IV_LEN;

	case WPA2_AES:
	case WPA_AES:
		return DOT11_IV_AES_CCM_LEN;

	case WPA2_TKIP:
	case WPA_TKIP:
		return DOT11_IV_TKIP_LEN;

	default:
		return 0;
	}
}

u8 wland_get_wep(u8* header)
{
	return ((header[1] & 0x40) >> 6);
}


u8 wland_get_sec_mic_icv_len(u8 ct)
{
	switch(ct) {

	case WEP_40:
	case WEP_104:
		return DOT11_ICV_LEN;

	case WPA2_AES:
	case WPA_AES:
		return AES_MIC_SIZE;

	case WPA2_TKIP:
	case WPA_TKIP:
		return TKIP_MIC_SIZE + DOT11_ICV_LEN;

	default:
		return 0;
}

}

/* This function extracts the updates the SA, DA & BSSID address pointers to */
/* addr1, addr2 & addr3 fields in the WLAN RX structure.                     */
void wland_set_host_eth_addr(u8 *data, u8 *da, u8 *sa)
{
	u8 frm_ds = wland_get_from_ds(data);
	u8 to_ds  = wland_get_to_ds(data);

	if((to_ds == 0) && (frm_ds == 0)) {
		wland_get_address2(data, sa);
		wland_get_address1(data, da);

	} else if((to_ds == 0) && (frm_ds == 1)) {
		wland_get_address3(data, sa);
		wland_get_address1(data, da);

	} else if((to_ds == 1) && (frm_ds == 0)) {
		wland_get_address2(data, sa);
		wland_get_address3(data, da);

	}
}

/* This function checks whether SNAP header is present in the frame */
bool wland_is_snap_header_present(u8 *data)
{
	if(memcmp(data, g_snap_header, SNAP_HDR_ID_LEN) != 0)
		return false;

	return true;
}

#endif

#ifdef WLAND_TX_SOFT_MAC
void wland_set_to_ds(u8* header, u8 to_ds)
{
	header[1] &= 0xFE;
	header[1] |= to_ds;
}
void wland_set_address1(u8* pu8msa, u8* addr)
{
	memcpy(pu8msa + 4, addr, 6);
}
void wland_set_address2(u8 * pu8msa, u8 * addr)
{
	memcpy(pu8msa + 10, addr, 6);
}
void wland_set_address3(u8 * pu8msa, u8 * addr)
{
	memcpy(pu8msa + 16, addr, 6);
}
void wland_set_snap_header(u8 *frame)
{
	memcpy(frame, g_snap_header, SNAP_HDR_ID_LEN) ;
}
#endif

#ifdef WLAND_DEAMSDU_RX
u8 wland_get_deamsdu_order(u8 *header)
{
	return ((u8) (header[0] & 0x03));
}
#endif