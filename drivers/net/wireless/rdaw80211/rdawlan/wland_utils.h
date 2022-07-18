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

#ifndef	_WLAND_UTILS_H_
#define	_WLAND_UTILS_H_

#include <linux/skbuff.h>
#include <80211.h>

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0))
#define RANDOM32        prandom_u32
#else
#define RANDOM32        random32
#endif

#ifndef ABS
#define	ABS(a)			            (((a) < 0) ? -(a) : (a))
#endif /* ABS */

#ifndef MIN
#define	MIN(a, b)		            (((a) < (b)) ? (a) : (b))
#endif /* MIN */

#ifndef MAX
#define	MAX(a, b)		            (((a) > (b)) ? (a) : (b))
#endif /* MAX */

/*
 * Spin at most 'us' microseconds while 'exp' is true.
 * Caller should explicitly test 'exp' when this completes
 * and take appropriate error action if 'exp' is still true.
 */
#define SPINWAIT(exp, us) { \
	uint countdown = (us) + 9; \
	while ((exp) && (countdown >= 10)) {\
		udelay(10); \
		countdown -= 10; \
	} \
}

/* osl multi-precedence packet queue */
#define PKTQ_LEN_DEFAULT        128	/* Max 128 packets */
#define PKTQ_MAX_PREC           16	/* Maximum precedence levels */

/* the largest reasonable packet buffer driver uses for ethernet MTU in bytes */
#define	PKTBUFSZ	            2048

#ifndef setbit
#ifndef NBBY			        /* the BSD family defines NBBY */
#define	NBBY	8		        /* 8 bits per byte */
#endif				            /* #ifndef NBBY */
#define	setbit(a, i)	        (((u8 *)a)[(i)/NBBY] |= 1<<((i)%NBBY))
#define	clrbit(a, i)	        (((u8 *)a)[(i)/NBBY] &= ~(1<<((i)%NBBY)))
#define	isset(a, i)	            (((const u8 *)a)[(i)/NBBY] & (1<<((i)%NBBY)))
#define	isclr(a, i)	            ((((const u8 *)a)[(i)/NBBY] & (1<<((i)%NBBY))) == 0)
#endif				            /* setbit */

#define	NBITS(type)	            (sizeof(type) * 8)
#define NBITVAL(nbits)	        (1 << (nbits))
#define MAXBITVAL(nbits)	    ((1 << (nbits)) - 1)
#define	NBITMASK(nbits)	        MAXBITVAL(nbits)
#define MAXNBVAL(nbyte)	        MAXBITVAL((nbyte) * 8)

#ifdef WLAND_TX_SOFT_MAC
#define MAC_HEADER_OFFSET		(0)
#endif

#ifdef WLAND_RX_SOFT_MAC
enum WIFI_FRAME_TYPE {
	WIFI_MGT_TYPE  =	(0),
	WIFI_CTRL_TYPE =	(BIT2),
	WIFI_DATA_TYPE =	(BIT3),
	WIFI_QOS_DATA_TYPE	= (BIT7|BIT3),	//!< QoS Data
};

#define _TO_DS_		BIT8
#define _FROM_DS_	BIT9
#define _MORE_FRAG_	BIT10
#define _RETRY_		BIT11
#define _PWRMGT_	BIT12
#define _MORE_DATA_	BIT13
#define _PRIVACY_	BIT14
#define _ORDER_		BIT15

#define get_tofr_ds(pframe)	((GetToDs(pframe) << 1) | GetFrDs(pframe))
#define GetFragNum(pbuf)	(cpu_to_le16(*(unsigned short *)((size_t)(pbuf) + 22)) & 0x0f)
#define GetSequence(pbuf)	(cpu_to_le16(*(unsigned short *)((size_t)(pbuf) + 22)) >> 4)
#define GetPwrMgt(pbuf)		(((*(unsigned short *)(pbuf)) & le16_to_cpu(_PWRMGT_)) != 0)
#define GetMData(pbuf)		(((*(unsigned short *)(pbuf)) & le16_to_cpu(_MORE_DATA_)) != 0)
#define GetPrivacy(pbuf)	(((*(unsigned short *)(pbuf)) & le16_to_cpu(_PRIVACY_)) != 0)
#define GetOrder(pbuf)		(((*(unsigned short *)(pbuf)) & le16_to_cpu(_ORDER_)) != 0)

#define GetRetry(pbuf)		(((*(unsigned short *)(pbuf)) & le16_to_cpu(_RETRY_)) != 0)
#define GetToDs(pbuf)		(((*(unsigned short *)(pbuf)) & le16_to_cpu(_TO_DS_)) != 0)
#define GetFrDs(pbuf)		(((*(unsigned short *)(pbuf)) & le16_to_cpu(_FROM_DS_)) != 0)

#define GetAid(pbuf)		(cpu_to_le16(*(unsigned short *)((size_t)(pbuf) + 2)) & 0x3fff)
#define GetTid(pbuf)		(cpu_to_le16(*(unsigned short *)((size_t)(pbuf) + (((GetToDs(pbuf)<<1)|GetFrDs(pbuf))==3?30:24))) & 0x000f)
#define GetAddr1Ptr(pbuf)	((unsigned char *)((size_t)(pbuf) + 4))
#define GetAddr2Ptr(pbuf)	((unsigned char *)((size_t)(pbuf) + 10))
#define GetAddr3Ptr(pbuf)	((unsigned char *)((size_t)(pbuf) + 16))
#define GetAddr4Ptr(pbuf)	((unsigned char *)((size_t)(pbuf) + 24))
#define GetPriority(pbuf)	((le16_to_cpu(*(unsigned short *)(pbuf))) & 0xf)
#define GetAckpolicy(pbuf) 	(((le16_to_cpu(*(unsigned short *)pbuf)) >> 5) & 0x3)
#define GetAMsdu(pbuf)		(((le16_to_cpu(*(unsigned short *)pbuf)) >> 7) & 0x1)

#define SET_ICE_IV_LEN( iv_len, icv_len, encrypt)\
do{\
	switch(encrypt)\
	{\
		case WEP_40:\
		case WEP_104:\
			iv_len = 4;\
			icv_len = 4;\
			break;\
		case WPA2_TKIP:\
		case WPA_TKIP:\
			iv_len = 8;\
			icv_len = 4;\
			break;\
		case WPA2_AES:\
		case WPA_AES:\
			iv_len = 8;\
			icv_len = 8;\
			break;\
		default:\
			iv_len = 0;\
			icv_len = 0;\
			break;\
	}\
}while(0)

#endif

/* callback function, taking one arg */
typedef void (*timer_cb_fn_t)(void *);


struct pktq_prec {
	struct sk_buff_head skblist;
	u16                 max;		/* maximum number of queued packets */
};

/* multi-priority pkt queue */
struct pktq {
	u16              num_prec;	/* number of precedences in use */
	u16              hi_prec;	/* rapid dequeue hint (>= highest non-empty prec) */
	u16              max;	    /* total max packets */
	u16              len;	    /* total number of packets */
	/* q array must be last since # of elements can be either PKTQ_MAX_PREC or 1 */
	struct pktq_prec q[PKTQ_MAX_PREC];
};


/* operations on a specific precedence in packet queue */
static inline int pktq_plen(struct pktq *pq, int prec)
{
	return pq->q[prec].skblist.qlen;
}

static inline int pktq_pavail(struct pktq *pq, int prec)
{
	return pq->q[prec].max - pq->q[prec].skblist.qlen;
}

static inline bool pktq_pfull(struct pktq *pq, int prec)
{
	return pq->q[prec].skblist.qlen >= pq->q[prec].max;
}

static inline bool pktq_pempty(struct pktq *pq, int prec)
{
	return skb_queue_empty(&pq->q[prec].skblist);
}

static inline struct sk_buff *pktq_ppeek(struct pktq *pq, int prec)
{
	return skb_peek(&pq->q[prec].skblist);
}

static inline struct sk_buff *pktq_ppeek_tail(struct pktq *pq, int prec)
{
	return skb_peek_tail(&pq->q[prec].skblist);
}

static inline void wland_sched_timeout(u32 millisec)
{
	ulong timeout = 0, expires = 0;
	expires = jiffies + msecs_to_jiffies(millisec);
	timeout = millisec;

	while (timeout) {
		timeout = schedule_timeout(timeout);

		if (time_after(jiffies, expires))
			break;
	}
}

static inline int pktq_avail(struct pktq *pq)
{
	return (int)(pq->max - pq->len);
}

static inline bool pktq_full(struct pktq *pq)
{
	return pq->len >= pq->max;
}

static inline bool pktq_empty(struct pktq *pq)
{
	return pq->len == 0;
}

/*
 * bitfield macros using masking and shift
 *
 * remark: the mask parameter should be a shifted mask.
 */
static inline void brcmu_maskset32(u32 *var, u32 mask, u8 shift, u32 value)
{
	value = (value << shift) & mask;
	*var  = (*var & ~mask) | value;
}

static inline u32 brcmu_maskget32(u32 var, u32 mask, u8 shift)
{
	return (var & mask) >> shift;
}

static inline void brcmu_maskset16(u16 *var, u16 mask, u8 shift, u16 value)
{
	value = (value << shift) & mask;
	*var = (*var & ~mask) | value;
}

static inline u16 brcmu_maskget16(u16 var, u16 mask, u8 shift)
{
	return (var & mask) >> shift;
}

extern struct sk_buff *wland_pktq_penq(struct pktq *pq, int prec,struct sk_buff *p);
extern struct sk_buff *wland_pktq_penq_head(struct pktq *pq, int prec, struct sk_buff *p);
extern struct sk_buff *wland_pktq_pdeq(struct pktq *pq, int prec);
extern struct sk_buff *wland_pktq_pdeq_tail(struct pktq *pq, int prec);
extern struct sk_buff *wland_pktq_pdeq_match(struct pktq *pq, int prec, bool (*match_fn)(struct sk_buff *p, void *arg), void *arg);

/* packet primitives */
extern struct sk_buff *wland_pkt_buf_get_skb(uint len);
extern void wland_pkt_buf_free_skb(struct sk_buff *skb);

/* operations on a set of precedences in packet queue */
extern int  wland_pktq_mlen(struct pktq *pq, uint prec_bmp);
extern struct sk_buff *wland_pktq_mdeq(struct pktq *pq);

extern void wland_pktq_init(struct pktq *pq, int num_prec, int max_len);
/* prec_out may be NULL if caller is not interested in return value */
extern struct sk_buff *wland_pktq_peek_tail(struct pktq *pq, int *prec_out);
extern void wland_pktq_flush(struct pktq *pq, bool dir,	bool (*fn)(struct sk_buff *, void *), void *arg);
extern bool wland_prec_enq(struct device *dev, struct pktq *q,
	struct sk_buff *pkt, int prec);

extern u16  wland_get_cap_info(u8 *data);
extern void wland_get_ssid(u8 *data, u8 *ssid, u8 *p_ssid_len);
extern void wland_get_BSSID(u8 *data, u8 *bssid);
extern u8   wland_get_current_channel(u8 *data, u16 rx_len);
extern u8  *wland_get_data_rate(u8 *data, u16 rx_len, u8 type, u8 *rate_size);
extern u8  *wland_get_tim_elm(u8 *data, u16 rx_len, u16 tag_param_offset);
extern u16  wland_get_beacon_period(u8 *data);

#ifdef WLAND_RX_SOFT_MAC
extern u8 *wland_get_da(unsigned char *pframe);
extern u8 *wland_get_sa(unsigned char *pframe);
extern u8 *wland_get_hdr_bssid(unsigned char *pframe);
extern u16 wland_get_mac_hdr_len(u8 * msa);
extern void wland_set_host_eth_addr(u8 *data, u8 *da, u8 *sa);
extern u8 wland_get_sec_header_len(u8 ct);
extern u8 wland_get_sec_mic_icv_len(u8 ct);
extern u8 wland_get_wep(u8* header);
extern bool wland_is_snap_header_present(u8 *data);
extern u8 wland_get_type(u8 * header);
extern u8 wland_get_protocol_version(u8 * header);
#endif

#if defined WLAND_RX_SOFT_MAC || defined WLAND_RX_8023_REORDER
extern u8 wland_get_sub_type(u8 * header);
#endif

#ifdef WLAND_TX_SOFT_MAC
extern void wland_set_to_ds(u8* header, u8 to_ds);
extern void wland_set_address1(u8* pu8msa, u8* addr);
extern void wland_set_address2(u8 * pu8msa, u8 * addr);
extern void wland_set_address3(u8 * pu8msa, u8 * addr);
extern void wland_set_snap_header(u8 *frame);
#endif

#ifdef WLAND_DEAMSDU_RX
u8 wland_get_deamsdu_order(u8 *header);
#endif

#endif /* _WLAND_UTILS_H_ */

