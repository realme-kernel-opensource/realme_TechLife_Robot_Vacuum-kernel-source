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
#ifndef _WLAND_RX_H_
#define _WLAND_RX_H_

struct wland_arphdr {
	__be16		ar_hrd;		/* format of hardware address	*/
	__be16		ar_pro;		/* format of protocol address	*/
	unsigned char	ar_hln;		/* length of hardware address	*/
	unsigned char	ar_pln;		/* length of protocol address	*/
	__be16		ar_op;		/* ARP opcode (command)		*/

	 /*
	  *	 Ethernet looks like this : This bit is variable sized however...
	  */
	unsigned char		ar_sha[ETH_ALEN];	/* sender hardware address	*/
	unsigned char		ar_sip[4];		/* sender IP address		*/
	unsigned char		ar_tha[ETH_ALEN];	/* target hardware address	*/
	unsigned char		ar_tip[4];		/* target IP address		*/

};

#define PRIOMASK	                    7
#define RXQLEN		                    200	/* bulk rx queue length */

struct dhcpMessage {
	u8 op;
	u8 htype;
	u8 hlen;
	u8 hops;
	u32 xid;
	u16 secs;
	u16 flags;
	u32 ciaddr;
	u32 yiaddr;
	u32 siaddr;
	u32 giaddr;
	u8 chaddr[16];
	u8 sname[64];
	u8 file[128];
	u32 cookie;
	u8 options[308]; /* 312 - cookie */
};
#define SERVER_PORT			67
#define CLIENT_PORT			68
#define DHCP_MAGIC			0x63825363
#define DHCP_ACK      5
#define DHCP_OPTION_MESSAGE_TYPE 53 /* RFC 2132 9.6, important for DHCP */
#define DHCP_OPTION_ROUTERS 3 /* RFC 2132 9.6, important for DHCP */
#define DHCP_OPTION_END 255

#if defined WLAND_RX_SOFT_MAC || defined WLAND_RX_8023_REORDER

#define NR_RECVFRAME	250
#define SN_LESS(a, b)	(((a-b)&0x800)!=0)
#define SN_EQUAL(a, b)	(a == b)

#define REORDER_WAIT_TIME	120 // (ms)
#define P80211_OUI_LEN 3

#ifdef WLAND_RX_SOFT_MAC
#define WLAND_REORDER_WINSIZE 64
#elif defined WLAND_RX_8023_REORDER
#define WLAND_REORDER_WINSIZE 32
#endif

struct ieee80211_snap_hdr {
        u8    dsap;   /* always 0xAA */
        u8    ssap;   /* always 0xAA */
        u8    ctrl;   /* always 0x03 */
        u8    oui[P80211_OUI_LEN];    /* organizational universal id */
} __attribute__ ((packed));

#define PROTOCOL_VERSION 0x00
#define SNAP_SIZE sizeof(struct ieee80211_snap_hdr)

/*
struct	stainfo_rxcache	{
	u16 	tid_rxseq[16];
};
*/

struct rx_pkt_attrib	{
	u16	pkt_len;
	u8	physt;
	u8	drvinfo_sz;
	u8	shift_sz;
	u8	hdrlen; //the WLAN Header Len
	u8 	to_fr_ds;
	u8 	amsdu;
	u8	qos;
	u8	priority;
	u8	pw_save;
	u8	mdata;
	u16	seq_num;
	u8	frag_num;
	u8	mfrag;
	u8	order;
	u8	privacy; //in frame_ctrl field
	u8	bdecrypted;
	u8	encrypt; //when 0 indicate no encrypt. when non-zero, indicate the encrypt algorith
	u8	iv_len;
	u8	icv_len;
	u8	crc_err;
	u8	icv_err;

	u16	eth_type;

	u8 	dst[ETH_ALEN];
	u8 	src[ETH_ALEN];
	u8 	ta[ETH_ALEN];
	u8 	ra[ETH_ALEN];
	u8 	bssid[ETH_ALEN];

	u8	ack_policy;

	u8	tcpchk_valid; // 0: invalid, 1: valid
	u8	ip_chkrpt; //0: incorrect, 1: correct
	u8	tcp_chkrpt; //0: incorrect, 1: correct

	u8 	key_index;

	u8	data_rate;
	u8	bw;
	u8	stbc;
	u8	ldpc;
	u8 	sgi;
	u8 	pkt_rpt_type;
	u32 tsfl;
	u32	MacIDValidEntry[2];	// 64 bits present 64 entry.
};

//for Rx reordering buffer control
struct recv_reorder_ctrl {
    struct wland_rx_info *rx_info;
	u8 enable;
	u16 indicate_seq;//=wstart_b, init_value=0xffff
	u16 wend_b;
	u8 wsize_b;
	u16 tid_rxseq;
	spinlock_t pending_recvframe_queue_lock;
	struct list_head pending_recvframe_queue;
	struct timer_list reordering_ctrl_timer;
	struct work_struct reordering_ctrl_timer_work;
#ifdef WLAND_DEAMSDU_RX
    u16 wait_deamsdu_seq;
    enum deamsdu_rx_state_e wait_deamsdu_state;
    void *curr_deamsdu;
#endif
};
struct rx_reorder_msg {
	u8 mac_addr[ETH_ALEN];
	struct recv_reorder_ctrl preorder_ctrl[16];
	struct list_head list;
};

struct recv_frame {
	struct list_head	list; //used for uc_sw_dec_pending_queue
	struct list_head	list2; //used for free_recv_queue

#ifdef WLAND_DEAMSDU_RX
	struct list_head deamsdu_list;
    u8 deamsdu_order;
    int deamsdu_cnt;       /* DEBUG */
#endif

	struct sk_buff	 *pkt;

	struct rx_pkt_attrib attrib;

	uint len;
	u8 *rx_head;
	u8 *rx_data;
	u8 *rx_tail;
	u8 *rx_end;

	struct recv_reorder_ctrl* preorder_ctrl;
};
#endif

struct wland_rx_info {

#ifdef WLAND_SDIO_SUPPORT
	struct wland_sdio *bus;
#endif
#ifdef WLAND_USB_SUPPORT
	struct wland_usbdev_info *devinfo;
#endif

	struct workqueue_struct *wland_rxwq;
	struct work_struct RxWork;
	atomic_t rx_dpc_tskcnt;
	spinlock_t rxqlock;

	u8 *rxbuf;		/* Buffer for receiving control packets */
	uint rxblen;	/* Allocated length of rxbuf */
	u8 *rxctl;		/* Aligned pointer into rxbuf */

	uint rxlen;		/* Length of valid data in buffer */
	spinlock_t rxctl_lock;

	struct pktq rxq;
	u8 flowcontrol;		/* per prio flow control bitmask */

#if defined WLAND_RX_SOFT_MAC || defined WLAND_RX_8023_REORDER
	spinlock_t free_recv_lock;
	struct list_head free_recv_queue;
	u8 free_recv_cnt;
	struct list_head rx_reorder_msg_list;
	spinlock_t rx_reorder_msg_lock;
	//u16	BA_starting_seqctrl[16];
	//struct stainfo_rxcache rxcache;
	u32 dbg_rx_ampdu_loss_count;
	struct recv_frame *recv_frames;
#endif
};

#if defined WLAND_RX_SOFT_MAC || defined WLAND_RX_8023_REORDER
extern struct rx_reorder_msg *wland_rx_reorder_msg_init(
		struct wland_rx_info* rx_info, const u8 *mac_addr);
extern void wland_rx_reorder_msg_deinit(struct wland_rx_info* rx_info,
	struct rx_reorder_msg *reorder_msg);
extern void wland_recvframe_enq(spinlock_t *lock,
	struct list_head *q, struct list_head *list, u8 *counter);
#endif

extern struct wland_rx_info* wland_rx_init(void *arg);
extern void wland_rx_uinit(struct wland_rx_info* rx_info);

#ifdef WLAND_WLAN0_NOSCAN_WHEN_P2P0_DATAINCOMING
#define RECV_TIME	200 //ms
#define RECV_CNT	20
struct pkt_recv_statistics {
	unsigned long time[RECV_CNT];
	u8 index;
};
extern struct pkt_recv_statistics prs;
extern int wland_p2p_pkt_recv_statistics(struct pkt_recv_statistics *p, int cnt, int ms);
#endif

#ifdef WLAND_USE_RXQ
extern void wland_dhd_os_sdlock_rxq(struct wland_rx_info *rx_info, unsigned long *flags);
extern void wland_dhd_os_sdunlock_rxq(struct wland_rx_info *rx_info, unsigned long *flags);
#else
extern int wland_process_rxframes(struct wland_rx_info *rx_info, struct sk_buff *pkt);
#endif
void wland_process_8023_pkt(struct wland_bus *bus_if, struct sk_buff *skb);
#endif
