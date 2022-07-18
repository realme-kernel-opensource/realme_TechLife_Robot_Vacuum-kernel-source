
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
#include <linux_osl.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/if_arp.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/wireless.h>
#include <linux/ieee80211.h>
#include <linux/debugfs.h>
#include <net/cfg80211.h>
#include <net/rtnetlink.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_arp.h>
#include <linux/ppp_defs.h>

#include "ethernet.h"
#include "wland_defs.h"
#include "wland_utils.h"
#include "wland_fweh.h"
#include "wland_dev.h"
#include "wland_dbg.h"
#include "wland_wid.h"
#include "wland_bus.h"
#include "wland_sdmmc.h"
#include "wland_p2p.h"
#include "wland_amsdu.h"
#include "wland_cfg80211.h"
#include "wland_android.h"
#include "wland_rf.h"
#include "wland_rx.h"

#define MAX_WAIT_FOR_8021X_TX		        50	/* msecs */

char *wland_ifname(struct wland_private *drvr, int ifidx)
{
	if (ifidx < 0 || ifidx >= WLAND_MAX_IFS) {
		WLAND_ERR("ifidx %d out of range\n", ifidx);
		return "<if_bad>";
	}

	if (drvr->iflist[ifidx] == NULL) {
		WLAND_ERR("null i/f %d\n", ifidx);
		return "<if_null>";
	}

	return ((drvr->iflist[ifidx]->ndev) ?
		drvr->iflist[ifidx]->ndev->name : "<if_none>");
}

struct net_device *wland_dhd_idx2net(void *pub, s32 ifidx)
{
	struct wland_private *priv = (struct wland_private *) pub;

	if (!pub || ifidx < 0 || ifidx >= WLAND_MAX_IFS)
		return NULL;

	if (priv && priv->iflist[ifidx])
		return priv->iflist[ifidx]->ndev;

	return NULL;
}

s32 wland_dhd_net2idx(struct wland_private *driv, struct net_device *net)
{
	int i = 0;

	ASSERT(driv);

	while (i < WLAND_MAX_IFS) {
		if (driv->iflist[i] && (driv->iflist[i]->ndev == net))
			return i;
		i++;
	}

	return ALL_INTERFACES;
}

static void _wland_set_multicast_list(struct work_struct *work)
{
	struct wland_if *ifp =
		container_of(work, struct wland_if, multicast_work);
	struct net_device *ndev = ifp->ndev;

	struct netdev_hw_addr *ha;
	u32 cmd_value, cnt, buflen;
	__le32 cnt_le;
	char *buf, *bufp;
	s32 err;

	/*
	 * Determine initial value of allmulti flag
	 */
	cmd_value = (ndev->flags & IFF_ALLMULTI) ? true : false;

	/*
	 * Send down the multicast list first.
	 */
	netif_addr_lock_bh(ndev);
	cnt = netdev_mc_count(ndev);
	netif_addr_unlock_bh(ndev);

	buflen = sizeof(cnt) + (cnt * ETH_ALEN);
	buf = kmalloc(buflen, GFP_ATOMIC);

	WLAND_DBG(DEFAULT, TRACE, "Enter(idx:%d,cmd_value:%d,cnt:%d)\n",
		ifp->bssidx, cmd_value, cnt);

	if (!buf)
		return;

	bufp = buf;
	cnt_le = cpu_to_le32(cnt);
	memcpy(bufp, &cnt_le, sizeof(cnt_le));
	bufp += sizeof(cnt_le);

	netif_addr_lock_bh(ndev);
	netdev_for_each_mc_addr(ha, ndev) {
		if (!cnt)
			break;
		memcpy(bufp, ha->addr, ETH_ALEN);
		bufp += ETH_ALEN;
		cnt--;
	}

	netif_addr_unlock_bh(ndev);

	err = wland_fil_iovar_data_set(ifp, "mcast_list", buf, buflen);
	if (err < 0) {
		WLAND_ERR("Setting mcast_list failed, %d\n", err);
		cmd_value = cnt ? true : cmd_value;
	}

	kfree(buf);

	/*
	 * Now send the allmulti setting.  This is based on the setting in the
	 * net_device flags, but might be modified above to be turned on if we
	 * were trying to set some addresses and dongle rejected it...
	 */
	err = wland_fil_iovar_data_set(ifp, "allmulti", &cmd_value,
		sizeof(cmd_value));
	if (err < 0)
		WLAND_ERR("Setting allmulti failed, %d\n", err);

	/*
	 * Finally, pick up the PROMISC flag
	 */
	cmd_value = (ndev->flags & IFF_PROMISC) ? true : false;
	err = wland_fil_iovar_data_set(ifp, "promisc", &cmd_value,
		sizeof(cmd_value));
	if (err < 0)
		WLAND_ERR("Setting failed,err:%d\n", err);
}

static void _wland_set_mac_address(struct work_struct *work)
{
	s32 err;
	struct wland_if *ifp =
		container_of(work, struct wland_if, setmacaddr_work);

	WLAND_DBG(DEFAULT, TRACE, "Enter, idx=%d\n", ifp->bssidx);

	err = wland_fil_iovar_data_set(ifp, "cur_etheraddr", ifp->mac_addr,
		ETH_ALEN);
	if (err < 0) {
		WLAND_ERR("Setting cur_etheraddr failed, %d\n", err);
	} else {
		WLAND_DBG(DEFAULT, TRACE, "MAC address updated to %pM\n",
			ifp->mac_addr);
		memcpy(ifp->ndev->dev_addr, ifp->mac_addr, ETH_ALEN);
	}
}

static int wland_netdev_set_mac_address(struct net_device *ndev, void *addr)
{
	struct wland_if *ifp = netdev_priv(ndev);
	struct sockaddr *sa = (struct sockaddr *) addr;

	memcpy(ifp->mac_addr, sa->sa_data, ETH_ALEN);

	WLAND_DBG(DEFAULT, TRACE, "Enter %pM\n", sa->sa_data);

	schedule_work(&ifp->setmacaddr_work);
	return 0;
}

static void wland_netdev_set_multicast_list(struct net_device *ndev)
{
	struct wland_if *ifp = netdev_priv(ndev);

	WLAND_DBG(DEFAULT, TRACE, "Enter\n");

	schedule_work(&ifp->multicast_work);
}

#if 0
static u8 wland_pro2tid(u8 pro)
{
	switch (pro) {
	case PRIO_8021D_NONE:
	case PRIO_8021D_BK:
		return AC_BK;
	case PRIO_8021D_BE:
	case PRIO_8021D_EE:
		return AC_BE;
	case PRIO_8021D_CL:
	case PRIO_8021D_VI:
		return AC_VI;
	case PRIO_8021D_VO:
	case PRIO_8021D_NC:
		return AC_VO;
	default:
		return AC_BE;
	}
}
#endif

static int wland_check_arp(struct wland_if *ifp, struct sk_buff *pktbuf)
{
	struct wland_cfg80211_profile *profile = &ifp->vif->profile;

	struct sk_buff *skb = NULL;
	struct ethhdr arp_rsp_eth;
	struct wland_arphdr arp_rsp;

	WLAND_DBG(DEFAULT, TRACE, "Enter\n");

	if (pktbuf->protocol == htons(ETH_P_ARP)) {
		struct ethhdr *arp_eth = (struct ethhdr *)(pktbuf->data);
		struct wland_arphdr *arph = (struct wland_arphdr *)(pktbuf->data + ETH_HLEN);
		//dump_buf(pktbuf->data, pktbuf->len);
		//printk("mode:%d, op:%x, ar_tip:%x, ser_ip%x\n", ifp->vif->mode, arph->ar_op, arph->ar_tip[0], profile->dhcp_server_ip[0]);
		if (ifp->vif->mode == WL_MODE_BSS) {
			if (arph->ar_op == htons(ARPOP_REQUEST) &&
				memcmp(arph->ar_tip, profile->dhcp_server_ip, 4) == 0) {

				skb =  dev_alloc_skb(ETH_HLEN + sizeof(struct wland_arphdr) + NET_IP_ALIGN + 3);
				if (!skb) {
					WLAND_ERR("dev_alloc_skb alloc skb failed \n");
					return -1;
				}

				skb->dev = ifp->ndev;

				skb_reserve(skb, NET_IP_ALIGN);
				//4byte align
				//wland_pkt_word_align(skb);

				memcpy(arp_rsp_eth.h_dest, arp_eth->h_source, ETH_ALEN);
				memcpy(arp_rsp_eth.h_source, arp_eth->h_dest, ETH_ALEN);
				arp_rsp_eth.h_proto = arp_eth->h_proto;

				memcpy(&arp_rsp, arph, sizeof(arp_rsp));
				arp_rsp.ar_op = htons(ARPOP_REPLY);
				memcpy(arp_rsp.ar_sha, profile->dhcp_server_bssid, ETH_ALEN);
				memcpy(arp_rsp.ar_sip, profile->dhcp_server_ip, 4);
				memcpy(arp_rsp.ar_tha, arph->ar_sha, ETH_ALEN);
				memcpy(arp_rsp.ar_tip, arph->ar_sip, 4);

				memcpy(skb->data, &arp_rsp_eth, ETH_HLEN);
				memcpy(skb->data + ETH_HLEN, &arp_rsp, sizeof(arp_rsp));
				skb_put(skb, ETH_HLEN + sizeof(arp_rsp));
				//dump_buf(skb->data, skb->len);

				wland_process_8023_pkt(ifp->drvr->bus_if, skb);

				//printk("###arp for ap, reply it\n");
				return 0;
			}
		}
	}
	return -1;
}

static void wland_check_tid(struct wland_if *ifp, struct sk_buff *pktbuf)
{
	u8 tid = 0;
	struct wland_cfg80211_connect_info *conn_info = &ifp->vif->conn_info;
	struct wland_cfg80211_profile *profile = &ifp->vif->profile;
	struct wland_sta_info *sta_info;
	struct wland_event_msg event_packet;
	struct wland_addba_msg addba_msg;
	struct wland_cfg80211_info *cfg = ifp->drvr->config;
	struct iphdr *iph;
	u16 proto;
	u8 *data = pktbuf->data;

	WLAND_DBG(DEFAULT, TRACE, "Enter\n");

	//u02 doesn't open mac1 tx aggregation
	if (ifp->drvr->bus_if->chip_version<4 && ifp->bssidx==1)
		return;

	memset(&event_packet, 0, sizeof(event_packet));

	if (pktbuf->protocol == htons(ETH_P_ARP) ||
		pktbuf->protocol == htons(ETH_P_PAE) ||
		pktbuf->protocol == htons(0x88b4))
		return;

	if (test_bit(SCAN_STATUS_BUSY, &cfg->scan_status)) {
		WLAND_DBG(DEFAULT, DEBUG, "Scanning, delay addba\n");
		return;
	}

	if (pktbuf->protocol == htons(ETH_P_IP) ||
		pktbuf->protocol == htons(ETH_P_PPP_SES)) {

		if (pktbuf->protocol == htons(ETH_P_IP))
			iph = (struct iphdr *)(pktbuf->data + ETH_HLEN);

		else { /*pktbuf->protocol == htons(ETH_P_PPP_SES)*/
			proto = MAKE_WORD16(data[21], data[20]);
			if (proto != PPP_IP)
				return;
			iph = (struct iphdr *)(pktbuf->data + ETH_HLEN + PPP_HDR_LEN);
		}

		if(iph->protocol == IPPROTO_UDP) { // UDP
			struct udphdr *udph = (struct udphdr *)((u8 *)iph + (iph->ihl << 2));
			if((udph->source == htons(SERVER_PORT)	&& udph->dest == htons(CLIENT_PORT)) ||
				(udph->source == htons(CLIENT_PORT)	&& udph->dest == htons(SERVER_PORT))) {  // DHCP offset/ack
				//WLAND_ERR("DHCP\n");
				return;
			}
		}

		//tid = wland_pro2tid(iph->tos >> 5);
		tid = iph->tos >> 5;

		if (tid > 7)
			return ;

		if (pktbuf->priority != tid) {
			//WLAND_ERR("priority%u:tid%u\n", pktbuf->priority, tid);
			//tid = pktbuf->priority;
			//iph->tos &= 0x1F;
			//iph->tos |= pktbuf->priority<<5;
		}

		if (ifp->vif->mode == WL_MODE_BSS) {
#ifdef WLAND_SET_TID
			tid = WLAND_TID_NUM;
#endif
			if (conn_info->wmm_enable && conn_info->n_enable && (atomic_read(&conn_info->tid_map)&BIT(tid))==0) {

				//WLAND_DBG(CFG80211, INFO, "send tid:%d without section for:%pM\n", tid, profile->bssid);
				//printk("%d ms\n", jiffies_to_msecs(jiffies - conn_info->tid_jiffies[tid]));
				if (time_after(conn_info->tid_jiffies[tid], jiffies - msecs_to_jiffies(WLAND_SECTION_TIMEOUT))) {
					if (conn_info->tid_num[tid] < WLAND_SECTION_COUNTER) {
						conn_info->tid_num[tid] = conn_info->tid_num[tid] + 1;
						return ;
					} else {
						conn_info->tid_jiffies[tid] = jiffies;
						conn_info->tid_num[tid] = 0;
					}

					atomic_set(&conn_info->tid_map,
						atomic_read(&conn_info->tid_map) | BIT(tid));
					event_packet.bsscfgidx = ifp->bssidx;
					event_packet.event_code = WLAND_E_ADDBA;
					event_packet.action= WLAND_ACTION_ADDBA_SEND;
					addba_msg.action = 1;
					addba_msg.tid = tid;
					memcpy(addba_msg.mac_addr, profile->bssid, ETH_ALEN);
					event_packet.datalen = sizeof(addba_msg);
					wland_fweh_push_event(ifp->drvr, &event_packet, (void *)(&addba_msg));
				} else {
					conn_info->tid_jiffies[tid] = jiffies;
					conn_info->tid_num[tid] = 0;
				}
			}

		} else if (ifp->vif->mode == WL_MODE_AP) {
			if (is_multicast_ether_addr(pktbuf->data))
				return ;

			if (ifp->bssidx == 0)
				tid = WLAND_TID_NUM;

			spin_lock_bh(&conn_info->sta_info_lock);
			list_for_each_entry(sta_info, &conn_info->sta_info_list, list) {
				if (memcmp(pktbuf->data, sta_info->mac_addr, ETH_ALEN) == 0) {
					if (sta_info->wmm_enable && sta_info->n_enable && (atomic_read(&sta_info->tid_map)&BIT(tid))==0) {

						//WLAND_DBG(CFG80211, INFO, "send tid:%d without section for:%pM\n", tid, sta_info->mac_addr);
						//printk("%d ms\n", jiffies_to_msecs(jiffies - sta_info->tid_jiffies[tid]));
						if (time_after(sta_info->tid_jiffies[tid], jiffies - msecs_to_jiffies(WLAND_SECTION_TIMEOUT))) {
							if (sta_info->tid_num[tid] < WLAND_SECTION_COUNTER) {
								sta_info->tid_num[tid] = sta_info->tid_num[tid] + 1;
								break ;
							} else {
								sta_info->tid_jiffies[tid] = jiffies;
								sta_info->tid_num[tid] = 0;
							}
							atomic_set(&sta_info->tid_map,
								atomic_read(&sta_info->tid_map) | BIT(tid));
							event_packet.bsscfgidx = ifp->bssidx;
							event_packet.event_code = WLAND_E_ADDBA;
							event_packet.action= WLAND_ACTION_ADDBA_SEND;
							addba_msg.action = 1;
							addba_msg.tid = tid;
							memcpy(addba_msg.mac_addr, sta_info->mac_addr, ETH_ALEN);
							event_packet.datalen = sizeof(addba_msg);
							wland_fweh_push_event(ifp->drvr, &event_packet, (void *)(&addba_msg));
						} else {
							sta_info->tid_jiffies[tid] = jiffies;
							sta_info->tid_num[tid] = 0;
						}
					}
					break;
				}
			}
			spin_unlock_bh(&conn_info->sta_info_lock);
		}
	}
}
int wland_sendpkt(struct wland_if *ifp, struct sk_buff *pktbuf)
{
	struct wland_private *drvr = ifp->drvr;
	struct ethhdr *eh = (struct ethhdr *) (pktbuf->data);
	bool multicast = is_multicast_ether_addr(eh->h_dest);
	bool pae = eh->h_proto == htons(ETH_P_PAE);
	u8 *frame;
	int len, ifidx = 0;
#ifdef WLAND_TX_SOFT_MAC
	u8 h_source[6];
	struct wland_cfg80211_connect_info *conn_info = &ifp->vif->conn_info;
	struct Assoc_ie *assocrsp_ie = &conn_info->assocrsp_ie;
	struct net_device *ndev = ifp->ndev;
	struct wland_cfg80211_profile *profile = ndev_to_prof(ndev);
	u8 to_ds = true;
	u8 *mac_hdr;
	u8 mac_header_len = MAC_HDR_LEN;//24
	u8 h_dest[6];
	u16 eth_type;
	u8 *snap_hdr;
	u16 data_len;
	u8 data_offset;
	u16 eth_pkt_len;
	u8 push_len = 0;
#endif

	WLAND_DBG(DCMD, DEBUG,
		"Enter(dest:%pM source:%pM tx_proto:0x%X, is_multicast:%d, pae:%d)\n",
		eh->h_source, eh->h_dest, ntohs(eh->h_proto), multicast, pae);

	/*
	 * Update multicast statistic
	 */
	drvr->tx_multicast += !!multicast;
	if (pae) {
		atomic_inc(&ifp->pend_8021x_cnt);
		WLAND_DBG(DCMD, DEBUG, "tx eapol:%d, %d\n",
			ifp->bssidx, atomic_read(&ifp->pend_8021x_cnt));
	}
#ifdef WLAND_TX_SOFT_MAC
	memcpy(h_source, eh->h_source, ETH_ALEN);

	///TODO: fix this bug
	assocrsp_ie->WMM_enable = true;

	memcpy(h_dest, eh->h_dest, ETH_ALEN);
	eth_type = ntohs(eh->h_proto);
	eth_pkt_len = pktbuf->len;

	if(assocrsp_ie->WMM_enable == true) {
		mac_header_len += QOS_CTRL_HDR_LEN;//24+2=26
	}

	mac_header_len += HT_CTRL_HDR_LEN;//26+4=30

	if(mac_header_len&3)
		mac_header_len += 2;//30+2=32

	push_len = MAC_HEADER_OFFSET + mac_header_len +  SNAP_HDR_LEN - ETHER_HDR_LEN;
				//0+32+8-(6*2+2) = 26

	if (skb_headroom(pktbuf) < push_len) {

		struct sk_buff *skb2;
		skb2 = skb_realloc_headroom(pktbuf, push_len);
		dev_kfree_skb(pktbuf);
		pktbuf = skb2;
		if (pktbuf == NULL) {
			WLAND_ERR("%s: skb_realloc_headroom failed\n",
				wland_ifname(drvr, ifp->bssidx));
			return -ENOMEM;
		}
	}
	skb_push(pktbuf, push_len);//26

	data_offset = mac_header_len + MAC_HEADER_OFFSET;//32 + 0

	frame = (u8 *) (pktbuf->data);

	mac_hdr = frame + MAC_HEADER_OFFSET;

	memset(frame, 0, data_offset);//32

	/*Infrastructure to_ds is true*/
	if (to_ds == true) {
		//wland_set_to_ds(mac_hdr, to_ds);

		wland_set_address1(mac_hdr, profile->bssid);

		if(eth_type == LLTD_TYPE) {
			wland_set_address2(mac_hdr, h_source);
		} else {
			wland_set_address2(mac_hdr, ifp->mac_addr);
		}

		wland_set_address3(mac_hdr, h_dest);
	}

	if((eth_type == ETHER_TYPE_ARP) ||
	   (eth_type == ETHER_TYPE_IP) ||
	   (eth_type == ETHER_TYPE_802_1X) ||
	   (eth_type == ETHER_TYPE_8021Q) ||
	   (eth_type == LLTD_TYPE)
#ifdef MAC_RDA_WAPI
	   || (eth_type == ETHER_TYPE_WAI)
#endif
	) {
		/* The SNAP header is set before the ethernet payload. */
		/*													 */
		/* +--------+--------+--------+----------+---------+---------+ */
		/* | DSAP	| SSAP	 | UI	  | OUI 	 | EthType | EthPayload    | */
		/* +--------+--------+--------+----------+---------+--------+ */
		/* | 1 byte | 1 byte | 1 byte | 3 bytes  | 2 bytes | x bytes	   | */
		/* +--------+--------+--------+----------+---------+---------+ */
		/* <----------------  SNAP Header  ---------------->  */
		/* <------------------------ 802.11 Payload --------> */
		snap_hdr = mac_hdr + mac_header_len;

		wland_set_snap_header(snap_hdr);
#if 0
		/* An ARP request/response frame has to be dissected to modify the	 */
		/* MAC address, for the host interface. MAC layer acts as an		 */
		/* interface to the packets from Etherent and WLAN and takes the	 */
		/* responsibility of ensuring proper interfacing.  */

		if(eth_type == ETHER_TYPE_ARP) {
			/* The source MAC address is modified only if the packet is an	 */
			/* ARP Request or a Response. The appropriate bytes are checked. */
			/* Type field (2 bytes): ARP Request (1) or an ARP Response (2)  */
			if((snap_hdr[8] == 0x00) && (snap_hdr[9] == 0x02 || snap_hdr[9] == 0x01)) {
					/* Set Address2 field in the WLAN Header with source address */
					wland_set_address2(snap_hdr, ifp->mac_addr);
			}
		}
#endif
		/* Set the data length parameter to the MAC data length only (does	 */
		/* not include headers)  */
		data_len = eth_pkt_len - ETHER_HDR_LEN + SNAP_HDR_LEN;
	}	else {
		data_len = eth_pkt_len - ETHER_HDR_LEN;
		data_offset = mac_header_len + SNAP_HDR_LEN;
	}

	*(frame + 2) = data_offset;//32
	*(frame + 3) = push_len;//26

#else /*WLAND_TX_SOFT_MAC*/
	skb_push(pktbuf, WID_HEADER_LEN);
	frame = (u8 *) (pktbuf->data);
#endif /*WLAND_TX_SOFT_MAC*/

	len = pktbuf->len;

	if (pktbuf->len > CDC_DCMD_LEN_MASK) {
		WLAND_ERR("pkt->len is over flow!\n");
#ifdef WLAND_TX_SOFT_MAC
		skb_pull(pktbuf, push_len);
#else
		skb_pull(pktbuf, WID_HEADER_LEN);
#endif
		dev_kfree_skb(pktbuf);

		return -EINVAL;
	}

	ifidx = ifp->bssidx;

#ifdef WLAND_DMA_TX1536_BLOCKS
#ifdef WLAND_5991H_MAC1_SUPPORT
	if (ifidx == 0)
		len |= (PKT_TYPE_AGGR_MAC0 << CDC_DCMD_LEN_SHIFT);
	else
		len |= (PKT_TYPE_AGGR_MAC1 << CDC_DCMD_LEN_SHIFT);
#else
	len |= (PKT_TYPE_AGGR_MAC0 << CDC_DCMD_LEN_SHIFT);
#endif
#else /*WLAND_DMA_TX1536_BLOCKS*/
#ifdef WLAND_5991H_MAC1_SUPPORT
	if (ifidx == 0)
		len |= (PKT_TYPE_REQ << CDC_DCMD_LEN_SHIFT);
	else
		len |= (PKT_TYPE_DATA_MAC1 << CDC_DCMD_LEN_SHIFT);
#else
	len |= (PKT_TYPE_REQ << CDC_DCMD_LEN_SHIFT);
#endif
#endif /*WLAND_DMA_TX1536_BLOCKS*/

	*(__le16 *) frame = cpu_to_le16(len);

	/*
	 * Use bus module to send data frame
	 */
	return wland_bus_txdata(drvr->bus_if, pktbuf);
}

#ifdef DHCP_PKT_MEMCOPY_BEFORE_SEND
static void wland_check_dhcp(struct sk_buff *skb)
{
	u8* data = skb->data;
	u16 proto = ((data[12] << 8) | data[13]);

	if (proto == ETH_P_IP) { // IP
		u8* ipheader = skb->data + 14;
		struct iphdr *iph = (struct iphdr *)(ipheader);
		if(iph->protocol == IPPROTO_UDP) { // UDP
			struct udphdr *udph = (struct udphdr *)((u8 *)iph + (iph->ihl << 2));
			if(((udph->source == __constant_htons(SERVER_PORT))
				&& (udph->dest == __constant_htons(CLIENT_PORT))) ||
				((udph->source == __constant_htons(CLIENT_PORT))
				&& (udph->dest == __constant_htons(SERVER_PORT)))
			) { // DHCP
				WLAND_DBG(DEFAULT, INFO, "dhcp pkt!\n");
				skb->protocol = htons(0x0801); //inform dhcp pkt
			}
		}
	}
}
#endif

int wland_netdev_start_xmit(struct sk_buff *skb, struct net_device *ndev)
{
	int ret = NETDEV_TX_OK;
	struct wland_if *ifp = netdev_priv(ndev);
	struct wland_private *drvr = ifp->drvr;
	struct ethhdr *eh;

	WLAND_DBG(DEFAULT, TRACE, "Enter, ifp->bssidx=%d, skb->len=%d\n",
		ifp->bssidx, skb->len);

	/*
	 * Can the device send data?
	 */
	if (drvr->bus_if->state != WLAND_BUS_DATA) {
		WLAND_ERR("xmit rejected state=%d\n", drvr->bus_if->state);
		netif_stop_queue(ndev);
		dev_kfree_skb(skb);
		ret = NETDEV_TX_BUSY;
		goto done;
	}

	if (netif_queue_stopped(ndev)) {
		dev_kfree_skb(skb);
		WLAND_ERR("queue is already stopped!\n");
		ret = NETDEV_TX_BUSY;
		goto done;
	}

	if (!drvr->iflist[ifp->bssidx]) {
		WLAND_ERR("bad ifidx %d\n", ifp->bssidx);
		netif_stop_queue(ndev);
		dev_kfree_skb(skb);
		ret = NETDEV_TX_BUSY;
		goto done;
	}

#ifdef WLAND_SDIO_SUPPORT
	if (wland_check_test_mode()) {
		WLAND_DBG(DEFAULT, DEBUG, "WIFI in test mode.\n");
		dev_kfree_skb(skb);
		goto done;
	}
#endif
	//printk("#x:%d:%x\n", ifp->bssidx, ntohs(skb->protocol));
	//if (skb->protocol == htons(ETH_P_IPV6)) {
		//WLAND_DBG(DEFAULT, ERROR, "discard ipv6 pkt.\n");
		//dev_kfree_skb(skb);
		//goto done;
	//}

#ifdef DHCP_PKT_MEMCOPY_BEFORE_SEND
	wland_check_dhcp(skb);
#endif

#ifndef WLAND_TX_SOFT_MAC
	/*
	 * Make sure there's enough room for any header
	 */
	if (skb_headroom(skb) < drvr->hdrlen) {
		struct sk_buff *skb2;

		WLAND_DBG(DEFAULT, TRACE,
			"%s: insufficient headroom and realloc skb.\n",
			wland_ifname(drvr, ifp->bssidx));
		skb2 = skb_realloc_headroom(skb, drvr->hdrlen);
		dev_kfree_skb(skb);
		skb = skb2;
		if (skb == NULL) {
			WLAND_ERR("%s: skb_realloc_headroom failed\n",
				wland_ifname(drvr, ifp->bssidx));
			ret = -ENOMEM;
			goto done;
		}
	}
#endif /*WLAND_TX_SOFT_MAC*/
	/*
	 * validate length for ether packet
	 */
	if (skb->len < sizeof(*eh)) {
		WLAND_ERR("validate length for ether packet!\n");
		ret = -EINVAL;
		dev_kfree_skb(skb);
		goto done;
	}

	ret = wland_check_arp(ifp, skb);
	if (ret == 0)
		goto done;

	wland_check_tid(ifp, skb);

#ifdef WLAND_AMSDU_TX
    ret = wland_amsdu_tx(ifp, skb);
    if (ret == 0)
        goto done;
#endif

	ret = wland_sendpkt(ifp, skb);

done:
	if (ret < 0) {
		ifp->stats.tx_dropped++;
	} else {
		ifp->stats.tx_packets++;
		ifp->stats.tx_bytes += skb->len;
	}

	/*
	 * Return ok: we always eat the packet
	 */
	return NETDEV_TX_OK;
}

static struct net_device_stats *wland_netdev_get_stats(struct net_device *ndev)
{
	struct wland_if *ifp = netdev_priv(ndev);

	if (ifp == NULL) {
		WLAND_ERR("BAD_IF\n");
		return NULL;
	}

	WLAND_DBG(DEFAULT, TRACE, "Done, idx:%d\n", ifp->bssidx);

	return &ifp->stats;
}

static void wland_ethtool_get_drvinfo(struct net_device *ndev,
	struct ethtool_drvinfo *info)
{
	struct wland_if *ifp = netdev_priv(ndev);
	struct wland_private *drvr = ifp->drvr;

	strlcpy(info->driver, KBUILD_MODNAME, sizeof(info->driver));
	snprintf(info->version, sizeof(info->version), "%d", drvr->drv_version);
	strlcpy(info->bus_info, dev_name(drvr->bus_if->dev),
		sizeof(info->bus_info));
}

static const struct ethtool_ops wland_ethtool_ops = {
	.get_drvinfo = wland_ethtool_get_drvinfo,
};

static int wland_ethtool(struct wland_if *ifp, void __user *uaddr)
{
	struct wland_private *drvr = ifp->drvr;
	struct ethtool_drvinfo info;
	char drvname[sizeof(info.driver)];
	u32 cmd;
	struct ethtool_value edata;
	u32 toe_cmpnt, csum_dir;
	int ret;

	WLAND_DBG(DEFAULT, TRACE, "Enter, idx=%d\n", ifp->bssidx);

	/*
	 * all ethtool calls start with a cmd word
	 */
	if (copy_from_user(&cmd, uaddr, sizeof(u32)))
		return -EFAULT;

	switch (cmd) {
	case ETHTOOL_GDRVINFO:
		/*
		 * Copy out any request driver name
		 */
		if (copy_from_user(&info, uaddr, sizeof(info)))
			return -EFAULT;
		strncpy(drvname, info.driver, sizeof(info.driver));
		drvname[sizeof(info.driver) - 1] = '\0';

		/*
		 * clear struct for return
		 */
		memset(&info, 0, sizeof(info));
		info.cmd = cmd;

		/*
		 * if requested, identify ourselves
		 */
		if (strcmp(drvname, "?dhd") == 0) {
			sprintf(info.driver, "dhd");
			strcpy(info.version, WLAND_VERSION_STR);
		}
		/*
		 * report dongle driver type
		 */
		else {
			sprintf(info.driver, "wl");
		}

		sprintf(info.version, "%d", drvr->drv_version);

		if (copy_to_user(uaddr, &info, sizeof(info)))
			return -EFAULT;
		WLAND_DBG(DEFAULT, TRACE, "given %*s, returning %s\n",
			(int) sizeof(drvname), drvname, info.driver);
		break;

		/*
		 * Get toe offload components from dongle
		 */
	case ETHTOOL_GRXCSUM:
	case ETHTOOL_GTXCSUM:
		ret = wland_fil_iovar_data_get(ifp, "toe_ol", &toe_cmpnt,
			sizeof(toe_cmpnt));
		if (ret < 0)
			return ret;

		csum_dir = (cmd == ETHTOOL_GTXCSUM) ?
			TOE_TX_CSUM_OL : TOE_RX_CSUM_OL;

		edata.cmd = cmd;
		edata.data = (toe_cmpnt & csum_dir) ? 1 : 0;

		if (copy_to_user(uaddr, &edata, sizeof(edata)))
			return -EFAULT;
		break;

		/*
		 * Set toe offload components in dongle
		 */
	case ETHTOOL_SRXCSUM:
	case ETHTOOL_STXCSUM:
		if (copy_from_user(&edata, uaddr, sizeof(edata)))
			return -EFAULT;

		/*
		 * Read the current settings, update and write back
		 */
		ret = wland_fil_iovar_data_get(ifp, "toe_ol", &toe_cmpnt,
			sizeof(toe_cmpnt));
		if (ret < 0)
			return ret;

		csum_dir = (cmd == ETHTOOL_STXCSUM) ?
			TOE_TX_CSUM_OL : TOE_RX_CSUM_OL;

		if (edata.data != 0)
			toe_cmpnt |= csum_dir;
		else
			toe_cmpnt &= ~csum_dir;

		/*
		 * If setting TX checksum mode, tell Linux the new mode
		 */
		if (cmd == ETHTOOL_STXCSUM) {
			if (edata.data)
				ifp->ndev->features |= NETIF_F_IP_CSUM;
			else
				ifp->ndev->features &= ~NETIF_F_IP_CSUM;
		}
		break;

	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

static int wland_get_nickname(struct net_device *ndev, struct ifreq *ifr, int cmd)
{
	struct wland_cfg80211_profile *profile = ndev_to_prof(ndev);
	struct iwreq *wrq = (struct iwreq *)ifr;

	WLAND_DBG(DEFAULT, TRACE, "Enter ssid:%s ssid_len:%d\n", profile->ssid.SSID,profile->ssid.SSID_len);

	if ((profile->ssid.SSID_len) && (wrq->u.data.pointer)) {
		if (copy_to_user(wrq->u.data.pointer,
			profile->ssid.SSID, profile->ssid.SSID_len+1)) {
			WLAND_ERR("copy ssid failed!\n");
			return -EFAULT;
		} else
			return 0;
	} else {
		WLAND_ERR("can not get nick name\n");
		return -EFAULT;
	}

}

#ifdef WLAND_SMART_CONFIG_SUPPORT
enum {	  
	MP_START = 1,
	MP_STOP,
	MP_CHANNEL,
};

struct iw_priv_args iw_cmd[] = {
	{ SIOCIWFIRSTPRIV + 0x0E, IW_PRIV_TYPE_CHAR | 1024, 0 , ""},  //set 
	{ SIOCIWFIRSTPRIV + 0x0F, IW_PRIV_TYPE_CHAR | 1024, IW_PRIV_TYPE_CHAR | IW_PRIV_SIZE_MASK , ""},//get
//sub cmd:
	{ MP_START , IW_PRIV_TYPE_CHAR | 1024, 0, "mp_start" }, //set
	{ MP_STOP , IW_PRIV_TYPE_CHAR | 1024, 0, "mp_stop" }, //set
	{ MP_CHANNEL , IW_PRIV_TYPE_CHAR | 1024, 0, "mp_channel" }, //set
	{ MP_CHANNEL , IW_PRIV_TYPE_CHAR | 1024 , IW_PRIV_TYPE_CHAR | IW_PRIV_SIZE_MASK, "mp_channel" },//get
};
static int wland_iwpriv_cmd(struct net_device *ndev,	struct ifreq *ifr, int cmd)
{
	struct wland_if *ifp = netdev_priv(ndev);
	struct iwreq *wrq = (struct iwreq *)ifr;
	union iwreq_data *wrq_data = &wrq->u;
	struct iw_point *dwrq = &wrq_data->data;
	u16 subcmd = dwrq->flags;
	u16 len = dwrq->length;
	int ret = 0;
	char *str = NULL;
	u8 channel = 0;

	WLAND_DBG(DEFAULT, INFO, "cmd:%x subcmd:%x", cmd, subcmd);

	switch(cmd)
	{
		case SIOCGIWPRIV:
			if (dwrq) {
				if (access_ok(VERIFY_WRITE, dwrq->pointer, sizeof(iw_cmd)) != TRUE) {
					WLAND_ERR("acess not ok\n");
					return -1;
				}

				if ((sizeof(iw_cmd) / sizeof(iw_cmd[0])) <= len)
				{
					len = sizeof(iw_cmd) / sizeof(iw_cmd[0]);
					if (copy_to_user(dwrq->pointer, iw_cmd, sizeof(iw_cmd))) {
						WLAND_ERR("copy failed\n");
						return -1;
					}
				} else {
					WLAND_ERR("too many cmds\n");
					return -1;
				}
			}
			break;
		case SIOCIWFIRSTPRIV + 0x0E:
			switch(subcmd)
			{
				case MP_START:
					if (ifp->vif->mode != WL_MODE_BSS) {
						WLAND_ERR("sniffer mode can only be setted from sta mode!\n");
						return -1;
					}

					if (ifp->sniffer_enable) {
						WLAND_ERR("sniffer already enabled\n");
						return 0;
					}
					ret = wland_sniffer_en_dis_able(ndev, true);
					if (ret < 0) {
						WLAND_ERR("enable sniffer failed!\n");
						return -1;
					} else {
						ifp->sniffer_enable = true;
					}
					break;
				case MP_STOP:
					if (!ifp->sniffer_enable) {
						WLAND_ERR("sniffer already disabled\n");
						return 0;
					}
					ret = wland_sniffer_en_dis_able(ndev, false);
					if (ret < 0) {
						WLAND_ERR("disable sniffer failed!\n");
						return -1;
					} else {
						ifp->sniffer_enable = false;
					}
					break;
				case MP_CHANNEL:
					if (!ifp->sniffer_enable) {
						WLAND_ERR("you can just set channel in sniffer mode!\n");
						return -1;
					}
					if (len == 0) {
						WLAND_ERR("no channel info!\n");
						return -1;
					}
					str = kzalloc(len, GFP_KERNEL);
					if (!str) {
						WLAND_ERR("no memory\n");
						return -1;
					}
					copy_from_user(str, dwrq->pointer, len);
					channel = simple_strtol(str, &str, 10);
					if ((channel == 0) || (channel > 14)) {
						WLAND_ERR("invalid channel:%d\n", channel);
						return -1;
					}
					ret = wland_set_channel(ifp, channel);
					if (ret < 0) {
						WLAND_ERR("set channel failed!\n");
						return -1;
					}
					break;
				default:
					WLAND_ERR("invalid cmd!\n");
					return -1;
					break;
			}
			break;
		default:
			WLAND_ERR("invalid cmd!\n");
			return -1;
			break;
	}

	return 0;
}
#endif
static int wland_netdev_ioctl_entry(struct net_device *ndev, struct ifreq *ifr,
	int cmd)
{
	struct wland_if *ifp = netdev_priv(ndev);
	//struct wland_private *drvr = ifp->drvr;
	int ret = 0;

	WLAND_DBG(DEFAULT, TRACE, "Enter, idx=%d, cmd=0x%x\n", ifp->bssidx,
		cmd);

	if (cmd == SIOCETHTOOL) {
		ret = wland_ethtool(ifp, ifr->ifr_data);
		return ret;
	}

	/*
	 * linux wireless extensions
	 */
	if (cmd == SIOCDEVPRIVATE + 1) {
		ret = wland_android_priv_cmd(ndev, ifr, cmd);
		//dhd_check_hang(net, &dhd->pub, ret);
		return ret;
	} else if (cmd == SIOCDEVPRIVATE + 5) {
		ret = wland_rf_test_cmd(ndev, ifr, cmd);
		//dhd_check_hang(net, &dhd->pub, ret);
		return ret;
	} else if (cmd == SIOCGIWNICKN)
		ret = wland_get_nickname(ndev, ifr, cmd);
#ifdef WLAND_SMART_CONFIG_SUPPORT
	else if ((cmd == SIOCGIWPRIV) || (cmd == SIOCSIWPRIV)
		|| (cmd == (SIOCIWFIRSTPRIV + 0x0E)))
		ret = wland_iwpriv_cmd(ndev, ifr, cmd);
#endif
	WLAND_DBG(DEFAULT, TRACE, "Done.\n");

	return ret;
}

static int wland_netdev_stop(struct net_device *ndev)
{
	struct wland_if *ifp = netdev_priv(ndev);

	WLAND_DBG(DEFAULT, INFO, "Enter, idx=%d\n", ifp->bssidx);

	/*
	 * Set state and stop OS transmissions
	 */
	if (!netif_queue_stopped(ndev)) {
		netif_stop_queue(ndev);
		WLAND_DBG(DEFAULT, TRACE, "netif_stop_queue(ndev)\n");
	}
	if (netif_carrier_ok(ndev)) {
		netif_carrier_off(ndev);
		WLAND_DBG(DEFAULT, TRACE, "netif_carrier_off(ndev)\n");
	}

	wland_cfg80211_down(ndev);
	//wland_stop_chip(ndev);

	return 0;
}

static int wland_netdev_open(struct net_device *ndev)
{
	struct wland_if *ifp = netdev_priv(ndev);
	struct wland_private *drvr = ifp->drvr;
	struct wland_bus *bus_if = drvr->bus_if;

#ifdef WLAND_TBD_SUPPORT
	u32 toe_ol;
#endif /*WLAND_TBD_SUPPORT */
	s32 ret = 0;

	WLAND_DBG(DEFAULT, INFO, "Enter, idx=%d\n", ifp->bssidx);

	ret = wland_start_chip(ndev);
	if (ret < 0) {
		WLAND_ERR("failed to bring up chip!\n");
		return -ENODEV;
	}

	/*
	 * If bus is not ready, can't continue
	 */
	if (bus_if->state != WLAND_BUS_DATA) {
		WLAND_ERR("failed bus is not ready\n");
		return -EAGAIN; //USB_SUPPORT may be need to remove this
	}

	atomic_set(&ifp->pend_8021x_cnt, 0);

#ifdef WLAND_TBD_SUPPORT
	/*
	 * Get current TOE mode from dongle
	 */
	if (wland_fil_iovar_data_get(ifp, "toe_ol", &toe_ol,
			sizeof(toe_ol)) >= 0 && (toe_ol & TOE_TX_CSUM_OL) != 0)
		ndev->features |= NETIF_F_IP_CSUM;
	else
		ndev->features &= ~NETIF_F_IP_CSUM;
#endif /*WLAND_TBD_SUPPORT */

	if (wland_cfg80211_up(ndev) < 0) {
		WLAND_ERR("failed to bring up cfg80211\n");
		ret = -ENODEV;
	}

	/*
	 * Allow transmit calls
	 */
	if (!ret) {
		netif_carrier_on(ndev);
		WLAND_DBG(DEFAULT, TRACE, "netif_carrier_on(ndev)\n");
		netif_start_queue(ndev);
		WLAND_DBG(DEFAULT, TRACE, "netif_start_queue(ndev)\n");
	}

	return ret;
}

static void wland_netdev_tx_timeout(struct net_device *dev)
{
	WLAND_DBG(DEFAULT, TRACE, "Enter\n");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
	netif_trans_update(dev);
#else
	dev->trans_start = jiffies;	/* prevent tx timeout */
#endif
	netif_wake_queue(dev);
	dev->stats.tx_errors++;

	WLAND_DBG(DEFAULT, TRACE, "Done\n");
}

static const struct net_device_ops wland_netdev_ops_pri = {
	.ndo_open = wland_netdev_open,
	.ndo_stop = wland_netdev_stop,
	.ndo_get_stats = wland_netdev_get_stats,
	.ndo_do_ioctl = wland_netdev_ioctl_entry,
	.ndo_start_xmit = wland_netdev_start_xmit,
	.ndo_tx_timeout = wland_netdev_tx_timeout,
	.ndo_set_mac_address = wland_netdev_set_mac_address,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0))
	.ndo_set_rx_mode = wland_netdev_set_multicast_list,
#else /*(LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)) */
	.ndo_set_multicast_list = wland_netdev_set_multicast_list,
#endif /*(LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)) */
};

static int wland_get_fw_tx_status(struct wland_if *ifp, u32 *tx_success,
	u32 *tx_rts_fail, u32 *tx_msdu_lifttime_fail,
	u32 *tx_mpdu_noack, u32 *tx_ampdu_noba)
{
	int ret;
	char buf[24];

	ret = wland_fil_get_cmd_data(ifp, WID_GET_TX_STATUS, buf, 24);
	if (ret != 20) {
		WLAND_ERR("get tx status fail, ret:%d\n", ret);
		return -1;
	}
	//dump_buf(buf, 24);

	*tx_success = le32_to_cpup((const __le32 *)(buf));
	*tx_rts_fail = le32_to_cpup((const __le32 *)(buf+4));
	*tx_msdu_lifttime_fail = le32_to_cpup((const __le32 *)(buf+8));
	*tx_mpdu_noack = le32_to_cpup((const __le32 *)(buf+12));
	*tx_ampdu_noba = le32_to_cpup((const __le32 *)(buf+16));

	return 0;
}

int wland_dev_get_tx_status(struct net_device *ndev, char *data, int len)
{
	int ret = 0;
	u32 tx_success, tx_rts_fail, tx_msdu_lifttime_fail, tx_mpdu_noack, tx_ampdu_noba;
	struct wland_if *ifp = netdev_priv(ndev);
	WLAND_DBG(RFTEST, DEBUG, "Enter\n");

	ret = wland_get_fw_tx_status(ifp, &tx_success,
		&tx_rts_fail, &tx_msdu_lifttime_fail, &tx_mpdu_noack, &tx_ampdu_noba);
	if (ret != 0) {
		WLAND_ERR("Get RSSI_SNR failed!\n");
		return ret;
	}
	WLAND_DBG(RFTEST, DEBUG, "tx_success:%u, tx_rts_fail:%u, "
		"tx_msdu_lifttime_fail:%u, tx_mpdu_noack:%u, tx_ampdu_noba:%u\n",
		tx_success, tx_rts_fail, tx_msdu_lifttime_fail, tx_mpdu_noack, tx_ampdu_noba);

	ret = snprintf(data, len, "tx_success:%u, tx_rts_fail:%u, "
		"tx_msdu_lifttime_fail:%u, tx_mpdu_noack:%u, tx_ampdu_noba:%u\n",
		tx_success, tx_rts_fail, tx_msdu_lifttime_fail, tx_mpdu_noack, tx_ampdu_noba);
	return ret;
}

int wland_netdev_attach(struct wland_if *ifp)
{
	struct wland_private *drvr = ifp->drvr;
	struct net_device *ndev = ifp->ndev;
	s32 err = 0;

	/*
	 * set appropriate operations
	 */
	ndev->netdev_ops = &wland_netdev_ops_pri;

	ndev->hard_header_len += drvr->hdrlen;
	ndev->flags |= IFF_BROADCAST | IFF_MULTICAST;

	ndev->ethtool_ops = &wland_ethtool_ops;

	/*
	 * set the mac address
	 */
	memcpy(ndev->dev_addr, ifp->mac_addr, ETH_ALEN);

	WLAND_DBG(DEFAULT, TRACE, "Enter,(%s:idx:%d,ifidx:0x%x)\n", ndev->name,
		ifp->bssidx, ifp->ifidx);

	if (rtnl_is_locked())
		err = register_netdevice(ndev);
	else
		err = register_netdev(ndev);
	if (err != 0) {
		WLAND_ERR("couldn't register the net device\n");
		goto fail;
	}

	WLAND_DBG(DEFAULT, TRACE,
		"%s: Rdamicro Host Driver(mac:%pM,ndevmtu:0x%x)\n", ndev->name,
		ndev->dev_addr, ndev->mtu);

	INIT_WORK(&ifp->setmacaddr_work, _wland_set_mac_address);
	INIT_WORK(&ifp->multicast_work, _wland_set_multicast_list);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
	ndev->priv_destructor = free_netdev;
#else
	ndev->destructor = free_netdev;
#endif

	return 0;

fail:
	drvr->iflist[ifp->bssidx] = NULL;
	ndev->netdev_ops = NULL;
	free_netdev(ndev);
	return -EBADE;
}

#ifdef WLAND_P2P_SUPPORT
static int wland_netdev_p2p_open(struct net_device *ndev)
{
	WLAND_DBG(DEFAULT, INFO, "Enter\n");

	return wland_cfg80211_up(ndev);
}

static int wland_netdev_p2p_stop(struct net_device *ndev)
{
	WLAND_DBG(DEFAULT, INFO, "Enter\n");

	if (!netif_queue_stopped(ndev)) {
		netif_stop_queue(ndev);
		WLAND_DBG(DEFAULT, TRACE, "netif_stop_queue(ndev)\n");
	}
	if (netif_carrier_ok(ndev)) {
		netif_carrier_off(ndev);
		WLAND_DBG(DEFAULT, TRACE, "netif_carrier_off(ndev)\n");
	}

	wland_cfg80211_down(ndev);
	//wland_stop_chip(ndev);
	return 0;
}

static int wland_netdev_p2p_do_ioctl(struct net_device *ndev, struct ifreq *ifr,
	int cmd)
{
	int ret = 0;

	WLAND_DBG(DEFAULT, TRACE, "Enter\n");

	/*
	 * There is no ifidx corresponding to p2p0 in our firmware. So we should
	 * * not Handle any IOCTL cmds on p2p0 other than ANDROID PRIVATE CMDs.
	 * * For Android PRIV CMD handling map it to primary I/F
	 */
	if (cmd == SIOCDEVPRIVATE + 1) {
		ret = wland_android_priv_cmd(ndev, ifr, cmd);
	} else {
		WLAND_ERR("IOCTL req 0x%x on p2p0 I/F. Ignoring. \n", cmd);
		ret = -1;
	}

	return ret;
}

static const struct net_device_ops wland_netdev_ops_p2p = {
	.ndo_open = wland_netdev_p2p_open,
	.ndo_stop = wland_netdev_p2p_stop,
	.ndo_do_ioctl = wland_netdev_p2p_do_ioctl,
	.ndo_start_xmit = wland_netdev_start_xmit,
};

static void wland_cfgp2p_ethtool_get_drvinfo(struct net_device *net,
	struct ethtool_drvinfo *info)
{
	snprintf(info->driver, sizeof(info->driver), "p2p");
	snprintf(info->version, sizeof(info->version), "%lu", (ulong) (0));
}

struct ethtool_ops wland_cfgp2p_ethtool_ops = {
	.get_drvinfo = wland_cfgp2p_ethtool_get_drvinfo
};

/* register "p2p0" interface */
int wland_netdev_p2p_attach(struct wland_if *ifp)
{
	struct net_device *ndev = ifp->ndev;

	if (!ndev) {
		WLAND_ERR("p2p net device is empty\n");
		return -EBADE;
	}
	ndev->netdev_ops = &wland_netdev_ops_p2p;
	ndev->ethtool_ops = &wland_cfgp2p_ethtool_ops;

	/*
	 * set the mac address
	 */
	memcpy(ndev->dev_addr, ifp->mac_addr, ETH_ALEN);

	WLAND_DBG(DEFAULT, TRACE, "Enter(idx:%d,mac:%pM)\n", ifp->bssidx,
		ifp->mac_addr);

	if (register_netdev(ndev)) {
		WLAND_ERR("couldn't register the p2p net device\n");
		goto fail;
	}
	WLAND_DBG(DEFAULT, TRACE, "Done(%s: Rdamicro Host Driver For P2P0)\n",
		ndev->name);

	return 0;
fail:
	ifp->drvr->iflist[ifp->bssidx] = NULL;
	ndev->netdev_ops = NULL;
	free_netdev(ndev);
	return -EBADE;
}
#endif /* WLAND_P2P_SUPPORT */

struct wland_if *wland_add_if(struct wland_private *drvr, s32 bssidx, s32 ifidx,
	char *name, u8 * mac_addr)
{
	struct net_device *ndev;
	struct wland_if *ifp = NULL;

	WLAND_DBG(DEFAULT, TRACE, "Enter, idx:%d, ifidx:%d.\n", bssidx, ifidx);

	if (!(drvr && (bssidx < WLAND_MAX_IFS))) {
		WLAND_ERR("private not setup!\n");
		return ERR_PTR(-EINVAL);
	}
	ifp = drvr->iflist[bssidx];

	/*
	 * Delete the existing interface before overwriting it in case we missed the WLAND_E_IF_DEL event.
	 */
	if (ifp) {
		WLAND_ERR("netname:%s,netdev:%p,ifidx:%d,already exists\n",
			ifp->ndev->name, ifp->ndev, ifidx);

		if (ifidx) {
			if (ifp->ndev) {
				netif_stop_queue(ifp->ndev);
				unregister_netdev(ifp->ndev);
				free_netdev(ifp->ndev);
				drvr->iflist[bssidx] = NULL;
			}
		} else {
			WLAND_ERR("ignore IF event\n");
			return ERR_PTR(-EINVAL);
		}
	}

	WLAND_DBG(DEFAULT, TRACE, "drvr->p2p_enable:%d,bssidx:%d\n",
		drvr->p2p_enable, bssidx);

	if (!drvr->p2p_enable && bssidx == 1) {
		/*
		 * this is P2P_DEVICE interface
		 */
		WLAND_DBG(DEFAULT, TRACE, "allocate non-netdev interface\n");
		ifp = kzalloc(sizeof(struct wland_if), GFP_KERNEL);
		if (!ifp)
			return ERR_PTR(-ENOMEM);
		memset(ifp, '\0', sizeof(struct wland_if));
	} else {
		WLAND_DBG(DEFAULT, TRACE, "allocate netdev interface\n");
		/*
		 * Allocate netdev, including space for private structure
		 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0)
		ndev = alloc_netdev(sizeof(struct wland_if), name, NET_NAME_UNKNOWN, ether_setup);
#else
		ndev = alloc_netdev(sizeof(struct wland_if), name, ether_setup);
#endif
		if (!ndev)
			return ERR_PTR(-ENOMEM);

#ifdef WLAND_TX_AGGRPKTS
		ndev->needed_tailroom = 2;
#endif
		ndev->netdev_ops = NULL;

		ifp = netdev_priv(ndev);
		ifp->ndev = ndev;
	}

	ifp->drvr = drvr;
	ifp->ifidx = ifidx;
	ifp->bssidx = bssidx;
	ifp->tx_flowblock = false;
#ifdef WLAND_SMART_CONFIG_SUPPORT
	ifp->sniffer_enable = false;
#endif
	drvr->iflist[bssidx] = ifp;

	init_waitqueue_head(&ifp->pend_8021x_wait);

	spin_lock_init(&ifp->netif_stop_lock);

	if (mac_addr)
		memcpy(ifp->mac_addr, mac_addr, ETH_ALEN);

	WLAND_DBG(DEFAULT, TRACE, "Done, pid:%x, if:%s (%pM) created ===\n",
		current->pid, ifp->ndev->name, ifp->mac_addr);

	return ifp;
}

void wland_del_if(struct wland_private *drvr, s32 bssidx)
{
	struct wland_if *ifp = drvr->iflist[bssidx];

	if (!ifp) {
		WLAND_ERR("Null interface,idx:%d\n", bssidx);
		return;
	}

	WLAND_DBG(DEFAULT, TRACE, "Enter,idx:%d,ifidx:%d,ndev:%p.\n", bssidx,
		ifp->ifidx, ifp->ndev);

	if (ifp->ndev) {
		if (bssidx == 0) {
			if (ifp->ndev->netdev_ops == &wland_netdev_ops_pri) {
				WLAND_DBG(DEFAULT, TRACE, "wlan0 interface ops.\n");

				if (!rtnl_is_locked())
					rtnl_lock();
				wland_netdev_stop(ifp->ndev);
				if (rtnl_is_locked())
					rtnl_unlock();
			}
		} else {
			WLAND_DBG(DEFAULT, TRACE, "stop netdev:%p.\n",
				ifp->ndev);
			netif_stop_queue(ifp->ndev);
		}

		if (ifp->ndev->netdev_ops == &wland_netdev_ops_pri) {
			cancel_work_sync(&ifp->setmacaddr_work);
			cancel_work_sync(&ifp->multicast_work);
		}

		/*
		 * unregister will take care of freeing it
		 */
		WLAND_DBG(DEFAULT, TRACE, "detach netdev:%p.\n", ifp->ndev);

		unregister_netdev(ifp->ndev);
		if (bssidx == 0 && drvr->config && !IS_ERR(drvr->config)) {
			wland_cfg80211_detach(drvr->config);
			drvr->config = NULL;
		}
		drvr->iflist[bssidx] = NULL;

	} else {
		drvr->iflist[bssidx] = NULL;
		kfree(ifp);
	}
}

int wland_netdev_wait_pend8021x(struct net_device *ndev)
{
	int err = 1;
	//sdio use tx aggrpkt, txcomplete is not right
#ifdef WLAND_USB_SUPPORT
	struct wland_if *ifp = netdev_priv(ndev);
	err = wait_event_timeout(ifp->pend_8021x_wait,
		!atomic_read(&ifp->pend_8021x_cnt),
		msecs_to_jiffies(MAX_WAIT_FOR_8021X_TX));

	WARN_ON(!err);
#endif /*WLAND_USB_SUPPORT*/
	return !err;
}

/* Module Entery For Linux OS */
static void wland_driver_init(struct work_struct *work)
{
#ifdef WLAND_SDIO_SUPPORT
	wland_sdio_register();
#endif /* WLAND_SDIO_SUPPORT */
#ifdef WLAND_USB_SUPPORT
	wland_usb_register();
#endif /* WLAND_USB_SUPPORT  */
}

static DECLARE_WORK(wland_driver_work, wland_driver_init);

struct semaphore registration_sem;
bool registration_check = false;

/* msec : allowed time to finished dhd registration */
#define REGISTRATION_TIMEOUT                     9000

void wland_registration_sem_up(bool check_flag)
{
	registration_check = check_flag;
	up(&registration_sem);
}

//#define INSMOD_TEST

static int wlanfmac_module_init(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
	char wland_ver[] =
		"Compiled on " __DATE__ " at " __TIME__;
	pr_err("[RDAWLAN_DRIVER] %s.\n", wland_ver);
#endif /*LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)*/

	pr_err("[RDAWLAN_DRIVER] Ver: %d.%d.%d.\n", WLAND_VER_MAJ,
		WLAND_VER_MIN, WLAND_VER_BLD);

#ifdef WLAND_DRIVER_RELOAD_FW
	first_download_fw = true;
#endif

	sema_init(&registration_sem, 0);

#ifdef INSMOD_TEST
	rda_wifi_power_on();
#endif /*INSMOD_TEST */

	wland_debugfs_init();

	if (!schedule_work(&wland_driver_work))
		return -EBUSY;

	/*
	 * Wait till MMC sdio_register_driver callback called and made driver attach.
	 * It's needed to make sync up exit from dhd insmod and Kernel MMC sdio device callback registration
	 */
	if ((down_timeout(&registration_sem, msecs_to_jiffies(REGISTRATION_TIMEOUT)) != 0)
		|| (!registration_check )) {
		WLAND_ERR("register_driver timeout or error\n");
		cancel_work_sync(&wland_driver_work);

#ifdef WLAND_SDIO_SUPPORT
		wland_sdio_exit();
#endif /* WLAND_SDIO_SUPPORT */

#ifdef WLAND_USB_SUPPORT
		wland_usb_exit();
#endif /*WLAND_USB_SUPPORT */

		wland_debugfs_exit();

#ifdef INSMOD_TEST
		rda_wifi_power_off();
#endif /* INSMOD_TEST */
		return -ENODEV;
	}
	return 0;
}

static void __exit wlanfmac_module_exit(void)
{
	WLAND_DBG(DEFAULT, INFO, "Enter\n");

#ifdef WLAND_AP_RESET
	cancel_work_sync(&wland_chip_reset_work);
	while(ap_reseting) {
		schedule();
	}
#endif

	cancel_work_sync(&wland_driver_work);

#ifdef WLAND_SDIO_SUPPORT
	wland_sdio_exit();
#endif /* WLAND_SDIO_SUPPORT */

#ifdef WLAND_USB_SUPPORT
	wland_usb_exit();
#endif /*WLAND_USB_SUPPORT */

	wland_debugfs_exit();

#ifdef INSMOD_TEST
	rda_wifi_power_off();
#endif /* INSMOD_TEST */
	WLAND_DBG(DEFAULT, INFO, "Done\n");
}

late_initcall(wlanfmac_module_init);
module_exit(wlanfmac_module_exit);

char rdawlan_firmware_path[MOD_PARAM_PATHLEN]="sta";
unsigned char WifiMac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
int n_WifiMac = 0;
static u8 wifi_in_test_mode = 0;

u8 wland_check_test_mode(void)
{
	return wifi_in_test_mode;
}
void wland_set_test_mode(u8 mode)
{
	wifi_in_test_mode = mode;
}

module_param(amsdu_operation, uint, S_IRUGO|S_IWUSR);
module_param_string(firmware_path, rdawlan_firmware_path, MOD_PARAM_PATHLEN, 0660);
module_param_array(WifiMac, byte, &n_WifiMac, S_IRUGO);

MODULE_AUTHOR("RdaMicro");
MODULE_DESCRIPTION("RdaMicro 802.11 Wireless LAN FullMac Driver.");
MODULE_LICENSE("GPL v2");
