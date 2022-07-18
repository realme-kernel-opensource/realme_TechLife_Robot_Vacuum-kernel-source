/*
 * Copyright (c) 2015 iComm-semi Ltd.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _SSV6XXX_PREALLOC_SKB_H_
#define _SSV6XXX_PREALLOC_SKB_H_

#define AMPDU_RECYCLE_MAX_SKBS		512
#define RX_AGG_RECYCLE_MAX_SKBS		64
#define MAX_AMPDU_SKB_SIZE		24*1024

struct ssv6xxx_prealloc {
    //for TX AMPDU
    struct sk_buff_head ampdu_recycle_list;

    //for HCI RX aggregation
    struct sk_buff_head rx_agg_recycle_list;
};

struct sk_buff *ssv_tx_recycle_skb_alloc(unsigned int len);
struct sk_buff *ssv_rx_recycle_skb_alloc(unsigned int len);
void ssv_tx_recycle_skb_free(struct sk_buff *skb);
void ssv_rx_recycle_skb_free(struct sk_buff *skb);
#endif
