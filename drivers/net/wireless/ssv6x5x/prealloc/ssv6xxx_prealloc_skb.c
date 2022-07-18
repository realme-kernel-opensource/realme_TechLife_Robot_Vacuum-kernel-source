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

#include <linux/version.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include "ssv6xxx_common.h"
#include "ssv6xxx_prealloc_skb.h"

MODULE_AUTHOR("iComm-semi, Ltd");
MODULE_DESCRIPTION("Pre-allocated memory for SSV wireless LAN cards.");
MODULE_LICENSE("Dual BSD/GPL");

int ssv_tx_recycle_max_skbs = AMPDU_RECYCLE_MAX_SKBS;
EXPORT_SYMBOL(ssv_tx_recycle_max_skbs);
module_param(ssv_tx_recycle_max_skbs, int, 0644);
MODULE_PARM_DESC(ssv_tx_recycle_max_skbs, "Max length of TX recycle list");

int ssv_rx_recycle_max_skbs = RX_AGG_RECYCLE_MAX_SKBS;
EXPORT_SYMBOL(ssv_rx_recycle_max_skbs);
module_param(ssv_rx_recycle_max_skbs, int, 0644);
MODULE_PARM_DESC(ssv_rx_recycle_max_skbs, "Max length of RX recycle list");

int ssv_tx_recycle_skb_size = MAX_AMPDU_SKB_SIZE;
EXPORT_SYMBOL(ssv_tx_recycle_skb_size);
module_param(ssv_tx_recycle_skb_size, int, 0644);
MODULE_PARM_DESC(ssv_tx_recycle_skb_size, "Max size of TX recycle skb");

int ssv_rx_recycle_skb_size = MAX_HCI_RX_AGGR_SIZE;
EXPORT_SYMBOL(ssv_rx_recycle_skb_size);
module_param(ssv_rx_recycle_skb_size, int, 0644);
MODULE_PARM_DESC(ssv_rx_recycle_skb_size, "Max size of RX recycle skb");

struct ssv6xxx_prealloc ssv_prealloc;
EXPORT_SYMBOL(ssv_prealloc);

struct sk_buff *ssv_tx_recycle_skb_alloc(unsigned int len) {
    struct sk_buff *skb;

    if (len > ssv_tx_recycle_skb_size) {
        printk("%s(): len %u is too big!", __func__, len);
        return NULL;
    }

    skb = skb_dequeue(&ssv_prealloc.ampdu_recycle_list);
    if (skb) {
    	struct skb_shared_info *s = skb_shinfo(skb);
        memset(s, 0, offsetof(struct skb_shared_info, dataref));
        atomic_set(&s->dataref, 1);
        memset(skb, 0, offsetof(struct sk_buff, tail));
        skb->data = skb->head;
        skb_reset_tail_pointer(skb);
    } else {
        printk("%s(): ampdu_recycle_list is empty!", __func__);
    }
    //printk("%s(): ampdu_recycle_list: %d\n", __func__, skb_queue_len(&ssv_prealloc.ampdu_recycle_list));

    return skb;
}
EXPORT_SYMBOL(ssv_tx_recycle_skb_alloc);

struct sk_buff *ssv_rx_recycle_skb_alloc(unsigned int len) {
    struct sk_buff *skb;

    if (len > ssv_rx_recycle_skb_size) {
        printk("%s(): len %u is too big!", __func__, len);
        return NULL;
    }

    skb = skb_dequeue(&ssv_prealloc.rx_agg_recycle_list);
    if (skb) {
    	struct skb_shared_info *s = skb_shinfo(skb);
        memset(s, 0, offsetof(struct skb_shared_info, dataref));
        atomic_set(&s->dataref, 1);
        memset(skb, 0, offsetof(struct sk_buff, tail));
        skb->data = skb->head;
        skb_reset_tail_pointer(skb);
    } else {
        printk("%s(): rx_agg_recycle_list is empty!", __func__);
    }
    //printk("%s(): rx_agg_recycle_list: %d\n", __func__, skb_queue_len(&ssv_prealloc.rx_agg_recycle_list));

    return skb;
}
EXPORT_SYMBOL(ssv_rx_recycle_skb_alloc);

void ssv_tx_recycle_skb_free(struct sk_buff *skb) {
#if IS_ENABLED(CONFIG_NF_CONNTRACK)
#if LINUX_VERSION_CODE > KERNEL_VERSION(4,10,17)
    struct nf_conntrack *nfct = (struct nf_conntrack *)(skb->_nfct & SKB_NFCT_PTRMASK);
#else
    struct nf_conntrack *nfct = (struct nf_conntrack *)(skb->nfct);
#endif
#endif

    if (skb) {
#if IS_ENABLED(CONFIG_NF_CONNTRACK)
        if (nfct && atomic_dec_and_test(&nfct->use)) {
            nf_conntrack_destroy(nfct);
        }
#endif

        skb_queue_head(&ssv_prealloc.ampdu_recycle_list, skb);
        //printk("%s(): ampdu_recycle_list: %d\n", __func__, skb_queue_len(&ssv_prealloc.ampdu_recycle_list));
    }
}
EXPORT_SYMBOL(ssv_tx_recycle_skb_free);

void ssv_rx_recycle_skb_free(struct sk_buff *skb) {
#if IS_ENABLED(CONFIG_NF_CONNTRACK)
#if LINUX_VERSION_CODE > KERNEL_VERSION(4,10,17)
    struct nf_conntrack *nfct = (struct nf_conntrack *)(skb->_nfct & SKB_NFCT_PTRMASK);
#else
    struct nf_conntrack *nfct = (struct nf_conntrack *)(skb->nfct);
#endif
#endif

    if (skb) {
#if IS_ENABLED(CONFIG_NF_CONNTRACK)
        if (nfct && atomic_dec_and_test(&nfct->use)) {
            nf_conntrack_destroy(nfct);
        }
#endif

        skb_queue_head(&ssv_prealloc.rx_agg_recycle_list, skb);
        //printk("%s(): rx_agg_recycle_list: %d\n", __func__, skb_queue_len(&ssv_prealloc.rx_agg_recycle_list));
    }
}
EXPORT_SYMBOL(ssv_rx_recycle_skb_free);

static int __init ssv_prealloc_init(void)
{
    struct sk_buff *skb;
    int i;

    printk("ENTER SSV PREALLOC MODULE\n");

    skb_queue_head_init(&ssv_prealloc.ampdu_recycle_list);
    skb_queue_head_init(&ssv_prealloc.rx_agg_recycle_list);

    for (i = 0 ; i < ssv_tx_recycle_max_skbs ; i++) {
        skb = __dev_alloc_skb(ssv_tx_recycle_skb_size, GFP_KERNEL);
        if (skb) {
            skb_queue_head(&ssv_prealloc.ampdu_recycle_list, skb);
        } else {
            printk("Can't alloc skb for tx ampdu recycle list.");
        }
    }

    for (i = 0 ; i < ssv_rx_recycle_max_skbs ; i++) {
        skb = __dev_alloc_skb(ssv_rx_recycle_skb_size, GFP_KERNEL);
        if (skb) {
            skb_queue_head(&ssv_prealloc.rx_agg_recycle_list, skb);
        } else {
            printk("Can't alloc skb for hci rx agg recycle list.");
        }
    }

    return 0;
}

static void __exit ssv_prealloc_exit(void)
{
    struct sk_buff *skb;

    while ((skb = skb_dequeue(&ssv_prealloc.ampdu_recycle_list)) != NULL) {
        dev_kfree_skb_any(skb);
    }

    while ((skb = skb_dequeue(&ssv_prealloc.rx_agg_recycle_list)) != NULL) {
        dev_kfree_skb_any(skb);
    }
    printk("EXIT SSV PREALLOC MODULE\n");
}
module_init(ssv_prealloc_init);
module_exit(ssv_prealloc_exit);

