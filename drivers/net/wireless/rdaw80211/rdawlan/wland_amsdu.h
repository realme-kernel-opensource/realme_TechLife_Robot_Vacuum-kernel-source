/*
 * Copyright (c) 2018 Rdamicro Corporation
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

#ifndef _WLAND_AMSDU_H_
#define _WLAND_AMSDU_H_

#define AMSDU_OPERATION_DEF         0   /* BIT0: AMSDU-TX, BIT1: DeAMSDU-RX */

extern uint amsdu_operation;

/* AMSDU-TX */
#define DEFAULT_AMSDU_TX_SIZE       (1200)
#define DEFAULT_AMSDU_TX_CNT        (6)
#define DEFAULT_AMSDU_TX_TIMEOUT    (3)
#define DEFAULT_AMSDU_TX_BYPASS     (20)

#define AMSDU_TX_MSDU_SZ            (120)
#define AMSDU_TX_DUMMY_HDR_SZ       (14)
#define AMSDU_TX_DUMMY_HDR_TYPE     (0xffff)

enum wland_amsdu_tx_mode {
    AMSDU_TX_MODE_DISABLED = 0,     /* Disabled */
    AMSDU_TX_MODE_AMSDU,            /* Only AMSDU */
    AMSDU_TX_MODE_AMSDU_IN_AMPDU,   /* Allow AMSDU-in-AMPDU */
};

struct wland_amsdu_tid_info {
    void *parent;
    spinlock_t aggr_lock;
    struct sk_buff *aggr_pkt;
    struct timer_list aggr_timer;
    unsigned long tx_time;
    int max_aggr_to;
    int max_aggr_sz;
    int max_aggr_cnt;
    int curr_aggr_sz;
    int curr_aggr_cnt;
    u32 curr_bypass;
};

struct wland_amsdu_info {
    struct wland_amsdu_tid_info amsdu_tid[8];
    spinlock_t amsdu_lock;
    u8 aggr_enabled;
};

void wland_amsdu_tx_init(struct wland_if *ifp);
void wland_amsdu_tx_deinit(struct wland_if *ifp);
void wland_amsdu_tx_conf(struct wland_if *ifp, u8 tid, u8 enable);
int wland_amsdu_tx(struct wland_if *ifp, struct sk_buff *pktbuf);

/* DEAMSDU-RX */
enum deamsdu_proc_e {
    DEAMSDU_PROC_WAIT_NEXT,
    DEAMSDU_PROC_MSDUS_DONE,
    DEAMSDU_PROC_ERROR,
};

enum deamsdu_rx_state_e {
    DEAMSDU_STATE_COMPLETE,
    DEAMSDU_STATE_WAIT_FIRST_MSDU,
    DEAMSDU_STATE_WAIT_LAST_MSDU,
};

void wland_deamsdu_rx_free(void *deamsdu_frame);
int wland_deamsdu_rx_indicatepkt(void *deamsdu_frame, struct wland_bus *bus_if);
enum deamsdu_proc_e wland_deamsdu_rx_process(void *deamsdu_frame, u16 seq);
#endif
