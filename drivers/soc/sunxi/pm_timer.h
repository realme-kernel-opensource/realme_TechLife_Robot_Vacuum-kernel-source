/*
 * drivers/soc/sunxi/pm_timer.h
 * (C) Copyright 2017-2023
 * Allwinner Technology Co., Ltd. <www.allwinnertech.com>
 * fanqinghua <xuqiang@allwinnertech.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 */

#ifndef __AW_PM_TIMER_H_
#define __AW_PM_TIMER_H_
#include <asm/io.h>

typedef struct __MEM_TMR_REG {
	/*  offset:0x00 */
	volatile __u32 IntCtl;
	volatile __u32 IntSta;
	volatile __u32 reserved0[2];
	/*  offset:0x10 */
	volatile __u32 Tmr0Ctl;
	volatile __u32 Tmr0IntVal;
	volatile __u32 Tmr0CntVal;
	volatile __u32 reserved1;
	/*  offset:0x20 */
	volatile __u32 Tmr1Ctl;
	volatile __u32 Tmr1IntVal;
	volatile __u32 Tmr1CntVal;
	volatile __u32 reserved2;
	/*  offset:0x30 */
	volatile __u32 Tmr2Ctl;
	volatile __u32 Tmr2IntVal;
	volatile __u32 Tmr2CntVal;
	volatile __u32 reserved3;
} __mem_tmr_reg_t;


enum {
	TIMER_MODE_CONTINUE,
	TIMER_MODE_SINGLE,
};

enum {
	TIMER_SRC_LOSC,
	TIMER_SRC_OSC24M,
};

enum {
	TIMER_CLKPRES1,
	TIMER_CLKPRES2,
	TIMER_CLKPRES4,
	TIMER_CLKPRES8,
	TIMER_CLKPRES16,
	TIMER_CLKPRES32,
	TIMER_CLKPRES64,
	TIMER_CLKPRES128,
};


#endif

