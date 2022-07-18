/*
 * nand_base.h for  SUNXI NAND .
 *
 * Copyright (C) 2016 Allwinner.
 *
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2.  This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */
#ifndef _NAND_BASE_H_
#define _NAND_BASE_H_

#include "nand_blk.h"
#include "nand_dev.h"

#define BLK_ERR_MSG_ON

extern struct nand_blk_ops mytr;
extern struct _nand_info *p_nand_info;
extern void NAND_Interrupt(__u32 nand_index);
extern __u32 NAND_GetCurrentCH(void);
extern int  init_blklayer(void);
extern void   exit_blklayer(void);
extern void set_cache_level(struct _nand_info *nand_info, unsigned short cache_level);
extern int NAND_get_storagetype(void);
extern __u32 PHY_erase_chip(void);
extern void set_capacity_level(struct _nand_info *nand_info, unsigned short capacity_level);
extern int NAND_Print_DBG(const char *fmt, ...);
extern void NAND_PhysicLock(void);
extern void NAND_PhysicUnLock(void);
extern int nand_thread(void *arg);

#endif
