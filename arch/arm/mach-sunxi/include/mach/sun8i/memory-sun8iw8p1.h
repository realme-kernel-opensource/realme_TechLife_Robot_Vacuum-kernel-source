/*
 * arch/arm/mach-sunxi/include/mach/sun8i/memory-sun8iw8p1.h
 *
 * Copyright (c) 2013-2015 Allwinnertech Co., Ltd.
 *      http://www.allwinnertech.com
 *
 * Author: Sugar <shuge@allwinnertech.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef __MEMORY_SUN8I_W8P1_H
#define __MEMORY_SUN8I_W8P1_H

/* #define PLAT_PHYS_OFFSET         UL(0x40000000) */

#ifdef CONFIG_EVB_PLATFORM
#define PLAT_MEM_SIZE            SZ_2G
#else
#define PLAT_MEM_SIZE            SZ_256M
#endif

#define SYS_CONFIG_MEMBASE       (0x40000000 + SZ_16M)           /* 0x43000000 */
#define SYS_CONFIG_MEMSIZE       (SZ_128K)                                      /* 0x00020000 */

#define SUPER_STANDBY_MEM_BASE   (SYS_CONFIG_MEMBASE + SZ_512K) /* 0x43080000 */
#define SUPER_STANDBY_MEM_SIZE   (SZ_2K)                                        /* 0x00000800 */

#ifdef CONFIG_ANDROID_RAM_CONSOLE
#define RC_MEM_BASE              (SUPER_STANDBY_MEM_BASE + SUPER_STANDBY_MEM_SIZE)
#define RC_MEM_SIZE              (SZ_64K)
#endif

#endif /* __MEMORY_SUN8I_W8P1_H */
