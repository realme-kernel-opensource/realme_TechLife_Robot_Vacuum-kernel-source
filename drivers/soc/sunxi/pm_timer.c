/*
 * drivers/soc/sunxi/pm_timer.c
 * (C) Copyright 2017-2023
 * Allwinner Technology Co., Ltd. <www.allwinnertech.com>
 * fanqinghua <xuqiang@allwinnertech.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/suspend.h>
#include <linux/syscore_ops.h>
#include <linux/time.h>
#include <linux/timekeeping.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/of.h>

#include "pm.h"
#include "pm_timer.h"

#define TIMER0   0x0
#define TIMER1   0x1

#define TIMER_BASE    0x03009000
#define TIMER_INITVAL  0xffffffff

#define TIMER_MODE_SEL      TIMER_MODE_SINGLE
#define TIMER_SRC_SEL       TIMER_SRC_LOSC
#define TIMER_CLKPRES_SEL   TIMER_CLKPRES128
#define PM_USE_TIMERx       TIMER0


static int pm_tmr_start(int ch)
{
	volatile  u32 tmp = 0;

	/* config timer0 for mem */

	tmp  = (TIMER_SRC_SEL << 2)  | (0x1 << 1);	/* clk src */
	tmp |= (TIMER_MODE_SEL << 7) | (TIMER_CLKPRES_SEL << 4);	/* single mode | prescale */

	writel(tmp, ioremap((TIMER_BASE + 0x10 + 0x10*ch), 4));

	writel(TIMER_INITVAL, ioremap((TIMER_BASE + 0x14 + 0x10*ch), 4));

	/* start */
	writel(tmp|0x1, ioremap((TIMER_BASE + 0x10 + 0x10*ch), 4));

	return 0;
}

static int pm_tmr_stop(int ch)
{
	volatile  u32 tmp = 0;

	/* stop */
	tmp  = readl(ioremap((TIMER_BASE + 0x10 + 0x10*ch), 4));
	tmp &= ~0x1;
	writel(tmp, ioremap((TIMER_BASE + 0x10 + 0x10*ch), 4));

	return 0;
}

static u32 pm_tmr_count(int ch)
{
	volatile  u32 initval = readl(ioremap((TIMER_BASE + 0x14 + 0x10*ch), 4));
	volatile  u32 curval = readl(ioremap((TIMER_BASE + 0x18 + 0x10*ch), 4));

	pr_info("initval: %u\n", initval);
	pr_info("curval: %u\n", curval);

	if (initval > curval)
		return (initval - curval);
	else
		return (TIMER_INITVAL - curval + initval);
}


int sunxi_pm_timer_timing(struct device *dev)
{
	pr_info("call  %s...\n", __func__);

	pm_tmr_start(PM_USE_TIMERx);

	return 0;
}

int sunxi_pm_timer_compensate(struct device *dev)
{
	struct timespec64 sleep_time = {0};

	volatile u32 tmr_cnt  =  (u64)pm_tmr_count(PM_USE_TIMERx);
	volatile u32 tmr_coef =  (TIMER_SRC_SEL == TIMER_SRC_LOSC) ? 250 : 187500;

	pr_info("call  %s...\n", __func__);

	pm_tmr_stop(PM_USE_TIMERx);

	printk("--->tmr_cnt:  %u\n", tmr_cnt);
	printk("--->tmr_coef:  %u\n", tmr_coef);

	sleep_time.tv_sec  = tmr_cnt / tmr_coef;
	sleep_time.tv_nsec = 0;

	printk("--->sleeptime  sec: %lld\n", sleep_time.tv_sec);
	printk("--->sleeptime nsec: %ld\n", sleep_time.tv_nsec);

	if (sleep_time.tv_sec >= 0)
		timekeeping_inject_sleeptime64(&sleep_time);

	return 0;
}

int pm_timer_probe(struct platform_device *dev)
{
	pr_info("call  %s...\n", __func__);
	return 0;
}

int pm_timer_remove(struct platform_device *dev)
{
	pr_info("call  %s...\n", __func__);
	return 0;
}

static const struct of_device_id dt_ids[] = {
	{.compatible = "allwinner,pm_timer"},
	{},
};


const struct dev_pm_ops sunxi_pm_timer_ops = {
	.suspend_late = sunxi_pm_timer_timing,
	.resume_early = sunxi_pm_timer_compensate,
};

static struct platform_driver pm_timer_driver = {
	.driver = {
		   .name = "pm_timer",
		   .pm = &sunxi_pm_timer_ops,
		   .of_match_table = of_match_ptr(dt_ids),
		   },
	.probe = pm_timer_probe,
	.remove = pm_timer_remove,
};

static int pm_timer_init(void)
{
	int ret;

	ret = platform_driver_register(&pm_timer_driver);
	if (ret)
		pr_err("platform_driver_register() failed: %d\n", ret);

	return ret;
}

static void pm_timer_exit(void)
{
	platform_driver_unregister(&pm_timer_driver);
}

module_init(pm_timer_init);
module_exit(pm_timer_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Frank & Martin");
MODULE_DESCRIPTION("Allwinner pm timer");

