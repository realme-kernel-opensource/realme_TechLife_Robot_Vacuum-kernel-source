#include <linux/version.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/regulator/consumer.h>
#include <linux/delay.h>

#include <asm/io.h>

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0))
#include <linux/printk.h>
#include <linux/err.h>
#else
#include <config/printk.h>
#endif

#include <linux/mmc/host.h>
#include <linux/sunxi-gpio.h>
#include <linux/power/aw_pm.h>

unsigned int oob_irq = 0;

//extern unsigned int oob_irq;
extern void sunxi_mmc_rescan_card(unsigned ids);
extern void sunxi_wlan_set_power(bool on);
extern int sunxi_wlan_get_bus_index(void);
extern int sunxi_wlan_get_oob_irq(void);
extern int sunxi_wlan_get_oob_irq_flags(void);
extern void sunxi_mmc_disable_power_save_mode_v4p1x(void);


extern int ssvdevice_init(void);
extern void ssvdevice_exit(void);


static irqreturn_t ssv_wifi_wakeup_irq_handler(int irq, void *dev)
{
    printk("== %s ==\n", __func__);
    /* Disable interrupt before calling handler */
    // disable_irq_nosync(irq);
    //wake_lock_timeout(&icomm_wake_lock, HZ);

    return IRQ_HANDLED;
}

void ssv_setup_wifi_wakeup(void)
{
    int err;

    oob_irq = sunxi_wlan_get_oob_irq();
    if (oob_irq <= 0) {
        printk("%s: oob_irq NULL\n", __func__);
        return; 
    }

    err = request_threaded_irq(oob_irq, 
                               ssv_wifi_wakeup_irq_handler, 
                               NULL, 
                               IRQF_TRIGGER_RISING,
                               "ssv_wakeup_irq",
                               NULL);
    printk("%s: set oob_irq:%d %s\n", __func__, oob_irq, (err < 0) ? "NG": "OK");
    enable_irq_wake(oob_irq);
}

void ssv_free_wifi_wakeup(void)
{
    if (oob_irq > 0) {
        disable_irq_wake(oob_irq);
        free_irq(oob_irq, NULL);    
        oob_irq = 0;
    }
}


int initWlan(void)
{
    int ret=0;
    int wlan_bus_index = 0;
    printk(KERN_INFO "wlan.c initWlan\n");
    printk("=======================================================\n");
    printk("=====  Launch WiFi Driver SSV6x5x  by  LdRobot   ======\n");
    printk("=======================================================\n");

    sunxi_mmc_disable_power_save_mode_v4p1x();
    sunxi_wlan_set_power(1);
    mdelay(100);

    wlan_bus_index = sunxi_wlan_get_bus_index();
    if(wlan_bus_index < 0){ 
            printk("get wifi_sdc_id failed\n");
            return -1; 
    } else {
            printk("----- %s sdc_id: %d\n", __FUNCTION__, wlan_bus_index);
            sunxi_mmc_rescan_card(wlan_bus_index);
    }   

    ssv_setup_wifi_wakeup();
    ret = ssvdevice_init();
    return ret;
}

void exitWlan(void)
{
    ssv_free_wifi_wakeup();
    ssvdevice_exit();

    sunxi_wlan_set_power(0);
    mdelay(100);
    printk("%s: remove card, power off.\n", __FUNCTION__);

    return;
}

static int generic_wifi_init_module(void)
{
	return initWlan();
}

static void generic_wifi_exit_module(void)
{
	exitWlan();
}

EXPORT_SYMBOL(generic_wifi_init_module);
EXPORT_SYMBOL(generic_wifi_exit_module);

#ifdef CONFIG_SSV6X5X //CONFIG_SSV6XXX=y
late_initcall(generic_wifi_init_module);
#else //CONFIG_SSV6X5X=m or =n
module_init(generic_wifi_init_module);
#endif
module_exit(generic_wifi_exit_module);

MODULE_LICENSE("Dual BSD/GPL");
