#define pr_fmt(x) KBUILD_MODNAME ": " x "\n"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/param.h>
#include <linux/jiffies.h>
#include <linux/platform_device.h>
#include <linux/power_supply.h>
#include <linux/fs.h>
#include <linux/of.h>
#include <linux/types.h>
#include <linux/string.h>
#include <asm/irq.h>
#include <linux/cdev.h>
#include <linux/delay.h>
#include <linux/pm_runtime.h>
#include <linux/gpio/consumer.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include "../axp-core.h"

#include <linux/err.h>
#include "../../drivers/gpio/gpiolib.h"
#include "axp2101.h"
#include "axp2101-chg.h"
/* #define DONOT_Correction */
/* #define POLL_READ */
#define SOC_RISE_INTERVAL (30)
#define POLL_INTERVAL     (1 * HZ)

#define AXP210X_MASK_WDT    (0x1 << 3)
#define AXP210X_MASK_OT     (0x1 << 2)
#define AXP210X_MASK_NEWSOC (0x1 << 1)
#define AXP210X_MASK_LOWSOC (0x1 << 0)

#define AXP210X_MODE_RSTMCU (0x1 << 2)
#define AXP210X_MODE_POR    (0x1 << 4)
#define AXP210X_MODE_SLEEP  (0x1 << 0)

#define AXP210X_CFG_ENWDT       (0x1 << 5)
#define AXP210X_CFG_UPDATE_MARK (0x1 << 4)
#define AXP210X_CFG_BROMUP      (0x1 << 0)

#define AXP210X_MASK_VBUS_STATE (BIT(5))

#define AXP210X_VBAT_MAX        (8000)
#define AXP210X_VBAT_MIN        (2000)
#define AXP210X_SOC_MAX         (100)
#define AXP210X_SOC_MIN         (0)

/* when charge plugged , charger_plugged = 1,  remove is 0 */
int charger_plugged = 1;
EXPORT_SYMBOL_GPL(charger_plugged);

/*
struct class *my_class;
struct cdev cdev;
dev_t devno;
*/

#ifdef AXP2101_DEBUG
u32 debug_level = XPOWER_DBG_DEFAULT;
#endif

struct axp210x_device_info *axp210x_info;

static enum power_supply_property axp2101_props[] = {
	POWER_SUPPLY_PROP_PRESENT,
	POWER_SUPPLY_PROP_VOLTAGE_NOW,
	POWER_SUPPLY_PROP_CAPACITY,
	POWER_SUPPLY_PROP_CAPACITY_ALERT_MIN,
	POWER_SUPPLY_PROP_TEMP,
	POWER_SUPPLY_PROP_TEMP_ALERT_MIN,
	POWER_SUPPLY_PROP_TIME_TO_EMPTY_NOW,
	POWER_SUPPLY_PROP_TIME_TO_FULL_NOW,
	POWER_SUPPLY_PROP_MANUFACTURER,
	POWER_SUPPLY_PROP_CAPACITY_LEVEL,
};

static enum power_supply_property axp2101_usb_ac_props[] = {
	POWER_SUPPLY_PROP_PRESENT,
	POWER_SUPPLY_PROP_ONLINE,
};
/* not test yelt
static enum power_supply_property axp2602_props[] = {
	POWER_SUPPLY_PROP_STATUS,
	...
};
*/
static unsigned char axp2101_model[] = {

	0x01, 0xF5, 0x00, 0x00, 0xFB, 0x00, 0x00, 0xFB, 0x00, 0x1E, 0x32, 0x01,
	0x14, 0x04, 0xD8, 0x04, 0x74, 0xFD, 0x58, 0x0B, 0xB3, 0x10, 0x3F, 0xFB,
	0xC8, 0x00, 0xBE, 0x03, 0x4E, 0x06, 0x3F, 0x06, 0x02, 0x0A, 0xD3, 0x0F,
	0x74, 0x0F, 0x31, 0x09, 0xE5, 0x0E, 0xB9, 0x0E, 0xC0, 0x04, 0xBE, 0x04,
	0xBB, 0x09, 0xB4, 0x0E, 0xA0, 0x0E, 0x92, 0x09, 0x79, 0x0E, 0x4C, 0x0E,
	0x27, 0x03, 0xFC, 0x03, 0xD5, 0x08, 0xBC, 0x0D, 0x9C, 0x0D, 0x55, 0x06,
	0xB8, 0x2E, 0x24, 0x2E, 0x2E, 0x24, 0x2E, 0x24, 0xC5, 0x98, 0x7E, 0x66,
	0x4E, 0x44, 0x38, 0x1A, 0x12, 0x0A, 0xF6, 0x00, 0x00, 0xF6, 0x00, 0xF6,
	0x00, 0xFB, 0x00, 0x00, 0xFB, 0x00, 0x00, 0xFB, 0x00, 0x00, 0xF6, 0x00,
	0x00, 0xF6, 0x00, 0xF6, 0x00, 0xFB, 0x00, 0x00, 0xFB, 0x00, 0x00, 0xFB,
	0x00, 0x00, 0xF6, 0x00, 0x00, 0xF6, 0x00, 0xF6,
};

static struct axp210x_model_data axp2101_model_data = {
	.model = axp2101_model,
	.model_size = ARRAY_SIZE(axp2101_model),
};

static uint8_t axp2101_regaddrs[] = {
	[AXP210X_REG_BROM]        = 0xA1,
	[AXP210X_REG_MODE]        = 0x17,
	[AXP210X_REG_COMSTAT0]    = 0x00,
	[AXP210X_REG_CONFIG]      = 0xA2,
	[AXP210X_REG_VBAT]        = 0x34,
	[AXP210X_REG_TM]          = 0x3C,
	[AXP210X_REG_SOC]         = 0xA4,
	[AXP210X_REG_T2E]         = 0xA6,
	[AXP210X_REG_T2F]         = 0xA8,
	[AXP210X_REG_LOWSOC]      = 0x1a,
	[AXP210X_REG_IIN_LIM]     = 0x16,
	[AXP210X_REG_ICC_CFG]     = 0x62,
	/* [AXP210X_REG_IRQ] = 0x20, */
	/* [AXP210X_REG_IRQMASK] = 0x21, */
};

static int axp210x_read_vbat(union power_supply_propval *val)
{
	uint8_t data[2];
	uint16_t vtemp[3], tempv;
	int ret = 0;
	uint8_t i;

	for (i = 0; i < 3; i++) {
		ret = axp210x_info->read(
			axp210x_info->regaddrs[AXP210X_REG_VBAT], data, 2);
		if (ret < 0)
			return ret;

		vtemp[i] = (((data[0] & GENMASK(5, 0)) << 0x08) | (data[1]));
	}
	if (vtemp[0] > vtemp[1]) {
		tempv = vtemp[0];
		vtemp[0] = vtemp[1];
		vtemp[1] = tempv;
	}
	if (vtemp[1] > vtemp[2]) {
		tempv = vtemp[1];
		vtemp[1] = vtemp[2];
		vtemp[2] = tempv;
	}
	if (vtemp[0] > vtemp[1]) {
		tempv = vtemp[0];
		vtemp[0] = vtemp[1];
		vtemp[1] = tempv;
	}
	/*incase vtemp[1] exceed AXP210X_VBAT_MAX */
	if ((vtemp[1] > AXP210X_VBAT_MAX) || (vtemp[1] < AXP210X_VBAT_MIN)) {
		val->intval = axp210x_info->regcache.vbat;
		return 0;
	}
	axp210x_info->regcache.vbat = vtemp[1];
	val->intval = vtemp[1];
	return 0;
}

/* read temperature */
static int axp210x_read_temp(union power_supply_propval *val)
{
	uint8_t data[2];
	int ret = 0;
	ret = axp210x_info->read(axp210x_info->regaddrs[AXP210X_REG_TM], data,
				 2);
	if (ret < 0)
		return ret;
	axp210x_info->regcache.temp = (data[0] << 8) + data[1];
	val->intval = axp210x_info->regcache.temp;
	return 0;
}

static int axp210x_read_soc(union power_supply_propval *val)
{
	uint8_t data[2];
#ifdef DONOT_Correction
	static long int lasttime;
	struct timeval sysday;
#endif
	int ret = 0;
	ret = axp210x_info->read(axp210x_info->regaddrs[AXP210X_REG_SOC], data,
				 1);
	if (ret < 0)
		return ret;
	if (data[0] > AXP210X_SOC_MAX)
		data[0] = AXP210X_SOC_MAX;
	else if (data[0] < AXP210X_SOC_MIN)
		data[0] = AXP210X_SOC_MIN;
#ifdef DONOT_Correction
	if (charger_plugged) {
		do_gettimeofday(&sysday);
		printk("systime = %ld, lastime = %ld \r\n", sysday.tv_sec,
		       lasttime);
		if (lasttime == 0) {
			lasttime = sysday.tv_sec;
		}
		if (data[0] > axp210x_info->regcache.soc) {
			if (axp210x_info->regcache.soc < 92) {
				if (sysday.tv_sec - lasttime >
				    (SOC_RISE_INTERVAL)) {
					axp210x_info->regcache.soc++;
					val->intval =
						axp210x_info->regcache.soc;
					lasttime = sysday.tv_sec;
					//					printk("no
					//corrention socreal = %d, socnow = %d
					//\r\n",data[0],
					//axp210x_info->regcache.soc);
				}
			} else if (axp210x_info->regcache.soc >= 92) {
				if (sysday.tv_sec - lasttime >
				    (SOC_RISE_INTERVAL *
				     (axp210x_info->regcache.soc - 92))) {
					axp210x_info->regcache.soc++;
					val->intval =
						axp210x_info->regcache.soc;
					lasttime = sysday.tv_sec;
					//					printk("no
					//corrention socreg = %d, socnow = %d
					//\r\n",data[0],
					//axp210x_info->regcache.soc);
				}
			}
		} else if (data[0] < axp210x_info->regcache.soc) {
			axp210x_info->regcache.soc--;
			val->intval = axp210x_info->regcache.soc;
		}

	} else {
		if (data[0] < axp210x_info->regcache.soc) {
			axp210x_info->regcache.soc--;
			val->intval = axp210x_info->regcache.soc;
			lasttime = 0;
		}
	}
#else
	axp210x_info->regcache.soc = data[0];
	val->intval = data[0];
#endif
	return 0;
}

static int axp210x_read_time2empty(union power_supply_propval *val)
{
	uint8_t data[2];
	uint16_t ttemp[3], tempt;
	int ret = 0;
	uint8_t i;

	for (i = 0; i < 3; i++) {
		ret = axp210x_info->read(
			axp210x_info->regaddrs[AXP210X_REG_T2E], data, 2);
		if (ret < 0)
			return ret;
		ttemp[i] = ((data[0] << 0x08) | (data[1]));
	}
	if (ttemp[0] > ttemp[1]) {
		tempt = ttemp[0];
		ttemp[0] = ttemp[1];
		ttemp[1] = tempt;
	}
	if (ttemp[1] > ttemp[2]) {
		tempt = ttemp[1];
		ttemp[1] = ttemp[2];
		ttemp[2] = tempt;
	}
	if (ttemp[0] > ttemp[1]) {
		tempt = ttemp[0];
		ttemp[0] = ttemp[1];
		ttemp[1] = tempt;
	}
	axp210x_info->regcache.t2e = ttemp[1];
	val->intval = ttemp[1];
	return 0;
}

static int axp210x_read_vbus_state(union power_supply_propval *val)
{
	int ret = 0;
	uint8_t data;

	ret = axp210x_info->read(axp210x_info->regaddrs[AXP210X_REG_COMSTAT0],
				 &data, 1);
	if (ret < 0)
		return ret;
	/* vbus is good when vbus state set */
	val->intval = !!(data & AXP210X_MASK_VBUS_STATE);

	return ret;
}

static int axp210x_read_time2full(union power_supply_propval *val)
{
	uint8_t data[2];
	uint16_t ttemp[3], tempt;
	int ret = 0;
	uint8_t i;

	for (i = 0; i < 3; i++) {
		ret = axp210x_info->read(
			axp210x_info->regaddrs[AXP210X_REG_T2F], data, 2);
		if (ret < 0)
			return ret;
		ttemp[i] = ((data[0] << 0x08) | (data[1]));
	}
	if (ttemp[0] > ttemp[1]) {
		tempt = ttemp[0];
		ttemp[0] = ttemp[1];
		ttemp[1] = tempt;
	}
	if (ttemp[1] > ttemp[2]) {
		tempt = ttemp[1];
		ttemp[1] = ttemp[2];
		ttemp[2] = tempt;
	}
	if (ttemp[0] > ttemp[1]) {
		tempt = ttemp[0];
		ttemp[0] = ttemp[1];
		ttemp[1] = tempt;
	}
	axp210x_info->regcache.t2f = ttemp[1];
	val->intval = ttemp[1];
	return 0;
}

static int axp210x_read_lowsocth(union power_supply_propval *val)
{
	uint8_t data[2];
	int ret = 0;
	ret = axp210x_info->read(axp210x_info->regaddrs[AXP210X_REG_LOWSOC],
				 data, 1);
	if (ret < 0)
		return ret;
	axp210x_info->regcache.lowsocth = data[0] >> 4;
	val->intval = data[0];
	return 0;
}

static int axp210x_set_lowsocth(uint8_t val)
{
	int ret = 0;
	uint8_t data[2];

	data[0] = val;

	if (data[0] > 20)
		return -EINVAL;
	axp210x_info->read(axp210x_info->regaddrs[AXP210X_REG_LOWSOC], data, 1);
	if (ret < 0)
		return ret;

	data[0] &= ~GENMASK(7, 4);
	data[0] |= val << 4;
	ret = axp210x_info->write(axp210x_info->regaddrs[AXP210X_REG_LOWSOC],
				  data, 1);
	if (ret < 0)
		return ret;

	return 0;
}

static int axp210x_reset_mcu(void)
{
	int ret = 0;
	uint8_t data[2];

	ret = axp210x_info->read(axp210x_info->regaddrs[AXP210X_REG_MODE], data,
				 1);
	if (ret < 0)
		return ret;
	data[0] |= AXP210X_MODE_RSTMCU;
	ret = axp210x_info->write(axp210x_info->regaddrs[AXP210X_REG_MODE],
				  data, 1);
	if (ret < 0)
		return ret;
	data[0] &= ~AXP210X_MODE_RSTMCU;
	ret = axp210x_info->write(axp210x_info->regaddrs[AXP210X_REG_MODE],
				  data, 1);
	if (ret < 0)
		return ret;

	return 0;
}

int axp210x_model_update(void)
{
	int ret = 0;
	uint8_t data[2];
	uint8_t para[axp210x_info->data.model_size];
	uint8_t i;

	/* reset_mcu */
	ret = axp210x_reset_mcu();
	if (ret < 0)
		goto UPDATE_ERR;

	/* reset and open brom */
	ret = axp210x_info->read(axp210x_info->regaddrs[AXP210X_REG_CONFIG],
				 data, 1);
	if (ret < 0)
		goto UPDATE_ERR;
	data[0] &= ~AXP210X_CFG_BROMUP;
	ret = axp210x_info->write(axp210x_info->regaddrs[AXP210X_REG_CONFIG],
				  data, 1);
	if (ret < 0)
		goto UPDATE_ERR;
	data[0] |= AXP210X_CFG_BROMUP;
	ret = axp210x_info->write(axp210x_info->regaddrs[AXP210X_REG_CONFIG],
				  data, 1);
	if (ret < 0)
		goto UPDATE_ERR;

	/* down load battery parameters */
	for (i = 0; i < axp210x_info->data.model_size; i++) {
		ret = axp210x_info->write(
			axp210x_info->regaddrs[AXP210X_REG_BROM],
			&axp210x_info->data.model[i], 1);
	}
	if (ret < 0)
		goto UPDATE_ERR;

	/* reset and open brom */
	ret = axp210x_info->read(axp210x_info->regaddrs[AXP210X_REG_CONFIG],
				 data, 1);
	if (ret < 0)
		goto UPDATE_ERR;
	data[0] &= ~AXP210X_CFG_BROMUP;
	ret = axp210x_info->write(axp210x_info->regaddrs[AXP210X_REG_CONFIG],
				  data, 1);
	if (ret < 0)
		goto UPDATE_ERR;
	data[0] |= AXP210X_CFG_BROMUP;
	ret = axp210x_info->write(axp210x_info->regaddrs[AXP210X_REG_CONFIG],
				  data, 1);
	if (ret < 0)
		goto UPDATE_ERR;
	/* check battery parameters is ok ? */
	for (i = 0; i < axp210x_info->data.model_size; i++) {
		axp210x_info->read(axp210x_info->regaddrs[AXP210X_REG_BROM],
				   &para[i], 1);
		if (para[i] != axp210x_info->data.model[i]) {
			axp210x_warn(
				"model [%d] para reading %02x != write %02x\n",
				i, para[i], axp210x_info->data.model[i]);
			ret = -EINVAL;
			//	goto UPDATE_ERR;
		}
	}
	if (ret < 0)
		goto UPDATE_ERR;

	/* close brom and set battery update flag */
	ret = axp210x_info->read(axp210x_info->regaddrs[AXP210X_REG_CONFIG],
				 data, 1);
	if (ret < 0)
		goto UPDATE_ERR;
	data[0] &= ~AXP210X_CFG_BROMUP;
	data[0] |= AXP210X_CFG_UPDATE_MARK;
	ret = axp210x_info->write(axp210x_info->regaddrs[AXP210X_REG_CONFIG],
				  data, 1);
	ret = axp210x_info->read(axp210x_info->regaddrs[AXP210X_REG_CONFIG],
				 data, 1);
	if (ret < 0)
		goto UPDATE_ERR;

	/* reset_mcu */
	ret = axp210x_reset_mcu();
	if (ret < 0)
		goto UPDATE_ERR;

	/* update ok */
	return 0;

UPDATE_ERR:
	axp210x_info->read(axp210x_info->regaddrs[AXP210X_REG_CONFIG], data, 1);
	data[0] &= ~AXP210X_CFG_BROMUP;
	axp210x_info->write(axp210x_info->regaddrs[AXP210X_REG_CONFIG], data, 1);
	axp210x_reset_mcu();
	return ret;
}


static bool axp210x_model_update_check(void)
{
	int ret = 0;
	uint8_t data[2];
	ret = axp210x_info->read(axp210x_info->regaddrs[AXP210X_REG_CONFIG], data, 1);
	if (ret < 0)
		goto CHECK_ERR;
	if ((data[0] & AXP210X_CFG_UPDATE_MARK) == 0)
		goto CHECK_ERR;

#if 0
	/* if need check every bytes of battery parameters , due to battery parameters changed */
	/* reset and open brom */
	ret = axp210x_info->read(axp210x_info->regaddrs[AXP210X_REG_CONFIG], data, 1);
	if (ret < 0)
		goto CHECK_ERR;
	data[0] &= ~AXP210X_CFG_BROMUP;
	ret = axp210x_info->write(axp210x_info->regaddrs[AXP210X_REG_CONFIG], data, 1);
	if (ret < 0)
		goto CHECK_ERR;
	data[0] |= AXP210X_CFG_BROMUP;
	ret = axp210x_info->write(axp210x_info->regaddrs[AXP210X_REG_CONFIG], data, 1);
	if (ret < 0)
		goto CHECK_ERR;
	/* check battery parameters is ok ? */
	for (i = 0; i < axp210x_info->data.model_size; i++) {
		axp210x_info->read(axp210x_info->regaddrs[AXP210X_REG_BROM], &para[i], 1);
		//  if (ret < 0)
		//	break;
		if (para[i] != axp210x_info->data.model[i]) {
			axp210x_warn("model [%d] para reading %02x != write %02x\n", i, para[i], axp210x_info->data.model[i]);
			ret = -EINVAL;
			//	break;
		}
	}
	if (ret < 0) {
		ret = axp210x_reset_mcu();
		if (ret < 0)
			goto CHECK_ERR;
		ret = axp210x_info->read(axp210x_info->regaddrs[AXP210X_REG_CONFIG], data, 1);
		if (ret < 0)
			goto CHECK_ERR;
		data[0] &= ~AXP210X_CFG_BROMUP;
		ret = axp210x_info->write(axp210x_info->regaddrs[AXP210X_REG_CONFIG], data, 1);
		if (ret < 0)
			goto CHECK_ERR;
		data[0] |= AXP210X_CFG_BROMUP;
		ret = axp210x_info->write(axp210x_info->regaddrs[AXP210X_REG_CONFIG], data, 1);
		if (ret < 0)
			goto CHECK_ERR;
		/* check battery parameters is ok ? */
		for (i = 0; i < axp210x_info->data.model_size; i++) {
			axp210x_info->read(axp210x_info->regaddrs[AXP210X_REG_BROM], &para[i], 1);
			//if (ret < 0)
			//	goto CHECK_ERR;
			if (para[i] != axp210x_info->data.model[i]) {
				axp210x_warn("model [%d] para reading %02x != write %02x\n", i, para[i], axp210x_info->data.model[i]);
				ret = -EINVAL;
				//	goto CHECK_ERR;
			}
		}
		if (ret < 0)
			goto CHECK_ERR;
	}
	ret = axp210x_info->read(axp210x_info->regaddrs[AXP210X_REG_CONFIG], data, 1);
	if (ret < 0)
		goto CHECK_ERR;

	data[0] &= ~AXP210X_CFG_BROMUP;
	ret = axp210x_info->write(axp210x_info->regaddrs[AXP210X_REG_CONFIG], data, 1);
	if (ret < 0)
		goto CHECK_ERR;

#endif

	return true;

CHECK_ERR:

	axp210x_info->read(axp210x_info->regaddrs[AXP210X_REG_CONFIG], data, 1);
	data[0] &= ~AXP210X_CFG_BROMUP;
	ret = axp210x_info->write(axp210x_info->regaddrs[AXP210X_REG_CONFIG], data, 1);
	axp210x_reset_mcu();
	return false;
}

static int axp210x_reg_update(void)
{
	int ret = 0;
	uint8_t data[2];

	data[0] = 0x10;
	ret = axp210x_info->write(0x50, data, 1);
	if (ret < 0)
		return ret;

	ret = axp210x_info->read(axp210x_info->regaddrs[AXP210X_REG_CONFIG],
				 data, 1); // 0x03,
	if (ret < 0)
		return ret;
	axp210x_info->regcache.config.byte = data[0];

	ret = axp210x_info->read(axp210x_info->regaddrs[AXP210X_REG_VBAT], data,
				 2);
	if (ret < 0)
		return ret;
	axp210x_info->regcache.vbat =
		((data[0] & GENMASK(5, 0)) << 8) + data[1];

	ret = axp210x_info->read(axp210x_info->regaddrs[AXP210X_REG_TM], data,
				 2);
	axp210x_info->regcache.temp = (data[0] << 8) + data[1];
	if (ret < 0)
		return ret;

	ret = axp210x_info->read(axp210x_info->regaddrs[AXP210X_REG_SOC], data, 1);
	axp210x_info->regcache.soc = data[0];
	if (ret < 0)
		return ret;
	ret = axp210x_info->read(axp210x_info->regaddrs[AXP210X_REG_T2E], data, 2);
	if (ret < 0)
		return ret;
	axp210x_info->regcache.t2e = (data[0] << 8) + data[1];
	ret = axp210x_info->read(axp210x_info->regaddrs[AXP210X_REG_T2F], data, 2);
	if (ret < 0)
		return ret;
	axp210x_info->regcache.t2f = (data[0] << 8) + data[1];

	ret = axp210x_info->read(axp210x_info->regaddrs[AXP210X_REG_LOWSOC], data, 1);
	axp210x_info->regcache.lowsocth = data[0] >> 4;
	if (ret < 0)
		return ret;

	return 0;
}

static int axp210x_usb_ac_get_property(struct power_supply *psy,
				       enum power_supply_property psp,
				       union power_supply_propval *val)
{
	int ret = 0;

	switch (psp) {
	case POWER_SUPPLY_PROP_ONLINE:
	case POWER_SUPPLY_PROP_PRESENT:
		ret = axp210x_read_vbus_state(val);
		break;
	default:
		break;
	}

	return ret;
}

static int axp210x_get_property(struct power_supply *psy,
				enum power_supply_property psp,
				union power_supply_propval *val)
{
	int ret = 0;

	pr_debug("get_property:");
	switch (psp) {
	case POWER_SUPPLY_PROP_CAPACITY_LEVEL:							//customer modify
		if (axp210x_info->regcache.soc == 100)
			val->intval = POWER_SUPPLY_CAPACITY_LEVEL_FULL;
		else if (axp210x_info->regcache.soc > 80)
			val->intval = POWER_SUPPLY_CAPACITY_LEVEL_HIGH;
		else if (axp210x_info->regcache.soc > axp210x_info->regcache.lowsocth)
			val->intval = POWER_SUPPLY_CAPACITY_LEVEL_NORMAL;
		else if (axp210x_info->regcache.soc < axp210x_info->regcache.lowsocth)
			val->intval = POWER_SUPPLY_CAPACITY_LEVEL_LOW;
		else if (axp210x_info->regcache.soc <= 1)
			val->intval = POWER_SUPPLY_CAPACITY_LEVEL_CRITICAL;
		else
			val->intval = POWER_SUPPLY_CAPACITY_LEVEL_UNKNOWN;
		break;
	case POWER_SUPPLY_PROP_PRESENT:
		ret = axp210x_read_vbat(val);
		val->intval = axp210x_info->regcache.vbat > 0 ? 1 : 0;
		break;
	case POWER_SUPPLY_PROP_VOLTAGE_NOW:
		ret = axp210x_read_vbat(val);
		val->intval = val->intval * 1000; 											//unit uV;
		break;
	case POWER_SUPPLY_PROP_CAPACITY:
		ret = axp210x_read_soc(val);								//unit %;
		break;
	case POWER_SUPPLY_PROP_CAPACITY_ALERT_MIN:
		ret = axp210x_read_lowsocth(val);							//unit %;
		break;
	case POWER_SUPPLY_PROP_TEMP:
		ret = axp210x_read_temp(val);								//unit degree celsius
		break;
	case POWER_SUPPLY_PROP_TEMP_ALERT_MIN:							//unit degree celsius
		val->intval = 85;
		break;
	case POWER_SUPPLY_PROP_TIME_TO_EMPTY_NOW:
		ret = axp210x_read_time2empty(val);
		val->intval = val->intval * 60;												//unit second
		break;
	case POWER_SUPPLY_PROP_TIME_TO_FULL_NOW:
		ret = axp210x_read_time2full(val);
		val->intval = val->intval * 60;												//unit second
		break;
	case POWER_SUPPLY_PROP_MANUFACTURER:
		val->strval = AXP210X_MANUFACTURER;
		break;
	default:
		return -EINVAL;
	}
	return ret;
}

static int axp210x_set_property(struct power_supply *psy,
				enum power_supply_property psp,
				const union power_supply_propval *val)
{
	int ret = 0;

	if (psp != POWER_SUPPLY_PROP_CAPACITY_ALERT_MIN)
		ret = -EINVAL;
	else
		ret = axp210x_set_lowsocth((uint8_t) val->intval);

	pm_runtime_put_sync(axp210x_info->dev);
	return ret;
}

static int axp210x_writeable(struct power_supply *psy,
			     enum power_supply_property psp)
{
	int ret = 0;

	if (psp != POWER_SUPPLY_PROP_CAPACITY_ALERT_MIN)
		ret = -EINVAL;
	else
		ret = 0;

	return ret;
}

int axp210x_register_battery(struct axp210x_device_info *di)
{
	int ret = 0;
	struct power_supply_desc *psy_desc;
	struct power_supply_desc *usb_desc, *ac_desc;
	struct power_supply_config psy_cfg = {
		.of_node = di->dev->of_node,
		.drv_data = di,
	};

	psy_desc = devm_kzalloc(di->dev, sizeof(*psy_desc), GFP_KERNEL);
	if (!psy_desc)
		return -ENOMEM;

	psy_desc->name = "battery";
	psy_desc->type = POWER_SUPPLY_TYPE_BATTERY;
	psy_desc->properties = axp2101_props;
	psy_desc->num_properties = ARRAY_SIZE(axp2101_props);
	psy_desc->get_property = axp210x_get_property;
	psy_desc->set_property = axp210x_set_property;
	psy_desc->property_is_writeable = axp210x_writeable;

	di->bat = power_supply_register(di->dev, psy_desc, &psy_cfg);
	if (IS_ERR(di->bat)) {
		axp210x_err("failed to register battery\n");
		ret = PTR_ERR(di->bat);
		return ret;
	}

	usb_desc = devm_kzalloc(di->dev, sizeof(*usb_desc), GFP_KERNEL);
	if (!usb_desc) {
		ret = -ENOMEM;
		goto err1;
	}

	usb_desc->name = "usb";
	usb_desc->type = POWER_SUPPLY_TYPE_USB;
	usb_desc->properties = axp2101_usb_ac_props;
	usb_desc->num_properties = ARRAY_SIZE(axp2101_usb_ac_props);
	usb_desc->get_property = axp210x_usb_ac_get_property;
	usb_desc->set_property = NULL;
	usb_desc->property_is_writeable = NULL;

	di->usb = power_supply_register(di->dev, usb_desc, &psy_cfg);
	if (IS_ERR(di->usb)) {
		axp210x_err("failed to register usb\n");
		ret = PTR_ERR(di->bat);
		goto err1;
	}

	ac_desc = devm_kzalloc(di->dev, sizeof(*ac_desc), GFP_KERNEL);
	if (!ac_desc) {
		ret = -ENOMEM;
		goto err2;
	}

	ac_desc->name = "ac";
	ac_desc->type = POWER_SUPPLY_TYPE_MAINS;
	ac_desc->properties = axp2101_usb_ac_props;
	ac_desc->num_properties = ARRAY_SIZE(axp2101_usb_ac_props);
	ac_desc->get_property = axp210x_usb_ac_get_property;
	ac_desc->set_property = NULL;
	;
	ac_desc->property_is_writeable = NULL;

	di->ac = power_supply_register(di->dev, ac_desc, &psy_cfg);
	if (IS_ERR(di->ac)) {
		axp210x_err("failed to register battery\n");
		ret = PTR_ERR(di->bat);
		goto err2;
	}

	return ret;

err2:
	power_supply_unregister(di->usb);
err1:
	power_supply_unregister(di->bat);

	return ret;
}

void axp210x_teardown_battery(struct axp210x_device_info *di)
{
	if (di->bat)
		power_supply_unregister(di->bat);

	if (di->ac)
		power_supply_unregister(di->ac);

	if (di->usb)
		power_supply_unregister(di->usb);
}

int axp210x_init_chip(struct axp210x_device_info *di)
{
	int ret = 0;

	if (di == NULL) {
		axp210x_err("axp210x_info is invalid!\n");
		return -ENODEV;
	}

	ret = axp210x_reg_update();
	if (ret < 0) {
		axp210x_err("axp210x reg update, i2c communication err!\n");
		return ret;
	}

	if (!axp210x_model_update_check()) {
		ret = axp210x_model_update();
		if (ret < 0) {
			axp210x_err("axp210x model update fail!\n");
			return ret;
		}
	}
	axp210x_debug("axp210x model update ok\n");

	/* after 500ms can read soc */
	ret = axp210x_reg_update();
	if (ret < 0) {
		axp210x_err("axp210x reg update, i2c communication err!\n");
		return ret;
	}

	return ret;
}

static irqreturn_t axp210x_irq_handler_thread(int irq, void *data)
{
	int ret = 0;

	struct axp210x_device_info *di = data;

	union power_supply_propval val;
	pr_debug("%s: enter interrupt %d\n", __func__, irq);

	power_supply_changed(di->bat);
	switch (irq) {
	case axp2101_IRQ_CHGDN:
		pr_debug("interrupt:charger done");
		break;
	case axp2101_IRQ_CHGST:
		pr_debug("interrutp:charger start");
		break;
	case axp2101_IRQ_BINSERT:
		pr_debug("interrupt:battery insert");
		break;
	case axp2101_IRQ_BREMOV:
		pr_debug("interrupt:battery remove");
		break;
	default:
		pr_debug("interrupt:others");
		break;
	}

	ret = axp210x_read_soc(&val);
	if (ret != 0)
		printk(KERN_ALERT "%s: soc update fail!\n", __FUNCTION__);
	ret = axp210x_read_vbat(&val);
	if (ret != 0)
		printk(KERN_ALERT "%s: vbat update fail!\n", __FUNCTION__);

	ret = axp210x_read_temp(&val);
	if (ret != 0)
		printk(KERN_ALERT "%s: temprature update fail!\n", __FUNCTION__);

	ret = axp210x_read_time2empty(&val);
	if (ret != 0)
		printk(KERN_ALERT "%s: time2empty update fail!\n", __FUNCTION__);

	ret = axp210x_read_time2full(&val);
	if (ret != 0)
		printk(KERN_ALERT "%s: time2full update fail!\n", __FUNCTION__);

	/*
		if ((axp210x_info->regcache.irq.wdt) &&
	   (axp210x_info->regcache.irqmask.wdt == 0)){
			axp210x_init_chip(axp210x_info);
			printk("%s: wdt irq alert!\n",__func__);
			// inform sys
		}
		if ((axp210x_info->regcache.irq.ot) &&
	   (axp210x_info->regcache.irqmask.ot == 0)){
			//inform sys
			printk("%s: ot irq alert!\n",__func__);
		}
		if ((axp210x_info->regcache.irq.newsoc) &&
	   (axp210x_info->regcache.irqmask.newsoc == 0)){
			//inform sys
			printk("%s: newsoc irq alert!\n",__func__);
		}
		if ((axp210x_info->regcache.irq.lowsoc) &&
	   (axp210x_info->regcache.irqmask.lowsoc == 0)){
			//inform sys
			printk("%s: lowsoc irq alert!\n",__func__);
		}
		enable_irq(irq);
		*/
	return IRQ_HANDLED;
}


static int axp210x_read(uint8_t regaddr, uint8_t *regdata, uint8_t bytenum)
{
	int ret, i;
	struct axp_regmap *regmap = axp210x_info->regmap;

	if (!regmap) {
		return -ENODEV;
	}

	for (i = 0; i < bytenum; i++) {
		ret = axp_regmap_read(regmap, regaddr, regdata + i);
		if (ret < 0) {
			pr_debug("axp_regmap_read error");
			return ret;
		}
	}

	return 0;
}


static int axp210x_write(uint8_t regaddr, uint8_t *regdata, uint8_t bytenum)
{
	int ret, i;
	struct axp_regmap *regmap = axp210x_info->regmap;

	if (!regmap) {
		return -ENODEV;
	}

	for (i = 0; i < bytenum; i++) {
		ret = axp_regmap_write(regmap, regaddr, *(regdata + i));
		if (ret < 0)
			break;
	}

	return 0;
}

/*

static int axp210x_open(struct inode *ip, struct file * filp)
{
	return 0;
}

static int axp210x_release(struct inode *ip, struct file * filp)
{
	return 0;
}

static ssize_t axp210x_read(struct file * filp, char __user *buf, size_t size,
loff_t * ppos)
{

	union power_supply_propval val;
	int ret = 0;
//	ret = axp210x_read_vbat(&val);
	printk(KERN_INFO "ret %d, vbat = %d\n", ret, val.intval);
//	ret = axp210x_read_soc(&val);
	printk(KERN_INFO "ret %d, soc = %d\n", ret, val.intval);
//	ret = axp210x_read_time2empty(&val);
	printk(KERN_INFO "ret %d, t2e = %d\n", ret, val.intval);
//	ret = axp210x_read_time2full(&val);
	printk(KERN_INFO "ret %d, t2f = %d\n", ret, val.intval);
//	ret = axp210x_read_irq(&val);
	printk(KERN_INFO "ret %d, irq = %d\n", ret, val.intval);
	return ret;
}



struct file_operations axp210x_file_ops = {
	.owner = THIS_MODULE,
	.open = axp210x_open,
	.release = axp210x_release,
	.read = axp210x_read,
};
*/

#if ((defined DONOT_Correction) || (defined POLL_READ))
static void timer_handler(unsigned long arg)
{
	int ret = 0;
	union power_supply_propval val;
	printk("%s: timer_handler work!\n", __FUNCTION__);

	ret = axp210x_read_soc(&val);
	if (ret != 0)
		printk(KERN_ALERT "%s: soc update fail!\n", __FUNCTION__);
	ret = axp210x_read_vbat(&val);
	if (ret != 0)
		printk(KERN_ALERT "%s: vbat update fail!\n", __FUNCTION__);

	ret = axp210x_read_temp(&val);
	if (ret != 0)
		printk(KERN_ALERT "%s: temprature update fail!\n", __FUNCTION__);

	//	ret = axp210x_read_time2empty(&val);
	//	if (ret != 0)
	//		printk(KERN_ALERT "%s: time2empty update fail!\n",
	//__FUNCTION__);

	//	ret = axp210x_read_time2full(&val);
	//	if (ret != 0)
	//		printk(KERN_ALERT "%s: time2full update fail!\n",
	//__FUNCTION__);

	printk("%s: soc[%d] vbat[%d] \n", __func__, axp210x_info->regcache.soc,
	       axp210x_info->regcache.vbat);
}

static int thread_dosomthing(void *data)
{
	set_freezable();

	while (!kthread_should_stop()) {
		schedule_timeout_interruptible(POLL_INTERVAL);
		try_to_freeze();
		timer_handler(0);
	}

	return 0;
}
#endif


#if (AXP2101_DEBUG)
static ssize_t register_read(struct class *class,
		struct class_attribute *attr, const char *buf, size_t count)
{
	int address = 0;
	int value = 0;
	int ret = 0;
	char *endptr = NULL;

	address = simple_strtoul(buf, &endptr, 16);
	printk(KERN_ERR "address=%x\n", address);

	ret = axp210x_info->read(address, (uint8_t *)&value, sizeof(value));
	if (ret < 0)
		return 0;

	axp210x_alway("value=%x\n", value);
	return count;
}

static ssize_t register_write(struct class *class,
		struct class_attribute *attr, const char *buf, size_t count)
{
	int address = 0;
	int value = 0;
	int ret = 0;
	char *endptr = NULL;
	const char *start = &buf[0];

	address = simple_strtoul(buf, &endptr, 16);
	start = endptr + 1;
	if (start < buf + count)
		value = simple_strtoul(start, &endptr, 16);
	axp210x_alway("address=%x,value=%x\n", address, value);

	ret = axp210x_info->write(address, (uint8_t *)&value, sizeof(value));
	if (ret < 0)
		return 0;

	return count;
}

static struct class_attribute axp210x_user_define_property[] = {
	__ATTR(reg_read, S_IWUSR, NULL, register_read),
	__ATTR(reg_write, S_IWUSR, NULL, register_write),
	__ATTR_NULL,
};

static struct class axp210x_user_define = {
	.name = "axp210x_user_define",
	.class_attrs = axp210x_user_define_property,
};
#endif

static struct axp_interrupts axp_charger_irq[] = {
	{ "usb in", axp210x_irq_handler_thread },
	{ "usb out", axp210x_irq_handler_thread },
	{ "bat in", axp210x_irq_handler_thread },
	{ "bat out", axp210x_irq_handler_thread },
	{ "charging", axp210x_irq_handler_thread },
	{ "charge over", axp210x_irq_handler_thread },
	{ "low warning1", axp210x_irq_handler_thread },
	{ "low warning2", axp210x_irq_handler_thread },
	{ "bat untemp work", axp210x_irq_handler_thread },
	{ "bat ovtemp work", axp210x_irq_handler_thread },
	{ "bat untemp chg", axp210x_irq_handler_thread },
	{ "bat ovtemp chg", axp210x_irq_handler_thread },
};

static void axp_set_charger_info(struct axp210x_device_info *di)
{
	axp210x_info = di;
}

static uint32_t iin_lim_tbl[] = {100, 500, 900, 1000, 1500, 2000};

static void axp2101_parse_device_tree(struct axp210x_device_info *di)
{
	uint32_t prop, i;

	/* set input current limit */
	if (!di->dev->of_node) {
		pr_info("can not find device tree\n");
		return;
	}

	if (!of_property_read_u32(di->dev->of_node, "iin_limit", &prop)) {

		for (i = 0; i < ARRAY_SIZE(iin_lim_tbl); i++) {
			if (prop < iin_lim_tbl[i])
				break;
		}

		i = i ? i - 1 : i;
		axp_regmap_update(di->regmap,
				  axp2101_regaddrs[AXP210X_REG_IIN_LIM], i,
				  GENMASK(2, 0));
	}

	if (!of_property_read_u32(di->dev->of_node, "icc_cfg", &prop)) {

		prop = clamp_val(prop, 0, 2000);
		/* step is 25mA, and then 100mA step */
		if (prop <= 200)
			prop /= 25;
		else
			prop = 8 + (prop - 200) / 100;

		axp_regmap_update(di->regmap,
				  axp2101_regaddrs[AXP210X_REG_ICC_CFG], prop,
				  GENMASK(4, 0));
	}
}

static int axp2101_charger_probe(struct platform_device *pdev)
{
	int ret = 0;
	int i = 0, irq;
	struct axp210x_device_info *di;

	struct axp_dev *axp_dev = dev_get_drvdata(pdev->dev.parent);

	di = devm_kzalloc(&pdev->dev, sizeof(*di), GFP_KERNEL);
	if (di == NULL) {
		axp210x_err("axp210x_device_info alloc failed\n");
		ret = -ENOMEM;
		goto err;
	}

	di->name = "axp210x_chip";
	di->dev = &pdev->dev;
	di->chip = AXP2101;
	di->read = axp210x_read;
	di->write = axp210x_write;
	di->regaddrs = axp2101_regaddrs;
	di->data = axp2101_model_data;
	di->regmap = axp_dev->regmap;
	if (axp_dev->regmap)
		pr_info("axp_dev->regmap not null");
	else
		pr_info("axp_dev->regmap is null");

	axp_set_charger_info(di);

	ret = axp210x_init_chip(axp210x_info);
	if (ret < 0) {
		axp210x_err("axp210x init chip fail!\n");
		ret = -ENODEV;
		goto err;
	}

	/* for device tree parse */
	axp2101_parse_device_tree(di);

	ret = axp210x_register_battery(axp210x_info);
	if (ret < 0) {
		axp210x_err("axp210x register battery dev fail!\n");
		goto err;
	}

#if ((defined DONOT_Correction) || (defined POLL_READ))
	di->poll_read = kthread_run(thread_dosomthing, di, "axp2101");

#else
	for (i = 0; i < ARRAY_SIZE(axp_charger_irq); i++) {
		irq = platform_get_irq_byname(pdev, axp_charger_irq[i].name);
		if (irq < 0)
			continue;

		ret = axp_request_irq(axp_dev, irq, axp_charger_irq[i].isr, di);
		if (ret != 0) {
			dev_err(&pdev->dev, "failed to request %s IRQ %d: %d\n",
				axp_charger_irq[i].name, irq, ret);
			goto out_irq;
		}

		dev_dbg(&pdev->dev, "Requested %s IRQ %d: %d\n",
			axp_charger_irq[i].name, irq, ret);
	}
#endif

#if (AXP2101_DEBUG)
	ret = class_register(&axp210x_user_define);
	if (ret < 0) {
		axp210x_err("axp210x register class fail!\n");
		goto out_irq;
	}
#endif

	return ret;

out_irq:
	for (i = 0; i < ARRAY_SIZE(axp_charger_irq); i++) {
		struct resource *rs;

		rs = platform_get_resource_byname(pdev, IORESOURCE_IRQ,
						  axp_charger_irq[i].name);
		if (rs)
			axp_free_irq(axp_dev, rs->start);
	}

#if ((defined DONOT_Correction) || (defined POLL_READ))
	kthread_stop(di->poll_read);
#endif

err:
	axp210x_err("%s,probe fail, ret = %d\n", __func__, ret);

	return ret;
}

static int axp2101_charger_remove(struct platform_device *pdev)
{
	axp210x_alway("==============AXP2101 unegister==============\n");
#if ((defined DONOT_Correction) || (defined POLL_READ))
	kthread_stop(axp210x_info->poll_read);
#endif
	axp210x_teardown_battery(axp210x_info);
	axp210x_debug("axp210x teardown battery dev\n");

#if (AXP2101_DEBUG)
	class_unregister(&axp210x_user_define);
#endif

	axp210x_info = NULL;
	return 0;
}


static const struct platform_device_id axp2101_charger_dt_ids[] = {
	{ .name = "axp2101-charger", },
	{},
};
MODULE_DEVICE_TABLE(of, axp2101_charger_dt_ids);

static struct platform_driver axp210x_charger_driver = {
	.driver = {
		.name = "axp210x-charger",
	},
	.probe = axp2101_charger_probe,
	.remove = axp2101_charger_remove,
	.id_table = axp2101_charger_dt_ids,
};

module_platform_driver(axp210x_charger_driver);

MODULE_AUTHOR("wangxiaoliang <wangxiaoliang@x-powers.com>");
MODULE_DESCRIPTION("axp210x i2c driver");
MODULE_LICENSE("GPL");



























