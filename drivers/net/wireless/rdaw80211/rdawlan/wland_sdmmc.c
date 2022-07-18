
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
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/rtnetlink.h>
#include <linux/etherdevice.h>
#include <linux/random.h>
#include <linux/spinlock.h>
#include <linux/ethtool.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/ieee80211.h>
#include <linux/netdevice.h>
#include <linux/interrupt.h>
#include <linux/completion.h>
#include <linux/scatterlist.h>
#include <linux/mmc/sdio.h>
#include <linux/mmc/sdio_func.h>
#include <linux/mmc/card.h>
#include <linux/mmc/host.h>
#include <linux/semaphore.h>
#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/vmalloc.h>
#include <asm/unaligned.h>
#include <net/cfg80211.h>
#include <net/rtnetlink.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/signal.h>
#else
#include <linux/sched.h>
#endif

#include "wland_defs.h"
#include "wland_utils.h"
#include "wland_fweh.h"
#include "wland_dev.h"
#include "wland_dbg.h"
#include "wland_wid.h"
#include "wland_bus.h"
#include "wland_sdmmc.h"
#include "wland_p2p.h"
#include "wland_trap.h"
#include "wland_amsdu.h"
#include "wland_cfg80211.h"

#include <linux/sunxi-gpio.h>
#include <linux/power/aw_pm.h>

extern void sunxi_mmc_rescan_card(unsigned ids);
extern void sunxi_wlan_set_power(bool on);
extern int sunxi_wlan_get_bus_index(void);
extern int sunxi_wlan_get_oob_irq(void);
extern int sunxi_wlan_get_oob_irq_flags(void);

/* devices we support, null terminated */
static const struct sdio_device_id wland_sdmmc_ids[] = {
	{SDIO_DEVICE(SDIO_VENDOR_ID_RDAWLAN, SDIO_DEVICE_ID_RDA599X)},
	{ /* end: all zeroes */ },
};

MODULE_DEVICE_TABLE(sdio, wland_sdmmc_ids);

bool wland_pm_resume_error(struct wland_sdio_dev *sdiodev)
{
	bool is_err = false;

#if 0
#ifdef CONFIG_PM_SLEEP
	is_err = atomic_read(&sdiodev->suspend);
#endif /* CONFIG_PM_SLEEP */
#endif
	return is_err;
}

void wland_pm_resume_wait(struct wland_sdio_dev *sdiodev,
	wait_queue_head_t * wq)
{
#if 0
#ifdef CONFIG_PM_SLEEP
	int retry = 0;

	while (atomic_read(&sdiodev->suspend) && retry++ != 30)
		wait_event_timeout(*wq, false, HZ / 100);
#endif /* CONFIG_PM_SLEEP */
#endif
}

int wland_sdioh_request_byte(struct wland_sdio_dev *sdiodev, uint rw, uint regaddr,
	u8 *byte)
{
	int err_ret;

	WLAND_DBG(SDIO, TRACE, "rw=%d,addr=0x%05x\n", rw, regaddr);

	wland_pm_resume_wait(sdiodev, &sdiodev->request_byte_wait);

	if (wland_pm_resume_error(sdiodev))
		return -EIO;

	//sdio_claim_host(sdiodev->func);
	if (SDIOH_WRITE == rw)	/* CMD52 Write */
		sdio_writeb(sdiodev->func, *byte, regaddr, &err_ret);
	else
		*byte = sdio_readb(sdiodev->func, regaddr, &err_ret);
	//sdio_release_host(sdiodev->func);

	if (err_ret)
		WLAND_ERR("Failed to %s :@0x%05x=%02x,Err: %d.\n",
			rw ? "write" : "read", regaddr, *byte, err_ret);
#ifdef WLAND_INTPENDING_READ_CLEAN_BIT3
	else if (sdiodev->bus_if->chip_version >= 4 &&
		SDIOH_READ==rw && regaddr==URSDIO_FUNC1_INT_PENDING && (*byte)&BIT3) {
		atomic_set(&sdiodev->flow_ctrl, 1);
		//printk("#r1");
	}
#else
	else if (SDIOH_READ==rw && regaddr==URSDIO_FUNC1_INT_PENDING && (*byte)&BIT3) {
		atomic_set(&sdiodev->flow_ctrl, 1);
	}
#endif
	return err_ret;
}

int wland_sdioh_request_word(struct wland_sdio_dev *sdiodev, uint rw, uint addr,
	u32 *word, uint bytes)
{
	int err_ret = -EIO;

	WLAND_DBG(SDIO, TRACE, "rw=%d, addr=0x%05x, nbytes=%d\n", rw, addr, bytes);

	wland_pm_resume_wait(sdiodev, &sdiodev->request_word_wait);

	if (wland_pm_resume_error(sdiodev))
		return -EIO;

	sdio_claim_host(sdiodev->func);
	if (SDIOH_WRITE == rw) {	/* CMD52 Write */
		if (bytes == 4)
			sdio_writel(sdiodev->func, *word, addr, &err_ret);
		else if (bytes == 2)
			sdio_writew(sdiodev->func, (*word & 0xFFFF), addr, &err_ret);
		else
			WLAND_ERR("Invalid nbytes: %d\n", bytes);
	} else {		/* CMD52 Read */
		if (bytes == 4)
			*word = sdio_readl(sdiodev->func, addr, &err_ret);
		else if (bytes == 2)
			*word = sdio_readw(sdiodev->func, addr, &err_ret) & 0xFFFF;
		else
			WLAND_ERR("Invalid nbytes: %d\n", bytes);
	}
	sdio_release_host(sdiodev->func);

	if (err_ret)
		WLAND_ERR("Failed to %s word, Err: %d\n",
			rw ? "write" : "read", err_ret);

	return err_ret;
}

int wland_sdioh_request_bytes(struct wland_sdio_dev *sdiodev, uint rw, uint addr,
	u8 *byte, uint nbyte)
{
	int err_ret = 0;
#ifdef WLAND_RDAPLATFORM_SUPPORT
	int bytes_left = 0, offset = 0, batch = 0;
#endif /*WLAND_RDAPLATFORM_SUPPORT*/
	WLAND_DBG(SDIO, TRACE, "%s: addr=0x%05x, lenght=%d\n",
		rw ? "WRITE" : "READ", addr, nbyte);

	wland_pm_resume_wait(sdiodev, &sdiodev->request_buffer_wait);

	if (wland_pm_resume_error(sdiodev))
		return -EIO;

	//sdio_claim_host(sdiodev->func);
	if (SDIOH_WRITE == rw) {
#ifdef WLAND_RDAPLATFORM_SUPPORT
		bytes_left = nbyte;
		while (bytes_left > 0 && err_ret == 0) {
			batch = (bytes_left > sdiodev->func->cur_blksize) ?
				sdiodev->func->cur_blksize : bytes_left;
			{
				u8 *packet_to_send = NULL;
				struct page *pg = NULL;

				packet_to_send = byte + offset;
				if (((u32) packet_to_send >> PAGE_SHIFT) !=
					(((u32) packet_to_send + batch - 1) >> PAGE_SHIFT) ||
					(u32)packet_to_send & (ALIGNMENT -1)) {

					pg = alloc_page(GFP_KERNEL);
					if (!pg) {
						err_ret = -1;
						break;
					}
					memcpy(page_address(pg), packet_to_send, batch);
					packet_to_send = page_address(pg);
					WLAND_DBG(SDIO, DEBUG, "wlan data cross page boundary addr:%x size:%x \n",
						(u32)(packet_to_send), batch);
					err_ret = sdio_writesb(sdiodev->func, addr, packet_to_send, batch);
					__free_page(pg);
				} else
					err_ret = sdio_writesb(sdiodev->func, addr, packet_to_send, batch);
			}
			offset += batch;
			bytes_left -= batch;
		}
#else
		err_ret = sdio_writesb(sdiodev->func, addr, byte, nbyte);
#endif
	} else {
		err_ret = sdio_readsb(sdiodev->func, byte, addr, nbyte);
	}
	//sdio_release_host(sdiodev->func);

	if (err_ret)
		WLAND_ERR("Failed to %s bytes, Err: %d\n",
			(SDIOH_WRITE == rw) ? "write" : "read", err_ret);

	return err_ret;
}

int wland_sdio_reset_firmware(struct wland_sdio_dev *sdiodev)
{
	int err;
	u8 val = BIT2;

	wland_sdio_clkctl(sdiodev->bus, CLK_AVAIL);

	sdio_claim_host(sdiodev->func);
	err = wland_sdioh_request_byte(sdiodev, SDIOH_WRITE,
		URSDIO_FUNC1_INT_TO_DEVICE, &val);
	if(err != 0)
		WLAND_ERR("write URSDIO_FUNC1_INT_TO_DEVICE failed!n");

	err = wland_sdioh_request_byte(sdiodev, SDIOH_READ,
		URSDIO_FUNC1_INT_TO_DEVICE, &val);

	atomic_set(&sdiodev->bus_if->software_reset, 2);

	sdio_release_host(sdiodev->func);

	return err;
}
#ifdef WLAND_SDIO_FC_SUPPORT

static int wland_sdio_flow_ctrl_91h(struct wland_sdio_dev *sdiodev)
{
	int ret = 0;
	u8 status = BIT3;
	s32 int_sleep_count = 0, check_num = FLOW_CTRL_RXCMPL_RETRY_COUNT_91;

	WLAND_DBG(SDIO, TRACE, "Enter\n");

	if (sdiodev->bus_if->chip_ready == 0)
		goto out;

	if (sdiodev->bus_if->chip != WLAND_VER_91_H) {
		ret = -1;
		WLAND_ERR("WIFI chip version not match(sdiodev->bus_if->chip=%d)\n",
			sdiodev->bus_if->chip);
		goto out;
	}
	if ((atomic_read(&sdiodev->flow_ctrl) == 1)
		&& (atomic_read(&sdiodev->bus_if->software_reset) == 0)) {
		//printk("#f1");
#ifndef WLAND_INTPENDING_READ_CLEAN_BIT3
		wland_sdioh_request_byte(sdiodev, SDIOH_WRITE,
				URSDIO_FUNC1_INT_PENDING, &status);
#endif /*WLAND_INTPENDING_READ_CLEAN_BIT3*/
		atomic_set(&sdiodev->flow_ctrl, 0);
		return 0;
	}

	while (true) {
		if (atomic_read(&sdiodev->bus_if->software_reset)) {
			WLAND_ERR("in reseting abort flow control\n");
			msleep(100);
			return -1;
		}
		//sdio_claim_host(sdiodev->func);
		ret = wland_sdioh_request_byte(sdiodev, SDIOH_READ,
			URSDIO_FUNC1_INT_PENDING, &status);
		//sdio_release_host(sdiodev->func);
		if (ret) {
			WLAND_ERR("wland read URSDIO_FUNC1_INT_PENDING failed......ret = %d\n", ret);
			atomic_set(&sdiodev->flow_ctrl, 0);
			return ret;
		}

		if (status & BIT3) {
			status = BIT3;
			//sdio_claim_host(sdiodev->func);
#ifndef WLAND_INTPENDING_READ_CLEAN_BIT3
			if (atomic_read(&sdiodev->bus_if->software_reset)) {
				WLAND_ERR("in reseting abort flow control\n");
				msleep(100);
				return -1;
			}
			ret = wland_sdioh_request_byte(sdiodev, SDIOH_WRITE,
				URSDIO_FUNC1_INT_PENDING, &status);
#endif /*WLAND_INTPENDING_READ_CLEAN_BIT3*/
			//sdio_release_host(sdiodev->func);
			WLAND_DBG(SDIO, TRACE,
				"clear flowctrl flag, int_sleep_count=%d\n",
				int_sleep_count);
			break;
		} else {
			if (int_sleep_count >= check_num) {
				WLAND_DBG(SDIO,TRACE,"flows ctrl RXCMPL failed, count:%d over, return back \n",
					check_num);
				ret = -check_num;
				break;
			}
			int_sleep_count++;
			if (int_sleep_count < 5) {
				WLAND_DBG(SDIO, ERROR, "%d, udelay(2)\n", int_sleep_count);
				//udelay(2);
			} else {
			sdio_release_host(sdiodev->func);
				WLAND_DBG(SDIO, ERROR, "%d, msleep(1)\n", int_sleep_count);
				udelay(200);
			sdio_claim_host(sdiodev->func);
			}
		}
	}

out:
	WLAND_DBG(SDIO, TRACE, "Done(ret:%d)\n", ret);
	atomic_set(&sdiodev->flow_ctrl, 0);
	return ret;
}

int wland_sdio_flow_ctrl(struct wland_sdio_dev *sdiodev)
{
	int ret = 0;
#if 0
	u8 val = 0x02;
	int err = 0;
#endif
	WLAND_DBG(SDIO, TRACE, "Enter\n");

	if (atomic_read(&sdiodev->bus_if->software_reset)
#ifdef WLAND_AP_RESET
		|| ap_reseting
#endif
#ifdef WLAND_DRIVER_RELOAD_FW
		|| wland_repowering_chip
#endif
	) {
		msleep(100);
		return -1;
	}

	if (sdiodev->bus_if->chip == WLAND_VER_91_H) {
		if ((ret = wland_sdio_flow_ctrl_91h(sdiodev))) {
			sdiodev->fc_fail_count ++;
			if((sdiodev->fc_fail_count >= 5)
				&& (atomic_read(&sdiodev->bus_if->software_reset) == 0)) {
				WLAND_DBG(SDIO,INFO,"flow control failed %dtimes!\n",
					sdiodev->fc_fail_count);
					//printk("3times\n");
				//sdio_claim_host(sdiodev->func);
#if 0
				err = wland_sdioh_request_byte(sdiodev, SDIOH_WRITE,
					URSDIO_FUNC1_INT_TO_DEVICE, &val);
				if(err != 0)
					WLAND_ERR("write URSDIO_FUNC1_INT_TO_DEVICE failed!n");
#endif
				//sdio_release_host(sdiodev->func);
#ifdef WLAND_AP_RESET
				if ((strncasecmp(rdawlan_firmware_path, "ap", strlen("ap")) == 0)
						&& !ap_reseting && ap_gtk_len) {
					WLAND_DBG(DEFAULT, INFO, "start ap reseting\n");
					ap_reseting = true;
					schedule_work(&wland_chip_reset_work);
				}
#endif
				sdiodev->fc_fail_count = 0;
			}

			WLAND_DBG(SDIO, TRACE, "wland_sdio_flow_ctrl_91h failed! \n");
			goto out;
		} else {
			sdiodev->fc_fail_count = 0;
		}
	} else {
		ret = -1;
		WLAND_ERR("wlan_sdio_flow_ctrl unkown version:%d\n",
			sdiodev->bus_if->chip);
	}

out:
	WLAND_DBG(SDIO, TRACE, "Done(ret:%d)\n", ret);
	return ret;
}
#endif /*WLAND_SDIO_FC_SUPPORT */

int wland_sdio_send_pkt(struct wland_sdio *bus, struct sk_buff *pkt, uint count)
{
	int ret = 0;
	u8 size_l = 0, size_h = 0;
	u16 size = 0;
	u8 *buf = pkt->data;

	WLAND_DBG(SDIO, TRACE, "blockSize=%d, count=%d, pkt->len=%d, pkt->data=%p\n",
		bus->blocksize, count, pkt->len, pkt->data);
	//WLAND_DUMP(SDIO, pkt->data, count, "TX Data, len:%Zu\n", count);
#if 0
	if (wland_check_test_mode()) {
		WLAND_DBG(SDIO, INFO, "In Test Mode and do not send pkt!\n");
		return ret;
	}
#endif

	sdio_claim_host(bus->sdiodev->func);
#ifdef WLAND_TX_AGGRPKTS
	if (count>WLAND_AGGR_TXPKT_LEN) {
	  WLAND_ERR("too large len count:%d\n", count);
	  sdio_release_host(bus->sdiodev->func);
	  return -1;
	}
#ifdef WLAND_SDIO_FC_SUPPORT
	if ((ret = wland_sdio_flow_ctrl(bus->sdiodev))) {
		WLAND_DBG(SDIO, TRACE, "wland_sdio_flow_ctrl failed!\n");
		sdio_release_host(bus->sdiodev->func);
		return ret;
	}
#endif /*WLAND_SDIO_FC_SUPPORT */
#endif

#if 0
		if (bus->sdiodev->bus_if->chip == WLAND_VER_91_H) {
			dump_buf(buf, min(64u,count));
		}
#endif
	if (atomic_read(&bus->sdiodev->bus_if->software_reset)) {
		WLAND_ERR("in reseting but W !!\n");
		sdio_release_host(bus->sdiodev->func);
		return -1;
	}

	size = count / 4;

	size_l = size & 0xFF;
	size_h = ((size >> 8) & 0x7F) | 0x80;	//0x80 flags means lenght higer bytes
#ifdef WLAND_TXLEN_1536
	if (bus->sdiodev->bus_if->chip_ready == 0) {
#endif
		//sdio_claim_host(bus->sdiodev->func);
		if (bus->sdiodev->tx_size_l != size_l) {
			bus->sdiodev->tx_size_l = size_l;
			ret = wland_sdioh_request_byte(bus->sdiodev, SDIOH_WRITE,
				URSDIO_FUNC1_SPKTLEN_LO, &size_l);
		} else
			ret = 0;

		ret |= wland_sdioh_request_byte(bus->sdiodev, SDIOH_WRITE,
			URSDIO_FUNC1_SPKTLEN_HI, &size_h);
		if (ret) {
			WLAND_ERR(" wland_sdioh_request_byte failed!\n");
			//sdio_release_host(bus->sdiodev->func);
			goto out;
		}

#ifdef DHCP_PKT_MEMCOPY_BEFORE_SEND
		if (pkt->protocol == htons(0x0801)) {
			u8 *send_data = kzalloc(count, GFP_ATOMIC);
			WLAND_DBG(DEFAULT, INFO, "dhcp pkt!\n");
			if (!send_data) {
				WLAND_ERR("memory leak!\n");
				ret = wland_sdioh_request_bytes(bus->sdiodev, SDIOH_WRITE,
					URSDIO_FUNC1_FIFO_WR, buf, count);
			} else {
				memcpy(send_data, buf, count);
				ret = wland_sdioh_request_bytes(bus->sdiodev, SDIOH_WRITE,
					URSDIO_FUNC1_FIFO_WR, send_data, count);
				kfree(send_data);
			}
		} else
#endif
			ret = wland_sdioh_request_bytes(bus->sdiodev, SDIOH_WRITE,
				URSDIO_FUNC1_FIFO_WR, buf, count);
#ifdef WLAND_TXLEN_1536
	} else
		ret = wland_sdioh_request_bytes(bus->sdiodev, SDIOH_WRITE,
			URSDIO_FUNC1_FIFO_WR, buf, 1536);
#endif

out:
	sdio_release_host(bus->sdiodev->func);
#ifndef WLAND_TX_AGGRPKTS
	bus->fw_rxbuf = false;
#endif
	WLAND_DBG(SDIO, TRACE, "Done(ret:%d)\n", ret);
	return ret;
}

int wland_sdio_recv_pkt(struct wland_sdio *bus, struct sk_buff *skbbuf,
	uint size)
{
	int ret; /* Return code from calls */

	if ((!skbbuf) || (!size)) {
		WLAND_ERR("skb empty!\n");
		return -EINVAL;;
	}

	ret = wland_sdioh_request_bytes(bus->sdiodev, SDIOH_READ,
		URSDIO_FUNC1_FIFO_RD, skbbuf->data, size);
	if (ret < 0) {
		WLAND_ERR("SDIO read data failed! \n");
		return ret;
	}

#if 0
	if (bus->sdiodev->bus_if->chip == WLAND_VER_91_H) {
		dump_buf((u8 *)skbbuf->data, min(64u, size));
	}
#endif
	//printk("rd:%x, len:%d\n", skbbuf->data[1]>>4, skbbuf->data[0] | ((skbbuf->data[1]&0x0f)<<8));
#ifdef WLAND_RX_AGGRPKTS
	skbbuf->len = size;
#endif
	WLAND_DBG(SDIO, TRACE, "Done(ret:%d,RxData,len:%d)\n", ret, size);
	return ret;
}

static int wland_ops_sdio_probe(struct sdio_func *func,
	const struct sdio_device_id *id)
{
	struct mmc_host *host;
	struct wland_sdio_dev *sdiodev;
	struct wland_bus *bus_if;
	int err = -ENODEV;

	WLAND_DBG(SDIO, TRACE, "Enter\n");
	WLAND_DBG(SDIO, INFO, "Class=%x\n", func->class);
	WLAND_DBG(SDIO, INFO, "sdio vendor ID: 0x%04x\n", func->vendor);
	WLAND_DBG(SDIO, INFO, "sdio device ID: 0x%04x\n", func->device);
	WLAND_DBG(SDIO, INFO, "Function#: %d\n", func->num);

	if (id->vendor != SDIO_VENDOR_ID_RDAWLAN || id->device != SDIO_DEVICE_ID_RDA599X) {
		WLAND_ERR("Unmatch Vendor ID: 0x%x or Device ID: 0x:%x\n", id->vendor, id->device);
		return -ENODEV;
	}

	host = func->card->host;

#ifdef CONFIG_ARCH_ROCKCHIP
{
	struct dw_mci_slot *dw_slot = mmc_priv(host);
    struct dw_mci *dw_host = dw_slot->host;
	dw_host->bus_hz = dw_host->pdata->bus_hz;
	host->ios.clock = 70000000;
	//WLAND_ERR("RDA5995 Set clk %dM\n",host->ios.clock/1000000);
	host->ops->set_ios(host, &host->ios);
}
#endif /*CONFIG_ARCH_ROCKCHIP*/

#if 0
#ifdef WLAND_AMLOGIC_PLATFORM_SUPPORT
	host->ios.clock = 70000000;
	//WLAND_ERR("RDA5995 Set clk %dM\n",host->ios.clock/1000000);
	host->ops->set_ios(host, &host->ios);
#endif
#endif
#ifdef WLAND_AP_RESET
	if(ap_reseting && ap_bus_if) { //ap_resting
		struct wland_sdio *bus = NULL;
		WLAND_DBG(DEFAULT, INFO, "ap reseting just init sdio things.\n");
		bus_if = ap_bus_if;
		sdiodev = bus_if->bus_priv.sdio;
		bus = sdiodev->bus;
		atomic_set(&bus_if->software_reset, 0);
		sdiodev->func = func;
		dev_set_drvdata(&func->dev, bus_if);
		sdiodev->dev = &func->dev;
		bus_if->dev = &func->dev;
		atomic_set(&sdiodev->suspend, false);
		atomic_set(&sdiodev->flow_ctrl, 0);
		sdiodev->card_sleep = true;
		sdiodev->fc_fail_count = 0;
		err = wland_sdioh_attach(sdiodev);
		if (err < 0)
			goto fail;

		bus_if->chip_ready = 0;
		bus_if->up_data_mac = 0;
		memset(&(bus->sdcnt), 0, sizeof(struct wland_sdio_count));

		bus->wakelock_counter = 0;
		bus->wakelock_wd_counter = 0;
		bus->wakelock_rx_timeout_enable = 0;
		bus->wakelock_ctrl_timeout_enable = 0;
		bus->intr = false;
		bus->poll = true;
		bus->intdis = false;
		bus->polltick = 0;
		bus->activity = false;

		host->caps |= MMC_CAP_NONREMOVABLE;
		msleep(50);
		err = wland_start_chip(bus_if->drvr->iflist[0]->ndev);
		if (err < 0) {
			WLAND_ERR("failed to bring up chip!\n");
			return -ENODEV;
		}
		if (ap_gtk_len) {
			wland_reconfig_ap_inreseting(bus_if->drvr->iflist[0]);
			WLAND_DBG(DEFAULT, INFO, "ap reseting done!\n");
		}
		return 0;
	}
#endif
#ifdef WLAND_DRIVER_RELOAD_FW
	if (wland_repowering_chip) {
		WLAND_DBG(DEFAULT, INFO, "chip repowering use backup bus!\n");
		bus_if = bus_if_backup;
	} else {
#endif
		bus_if = kzalloc(sizeof(struct wland_bus), GFP_KERNEL);
		if (!bus_if) {
			return -ENOMEM;
		}
#ifdef WLAND_DRIVER_RELOAD_FW
	}
#endif

	atomic_set(&bus_if->software_reset, 0);

	sdiodev = kzalloc(sizeof(struct wland_sdio_dev), GFP_KERNEL);
	if (!sdiodev) {
		kfree(bus_if);
		return -ENOMEM;
	}

	/*
	 * initial sdiodev func parameters
	 */
	sdiodev->func = func;
	sdiodev->bus_if = bus_if;

	bus_if->bus_priv.sdio = sdiodev;

	dev_set_drvdata(&func->dev, bus_if);

	sdiodev->dev = &func->dev;

	atomic_set(&sdiodev->suspend, false);

	atomic_set(&sdiodev->flow_ctrl, 0);

	sdiodev->card_sleep = true;
	sdiodev->fc_fail_count = 0;

	init_waitqueue_head(&sdiodev->request_byte_wait);
	init_waitqueue_head(&sdiodev->request_word_wait);
	init_waitqueue_head(&sdiodev->request_buffer_wait);

	WLAND_DBG(SDIO, TRACE, "F1 found, calling real sdio probe...\n");

	err = wland_sdioh_attach(sdiodev);
	if (err < 0)
		goto fail;

	/*
	 * try to attach to the target device
	 */
	sdiodev->bus = wland_sdio_probe(sdiodev);
	if (!sdiodev->bus) {
		WLAND_ERR("device attach failed\n");
		goto fail;
	}

	//add for linux pm
	host->caps |= MMC_CAP_NONREMOVABLE;

	WLAND_DBG(SDIO, TRACE, "Done,init completed success...\n");

#ifdef WLAND_DRIVER_RELOAD_FW
	if (wland_repowering_chip) {
		err = wland_start_chip(bus_if->drvr->iflist[0]->ndev);
		if (err < 0) {
			WLAND_ERR("start chip failed, while repowering.\n");
			wland_repower_sem_up(true);
			return err;
		}
		wland_repower_sem_up(false);
	}
#endif
	return 0;
fail:
	wland_sdioh_detach(sdiodev);
	dev_set_drvdata(&func->dev, NULL);
	kfree(sdiodev);
	kfree(bus_if);
	return err;
}

static void wland_ops_sdio_remove(struct sdio_func *func)
{
	struct mmc_host *host;
	struct wland_bus *bus_if = NULL;
	struct wland_sdio_dev *sdiodev = NULL;

	WLAND_DBG(DEFAULT, INFO, "Enter\n");

	//add for linux pm
	host = func->card->host;
	host->caps &= ~MMC_CAP_NONREMOVABLE;

	bus_if = dev_get_drvdata(&func->dev);
	if (bus_if) {
		sdiodev = bus_if->bus_priv.sdio;
	} else {
		WLAND_ERR("bus_if == NULL and go out.\n");
		goto out;
	}
	if (sdiodev == NULL) {
		WLAND_ERR("sdiodev == NULL and go out.\n");
		goto out;
	}
	WLAND_DBG(SDIO, TRACE, "SDIO-VID:0x%04x,SDIO-DID:0x%04x,Function:%d\n",
		func->vendor, func->device, func->num);

#ifdef WLAND_AP_RESET
	if(ap_reseting) {
		unsigned long flags;
		struct rx_reorder_msg *reorder_msg, *reorder_msg1;
		struct wland_rx_info *rx_info = sdiodev->bus->rx_info;
		struct wland_if *ifp = bus_if->drvr->iflist[0];
		struct wland_cfg80211_connect_info *conn_info = &ifp->vif->conn_info;
		struct wland_sta_info *sta_info, *sta_info_tmp;
		WLAND_ERR("ap_reseting, just release sdio things!\n");

		spin_lock_bh(&conn_info->sta_info_lock);
		list_for_each_entry_safe(sta_info, sta_info_tmp, &conn_info->sta_info_list, list) {
			if (sta_info->connect) {
				WLAND_DBG(DEFAULT, INFO, "report delete sta:%pM\n",sta_info->mac_addr);
				cfg80211_del_sta(ifp->ndev, sta_info->mac_addr, GFP_ATOMIC);
				sta_info->connect = 0;
			}
		}
		spin_unlock_bh(&conn_info->sta_info_lock);

		if (timer_pending(&conn_info->connect_restorework_timeout)) {
			del_timer_sync(&conn_info->connect_restorework_timeout);
			WLAND_DBG(CFG80211, INFO, "###### delete connect restorework timer\n");
		}
		cancel_work_sync(&conn_info->connect_restorework_timeout_work);

		ap_bus_if = bus_if;
		wland_sdio_intr_unregister(sdiodev);
		bus_if->state = WLAND_BUS_DOWN;

#if defined WLAND_RX_SOFT_MAC || defined WLAND_RX_8023_REORDER
		spin_lock_irqsave(&rx_info->rx_reorder_msg_lock, flags);
		list_for_each_entry_safe(reorder_msg, reorder_msg1,
			&rx_info->rx_reorder_msg_list, list) {
			wland_rx_reorder_msg_deinit(rx_info, reorder_msg);
		}
		spin_unlock_irqrestore(&rx_info->rx_reorder_msg_lock, flags);
#endif
		wland_pktq_flush(&sdiodev->bus->txq, true, NULL, NULL);
		wland_pktq_flush(&rx_info->rxq, true, NULL, NULL);

		cancel_work_sync(&sdiodev->bus->TxWork);
		cancel_work_sync(&sdiodev->bus->rx_info->RxWork);
		wland_sdioh_detach(sdiodev);
		dev_set_drvdata(&sdiodev->func->dev, NULL);
		WLAND_DBG(DEFAULT, INFO, "Done\n");
		return;
	}
#endif
	if (sdiodev->bus) {
		wland_sdio_release(sdiodev->bus);
		sdiodev->bus = NULL;
	}
	sdiodev->bus_if->state = WLAND_BUS_DOWN;

	wland_sdioh_detach(sdiodev);

	dev_set_drvdata(&sdiodev->func->dev, NULL);

	kfree(sdiodev);
#ifdef WLAND_DRIVER_RELOAD_FW
	if (!wland_repowering_chip)
#endif
		kfree(bus_if);
#ifdef WLAND_DRIVER_RELOAD_FW
	else
		WLAND_DBG(DEFAULT, INFO, "chip repowering do not free bus_if!\n");
#endif
out:
	WLAND_DBG(DEFAULT, INFO, "Done\n");
}

#ifdef WLAND_HI3518EV300_REBOOT_POWER_OFF
#define FILE_EXPORT "/sys/class/gpio/export"
int wland_sw_gpio_set(int gpio_num,int value) {

	//FILE *fp;
	struct file *fp;
	char buf_name[50] = {0};
	unsigned int ret;
	char buf[5] = {0};

	if ( value != 1 && value != 0) {
		WLAND_ERR("invalid_argument value.\n");
		return -1;
	}

	sprintf(buf_name,"/sys/class/gpio/gpio%d/direction",gpio_num);
	WLAND_DBG(DEFAULT, INFO, "buf_name:%s\n", buf_name);
	fp = filp_open(buf_name, O_RDWR, 0644);
	if (IS_ERR(fp)) {
		WLAND_ERR("failed to open %s, write export!\n", buf_name);
		sprintf(buf, "%d", gpio_num);
		WLAND_DBG(DEFAULT, INFO, "buf:%s\n", buf);
		ret = wland_file_write(FILE_EXPORT, buf, 2, 0, O_WRONLY, 0200);
		if (ret < 0) {
			WLAND_ERR("failed to write export!\n");
			return -1;
		}
	} else {
		WLAND_DBG(DEFAULT, INFO, "%s exit!\n", buf_name);
		filp_close(fp, NULL);
	}

	//set gpio direction
	sprintf(buf_name,"/sys/class/gpio/gpio%d/direction", gpio_num);
	WLAND_DBG(DEFAULT, INFO, "buf_name:%s\n", buf_name);
	ret = wland_file_write(buf_name, "out", 3, 0, O_RDWR, 0644);
	if (ret < 0) {
		WLAND_ERR("failed to write export!\n");
		return -1;
	}

	//set gpio value
	sprintf(buf_name,"/sys/class/gpio/gpio%d/value",gpio_num);
	WLAND_DBG(DEFAULT, INFO, "buf_name:%s\n", buf_name);
	if (value)
	     ret = wland_file_write(buf_name, "1", 1, 0, O_RDWR, 0644);
	else
	     ret = wland_file_write(buf_name, "0", 1, 0, O_RDWR, 0644);
	if (ret < 0) {
	     WLAND_ERR("write %s-%d failed!\n", buf_name, value);
	     return -1;
	}

	return 0;
}
#endif /*WLAND_HI3518EV300_REBOOT_POWER_OFF*/

void wland_ops_sdio_shutdown(struct device *dev)
{
	struct wland_bus *bus_if = dev_get_drvdata(dev);
	struct wland_sdio_dev *sdiodev = bus_if->bus_priv.sdio;

	WLAND_DBG(DEFAULT, INFO, "Enter\n");

#ifdef WLAND_AP_RESET
	cancel_work_sync(&wland_chip_reset_work);
	while(ap_reseting) {
		schedule();
	}
#endif

	if (sdiodev->bus) {
		wland_sdio_release(sdiodev->bus);
		sdiodev->bus = NULL;
	}

#ifdef WLAND_HI3518EV300_REBOOT_POWER_OFF
	wland_sw_gpio_set(52, 0);
#endif

	WLAND_DBG(DEFAULT, TRACE, "Done\n");
}

#ifdef CONFIG_PM
//WID_CPU_SUSPEND-- 0:cpu suspend--1:cpu_resume
static int wland_sdio_suspend(struct device *dev)
{
	int ret = 0;
	struct wland_bus *bus_if = dev_get_drvdata(dev);
	struct wland_sdio_dev *sdiodev = bus_if->bus_priv.sdio;
	mmc_pm_flag_t sdio_flags;
	u8 sleep = 0;
	struct wland_if *ifp = bus_if->drvr->iflist[0];

	WLAND_DBG(DEFAULT, INFO, "Enter.\n");

	ret = wland_fil_set_cmd_data_without_rsp(ifp, WID_CPU_SUSPEND, &sleep, 1);
	if (ret < 0) {
		WLAND_ERR("send suspend cmd failed!\n");
		wland_sdio_clkctl(sdiodev->bus, CLK_AVAIL);
		return ret;
	}

	netif_device_detach(bus_if->drvr->iflist[0]->ndev);

	sdio_flags = sdio_get_host_pm_caps(sdiodev->func);
	if (!(sdio_flags & MMC_PM_KEEP_POWER)) {
		WLAND_ERR("Host can't keep power while suspended\n");
		return -EINVAL;
	}

	ret = sdio_set_host_pm_flags(sdiodev->func, MMC_PM_KEEP_POWER);
	if (ret) {
		WLAND_ERR("Failed to set pm_flags\n");
		return ret;
	}

	atomic_set(&sdiodev->suspend, true);

	/*
	 * Watchdog timer interface for pm ops
	 */
	while (sdiodev->card_sleep != true) {
		if (down_interruptible(&sdiodev->bus->txclk_sem)) {
			WLAND_ERR("Can not request bus->txclk_sem.wland_sdio_suspend\n");
			continue;
		}
		wland_sdio_clkctl(sdiodev->bus, CLK_NONE);
		up(&sdiodev->bus->txclk_sem);
		wland_sched_timeout(50);
	}

	WLAND_DBG(DEFAULT, INFO, "Done.\n");
	return 0;
}

static int wland_sdio_resume(struct device *dev)
{

	struct wland_bus *bus_if = dev_get_drvdata(dev);
	struct wland_sdio_dev *sdiodev = bus_if->bus_priv.sdio;
	int ret = 0;
	u8 sleep = 1;
	struct wland_if *ifp = bus_if->drvr->iflist[0];

	WLAND_DBG(DEFAULT, INFO, "Enter\n");
	netif_device_attach(bus_if->drvr->iflist[0]->ndev);

	atomic_set(&sdiodev->suspend, false);

	ret = wland_fil_set_cmd_data_without_rsp(ifp, WID_CPU_SUSPEND, &sleep, 1);
	if (ret < 0) {
		WLAND_ERR("send resume cmd failed!\n");
	}

	WLAND_DBG(DEFAULT, TRACE, "Done\n");
	return 0;
}

static const struct dev_pm_ops wland_sdio_pm_ops = {
	.suspend = wland_sdio_suspend,
	.resume = wland_sdio_resume,
};
#endif /* ifdef CONFIG_PM */

static struct sdio_driver wland_sdmmc_driver = {
	.probe = wland_ops_sdio_probe,
	.remove = wland_ops_sdio_remove,
	.name = WLAND_SDIO_NAME,
	.id_table = wland_sdmmc_ids,
	.drv = {
#ifdef CONFIG_PM
		.pm = &wland_sdio_pm_ops,
#endif
		.shutdown = &wland_ops_sdio_shutdown,
	},
};

/*	Public entry points & extern's */
int wland_sdioh_attach(struct wland_sdio_dev *sdiodev)
{
	int err_ret = 0;

	WLAND_DBG(SDIO, TRACE, "Enter.\n");
	sdio_claim_host(sdiodev->func);
	err_ret = sdio_set_block_size(sdiodev->func, SDIO_FUNC1_BLOCKSIZE);
	if (err_ret < 0) {
		WLAND_ERR("Failed to set F1 blocksize.\n");
		goto out;
	}
	/*
	 * Enable Function 1
	 */
	err_ret = sdio_enable_func(sdiodev->func);
	if (err_ret < 0)
		WLAND_ERR("Failed to enable F1 Err: %d.\n", err_ret);
out:
	sdio_release_host(sdiodev->func);
	WLAND_DBG(SDIO, TRACE, "Done.\n");
	return err_ret;
}

void wland_sdioh_detach(struct wland_sdio_dev *sdiodev)
{
	WLAND_DBG(SDIO, TRACE, "Enter\n");

	/*
	 * Disable Function 1
	 */
	sdio_claim_host(sdiodev->func);
	sdio_disable_func(sdiodev->func);
	sdio_release_host(sdiodev->func);

	WLAND_DBG(SDIO, TRACE, "Done\n");
}
#ifdef CONFIG_PLATFORM_JZ
#define SDIO_WIFI_POWER GPIO_PB(30)
#define WLAN_SDIO_INDEX 1
int platform_wifi_power_on(void)
{
	gpio_request(SDIO_WIFI_POWER, "sdio_wifi_power_on");
	gpio_direction_output(SDIO_WIFI_POWER, 0);
	msleep(100);
	gpio_direction_output(SDIO_WIFI_POWER, 1);
	printk("wlan power on\n");
	msleep(50);
	jzmmc_manual_detect(WLAN_SDIO_INDEX, 1);
	return 0;
}
int platform_wifi_power_off(void)
{
	gpio_direction_output(SDIO_WIFI_POWER, 0);
	gpio_free(SDIO_WIFI_POWER);
	printk("wlan power off\n");
	return 0;
}
#endif /*CONFIG_PLATFORM_JZ*/

#ifdef WLAND_HISILICON_PLATFORM_SUPPORT
typedef unsigned int            HI_U32;
typedef int                     HI_S32;
#define HI_SUCCESS		0
#define HI_FAILURE		(-1)
#include <mach/hardware.h>
#define REG_BASE_CTRL		__io_address(0xf8a20008)
extern HI_S32 HI_DRV_GPIO_SetDirBit(HI_U32 u32GpioNo, HI_U32 u32DirBit);
extern HI_S32 HI_DRV_GPIO_WriteBit(HI_U32 u32GpioNo, HI_U32 u32BitValue);
static int hi_gpio_set_value(u32 gpio, u32 value)
{
	HI_S32 s32Status;
	HI_U32 HI_DIR_OUT = 0;
	//HI_U32 HI_DIR_IN  = 1;

	WLAND_DBG(DEFAULT, INFO, "---%d\n", value);

	s32Status = HI_DRV_GPIO_SetDirBit(gpio, HI_DIR_OUT);
	if (s32Status != HI_SUCCESS) {
		pr_err("gpio(%d) HI_DRV_GPIO_SetDirBit HI_DIR_OUT failed\n",
			gpio);
		return -1;
	}

	s32Status = HI_DRV_GPIO_WriteBit(gpio, value);
	if (s32Status != HI_SUCCESS) {
		pr_err("gpio(%d) HI_DRV_GPIO_WriteBit value(%d) failed\n",
			gpio, value);
		return -1;
	}

	return 0;
}

static int hisi_wlan_set_carddetect(bool present)
{
	u32 regval;

	if (present) {
		pr_info("======== Card detection to detect SDIO card! ========\n");
		/* set card_detect low to detect card */
		regval = readl(REG_BASE_CTRL);
		regval |= 0x1;
		writel(regval, REG_BASE_CTRL);
	} else {
		pr_info("======== Card detection to remove SDIO card! ========\n");
		/* set card_detect high to remove card */
		regval = readl(REG_BASE_CTRL);
		regval &= ~(0x1);
		writel(regval, REG_BASE_CTRL);
	}

	return 0;
}
#endif

void wland_sdio_register(void)
{
	int wlan_bus_index = 0;
	
	WLAND_DBG(DEFAULT, INFO, "Enter\n");

#ifdef WLAND_HISILICON_PLATFORM_SUPPORT
	hi_gpio_set_value((4*8 + 3), 0);
	mdelay(100);
	hi_gpio_set_value((4*8 + 3), 1);
	mdelay(100);
	hisi_wlan_set_carddetect(1);
	mdelay(100);
#endif

#if 0
#ifdef WLAND_AMLOGIC_PLATFORM_SUPPORT
	extern_wifi_set_enable(0);
	mdelay(200);
	extern_wifi_set_enable(1);
	mdelay(200);
	sdio_reinit();
#endif /*WLAND_AMLOGIC_PLATFORM_SUPPORT*/
#endif

#if 0
#ifdef CONFIG_PLATFORM_JZ
	platform_wifi_power_on();
#endif /*CONFIG_PLATFORM_JZ*/
#endif

	sunxi_wlan_set_power(1);
	mdelay(100);

	wlan_bus_index = sunxi_wlan_get_bus_index();
	if(wlan_bus_index < 0){ 
			printk("get wifi_sdc_id failed\n");
			return; 
	} else {
			printk("----- %s sdc_id: %d\n", __FUNCTION__, wlan_bus_index);
			sunxi_mmc_rescan_card(wlan_bus_index);
	}

	if (sdio_register_driver(&wland_sdmmc_driver)) {
		WLAND_ERR("sdio_register_driver failed\n");
		wland_registration_sem_up(false);
	} else {

	/*
	 * disable sdio interrupt
	 * trigger sdio bus scan device
	 */
#ifdef WLAND_RDAPLATFORM_SUPPORT
		rda_mmc_set_sdio_irq(1, false);
		rda_mmc_bus_scan(1);
#endif /*WLAND_RDAPLATFORM_SUPPORT*/
	}

	WLAND_DBG(DEFAULT, INFO, "Done\n");
}

void wland_sdio_exit(void)
{

	WLAND_DBG(DEFAULT, INFO, "Enter\n");
	sdio_unregister_driver(&wland_sdmmc_driver);

	sunxi_wlan_set_power(0);
	mdelay(100);

#ifdef WLAND_HISILICON_PLATFORM_SUPPORT
	hisi_wlan_set_carddetect(0);
	hi_gpio_set_value((4*8 + 3), 0);
#endif

#if 0
#ifdef WLAND_AMLOGIC_PLATFORM_SUPPORT
	extern_wifi_set_enable(0);
#endif /*WLAND_AMLOGIC_PLATFORM_SUPPORT*/
#endif /*WLAND_AMLOGIC_PLATFORM_SUPPORT*/

#if 1
#ifdef CONFIG_PLATFORM_JZ
	platform_wifi_power_off();
#endif /*CONFIG_PLATFORM_JZ*/
#endif

	WLAND_DBG(DEFAULT, INFO, "Done\n");
}

void wland_dhd_os_sdlock(struct wland_sdio *bus)
{
	if (bus->threads_only)
		down(&bus->sdsem);
}

void wland_dhd_os_sdunlock(struct wland_sdio *bus)
{
	if (bus->threads_only)
		up(&bus->sdsem);
}

void wland_dhd_os_sdlock_txq(struct wland_sdio *bus, unsigned long *flags)
{
	if (bus)
		spin_lock_irqsave(&bus->txqlock, *flags);
}

void wland_dhd_os_sdunlock_txq(struct wland_sdio *bus, unsigned long *flags)
{
	if (bus)
		spin_unlock_irqrestore(&bus->txqlock, *flags);
}

int wland_dhd_os_ioctl_resp_wait(struct wland_sdio *bus, uint * condition,
	bool * pending)
{
	DECLARE_WAITQUEUE(wait, current);

	/*
	 * Convert timeout in millsecond to jiffies
	 */
	int timeout = msecs_to_jiffies(IOCTL_RESP_TIMEOUT);

	/*
	 * Wait until control frame is available
	 */
	add_wait_queue(&bus->dcmd_resp_wait, &wait);
	set_current_state(TASK_INTERRUPTIBLE);
#if defined CONFIG_PLATFORM_JZ || defined CONFIG_PLATFORM_ANYKA
	while (!(*condition) && (/*!signal_pending(current) && */timeout))
#else
	while (!(*condition) && (!signal_pending(current) && timeout))
#endif
		timeout = schedule_timeout(timeout);

	if (signal_pending(current))
		*pending = true;

	set_current_state(TASK_RUNNING);
	remove_wait_queue(&bus->dcmd_resp_wait, &wait);

	return timeout;
}

void wland_dhd_os_ioctl_resp_wake(struct wland_sdio *bus)
{
	if (waitqueue_active(&bus->dcmd_resp_wait))
		wake_up(&bus->dcmd_resp_wait);
}

int wland_dhd_os_wait_for_event(struct wland_sdio *bus, bool * lockvar)
{
	int ret = 0;
	int timeout = msecs_to_jiffies(IOCTL_RESP_TIMEOUT);
	ret = wait_event_interruptible_timeout(bus->ctrl_wait, !(*lockvar),
		timeout);
	return ret;
}

void wland_dhd_os_wait_event_wakeup(struct wland_sdio *bus)
{
	if (waitqueue_active(&bus->ctrl_wait))
		wake_up(&bus->ctrl_wait);
}

int wland_dhd_os_wake_lock(struct wland_sdio *bus)
{
	ulong flags;
	int ret = 0;

	if (bus) {
		spin_lock_irqsave(&bus->wakelock_spinlock, flags);
#ifdef CONFIG_HAS_WAKELOCK
		if (!bus->wakelock_counter) {
			//wake_lock(&bus->wl_wifi);
			WLAND_DBG(SDIO, TRACE, "wl_wifi locked.\n");
		}
#endif /*CONFIG_HAS_WAKELOCK */
		bus->wakelock_counter++;
		ret = bus->wakelock_counter;
		spin_unlock_irqrestore(&bus->wakelock_spinlock, flags);
	}
	return ret;
}

int wland_dhd_os_wake_lock_timeout(struct wland_sdio *bus)
{
	ulong flags;
	int ret = 0;

	if (bus) {
		spin_lock_irqsave(&bus->wakelock_spinlock, flags);
		ret = bus->wakelock_rx_timeout_enable >
			bus->wakelock_ctrl_timeout_enable ?
			bus->wakelock_rx_timeout_enable :
			bus->wakelock_ctrl_timeout_enable;
#ifdef CONFIG_HAS_WAKELOCK
		if (bus->wakelock_rx_timeout_enable)
			wake_lock_timeout(&bus->wl_rxwake,
				msecs_to_jiffies
				(bus->wakelock_rx_timeout_enable));
		if (bus->wakelock_ctrl_timeout_enable)
			wake_lock_timeout(&bus->wl_ctrlwake,
				msecs_to_jiffies
				(bus->wakelock_ctrl_timeout_enable));
#endif /*CONFIG_HAS_WAKELOCK */
		bus->wakelock_rx_timeout_enable = 0;
		bus->wakelock_ctrl_timeout_enable = 0;
		spin_unlock_irqrestore(&bus->wakelock_spinlock, flags);
	}
	return ret;
}

int wland_dhd_os_wake_unlock(struct wland_sdio *bus)
{
	ulong flags;
	int ret = 0;

	wland_dhd_os_wake_lock_timeout(bus);
	if (bus) {
		spin_lock_irqsave(&bus->wakelock_spinlock, flags);
		if (bus->wakelock_counter) {
			bus->wakelock_counter--;
#ifdef CONFIG_HAS_WAKELOCK
			if (!bus->wakelock_counter) {
				//wake_unlock(&bus->wl_wifi);
				WLAND_DBG(SDIO, TRACE, "wl_wifi unlock.\n");
			}
#endif /*CONFIG_HAS_WAKELOCK */
			ret = bus->wakelock_counter;
		}
		spin_unlock_irqrestore(&bus->wakelock_spinlock, flags);
	}
	return ret;
}

int wland_dhd_os_check_wakelock(struct wland_sdio *bus)
{
#ifdef CONFIG_HAS_WAKELOCK
	if (!bus)
		return 0;

	/*
	 * Indicate to the SD Host to avoid going to suspend if internal locks are up
	 */
	if (wake_lock_active(&bus->wl_wifi)
		|| wake_lock_active(&bus->wl_wdwake))
		return 1;
#endif /*CONFIG_HAS_WAKELOCK */
	return 0;
}

int wland_dhd_os_wd_wake_lock(struct wland_sdio *bus)
{
	ulong flags;
	int ret = 0;

	if (bus) {
		spin_lock_irqsave(&bus->wakelock_spinlock, flags);
#ifdef CONFIG_HAS_WAKELOCK
		/*
		 * if wakelock_wd_counter was never used : lock it at once
		 */
		if (!bus->wakelock_wd_counter) {
			wake_lock(&bus->wl_wdwake);
			WLAND_DBG(SDIO, TRACE, "wl_wdwake lock.\n");
		}
#endif /*CONFIG_HAS_WAKELOCK */
		bus->wakelock_wd_counter++;
		ret = bus->wakelock_wd_counter;
		spin_unlock_irqrestore(&bus->wakelock_spinlock, flags);
	}
	return ret;
}

int wland_dhd_os_wd_wake_unlock(struct wland_sdio *bus)
{
	ulong flags;
	int ret = 0;

	if (bus) {
		spin_lock_irqsave(&bus->wakelock_spinlock, flags);
		if (bus->wakelock_wd_counter) {
			bus->wakelock_wd_counter = 0;
#ifdef CONFIG_HAS_WAKELOCK
			wake_unlock(&bus->wl_wdwake);
			WLAND_DBG(SDIO, TRACE, "wl_wdwake unlock.\n");
#endif /*CONFIG_HAS_WAKELOCK */
		}
		spin_unlock_irqrestore(&bus->wakelock_spinlock, flags);
	}
	return ret;
}

ulong wland_dhd_os_spin_lock(struct wland_sdio * bus)
{
	ulong flags = 0;

	if (bus)
		spin_lock_irqsave(&bus->wakelock_spinlock, flags);

	return flags;
}

void wland_dhd_os_spin_unlock(struct wland_sdio *bus, ulong flags)
{
	if (bus)
		spin_unlock_irqrestore(&bus->wakelock_spinlock, flags);
}

