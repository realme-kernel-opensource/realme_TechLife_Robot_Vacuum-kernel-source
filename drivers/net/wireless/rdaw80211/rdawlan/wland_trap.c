
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
#include <linux/kernel.h>
#include <linux/if_arp.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/wireless.h>
#include <linux/ieee80211.h>
#include <linux/debugfs.h>
#include <net/cfg80211.h>
#include <linux/firmware.h>
#include <linux/crc16.h>
#include <linux/crc32.h>
#include <crypto/hash.h>

#include "wland_defs.h"
#include "wland_fweh.h"
#include "wland_dev.h"
#include "wland_bus.h"
#include "wland_dbg.h"
#include "wland_utils.h"
#include "wland_wid.h"
#include "wland_trap.h"
#include "wland_sdmmc.h"

s32 wland_assoc_power_save(struct wland_private * priv)
{
	int ret = 0;

	WLAND_DBG(TRAP, TRACE, "Enter\n");

	WLAND_DBG(TRAP, TRACE, "Done(ret:%d)\n", ret);

	return ret;
}

s32 wland_set_phy_timeout(struct wland_private *priv,
	u32 cipher_pairwise, u32 cipher_group)
{
	int ret = 0;

	WLAND_DBG(TRAP, TRACE, "Enter\n");

	WLAND_DBG(TRAP, TRACE, "Done(ret:%d)\n", ret);
	return ret;
}

#if 0
s32 wland_check_firmware_state(struct wland_if *ifp)
{
	//struct wland_proto *prot = priv->prot;
	s32 err = 0;
	u8 *buf = kzalloc(MAX_PHYHW_VERSION_LEN, GFP_KERNEL);

	WLAND_DBG(TRAP, TRACE, "Enter\n");

	err = wland_fil_get_cmd_data(ifp, WID_PHYHW_VERSION, buf,
		MAX_PHYHW_VERSION_LEN);
	if (err < 0) {
		WLAND_ERR("Retreiving version information failed!\n");
		return -EINVAL;
	}

	WLAND_DBG(DCMD, INFO, "FirmWareVer:%s \n", buf);

	kfree(buf);

	WLAND_DBG(TRAP, TRACE, "Done(err:%d)\n", err);
	return err;
}
#endif

#if defined DECRYPT_FIRMWARE_RC4 || defined DECRYPT_FIRMWARE_AES
static s32 wland_set_decrypt(struct wland_if *ifp,
	u32 addr, u32 len, u8 methord)
{
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;
	s32 ret = 0;

	WLAND_DBG(TRAP, INFO, "Enter\n");


	mutex_lock(&drvr->proto_block);

	ret = wland_push_wid(buf, WID_MEMORY_ADDRESS, &addr, sizeof(addr), false);
	if (ret < 0) {
		mutex_unlock(&drvr->proto_block);
		WLAND_ERR("put wid:0x%04x error\n", WID_MEMORY_ADDRESS);
		return -1;
	}
	buf += ret;

	ret = wland_push_wid(buf, WID_MEMORY_LENGTH, &len, sizeof(len), false);
	if (ret < 0) {
		mutex_unlock(&drvr->proto_block);
		WLAND_ERR("put wid:0x%04x error\n", WID_MEMORY_LENGTH);
		return -1;
	}
	buf += ret;

	ret = wland_push_wid(buf, WID_BOOTROM_DECRYPT, &methord, sizeof(methord), false);
	if (ret < 0) {
		mutex_unlock(&drvr->proto_block);
		WLAND_ERR("put wid:0x%04x error\n", WID_DECRYPT_TYPE);
		return -1;
	}
	buf += ret;

	ret = wland_proto_cdc_data(ifp->drvr, buf-(prot->buf) + FMW_HEADER_LEN);

	if (ret < 0)
		WLAND_ERR("WID Result Failed\n");

	mutex_unlock(&drvr->proto_block);

	WLAND_DBG(TRAP, INFO, "Done(err=%d)\n", ret);
	return ret;
}
#endif

s32 wland_run_firmware(struct wland_if *ifp, u32 addr)
{
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;
	s32 ret = 0;
	u8 result;

	WLAND_DBG(TRAP, INFO, "Enter\n");

	/* insure firmware statue */
	ret = wland_fil_get_cmd_data(ifp, WID_BOOTROM_START_APP, &result, 1);
	if (ret < 0 || result != 1)
		WLAND_ERR("query firmware state error\n");

	mutex_lock(&drvr->proto_block);
	prot->reqid = 0;
	ret = wland_push_wid(buf, WID_MEMORY_ADDRESS, &addr, sizeof(addr), false);
	if (ret < 0) {
		mutex_unlock(&drvr->proto_block);
		WLAND_ERR("put wid:0x%04x error\n", WID_MEMORY_ADDRESS);
		return -1;
	}
	buf += ret;

	result = 1;
	ret = wland_push_wid(buf, WID_BOOTROM_START_APP, &result, sizeof(u8), false);
	if (ret < 0) {
		mutex_unlock(&drvr->proto_block);
		WLAND_ERR("put wid:0x%04x error\n", WID_BOOTROM_START_APP);
		return -1;
	}
	buf += ret;

	ret = wland_proto_cdc_data(ifp->drvr, buf-(prot->buf) + FMW_HEADER_LEN);
	if (ret < 0)
		WLAND_ERR("WID Result Failed\n");

	mutex_unlock(&drvr->proto_block);

	WLAND_DBG(TRAP, INFO, "Done(err=%d)\n", ret);
	return ret;
}

static s32 wland_bootrom_send_bulk(struct wland_if *ifp,
	u32 addr, const void *buffer, u32 buflen)
{
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;
	s32 ret = 0;

	WLAND_DBG(TRAP, TRACE, "Enter, addr:0x%08x\n", addr);

	mutex_lock(&drvr->proto_block);

	ret = wland_push_wid(buf, WID_MEMORY_ADDRESS, &addr, sizeof(addr), false);
	if (ret < 0) {
		mutex_unlock(&drvr->proto_block);
		WLAND_ERR("put wid error\n");
		return -1;
	}
	buf += ret;

	ret = wland_push_wid(buf, WID_MEMORY_LENGTH, &buflen, sizeof(u32), false);
	if (ret < 0) {
		mutex_unlock(&drvr->proto_block);
		WLAND_ERR("put wid error\n");
		return -1;
	}
	buf += ret;

	ret = wland_push_wid(buf, WID_MEMORY_ACCESS, buffer, buflen, false);
	if (ret < 0) {
		mutex_unlock(&drvr->proto_block);
		WLAND_ERR("put wid error\n");
		return -1;
	}
	buf += ret;

	ret = wland_proto_cdc_data(ifp->drvr, buf-(prot->buf) + FMW_HEADER_LEN);
	if (ret < 0)
		WLAND_ERR("WID Result Failed\n");

	mutex_unlock(&drvr->proto_block);
	WLAND_DBG(TRAP, TRACE, "Done(err:%d)\n", ret);
	return ret;
}

#ifdef WLAND_FIRMWARE_PATH
struct file *wland_open_image(char *fw_name)
{
	struct file *fp;
	char filename[256];
	snprintf(filename, 256, "%s/%s", WLAND_FIRMWARE_PATH, fw_name);
	WLAND_DBG(TRAP, INFO, "firmware path:%s\n", filename);
	fp = filp_open(filename, O_RDONLY, 0);
	if (IS_ERR(fp))
		fp = NULL;
	else
		fp->f_pos = 0;
	return fp;
}
int wland_get_image_block(char *buf, int len, void *image)
{
	struct file *fp = (struct file *)image;
	int rdlen;

	if (!image)
		return 0;

	rdlen = kernel_read(fp, fp->f_pos, buf, len);
	if (rdlen > 0)
		fp->f_pos += rdlen;

	return rdlen;
}

void wland_close_image(void *image)
{
	if (image)
		filp_close((struct file *)image, NULL);
}

static s32 wland_download_image(
	struct wland_if *ifp, char* filename, u32 addr)
{
	s32 ret = -1;
	char *img = NULL;
	int img_size = 0;
	struct file *fp;
	u16 bulkchunk = 1518 - 25;
	bulkchunk = bulkchunk-(bulkchunk%4);

	WLAND_DBG(TRAP, INFO, "wland_download_image\n");

	img = kmalloc(bulkchunk, GFP_KERNEL);
	if (!img) {
		WLAND_ERR("malloc buf failed\n");
		return ret;
	}

	fp = wland_open_image(filename);
	if (!fp) {
		WLAND_ERR("open fild %s fail\n", filename);
		kfree(img);
		return ret;
	}

	while (true) {
		ret = wland_get_image_block(img, bulkchunk, fp);
		if (ret == 0)
			break;

		if (ret < 0) {
			WLAND_ERR("get image fail\n");
			goto err;
		}

		if (wland_bootrom_send_bulk(ifp, addr+img_size, img, ret) < 0) {
			WLAND_ERR("wland_send_bulk failed");
			goto err;
		}
		img_size += ret;
	}

#ifdef DECRYPT_FIRMWARE_RC4
	WLAND_DBG(TRAP, INFO, "wland_set_decrypt\n");
	ret = wland_set_decrypt(ifp, addr, img_size, HOST_DECRYPT_RC4);
	if (ret < 0) {
		ret = -1;
		WLAND_ERR("wland_sdio_set_decrypt:%d failed\n", HOST_DECRYPT_RC4);
		goto err;
	}
#elif defined DECRYPT_FIRMWARE_AES
	WLAND_DBG(TRAP, INFO, "wland_sdio_set_decrypt\n");
	ret = wland_set_decrypt(ifp, addr, img_size, HOST_DECRYPT_AES_CBC);
	if (ret < 0) {
		ret = -1;
		WLAND_ERR("wland_sdio_set_decrypt:%d failed\n", HOST_DECRYPT_AES_CBC);
		goto err;
	}
#endif

err:
	wland_close_image(fp);
	kfree(img);
	return ret;

}
#elif defined WLAND_DOWNLOAD_FIRMWARE_FROM_HEX

#ifdef CONFIG_RDAWFMAC_SDIO
#define data_p2p_hexcode "rda5995_sdio_data_p2p.bin.hex"
#define code_p2p_hexcode "rda5995_sdio_code_p2p.bin.hex"
#define code1_p2p_hexcode "rda5995_sdio_code1_p2p.bin.hex"
#define data_ap_hexcode "rda5995_sdio_data_ap.bin.hex"
#define code_ap_hexcode "rda5995_sdio_code_ap.bin.hex"
#ifdef WLAND_DOWNLOAD_FIRMWARE_FROM_HEX_FOR_RF
#define data_rf_hexcode "rda5995_sdio_data_rf.bin.hex"
#define code_rf_hexcode "rda5995_sdio_code_rf.bin.hex"
#endif
#else
#define data_p2p_hexcode "rda5995_usb_data_p2p.bin.hex"
#define code_p2p_hexcode "rda5995_usb_code_p2p.bin.hex"
#define code1_p2p_hexcode "rda5995_usb_code1_p2p.bin.hex"
#define data_ap_hexcode "rda5995_usb_data_ap.bin.hex"
#define code_ap_hexcode "rda5995_usb_code_ap.bin.hex"
#ifdef WLAND_DOWNLOAD_FIRMWARE_FROM_HEX_FOR_RF
#define data_rf_hexcode "rda5995_usb_data_rf.bin.hex"
#define code_rf_hexcode "rda5995_usb_code_rf.bin.hex"
#endif
#endif

#ifdef WLAND_DOWNLOAD_FIRMWARE_FROM_HEX_FOR_RF
static unsigned char data_rf_hex_buf[] = {
#include data_rf_hexcode
};
#define DATA_RF_HEX_SIZE sizeof(data_rf_hex_buf)

static unsigned char code_rf_hex_buf[] = {
#include code_rf_hexcode
};
#define CODE_RF_HEX_SIZE sizeof(code_rf_hex_buf)
#endif

static unsigned char data_p2p_hex_buf[] = {
#include data_p2p_hexcode
};
#define DATA_P2P_HEX_SIZE sizeof(data_p2p_hex_buf)

static unsigned char code_p2p_hex_buf[] = {
#include code_p2p_hexcode
};
#define CODE_P2P_HEX_SIZE sizeof(code_p2p_hex_buf)

static unsigned char code1_p2p_hex_buf[] = {
#include code1_p2p_hexcode
};
#define CODE1_P2P_HEX_SIZE sizeof(code1_p2p_hex_buf)

static unsigned char data_ap_hex_buf[] = {
#include data_ap_hexcode
};
#define DATA_AP_HEX_SIZE sizeof(data_ap_hex_buf)

static unsigned char code_ap_hex_buf[] = {
#include code_ap_hexcode
};
#define CODE_AP_HEX_SIZE sizeof(code_ap_hex_buf)

#ifdef WLAND_DOWNLOAD_FIRMWARE_FROM_HEX_FOR_RF
#define FIRMWARE_BIN_CNT 7
#else
#define FIRMWARE_BIN_CNT 5
#endif

static struct wland_image_info hex_buf[FIRMWARE_BIN_CNT] = {
#ifdef CONFIG_RDAWFMAC_SDIO
	{"rda5995_sdio_data_p2p.bin", data_p2p_hex_buf, DATA_P2P_HEX_SIZE},
	{"rda5995_sdio_code_p2p.bin", code_p2p_hex_buf, CODE_P2P_HEX_SIZE},
	{"rda5995_sdio_code1_p2p.bin", code1_p2p_hex_buf, CODE1_P2P_HEX_SIZE},
	{"rda5995_sdio_data_ap.bin", data_ap_hex_buf, DATA_AP_HEX_SIZE},
	{"rda5995_sdio_code_ap.bin", code_ap_hex_buf, CODE_AP_HEX_SIZE},
#ifdef WLAND_DOWNLOAD_FIRMWARE_FROM_HEX_FOR_RF
	{"rda5995_sdio_data_rf.bin", data_rf_hex_buf, DATA_RF_HEX_SIZE},
	{"rda5995_sdio_code_rf.bin", code_rf_hex_buf, CODE_RF_HEX_SIZE},
#endif
#else
	{"rda5995_usb_data_p2p.bin", data_p2p_hex_buf, DATA_P2P_HEX_SIZE},
	{"rda5995_usb_code_p2p.bin", code_p2p_hex_buf, CODE_P2P_HEX_SIZE},
	{"rda5995_usb_code1_p2p.bin", code1_p2p_hex_buf, CODE1_P2P_HEX_SIZE},
	{"rda5995_usb_data_ap.bin", data_ap_hex_buf, DATA_AP_HEX_SIZE},
	{"rda5995_usb_code_ap.bin", code_ap_hex_buf, CODE_AP_HEX_SIZE},
#ifdef WLAND_DOWNLOAD_FIRMWARE_FROM_HEX_FOR_RF
	{"rda5995_usb_data_rf.bin", data_rf_hex_buf, DATA_RF_HEX_SIZE},
	{"rda5995_usb_code_rf.bin", code_rf_hex_buf, CODE_RF_HEX_SIZE},
#endif
#endif
};
static s32 wland_download_image(
	struct wland_if *ifp, char* filename, u32 addr)
{
	s32 err = 0;
	u32 sent, dllen;
	u32 sendlen;
	const void *dlpos;
	int i = 0;
	u16 bulkchunk = 1518 - 25;
	u32 download_addr = addr;
	bulkchunk = bulkchunk-(bulkchunk%4);

	WLAND_DBG(TRAP, INFO, "wland_download_image WLAND_DOWNLOAD_FIRMWARE_FROM_HEX!\n");

	for(i = 0; i < FIRMWARE_BIN_CNT; i++) {
		if (strncasecmp(filename, hex_buf[i].bin_name, strlen(filename)) == 0)
			break;
	}
	if (i == FIRMWARE_BIN_CNT) {
		WLAND_ERR("No fw_hex_buf for:%s\n", filename);
		return -1;
	} else {
		WLAND_DBG(TRAP, INFO, "fw index:%d input filename:%s\n", i, filename);
		dlpos = hex_buf[i].buf;
		dllen = hex_buf[i].size;
	}

	sent = 0;

	while (sent != dllen) {
		if (dllen-sent < bulkchunk)
			sendlen = dllen-sent;
		else
			sendlen = bulkchunk;

		if (wland_bootrom_send_bulk(ifp, download_addr, dlpos, sendlen) < 0) {
			WLAND_ERR("wland_send_bulk failed");
			err = -1;
			break;
		}

		download_addr += sendlen;
		dlpos += sendlen;
		sent += sendlen;
	}

#ifdef DECRYPT_FIRMWARE_RC4
	WLAND_DBG(TRAP, INFO, "wland_set_decrypt\n");
	err = wland_set_decrypt(ifp, addr, dllen, HOST_DECRYPT_RC4);
	if (err < 0) {
		WLAND_ERR("wland_sdio_set_decrypt:%d failed\n", HOST_DECRYPT_RC4);
		return -1;
	}
#elif defined DECRYPT_FIRMWARE_AES
	WLAND_DBG(TRAP, INFO, "wland_sdio_set_decrypt\n");
	err = wland_set_decrypt(ifp, addr, dllen, HOST_DECRYPT_AES_CBC);
	if (err < 0) {
		WLAND_ERR("wland_sdio_set_decrypt:%d failed\n", HOST_DECRYPT_AES_CBC);
		return -1;
	}
#endif
	return 0;
}
#else
#if defined CHECK_FIRMWARE_MD5 || defined CHECK_FIRMWARE_SHA1
int wland_hash(char *name, const u8 *str, size_t len, u8 *hash)
{
	u32 size=0;
	struct shash_desc *sdesc;
	int err = 0;
	struct crypto_shash *c_hash = crypto_alloc_shash(name, 0, 0);
	if (IS_ERR(c_hash)) {
		WLAND_ERR("crypto_alloc_shash failed\n");
		return -1;
		}
	size = sizeof(struct shash_desc) + crypto_shash_descsize(c_hash);
	sdesc = kmalloc(size, GFP_KERNEL);
	if (!sdesc) {
		WLAND_ERR("kmalloc failed\n");
		err = -1;
		goto malloc_err;
	}
	sdesc->tfm = c_hash;
	sdesc->flags = 0x0;

	err = crypto_shash_init(sdesc);
	if (err) {
		WLAND_ERR("crypto_shash_init failed\n");
		err = -1;
		goto hash_err;
	}
	crypto_shash_update(sdesc, str, len);
	err = crypto_shash_final(sdesc, hash);

hash_err:
	kfree(sdesc);
malloc_err:
	crypto_free_shash(c_hash);
	WLAND_DBG(TRAP, INFO, "Done(err=%d)\n", err);
	return err;
}
#endif

#if defined CHECK_FIRMWARE_CRC32 || defined CHECK_FIRMWARE_SHA1 || defined CHECK_FIRMWARE_MD5
static s32 wland_check_firmware(struct wland_if *ifp,
	u32 addr, u32 len, u32 methord, u8 *result, u16 result_len)
{
	struct wland_private *drvr = ifp->drvr;
	struct wland_proto *prot = drvr->prot;
	u8 *buf = prot->buf;
	s32 ret = 0;

	WLAND_DBG(TRAP, TRACE, "Enter:result:%p\n", result);

	mutex_lock(&drvr->proto_block);

	ret = wland_push_wid(buf, WID_MEMORY_ADDRESS, &addr, sizeof(addr), false);
	if (ret < 0) {
		mutex_unlock(&drvr->proto_block);
		WLAND_ERR("put wid:0x%04x error\n", WID_MEMORY_ADDRESS);
		return -1;
	}
	buf += ret;

	ret = wland_push_wid(buf, WID_MEMORY_LENGTH, &len, sizeof(len), false);
	if (ret < 0) {
		mutex_unlock(&drvr->proto_block);
		WLAND_ERR("put wid:0x%04x error\n", WID_MEMORY_LENGTH);
		return -1;
	}
	buf += ret;

	ret = wland_push_wid(buf, WID_CHECKSUM_TYPE, &methord, sizeof(methord), false);
	if (ret < 0) {
		mutex_unlock(&drvr->proto_block);
		WLAND_ERR("put wid:0x%04x error\n", WID_CHECKSUM_TYPE);
		return -1;
	}
	buf += ret;

	ret = wland_proto_cdc_data(ifp->drvr, buf-(prot->buf) + FMW_HEADER_LEN);
	if (ret < 0)
		WLAND_ERR("WID Result Failed\n");

	mutex_unlock(&drvr->proto_block);

	ret = wland_fil_get_cmd_data(ifp, WID_BOOTROM_CHECKSUM, result, result_len);
	if (ret < 0)
		WLAND_ERR("WID Result Failed\n");
	WLAND_DBG(TRAP, INFO, "Done(err=%d)\n", ret);
	return ret;


}
#endif

static s32 wland_write_firmware(const struct firmware *fw_entry,
	struct wland_if *ifp, u32 addr)
{
	s32 err = 0;
	u32 sent, dllen;
	u32 sendlen;
	const void *dlpos;
	///TODO: The 10 length??
	u16 bulkchunk = 1518 - 25;//(CDC_MAX_MSG_SIZE-25);
	bulkchunk = bulkchunk-(bulkchunk%4);
		//1536 - sizeof(struct wland_dcmd) -
		 //sizeof(struct wland_wid_cmd) - 10 - 8;

	dlpos = fw_entry->data;
	dllen = fw_entry->size;

	WLAND_DBG(TRAP, INFO, "Enter, data_addr:%p,data_len:%u\n",
		dlpos, dllen);
	sent = 0;

	while (sent != dllen) {
		if (dllen-sent < bulkchunk)
			sendlen = dllen-sent;
		else
			sendlen = bulkchunk;
#ifdef debug_time
		{
			struct timespec t;
			jiffies_to_timespec(jiffies,&t);
			WLAND_DBG(TRAP, INFO, "%lu, %lu\n", t.tv_sec, t.tv_nsec);
		}
#endif
		WLAND_DBG(TRAP, INFO, "send one pkt, addr:0x%08x, dlpos:%p, sendlen:%u(all:%u)\n",
			addr, dlpos, sent, dllen);

		if (wland_bootrom_send_bulk(ifp, addr, dlpos, sendlen) < 0) {
			WLAND_ERR("wland_send_bulk failed");
			err = -1;
			break;
		}

		addr += sendlen;
		dlpos += sendlen;
		sent += sendlen;
	}

	WLAND_DBG(TRAP, INFO, "Done(err=%d)\n", err);
	return err;
}

static s32 wland_download_image(
	struct wland_if *ifp, char* filename, u32 addr)
{
	struct wland_private *drvr = ifp->drvr;
	s32 ret = -1;
#if defined(CHECK_FIRMWARE_CRC32) || defined(CHECK_FIRMWARE_MD5) || defined(CHECK_FIRMWARE_SHA1)
	u8 result[20] = {0};
#endif
	const struct firmware *fw_entry;
#ifdef CHECK_FIRMWARE_MD5
	u8 md5_result[MD5_DIGEST_LENGTH];
#endif
#ifdef CHECK_FIRMWARE_SHA1
	u8 sha1_result[SHA1_DIGEST_SIZE];
#endif

	WLAND_DBG(TRAP, INFO, "wland_trap_attach: Request firmware\n");
	ret = request_firmware(&fw_entry,filename, drvr->bus_if->dev);
	if (ret) {
		WLAND_ERR("Request firmware: request firmware:%s failed\n", filename);
		return ret;
	}

	WLAND_DBG(TRAP, INFO,
		"Write core patch: wland_write_firmware\n");
	ret = wland_write_firmware(fw_entry, ifp, addr);
	if (ret < 0) {
		WLAND_ERR("wland_write_firmware failed!\n");
		goto err;
	}

	//goto err;
#ifdef CHECK_FIRMWARE_CRC32
	WLAND_DBG(TRAP, INFO, "check firmware with crc32\n");
	ret = wland_check_firmware(ifp, addr,
		fw_entry->size, HOST_CHECKSUM_CRC, result, CRC32_DIGEST_SIZE);
	if (ret < 0) {
		ret = -1;
		WLAND_ERR("crc32 check firmware failed\n");
		goto err;
	} else if(*(u32 *)result != crc32(0xffffffff, fw_entry->data, fw_entry->size)) {
		ret = -2;
		WLAND_ERR("crc32 check result error.fw ret:%x, driver ret:%x\n",
			*(u32 *)result, crc32(0xffffffff, fw_entry->data, fw_entry->size));
		goto err;
	}
#endif

#ifdef CHECK_FIRMWARE_MD5
	WLAND_DBG(TRAP, INFO, "check firmware with md5. result:%p\n", result);
	ret = wland_check_firmware(ifp, addr,
		fw_entry->size, HOST_CHECKSUM_MD5, result, MD5_DIGEST_LENGTH);
	if (ret < 0) {
		ret = -1;
		WLAND_ERR("md5 check firmware failed\n");
		goto err;
	}

	if (wland_hash("md5", fw_entry->data, fw_entry->size, md5_result) < 0) {
		ret = -1;
		WLAND_ERR("count md5 failed\n");
		goto err;
	} else if(memcmp(result, md5_result, MD5_DIGEST_LENGTH)) {
		ret = -2;
		WLAND_ERR("md5 check result error. return result:%08x %08x %08x %08x"
			"my_result:%08x %08x %08x %08x\n",
			*(u32*)(result+0), *(u32*)(result+4), *(u32*)(result+8),*(u32*)(result+12),
			*(u32*)(md5_result+0), *(u32*)(md5_result+4), *(u32*)(md5_result+8),
			*(u32*)(md5_result+12));
		goto err;
	}
#endif

#ifdef CHECK_FIRMWARE_SHA1
	WLAND_DBG(TRAP, INFO, "check firmware with sh1\n");
	ret = wland_check_firmware(ifp, addr,
		fw_entry->size, HOST_CHECKSUM_SHA1, result, SHA1_DIGEST_SIZE);
	if (ret < 0) {
		ret = -1;
		WLAND_ERR("sh1 check firmware failed\n");
		goto err;
	}

	if (wland_hash("sha1", fw_entry->data, fw_entry->size, sha1_result) < 0) {
		ret = -1;
		WLAND_ERR("count sh1 failed\n");
		goto err;
	} else if(memcmp(result, sha1_result, SHA1_DIGEST_SIZE)) {
		ret = -2;
		WLAND_ERR("sh1 check result error. return result:%04x%04x%04x%04x%04x"
			"my_result:%04x%04x%04x%04x%04x\n",
			*(u32*)(result+0), *(u32*)(result+4), *(u32*)(result+8),*(u32*)(result+12),*(u32*)(result+16),
			*(u32*)(sha1_result+0), *(u32*)(sha1_result+4), *(u32*)(sha1_result+8),
			*(u32*)(sha1_result+12), *(u32*)(sha1_result+16));
		goto err;
	}
#endif

#ifdef DECRYPT_FIRMWARE_RC4
	WLAND_DBG(TRAP, INFO, "wland_set_decrypt\n");
	ret = wland_set_decrypt(ifp, addr, fw_entry->size, HOST_DECRYPT_RC4);
	if (ret < 0) {
		ret = -1;
		WLAND_ERR("wland_sdio_set_decrypt:%d failed\n", HOST_DECRYPT_RC4);
		goto err;
	}
#elif defined DECRYPT_FIRMWARE_AES
	WLAND_DBG(TRAP, INFO, "wland_sdio_set_decrypt\n");
	ret = wland_set_decrypt(ifp, addr, fw_entry->size, HOST_DECRYPT_AES_CBC);
	if (ret < 0) {
		ret = -1;
		WLAND_ERR("wland_sdio_set_decrypt:%d failed\n", HOST_DECRYPT_AES_CBC);
		goto err;
	}
#endif

err:
	release_firmware(fw_entry);
	return ret;

}
#endif /*WLAND_FIRMWARE_PATH*/

s32 wland_download_codefile(struct wland_if *ifp)
{
	s32 ret = -1;
	char *filename = NULL;
	struct wland_private *drvr= ifp->drvr;

	WLAND_DBG(TRAP, TRACE, "Enter, chip:%d,firmware_path%s\n",
		drvr->bus_if->chip, rdawlan_firmware_path);

	if(drvr->bus_if->chip == WLAND_VER_91_H) {
		if (strncasecmp(rdawlan_firmware_path, "sta", strlen("sta")) == 0)
#ifdef WLAND_SDIO_SUPPORT
			filename = RDA5991H_SDIO_CODE_STA;
#else
			filename = RDA5991H_USB_CODE_STA;
#endif
		else if (strncasecmp(rdawlan_firmware_path, "p2p", strlen("p2p")) == 0)
#ifdef WLAND_SDIO_SUPPORT
			filename = RDA5991H_SDIO_CODE_P2P;
#else
			filename = RDA5991H_USB_CODE_P2P;
#endif
		else if (strncasecmp(rdawlan_firmware_path, "ap", strlen("ap")) == 0)
#ifdef WLAND_SDIO_SUPPORT
			filename = RDA5991H_SDIO_CODE_AP;
#else
			filename = RDA5991H_USB_CODE_AP;
#endif
		else if (strncasecmp(rdawlan_firmware_path, "rf", strlen("rf")) == 0)
#ifdef WLAND_SDIO_SUPPORT
			filename = RDA5991H_SDIO_CODE_RF;
#else
			filename = RDA5991H_USB_CODE_RF;
#endif
	}

	if (filename)
		ret = wland_download_image(ifp, filename, RDA5991H_CODE_ADDR);

#ifndef DOWNLOAD_STA_FIRMWARE
	if (strncasecmp(rdawlan_firmware_path, "sta", strlen("sta")) == 0)
#ifdef WLAND_SDIO_SUPPORT
		ret = wland_download_image(ifp, RDA5991H_SDIO_CODE1_STA, RDA5991H_CODE1_ADDR_P2P);
#else
		ret = wland_download_image(ifp, RDA5991H_USB_CODE1_STA, RDA5991H_CODE1_ADDR_P2P);
#endif
#endif /*DOWNLOAD_STA_FIRMWARE*/
	return ret;
}

s32 wland_download_datafile(struct wland_if *ifp)
{
	char *filename = NULL;
	u32 addr;
	struct wland_private *drvr = ifp->drvr;

	WLAND_DBG(TRAP, TRACE, "Enter\n");
	addr = RDA5991H_DATA_ADDR_STA_AP;

#ifndef DOWNLOAD_STA_FIRMWARE
	if (strncasecmp(rdawlan_firmware_path, "sta", strlen("sta")) == 0)
		addr = RDA5991H_DATA_ADDR_P2P;
#endif /*DOWNLOAD_STA_FIRMWARE*/

	if(drvr->bus_if->chip == WLAND_VER_91_H) {
		if (strncasecmp(rdawlan_firmware_path, "sta", strlen("sta")) == 0)
#ifdef WLAND_SDIO_SUPPORT
			filename = RDA5991H_SDIO_DATA_STA;
#else
			filename = RDA5991H_USB_DATA_STA;
#endif
		else if (strncasecmp(rdawlan_firmware_path, "p2p", strlen("p2p")) == 0)
#ifdef WLAND_SDIO_SUPPORT
			filename = RDA5991H_SDIO_DATA_P2P;
#else
			filename = RDA5991H_USB_DATA_P2P;
#endif
		else if (strncasecmp(rdawlan_firmware_path, "ap", strlen("ap")) == 0)
#ifdef WLAND_SDIO_SUPPORT
			filename = RDA5991H_SDIO_DATA_AP;
#else
			filename = RDA5991H_USB_DATA_AP;
#endif
		else if (strncasecmp(rdawlan_firmware_path, "rf", strlen("rf")) == 0)
#ifdef WLAND_SDIO_SUPPORT
			filename = RDA5991H_SDIO_DATA_RF;
#else
			filename = RDA5991H_USB_DATA_RF;
#endif
	}

	if (filename)
		return wland_download_image(ifp, filename, addr);
	return -1;
}

