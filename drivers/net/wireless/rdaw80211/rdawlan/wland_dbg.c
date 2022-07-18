
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

#include "wland_defs.h"
#include "wland_fweh.h"
#include "wland_dev.h"
#include "wland_bus.h"
#include "wland_dbg.h"
#include "wland_wid.h"
#include "wland_rf.h"

/* Error Debug Area Bit Map */
int wland_dbg_area =
	//WLAND_DATA_VAL		|
	//WLAND_TRAP_VAL					|
	//WLAND_DCMD_VAL					|
	//WLAND_EVENT_VAL						|
	//WLAND_BUS_VAL					|
	WLAND_WEXT_VAL |
	//WLAND_DEFAULT_VAL					|
	//WLAND_SDIO_VAL					|
	//WLAND_USB_VAL |
	//WLAND_RX_VAL |
	WLAND_CFG80211_VAL |
	WLAND_RFTEST_VAL;

int wland_dbg_level = WLAND_INFO_LEVEL;

int wland_dump_area =
	//WLAND_TX_CTRL_AREA				|
	//WLAND_TX_MSDU_AREA					|
	//WLAND_RX_WIDRSP_AREA			|
	//WLAND_RX_MACSTAT_AREA			|
	//WLAND_RX_NETINFO_AREA			|
	//WLAND_RX_MSDU_AREA					|
	//WLAND_RX_NETEVENT_AREA				|
	//WLAND_TX_CFG80211_AREA				|
	//WLAND_USB_AREA |
	WLAND_NONE_AREA;

/* Set Default Debug Dir */
static struct dentry *root_folder = NULL;

#ifdef WLAND_SDIO_SUPPORT
static ssize_t wland_debugfs_sdio_counter_read(struct file *f,
	char __user * data, size_t count, loff_t * ppos)
{
	struct wland_sdio_count *sdcnt = f->private_data;
	int buf_size = 750;
	int res;
	int ret;
	char *buf;

	/*
	 * only allow read from start
	 */
	if (*ppos > 0)
		return 0;

	buf = kmalloc(buf_size, GFP_KERNEL);
	if (buf == NULL) {
		WLAND_ERR("kmalloc buf failed\n");
		return -ENOMEM;
	}


	res = scnprintf(buf, buf_size,
		"intrcount:    %u\nlastintrs:    %u\n"
		"pollcnt:      %u\nregfails:     %u\n"
		"tx_sderrs:    %u\nfcqueued:     %u\n"
		"rxrtx:        %u\nrx_toolong:   %u\n"
		"rxc_errors:   %u\nrx_hdrfail:   %u\n"
		"rx_badhdr:    %u\nrx_badseq:    %u\n"
		"fc_rcvd:      %u\nfc_xoff:      %u\n"
		"fc_xon:       %u\n                  "
		"f2rxhdrs:     %u\nf2rxdata:     %u\n"
		"f2txdata:     %u\nf1regdata:    %u\n"
		"tickcnt:      %u\ntx_ctlerrs:   %lu\n"
		"tx_ctlpkts:   %lu\nrx_ctlerrs:   %lu\n"
		"rx_ctlpkts:   %lu\nrx_readahead: %lu\n",
		sdcnt->intrcount, sdcnt->lastintrs,
		sdcnt->pollcnt, sdcnt->regfails,
		sdcnt->tx_sderrs, sdcnt->fcqueued,
		sdcnt->rxrtx, sdcnt->rx_toolong,
		sdcnt->rxc_errors, sdcnt->rx_hdrfail,
		sdcnt->rx_badhdr, sdcnt->rx_badseq,
		sdcnt->fc_rcvd, sdcnt->fc_xoff,
		sdcnt->fc_xon,
		sdcnt->f2rxhdrs, sdcnt->f2rxdata,
		sdcnt->f2txdata, sdcnt->f1regdata,
		sdcnt->tickcnt, sdcnt->tx_ctlerrs,
		sdcnt->tx_ctlpkts, sdcnt->rx_ctlerrs,
		sdcnt->rx_ctlpkts, sdcnt->rx_readahead_cnt);

	ret = simple_read_from_buffer(data, count, ppos, buf, res);
	kfree(buf);
	return ret;
}

static const struct file_operations wland_debugfs_sdio_counter_ops = {
	.owner = THIS_MODULE,
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 3, 0)
	.open = simple_open,
#endif
	.read = wland_debugfs_sdio_counter_read
};
#endif

static ssize_t wland_debugarea_read(struct file *file, char __user * userbuf,
	size_t count, loff_t *ppos)
{
	size_t pos = 0;
	unsigned long addr = get_zeroed_page(GFP_KERNEL);
	char *buf = (char *) addr;
	ssize_t res;

	WLAND_DBG(DEFAULT, TRACE, "get debug_area:0x%x\n", wland_dbg_area);

	pos += snprintf(buf + pos, PAGE_SIZE - pos, "%x\n", wland_dbg_area);

	res = simple_read_from_buffer(userbuf, count, ppos, buf, pos);

	free_page(addr);
	return res;
}

static ssize_t wland_debugarea_write(struct file *file,
	const char __user *user_buf, size_t count, loff_t *ppos)
{
	ssize_t ret;
	int debug_area;
	unsigned long addr = get_zeroed_page(GFP_KERNEL);
	char *buf = (char *) addr;

	WLAND_DBG(DEFAULT, TRACE, "Enter\n");

	if (copy_from_user(buf, user_buf, count)) {
		ret = -EFAULT;
		goto out_unlock;
	}

	ret = sscanf(buf, "%x", &debug_area);
	if (ret != 1) {
		ret = -EINVAL;
		goto out_unlock;
	}

	wland_dbg_area = debug_area;

	WLAND_DBG(DEFAULT, TRACE, "set debug_area = 0x%x\n", wland_dbg_area);

	ret = count;
out_unlock:
	free_page(addr);
	return ret;
}

static const struct file_operations wland_dbgarea_ops = {
	.owner = THIS_MODULE,
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 3, 0)
	.open = simple_open,
#endif
	.read = wland_debugarea_read,
	.write = wland_debugarea_write
};

static ssize_t wland_debuglevel_read(struct file *file, char __user *userbuf,
	size_t count, loff_t *ppos)
{
	size_t pos = 0;
	unsigned long addr = get_zeroed_page(GFP_KERNEL);
	char *buf = (char *) addr;
	ssize_t res;

	WLAND_DBG(DEFAULT, TRACE, "get debug_level:%d\n", wland_dbg_level);

	pos += snprintf(buf + pos, PAGE_SIZE - pos, "%d\n", wland_dbg_level);

	res = simple_read_from_buffer(userbuf, count, ppos, buf, pos);

	free_page(addr);
	return res;
}

static ssize_t wland_debuglevel_write(struct file *file,
	const char __user *user_buf, size_t count, loff_t *ppos)
{
	ssize_t ret;
	int debug_level;
	unsigned long addr = get_zeroed_page(GFP_KERNEL);
	char *buf = (char *) addr;

	WLAND_DBG(DEFAULT, TRACE, "Enter\n");

	if (copy_from_user(buf, user_buf, count)) {
		ret = -EFAULT;
		goto out_unlock;
	}

	ret = sscanf(buf, "%d", &debug_level);
	if (ret != 1) {
		ret = -EINVAL;
		goto out_unlock;
	}

	wland_dbg_level = debug_level;

	WLAND_DBG(DEFAULT, TRACE, "set debug_level = %d\n", wland_dbg_level);

	ret = count;
out_unlock:
	free_page(addr);
	return ret;
}

static const struct file_operations wland_dbglevel_ops = {
	.owner = THIS_MODULE,
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 3, 0)
	.open = simple_open,
#endif
	.read = wland_debuglevel_read,
	.write = wland_debuglevel_write
};

#ifdef DEBUG
#ifdef WLAND_SDIO_SUPPORT
static ssize_t wland_sdio_forensic_read(struct file *f, char __user *data,
	size_t count, loff_t *ppos)
{
	//wland_private *drvr = f->private_data;
	int res = 0;

	//res = brcmf_sdio_trap_info(bus, &sh, data, count);

	if (res > 0)
		*ppos += res;
	return (ssize_t) res;
}

static const struct file_operations sdio_forensic_ops = {
	.owner = THIS_MODULE,
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 3, 0)
	.open = simple_open,
#endif
	.read = wland_sdio_forensic_read
};
#endif
#endif /* DEBUG */

void wland_debugfs_create(struct wland_private *drvr)
{
#ifdef DEBUG
	struct dentry *dentry = drvr->dbgfs_dir;;

	if (IS_ERR_OR_NULL(dentry))
		return;
#ifdef WLAND_SDIO_SUPPORT
	debugfs_create_file("forensics", S_IRUGO, dentry, drvr,
		&sdio_forensic_ops);

	debugfs_create_file("counters", S_IRUGO, dentry, drvr,
		&wland_debugfs_sdio_counter_ops);
#endif
	debugfs_create_file("dbglevel", S_IRUGO, dentry, drvr,
		&wland_dbglevel_ops);

	debugfs_create_file("dbgarea", S_IRUGO, dentry, drvr,
		&wland_dbgarea_ops);
#endif /* DEBUG */
}

char *wland_dbgarea(int dbg_flags)
{
	switch (dbg_flags) {
	case WLAND_TRAP_VAL:
		return "[RDAWLAN_TRAP]";
	case WLAND_EVENT_VAL:
		return "[RDAWLAN_EVENT]";
	case WLAND_DCMD_VAL:
		return "[RDAWLAN_DCMD]";
	case WLAND_WEXT_VAL:
		return "[RDAWLAN_WEXT]";
	case WLAND_DEFAULT_VAL:
		return "[RDAWLAN_DEFAULT]";
	case WLAND_SDIO_VAL:
		return "[RDAWLAN_SDIO]";
	case WLAND_USB_VAL:
		return "[RDAWLAN_USB]";
	case WLAND_CFG80211_VAL:
		return "[RDAWLAN_CFG80211]";
	case WLAND_BUS_VAL:
		return "[RDAWLAN_BUS]";
	case WLAND_DATA_VAL:
		return "[RDAWLAN_DATA]";
	case WLAND_RX_VAL:
		return "[RDAWLAN_RX]";
	case WLAND_RFTEST_VAL:
		return "[RDAWLAN_RFTEST]";
	default:
		return "[RDAWLAN_UNKNOW]";
	}
}

#ifdef DEBUG
void wland_dbg_hex_dump(int level, const void *data, size_t size,
	const char *fmt, ...)
{
	pr_info("%s=======================Hex Data======================= [begin]\n",
		wland_dbgarea(level));
	print_hex_dump(KERN_ERR, wland_dbgarea(level), DUMP_PREFIX_OFFSET, 32, 1,
	       data, size, false);
	pr_info("%s=======================Hex Data======================= [end]\n",
		wland_dbgarea(level));
}
#endif

/* dbg attach */
int wland_debugfs_attach(struct wland_private *drvr)
{
	struct device *dev = drvr->bus_if->dev;

	WLAND_DBG(DEFAULT, TRACE, "Enter.\n");

	if (!root_folder) {
		WLAND_ERR("root folder is NULL\n");
		return -ENODEV;
	}

	drvr->dbgfs_dir = debugfs_create_dir(dev_name(dev), root_folder);

	if (IS_ERR_OR_NULL(drvr->dbgfs_dir)) {
		WLAND_ERR("drvr->dbgfs_dir is NULL\n");
		return -ENODEV;
	}

	WLAND_DBG(DEFAULT, TRACE, "Done.\n");

	return 0;
}

/* dbg dettach */
void wland_debugfs_detach(struct wland_private *drvr)
{
	WLAND_DBG(DEFAULT, TRACE, "Enter\n");

	if (!IS_ERR_OR_NULL(drvr->dbgfs_dir))
		debugfs_remove_recursive(drvr->dbgfs_dir);

	WLAND_DBG(DEFAULT, TRACE, "Done\n");
}

/* dbg dir init */
void wland_debugfs_init(void)
{
	WLAND_DBG(DEFAULT, TRACE, "Enter\n");
	root_folder = debugfs_create_dir(KBUILD_MODNAME, NULL);

	if (!root_folder || IS_ERR(root_folder)) {
		if (root_folder == ERR_PTR(-ENODEV))
			WLAND_ERR("debugfs is not enabled on this kernel\n");
		else
			WLAND_ERR("can not create debugfs directory:%ld\n", PTR_ERR(root_folder));
		root_folder = NULL;
	}
	WLAND_DBG(DEFAULT, TRACE, "Done\n");
}

/* dbg dir exit */
void wland_debugfs_exit(void)
{
	WLAND_DBG(DEFAULT, TRACE, "Enter\n");
	if (!root_folder)
		return;

	debugfs_remove_recursive(root_folder);

	root_folder = NULL;
	WLAND_DBG(DEFAULT, TRACE, "Done\n");
}

void dump_buf(const u8 *buf, u16 len)
{
	int i;

	for (i=0;i<len;i++) {
		if(i%8 == 0)
			printk("  ");
		printk("%02x ", buf[i]);
		if((i+1)%16 == 0)
			printk("\n");
	}
	printk("len:%d\n\n", len);
}

#ifdef DEBUG_FILE
static struct proc_dir_entry *wland_proc_create_dir(const char *name,
	struct proc_dir_entry *parent, void *data)
{
	struct proc_dir_entry *entry;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0))
	entry = proc_mkdir_data(name, S_IRUGO|S_IXUGO, parent, data);
#else
	//entry = proc_mkdir_mode(name, S_IRUGO|S_IXUGO, parent);
	entry = proc_mkdir(name, parent);
	if (entry)
		entry->data = data;
#endif

	return entry;
}
static struct proc_dir_entry *wland_proc_create_entry(const char *name,
	struct proc_dir_entry *parent, const struct file_operations *fops,
	void * data)
{
	struct proc_dir_entry *entry;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26))
	entry = proc_create_data(name,  S_IFREG|S_IRUGO|S_IWUGO, parent, fops, data);
#else
	entry = create_proc_entry(name, S_IFREG|S_IRUGO|S_IWUGO, parent);
	if (entry) {
		entry->data = data;
		entry->proc_fops = fops;
	}
#endif

	return entry;
}
#if 0
static int wland_txrx_info(struct seq_file *m, void *v)
{
	struct net_device *dev = m->private;
	WLAND_DBG(DEFAULT, INFO, "Enter\n");


	return 0;
}
#endif

static void proc_print(struct seq_file *m, char *data)
{
	if (m == 0)
		printk(data);
	else
		seq_printf(m, data);
}

static int wland_tx_stat(struct seq_file *m, void *v)
{
	struct net_device *ndev = m->private;
	char data[150] = {'\0'};
	u8 len = 0;

	WLAND_DBG(DEFAULT, DEBUG, "Enter\n");
	len = wland_dev_get_tx_status(ndev, data, sizeof(data));
	if (len <= 0) {
		WLAND_ERR("get tx state failed!\n");
		return 0;
	} else
		proc_print(m, data);
	return 0;
}

static int wland_get_version_info(struct seq_file *m, void *v)
{
	struct net_device *ndev = m->private;
	struct wland_if *ifp = netdev_priv(ndev);
	char data[150] = {'\0'};
	u8 len = 0;
	u8 total_len = 0;
	u8 firmware_version[20];
	u8 chip_version = 0;
	int err = -1;

	WLAND_DBG(DEFAULT, INFO, "Enter\n");

	//1. chip version
	err = wland_fil_get_cmd_data(ifp, WID_CHIP_VERSION,	&chip_version, 1);
	if (err < 0) {
		WLAND_ERR("Failed to get chip version!\n");
		return 0;
	} else {
		len = snprintf(data+total_len, sizeof(data)-total_len,
			"Chip Version:u%02d\n", chip_version);
		total_len += len;
	}

	//2. driver version
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
	len = snprintf(data+total_len, sizeof(data)-total_len,
		"Driver Compiled on " __DATE__ " at " __TIME__ "\n");
	total_len += len;
#endif /*LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)*/
	len = snprintf(data+total_len, sizeof(data)-total_len,
		"Driver Version: %d.%d.%d.\n", WLAND_VER_MAJ,
			WLAND_VER_MIN, WLAND_VER_BLD);
	total_len += len;

	//3. firmware version
	err = wland_fil_get_cmd_data(ifp, WID_FIRMWARE_VERSION, firmware_version, 20);
	if (err < 0) {
		WLAND_ERR("Failed to get Firmware version\n");
		return 0;
	} else {
		firmware_version[5] = '\0';
		len = snprintf(data+total_len, sizeof(data)-total_len,
			"Firmware Version:%s\n", firmware_version);
		total_len += len;
	}

	data[total_len] = '\0';
	proc_print(m, data);
	return 0;
}

static int wland_get_tx_power(struct seq_file *m, void *v)
{
	struct net_device *ndev = m->private;
	struct wland_if *ifp = netdev_priv(ndev);
	char data[300] = {'\0'};
	u8 len = 0;
	u8 total_len = 0;
	u16 value_11f, value_120;
	u8 g_n_offset;
	int err = -1;

	WLAND_DBG(DEFAULT, INFO, "Enter\n");

	err = wland_get_hardware_param(ndev, NULL, 0, 1, &value_11f);
	if (err < 0) {
		WLAND_ERR("can not get 11f value\n");
		return 0;
	}
	err = wland_get_hardware_param(ndev, NULL, 0, 2, &value_120);
	if (err < 0) {
		WLAND_ERR("can not get 120 value\n");
		return 0;
	}
	g_n_offset = ifp->drvr->power_g_n_offset;

	len = snprintf(data+total_len, sizeof(data)-total_len,
		"reg 11f, value:0x%02x\nreg 120, value:0x%02x\n"
		"11f g_n_offset:0x%02x\n",
		value_11f, value_120, g_n_offset);
	total_len += len;

	snprintf(data+total_len, sizeof(data)-total_len,
		"GET_REG_CHAN 8a");
	len = wland_get_reg_for_all_channels(ndev,
		data+total_len,sizeof(data)-total_len);
	if (len < 0) {
		WLAND_ERR("can not get 8a value\n");
		return 0;
	}
	total_len += len;

	proc_print(m, data);
	return 0;
}

static int wland_get_efuse_map(struct seq_file *m, void *v)
{
	struct net_device *ndev = m->private;
	char data[150] = {'\0'};
	u8 len = 0;

	WLAND_DBG(DEFAULT, INFO, "Enter\n");
	len = wland_get_efuse_data(ndev, data, sizeof(data));
	if (len <= 0) {
		WLAND_ERR("get efuse map failed!\n");
		return 0;
	} else
		proc_print(m, data);
	return 0;
}

const struct wland_proc_hdl wland_proc_hdls [] = {
	/*{"trx_info", wland_txrx_info, NULL},*/
	{"tx_stat", wland_tx_stat, NULL},
	{"verion_info", wland_get_version_info, NULL},
	{"tx_power", wland_get_tx_power, NULL},
	{"efuse_map", wland_get_efuse_map, NULL},
};
const int wland_proc_num = sizeof(wland_proc_hdls) / sizeof(struct wland_proc_hdl);
struct proc_dir_entry *rda_proc = NULL;

static int wland_proc_open(struct inode *inode, struct file *file)
{
	struct net_device *dev = proc_get_parent_data(inode);
	ssize_t index = (ssize_t)PDE_DATA(inode);
	const struct wland_proc_hdl *hdl = wland_proc_hdls + index;

	WLAND_DBG(DEFAULT, TRACE, "Enter\n");

	if(rda_proc)
		return single_open(file, hdl->show, dev);
	else
		return -EROFS;
}

static ssize_t wland_proc_write(struct file *file, const char __user *buffer, size_t count, loff_t *pos)
{
	ssize_t index = (ssize_t)PDE_DATA(file_inode(file));
	const struct wland_proc_hdl *hdl = wland_proc_hdls + index;
	ssize_t (*write)(struct file *, const char __user *, size_t, loff_t *, void *) = hdl->write;

	if ((rda_proc) && (write))
		return write(file, buffer, count, pos, NULL);

	return -EROFS;
}

static const struct file_operations wland_proc_fops = {
	.owner = THIS_MODULE,
	.open = wland_proc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
	.write = wland_proc_write,
};

int wland_proc_init(struct net_device *dev)
{
	int ret = -1;
	ssize_t i, j;
	struct proc_dir_entry *entry = NULL;

	WLAND_DBG(DEFAULT, INFO, "Enter\n");

	if (rda_proc != NULL) {
		WLAND_ERR("rda proc already exsits!\n");
		goto exit;
	}

	rda_proc = wland_proc_create_dir("rdawfmac", get_proc_net, dev);

	if (rda_proc == NULL) {
		WLAND_ERR("rda_proc create failed!\n");
		goto exit;
	}

	for (i=0; i<wland_proc_num; i++) {
		entry = wland_proc_create_entry(wland_proc_hdls[i].name,
			rda_proc, &wland_proc_fops, (void *)i);
		if (!entry) {
			WLAND_ERR("entry create failed!\n");
			for (j=0; j<i; j++)
				remove_proc_entry(wland_proc_hdls[j].name, rda_proc);
			remove_proc_entry("rdawfmac", get_proc_net);
			rda_proc = NULL;
			goto exit;
		}
	}

	ret = 0;

exit:
	return ret;
}

void wland_proc_deinit(void)
{
	int i;

	if (rda_proc == NULL)
		return;

	for (i=0;i<wland_proc_num;i++)
		remove_proc_entry(wland_proc_hdls[i].name, rda_proc);

	remove_proc_entry("rdawfmac", get_proc_net);
	rda_proc = NULL;
}

#endif

