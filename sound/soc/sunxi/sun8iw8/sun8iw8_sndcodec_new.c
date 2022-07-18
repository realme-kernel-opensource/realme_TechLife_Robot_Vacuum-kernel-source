/*
 * sound\soc\sunxi\sun8iw10_codec.c
 * (C) Copyright 2014-2017
 * Reuuimlla Technology Co., Ltd. <www.allwinnertech.com>
 * guoyingyang <guoyingyang@allwinnertech.com>
 *
 * some simple description for this code
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 */
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/clk.h>
#include <linux/gpio.h>
#include <linux/io.h>
#include <linux/regulator/consumer.h>
#include <sound/pcm.h>
#include <sound/pcm_params.h>
#include <sound/soc.h>
#include <sound/soc-dapm.h>
#include <sound/initval.h>
#include <sound/jack.h>
#include <sound/tlv.h>
#include <mach/gpio.h>
#include <linux/pinctrl/consumer.h>
#include <linux/pm.h>
#include <linux/pinctrl/consumer.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/of_address.h>
#include <linux/of_device.h>

#include "sunxi_codecdma.h"
#include "sun8iw8_sndcodec.h"

static const DECLARE_TLV_DB_SCALE(dig_vol_tlv, -7424, 0, 0);
static const DECLARE_TLV_DB_SCALE(headphone_vol_tlv, -6300, 100, 0);
static const DECLARE_TLV_DB_SCALE(linein_to_l_r_mix_vol_tlv, -450, 150, 0);
static const DECLARE_TLV_DB_SCALE(mic1_to_l_r_mix_vol_tlv, -450, 150, 0);
static const DECLARE_TLV_DB_SCALE(mic2_to_l_r_mix_vol_tlv, -450, 150, 0);
static const DECLARE_TLV_DB_SCALE(lineout_vol_tlv, -4800, 150, 0);
static const DECLARE_TLV_DB_SCALE(mic1_boost_vol_tlv, 0, 300, 0);
static const DECLARE_TLV_DB_SCALE(mic2_boost_vol_tlv, 0, 300, 0);
static const DECLARE_TLV_DB_SCALE(adc_input_gain_tlv, -450, 150, 0);


void __iomem *codec_digitaladress;
void __iomem *codec_analogadress;

static struct sunxi_dma_params sunxi_pcm_pcm_stereo_out = {
	.name		= "audio_play",
	.dma_addr	= CODEC_BASSADDRESS + SUNXI_DAC_TXDATA,//send data address
};

static struct sunxi_dma_params sunxi_pcm_pcm_stereo_in = {
	.name   	= "audio_capture",
	.dma_addr	= CODEC_BASSADDRESS + SUNXI_ADC_RXDATA,//accept data address
};

struct codec_sr {
	unsigned int samplerate;
	int srbit;
};

struct voltage_supply {
	struct regulator *hp_ldo;
};


struct sunxi_codec {
	void __iomem *codec_dbase;
	void __iomem *codec_abase;
	struct clk *srcclk;
	struct gain_config gain_config;
	struct codec_hw_config hwconfig;
	struct mutex dac_mutex;
	struct mutex adc_mutex;
	struct snd_soc_codec *codec;
	struct voltage_supply vol_supply;
	struct clk *pllclk;
	struct clk *moduleclk;
	u32 audio_pa_ctrl;
	u32 dac_enable;
	u32 adc_enable;
	u32 pa_sleep_time;
	bool hp_dirused;
	bool spkenable;
	u32 pa_double_used;
};


static const struct codec_sr codec_sr_s[] = {
	{44100, 0},
	{48000, 0},
	{8000, 5},
	{11025, 4},
	{12000, 4},
	{16000, 3},
	{22050, 2},
	{24000, 2},
	{32000, 1},
	{96000, 7},
	{192000, 6},
};

static struct label reg_labels[] = {
	LABEL(SUNXI_DAC_DPC),
	LABEL(SUNXI_DAC_FIFOC),
	LABEL(SUNXI_DAC_FIFOS),
	LABEL(SUNXI_ADC_FIFOC),
	LABEL(SUNXI_ADC_FIFOS),
	LABEL(SUNXI_ADC_RXDATA),
	LABEL(SUNXI_DAC_TXDATA),
	LABEL(SUNXI_DAC_CNT),
	LABEL(SUNXI_ADC_CNT),
	LABEL(SUNXI_DAC_DEBUG),
	LABEL(SUNXI_ADC_DEBUG),

	LABEL(HP_VOLC),
	LABEL(LOMIXSC),
	LABEL(ROMIXSC),
	LABEL(DAC_PA_SRC),
	LABEL(LINEIN_GCTRL),
	LABEL(MIC_GCTR),
	LABEL(HP_CTRL),
	LABEL(LINEOUT_VOLC),
	LABEL(MIC2_CTRL),
	LABEL(BIAS_MIC_CTRL),
	LABEL(LADC_MIX_MUTE),
	LABEL(RADC_MIX_MUTE),
	LABEL(PA_ANTI_POP_CTRL),
	LABEL(AC_ADC_CTRL),
	LABEL(OPADC_CTRL),
	LABEL(OPMIC_CTRL),
	LABEL(ZERO_CROSS_CTRL),
	LABEL(ADC_FUN_CTRL),
	LABEL(CALIBRTAION_CTRL),
	LABEL_END,
};

static u32 codec_wrreg_bits(void __iomem *address, u32 mask, u32 value)
{
	u32 old, new;
	old = readl(address);
	new = (old & ~mask) | value;
	writel(new, address);
	return 0;
}

static u32 codec_wr_control(void __iomem *reg, u32 mask, u32 shift, u32 val)
{
	u32 reg_val;
	reg_val = val << shift;
	mask = mask << shift;
	codec_wrreg_bits(reg, mask, reg_val);
	return 0;
}

void sun8iw8_codec_dac_drq_enable(int on)
{
	if (on) {
		codec_wr_control(codec_digitaladress + SUNXI_DAC_FIFOC, 0x1,
				DAC_FIFO_FLUSH, 0x1);
		codec_wr_control(codec_digitaladress + SUNXI_DAC_FIFOC, 0x1,
				DAC_DRQ, 0x1);
	} else {
		codec_wr_control(codec_digitaladress + SUNXI_DAC_FIFOC, 0x1,
				DAC_DRQ, 0x0);
	}
}
EXPORT_SYMBOL(sun8iw8_codec_dac_drq_enable);

void sun8iw8_codec_adc_drq_enable(int on)
{
	if (on) {
		codec_wr_control(codec_digitaladress + SUNXI_ADC_FIFOC, 0x1,
				ADC_FIFO_FLUSH, 0x1);
		codec_wr_control(codec_digitaladress + SUNXI_ADC_FIFOC, 0x1,
				ADC_DRQ, 0x1);
	} else {
		codec_wr_control(codec_digitaladress + SUNXI_ADC_FIFOC, 0x1,
				ADC_DRQ, 0x0);
	}
}
EXPORT_SYMBOL(sun8iw8_codec_adc_drq_enable);

u32 sun8iw8_codec_get_dac_cnt(void)
{
	return readl(codec_digitaladress + SUNXI_DAC_CNT);
}
EXPORT_SYMBOL(sun8iw8_codec_get_dac_cnt);

u32 sun8iw8_codec_get_adc_cnt(void)
{
	return readl(codec_digitaladress + SUNXI_ADC_CNT);
}
EXPORT_SYMBOL(sun8iw8_codec_get_adc_cnt);

static unsigned int read_prcm_wvalue(unsigned int addr, void __iomem *ADDA_PR_CFG_REG)
{
	unsigned int reg;
	reg = readl(ADDA_PR_CFG_REG);
	reg |= (0x1<<28);
	writel(reg, ADDA_PR_CFG_REG);

	reg = readl(ADDA_PR_CFG_REG);
	reg &= ~(0x1<<24);
	writel(reg, ADDA_PR_CFG_REG);

	reg = readl(ADDA_PR_CFG_REG);
	reg &= ~(0x1f<<16);
	reg |= (addr<<16);
	writel(reg, ADDA_PR_CFG_REG);

	reg = readl(ADDA_PR_CFG_REG);
	reg &= (0xff<<0);

	return reg;
}

static void write_prcm_wvalue(unsigned int addr, unsigned int val, void __iomem *ADDA_PR_CFG_REG)
{
  	unsigned int reg;
	reg = readl(ADDA_PR_CFG_REG);
	reg |= (0x1<<28);
	writel(reg, ADDA_PR_CFG_REG);

	reg = readl(ADDA_PR_CFG_REG);
	reg &= ~(0x1f<<16);
	reg |= (addr<<16);
	writel(reg, ADDA_PR_CFG_REG);

	reg = readl(ADDA_PR_CFG_REG);
	reg &= ~(0xff<<8);
	reg |= (val<<8);
	writel(reg, ADDA_PR_CFG_REG);

	reg = readl(ADDA_PR_CFG_REG);
	reg |= (0x1<<24);
	writel(reg, ADDA_PR_CFG_REG);

	reg = readl(ADDA_PR_CFG_REG);
	reg &= ~(0x1<<24);
	writel(reg, ADDA_PR_CFG_REG);
}


static void adcagc_config(struct snd_soc_codec *codec)
{
	return ;
}
static void adcdrc_config(struct snd_soc_codec *codec)
{
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_CTRL    , (0xffff << 0), (0x00000003 << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_LPFHAT  , (0xffff << 0), (0x0000000B << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_LPFLAT  , (0xffff << 0), (0x000077EF << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_RPFHAT  , (0xffff << 0), (0x0000000B << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_RPFLAT  , (0xffff << 0), (0x000077EF << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_LPFHRT  , (0xffff << 0), (0x000000FF << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_LPFLRT  , (0xffff << 0), (0x0000E1F8 << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_RPFHRT  , (0xffff << 0), (0x000000FF << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_RPFLRT  , (0xffff << 0), (0x0000E1F8 << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_LRMSHAT , (0xffff << 0), (0x00000001 << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_LRMSLAT , (0xffff << 0), (0x00002BAF << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_RRMSHAT , (0xffff << 0), (0x00000001 << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_RRMSLAT , (0xffff << 0), (0x00002BAF << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_HCT     , (0xffff << 0), (0x000005D0 << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_LCT     , (0xffff << 0), (0x00003948 << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_HKC     , (0xffff << 0), (0x00000100 << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_LKC     , (0xffff << 0), (0x00000000 << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_HOPC    , (0xffff << 0), (0x0000FA2F << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_LOPC    , (0xffff << 0), (0x0000C6B8 << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_HLT     , (0xffff << 0), (0x000001A9 << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_LLT     , (0xffff << 0), (0x000034F0 << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_HKI     , (0xffff << 0), (0x00000100 << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_LKI     , (0xffff << 0), (0x00000000 << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_HOPL    , (0xffff << 0), (0x0000FE56 << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_LOPL    , (0xffff << 0), (0x0000CB10 << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_HET     , (0xffff << 0), (0x000006A4 << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_LET     , (0xffff << 0), (0x0000D3C0 << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_HKE     , (0xffff << 0), (0x00000200 << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_LKE     , (0xffff << 0), (0x00000000 << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_HOPE    , (0xffff << 0), (0x0000F8B1 << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_LOPE    , (0xffff << 0), (0x00001713 << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_HKN     , (0xffff << 0), (0x000001CC << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_LKN     , (0xffff << 0), (0x0000CCCC << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_SFHAT   , (0xffff << 0), (0x00000002 << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_SFLAT   , (0xffff << 0), (0x00005600 << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_SFHRT   , (0xffff << 0), (0x00000000 << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_SFLRT   , (0xffff << 0), (0x00000F04 << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_MXGHS   , (0xffff << 0), (0x0000FE56 << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_MXGLS   , (0xffff << 0), (0x0000CB0F << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_MNGHS   , (0xffff << 0), (0x0000F95B << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_MNGLS   , (0xffff << 0), (0x00002C3F << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_EPSHC   , (0xffff << 0), (0x00000000 << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_EPSLC   , (0xffff << 0), (0x0000640C << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_OPT     , (0xffff << 0), (0x00000400 << 0));
}
static void dacdrc_config(struct snd_soc_codec *codec)
{
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_CTRL     , (0xffff <<  0), (0x00000003 << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_LPFHAT   , (0xffff <<  0), (0x0000000B << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_LPFLAT   , (0xffff <<  0), (0x000077EF << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_RPFHAT   , (0xffff <<  0), (0x0000000B << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_RPFLAT   , (0xffff <<  0), (0x000077EF << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_LPFHRT   , (0xffff <<  0), (0x000000FF << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_LPFLRT   , (0xffff <<  0), (0x0000E1F8 << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_RPFHRT   , (0xffff <<  0), (0x000000FF << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_RPFLRT   , (0xffff <<  0), (0x0000E1F8 << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_LRMSHAT  , (0xffff <<  0), (0x00000001 << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_LRMSLAT  , (0xffff <<  0), (0x00002BAF << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_RRMSHAT  , (0xffff <<  0), (0x00000001 << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_RRMSLAT  , (0xffff <<  0), (0x00002BAF << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_HCT      , (0xffff <<  0), (0x000004FB << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_LCT      , (0xffff <<  0), (0x00009ED0 << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_HKC      , (0xffff <<  0), (0x00000100 << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_LKC      , (0xffff <<  0), (0x00000000 << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_HOPC     , (0xffff <<  0), (0x0000FBD8 << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_LOPC     , (0xffff <<  0), (0x0000FBA8 << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_HLT      , (0xffff <<  0), (0x00000352 << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_LLT      , (0xffff <<  0), (0x000069E0 << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_HKI      , (0xffff <<  0), (0x00000080 << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_LKI      , (0xffff <<  0), (0x00000000 << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_HOPL     , (0xffff <<  0), (0x0000FD82 << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_LOPL     , (0xffff <<  0), (0x00003098 << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_HET      , (0xffff <<  0), (0x00000779 << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_LET      , (0xffff <<  0), (0x00006E38 << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_HKE      , (0xffff <<  0), (0x00000100 << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_LKE      , (0xffff <<  0), (0x00000000 << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_HOPE     , (0xffff <<  0), (0x0000F906 << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_LOPE     , (0xffff <<  0), (0x000021A9 << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_HKN      , (0xffff <<  0), (0x00000122 << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_LKN      , (0xffff <<  0), (0x00002222 << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_SFHAT    , (0xffff <<  0), (0x00000002 << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_SFLAT    , (0xffff <<  0), (0x00005600 << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_SFHRT    , (0xffff <<  0), (0x00000000 << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_SFLRT    , (0xffff <<  0), (0x00000F04 << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_MXGHS    , (0xffff <<  0), (0x0000FE56 << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_MXGLS    , (0xffff <<  0), (0x0000CB0F << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_MNGHS    , (0xffff <<  0), (0x0000F95B << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_MNGLS    , (0xffff <<  0), (0x00002C3F << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_EPSHC    , (0xffff <<  0), (0x00000000 << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_EPSLC    , (0xffff <<  0), (0x0000640C << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_OPT      , (0xffff <<  0), (0x00000400 << 0));

}

static void adcdrc_enable(struct snd_soc_codec *codec, bool on)
{
	if (on) {
		snd_soc_update_bits(codec, SUNXI_ADC_DAP_CTR, (0x3 << 25), (0x3 << 25));
	} else {
		snd_soc_update_bits(codec, SUNXI_ADC_DAP_CTR, (0x3 << 25), (0x0 << 25));
	}

}
static void dacdrc_enable(struct snd_soc_codec *codec, bool on)
{
	if (on) {
		/* detect noise when ET enable */
		snd_soc_update_bits(codec, SUNXI_DAC_DRC_CTRL, (0x1 << 4), (0x1 << 4));
		/* 0x0:RMS filter; 0x1:Peak filter */
		snd_soc_update_bits(codec, SUNXI_DAC_DRC_CTRL, (0x1 << 3), (0x1 << 3));
		/* delay function enable */
		snd_soc_update_bits(codec, SUNXI_DAC_DRC_CTRL, (0x1 << 2), (0x0 << 2));
		/* LT enable */
		snd_soc_update_bits(codec, SUNXI_DAC_DRC_CTRL, (0x1 << 1), (0x1 << 1));
		/* ET enable */
		snd_soc_update_bits(codec, SUNXI_DAC_DRC_CTRL, (0x1 << 0), (0x1 << 0));

		snd_soc_update_bits(codec, SUNXI_DAC_DAP_CTR, (0x1 << 15), (0x1 << 15));
		snd_soc_update_bits(codec, SUNXI_DAC_DAP_CTR, (0x1 << 31), (0x1	<< 31));

	} else {
		snd_soc_update_bits(codec, SUNXI_DAC_DAP_CTR, (0x1 << 15), (0 << 15));
		snd_soc_update_bits(codec, SUNXI_DAC_DAP_CTR, (0x1 << 31), (0 << 31));

		/* detect noise when ET enable */
		snd_soc_update_bits(codec, SUNXI_DAC_DRC_CTRL, (0x1 << 4), (0x0 << 4));
		/* 0x0:RMS filter; 0x1:Peak filter */
		snd_soc_update_bits(codec, SUNXI_DAC_DRC_CTRL, (0x1 << 3), (0x0 << 3));
		/* delay function enable */
		snd_soc_update_bits(codec, SUNXI_DAC_DRC_CTRL, (0x1 << 2), (0x0 << 2));
		/* LT enable */
		snd_soc_update_bits(codec, SUNXI_DAC_DRC_CTRL, (0x1 << 1), (0x0 << 1));
		/* ET enable */
		snd_soc_update_bits(codec, SUNXI_DAC_DRC_CTRL, (0x1 << 0), (0x0 << 0));
	}

}
static void adcagc_enable(struct snd_soc_codec *codec, bool on)
{
	if (on) {

	} else {

	}
}
static void adchpf_config(struct snd_soc_codec *codec)
{
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_HHPFC	, (0xffff << 0), (0x000000FF << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_DRC_LHPFC	, (0xffff << 0), (0x0000FAC1 << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_HPF_HG	, (0xffff << 0), (0x00000100 << 0));
	snd_soc_update_bits(codec, SUNXI_ADC_HPF_LG	, (0xffff << 0), (0x00000000 << 0));
}
static void dachpf_config(struct snd_soc_codec *codec)
{
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_HHPFC	, (0xffff << 0), (0x000000FF << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_DRC_LHPFC	, (0xffff << 0), (0x0000FAC1 << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_HPF_HG	, (0xffff << 0), (0x00000100 << 0));
	snd_soc_update_bits(codec, SUNXI_DAC_HPF_LG	, (0xffff << 0), (0x00000000 << 0));

}
static void dachpf_enable(struct snd_soc_codec *codec, bool on)
{
	if (on) {
		snd_soc_update_bits(codec, SUNXI_DAC_DAP_CTR, (0x1 << 14), (0x1 << 14));
		snd_soc_update_bits(codec, SUNXI_DAC_DAP_CTR, (0x1 << 31), (0x1 << 31));
	} else {
		snd_soc_update_bits(codec, SUNXI_DAC_DAP_CTR, (0x1 << 14), (0 << 14));
		snd_soc_update_bits(codec, SUNXI_DAC_DAP_CTR, (0x1 << 31), (0 << 31));
	}

}
static void adchpf_enable(struct snd_soc_codec *codec, bool on)
{
	if (on) {
		snd_soc_update_bits(codec, SUNXI_ADC_DAP_CTR, (0x1 << 24), (0x1 << 24));
		snd_soc_update_bits(codec, SUNXI_ADC_DAP_CTR, (0x1 << 26), (0x1 << 26));
	} else {
		snd_soc_update_bits(codec, SUNXI_ADC_DAP_CTR, (0x1 << 24), (0x0 << 24));
		snd_soc_update_bits(codec, SUNXI_ADC_DAP_CTR, (0x1 << 26), (0x0 << 26));
	}

}

/*
*enable the codec function which should be enable during system init.
*/
static int codec_init(struct sunxi_codec *sunxi_internal_codec)
{
	struct snd_soc_codec *codec = sunxi_internal_codec->codec;

	if (sunxi_internal_codec->hp_dirused) {
		snd_soc_update_bits(codec, HP_CTRL, (0x3<<HPCOM_FC), (0x3<<HPCOM_FC));
		snd_soc_update_bits(codec, HP_CTRL, (0x1<<COMPTEN), (0x1<<COMPTEN));
	} else {
		snd_soc_update_bits(codec, HP_CTRL, (0x3<<HPCOM_FC), (0x0<<HPCOM_FC));
		snd_soc_update_bits(codec, HP_CTRL, (0x1<<COMPTEN), (0x0<<COMPTEN));
	}

	if (sunxi_internal_codec->hwconfig.adcagc_cfg)
		adcagc_config(sunxi_internal_codec->codec);

	if (sunxi_internal_codec->hwconfig.adcdrc_cfg)
		adcdrc_config(sunxi_internal_codec->codec);

	if (sunxi_internal_codec->hwconfig.adchpf_cfg)
		adchpf_config(sunxi_internal_codec->codec);

	if (sunxi_internal_codec->hwconfig.dacdrc_cfg)
		dacdrc_config(sunxi_internal_codec->codec);

	if (sunxi_internal_codec->hwconfig.dachpf_cfg)
		dachpf_config(sunxi_internal_codec->codec);

	if (gpio_is_valid(sunxi_internal_codec->audio_pa_ctrl)) {
		gpio_direction_output(sunxi_internal_codec->audio_pa_ctrl, 1);
		gpio_set_value(sunxi_internal_codec->audio_pa_ctrl, 0);
	}
	snd_soc_update_bits(codec, HP_CTRL, (0x1<<HPPAEN), (0x1<<HPPAEN));
	snd_soc_update_bits(codec, DAC_PA_SRC, (0x1<<LHPPAMUTE), (0x0<<LHPPAMUTE));
	snd_soc_update_bits(codec, DAC_PA_SRC, (0x1<<RHPPAMUTE), (0x0<<RHPPAMUTE));

	/*ADC fifo delay function for waiting data after EN_AD */
	snd_soc_update_bits(codec, SUNXI_ADC_FIFOC, (0x1<<ADCDFEN), (0x1<<ADCDFEN));

	/*when TX FIFO available room less than or equal N,
	* DRQ Requeest will be de-asserted.
	*/
	snd_soc_update_bits(codec, SUNXI_DAC_FIFOC,
			(0x3<<DRA_LEVEL), (0x3<<DRA_LEVEL));
	snd_soc_update_bits(codec, SUNXI_DAC_FIFOC,
			(0x1<<DAC_FIFO_FLUSH), (0x1<<DAC_FIFO_FLUSH));
	/*
	*	0:64-Tap FIR
	*	1:32-Tap FIR
	*/
	snd_soc_update_bits(codec, SUNXI_DAC_FIFOC,
			(0x1<<FIR_VERSION), (0x0<<FIR_VERSION));

	snd_soc_update_bits(codec, SUNXI_ADC_FIFOC,
			(0x1<<ADC_FIFO_FLUSH), (0x1<<ADC_FIFO_FLUSH));
	snd_soc_update_bits(codec, PA_ANTI_POP_CTRL,
			(0x7<<PA_ANTI_POP_CTL), (0x02<<PA_ANTI_POP_CTL));
	return 0;
}

static int late_enable_dac(struct snd_soc_dapm_widget *w,
			  struct snd_kcontrol *kcontrol, int event)
{
	struct snd_soc_codec *codec = snd_soc_dapm_to_codec(w->dapm);;
	struct sunxi_codec *sunxi_internal_codec = snd_soc_codec_get_drvdata(codec);
	mutex_lock(&sunxi_internal_codec->dac_mutex);
	pr_debug("..dac power state change \n");
        switch (event) {
	case SND_SOC_DAPM_PRE_PMU:
		if (sunxi_internal_codec->dac_enable == 0) {
			snd_soc_update_bits(codec, SUNXI_DAC_DPC,
					(0x1<<DAC_EN), (0x1<<DAC_EN));
#ifdef CONFIG_SND_SUN8IW8_DAC_TRIGGER_SYNC_WITH_OTHER_CODEC
#else /* CONFIG_SND_SUN8IW8_DAC_TRIGGER_SYNC_WITH_OTHER_CODEC */
			snd_soc_update_bits(codec, SUNXI_DAC_FIFOC,
					(0x1<<DAC_FIFO_FLUSH), (0x1<<DAC_FIFO_FLUSH));
			snd_soc_update_bits(codec, SUNXI_DAC_FIFOC,
					(0x1<<DAC_DRQ), (0x1<<DAC_DRQ));
#endif /* CONFIG_SND_SUN8IW8_DAC_TRIGGER_SYNC_WITH_OTHER_CODEC */
		}
		sunxi_internal_codec->dac_enable++;
		break;
	case SND_SOC_DAPM_POST_PMD:
		if (sunxi_internal_codec->dac_enable > 0) {
			sunxi_internal_codec->dac_enable--;
			if (sunxi_internal_codec->dac_enable == 0) {
				snd_soc_update_bits(codec, SUNXI_DAC_DPC,
						(0x1<<DAC_EN), (0x0<<DAC_EN));
#ifdef CONFIG_SND_SUN8IW8_DAC_TRIGGER_SYNC_WITH_OTHER_CODEC
#else /* CONFIG_SND_SUN8IW8_DAC_TRIGGER_SYNC_WITH_OTHER_CODEC */
				snd_soc_update_bits(codec, SUNXI_DAC_FIFOC,
					(0x1<<DAC_DRQ), (0x0<<DAC_DRQ));
#endif /* CONFIG_SND_SUN8IW8_DAC_TRIGGER_SYNC_WITH_OTHER_CODEC */
			}
		}
		break;
	}
	mutex_unlock(&sunxi_internal_codec->dac_mutex);
	return 0;
}

static int late_enable_adc(struct snd_soc_dapm_widget *w,
			  struct snd_kcontrol *kcontrol, int event)
{
	struct snd_soc_codec *codec = snd_soc_dapm_to_codec(w->dapm);
	struct sunxi_codec *sunxi_internal_codec = snd_soc_codec_get_drvdata(codec);
	mutex_lock(&sunxi_internal_codec->adc_mutex);
	pr_debug("..adc power state change.\n");
	switch (event) {
	case SND_SOC_DAPM_PRE_PMU:
		if (sunxi_internal_codec->adc_enable == 0) {
			snd_soc_update_bits(codec, SUNXI_ADC_FIFOC,
					(0x1<<ADC_EN), (0x1<<ADC_EN));
#ifdef CONFIG_SND_SUN8IW8_ADC_TRIGGER_SYNC_WITH_OTHER_CODEC
#else /* CONFIG_SND_SUN8IW8_ADC_TRIGGER_SYNC_WITH_OTHER_CODEC */
			snd_soc_update_bits(codec, SUNXI_ADC_FIFOC,
					(0x1<<ADC_FIFO_FLUSH), (0x1<<ADC_FIFO_FLUSH));
			snd_soc_update_bits(codec, SUNXI_ADC_FIFOC,
					(0x1<<ADC_DRQ), (0x1<<ADC_DRQ));
#endif /* CONFIG_SND_SUN8IW8_ADC_TRIGGER_SYNC_WITH_OTHER_CODEC */
		}
		sunxi_internal_codec->adc_enable++;
		break;
	case SND_SOC_DAPM_POST_PMD:
		if (sunxi_internal_codec->adc_enable > 0) {
			sunxi_internal_codec->adc_enable--;
			if (sunxi_internal_codec->adc_enable == 0) {
				snd_soc_update_bits(codec, SUNXI_ADC_FIFOC,
					(0x1<<ADC_EN), (0x0<<ADC_EN));
#ifdef CONFIG_SND_SUN8IW8_ADC_TRIGGER_SYNC_WITH_OTHER_CODEC
#else /* CONFIG_SND_SUN8IW8_ADC_TRIGGER_SYNC_WITH_OTHER_CODEC */
				snd_soc_update_bits(codec, SUNXI_ADC_FIFOC,
					(0x1<<ADC_DRQ), (0x0<<ADC_DRQ));
#endif /* CONFIG_SND_SUN8IW8_ADC_TRIGGER_SYNC_WITH_OTHER_CODEC */
			}
		}
		break;
	}
	mutex_unlock(&sunxi_internal_codec->adc_mutex);
	return 0;
}

static int ac_headphone_event(struct snd_soc_dapm_widget *w,
			struct snd_kcontrol *k,	int event)
{
	struct snd_soc_codec *codec = snd_soc_dapm_to_codec(w->dapm);
	pr_debug("..headphone power state change.\n");
	switch (event) {
	case SND_SOC_DAPM_POST_PMU:
		/*open*/
		snd_soc_update_bits(codec, DAC_PA_SRC, (0x1<<LHPPAMUTE), (0x1<<LHPPAMUTE));
		snd_soc_update_bits(codec, DAC_PA_SRC, (0x1<<RHPPAMUTE), (0x1<<RHPPAMUTE));
		break;
	case SND_SOC_DAPM_PRE_PMD:
		/*close*/
		snd_soc_update_bits(codec, DAC_PA_SRC, (0x1<<LHPPAMUTE), (0x0<<LHPPAMUTE));
		snd_soc_update_bits(codec, DAC_PA_SRC, (0x1<<RHPPAMUTE), (0x0<<RHPPAMUTE));
		break;
	}
	return 0;
}

static int ac_speaker_event(struct snd_soc_dapm_widget *w,
				struct snd_kcontrol *k,
				int event)
{
	struct snd_soc_codec *codec = snd_soc_dapm_to_codec(w->dapm);
	struct sunxi_codec *sunxi_internal_codec = snd_soc_codec_get_drvdata(codec);
	pr_debug("..speaker power state change.\n");
	switch (event) {
		case SND_SOC_DAPM_POST_PMU:
			sunxi_internal_codec->spkenable = true;
			msleep(50);
			snd_soc_update_bits(codec, MIC2_CTRL, (0x1<<LINEOUTRIGHTEN), (0x1<<LINEOUTRIGHTEN));
			snd_soc_update_bits(codec, MIC2_CTRL, (0x1<<LINEOUTLEFTEN), (0x1<<LINEOUTLEFTEN));
			if (gpio_is_valid(sunxi_internal_codec->audio_pa_ctrl)) {
				gpio_set_value(sunxi_internal_codec->audio_pa_ctrl, 1);
			}
			break;
		case SND_SOC_DAPM_PRE_PMD :
			sunxi_internal_codec->spkenable = false;
			if (gpio_is_valid(sunxi_internal_codec->audio_pa_ctrl))
				gpio_set_value(sunxi_internal_codec->audio_pa_ctrl, 0);
			snd_soc_update_bits(codec, MIC2_CTRL, (0x1<<LINEOUTRIGHTEN), (0x0<<LINEOUTRIGHTEN));
			snd_soc_update_bits(codec, MIC2_CTRL, (0x1<<LINEOUTLEFTEN), (0x0<<LINEOUTLEFTEN));
		default:
			break;
	}
	return 0;
}

static const struct snd_kcontrol_new sunxi_codec_controls[] = {
	SOC_SINGLE_TLV("digital volume", SUNXI_DAC_DPC, DIGITAL_VOL, 0x3f, 0, dig_vol_tlv),
	/*analog control*/
	SOC_SINGLE_TLV("headphone volume", HP_VOLC, HPVOL, 0x3f, 0, headphone_vol_tlv),
	SOC_SINGLE_TLV("Lineout volume", LINEOUT_VOLC, LINEOUTVOL, 0x1f, 0, lineout_vol_tlv),
	/*mic1  and mic2 to output mixer gain*/
	SOC_SINGLE_TLV("MIC1_G boost stage output mixer control", MIC_GCTR, MIC1G, 0x7, 0, mic1_to_l_r_mix_vol_tlv),
	SOC_SINGLE_TLV("MIC2_G boost stage output mixer control", MIC_GCTR, MIC2G, 0x7, 0, mic2_to_l_r_mix_vol_tlv),

	SOC_SINGLE_TLV("MIC1 boost AMP gain control", BIAS_MIC_CTRL, MIC1BOOST, 0x7, 0, mic1_boost_vol_tlv),
	SOC_SINGLE_TLV("MIC2 boost AMP gain control", MIC2_CTRL, MIC2BOOST, 0x7, 0, mic2_boost_vol_tlv),

	SOC_SINGLE_TLV("LINEINL/R to L_R output mixer gain", LINEIN_GCTRL, LINEING, 0x7, 0, linein_to_l_r_mix_vol_tlv),
	/*ADC*/
	SOC_SINGLE_TLV("ADC input gain control", AC_ADC_CTRL, ADCG, 0x7, 0, adc_input_gain_tlv),

};


/*output mixer source select*/
/*analog:0x01:defined left output mixer*/
static const struct snd_kcontrol_new ac_loutmix_controls[] = {
	SOC_DAPM_SINGLE("DACR Switch", LOMIXSC, LMIXMUTEDACR, 1, 0),
	SOC_DAPM_SINGLE("DACL Switch", LOMIXSC, LMIXMUTEDACL, 1, 0),
	SOC_DAPM_SINGLE("LINEINL Switch", LOMIXSC, LMIXMUTELINEINL, 1, 0),
	SOC_DAPM_SINGLE("MIC1Booststage Switch", LOMIXSC, LMIXMUTEMIC1BOOST, 1, 0),
	SOC_DAPM_SINGLE("MIC2Booststage Switch", LOMIXSC, LMIXMUTEMIC2BOOST, 1, 0),
};

/*analog:0x02:defined right output mixer*/
static const struct snd_kcontrol_new ac_routmix_controls[] = {
	SOC_DAPM_SINGLE("DACL Switch", ROMIXSC, RMIXMUTEDACL, 1, 0),
	SOC_DAPM_SINGLE("DACR Switch", ROMIXSC, RMIXMUTEDACR, 1, 0),
	SOC_DAPM_SINGLE("LINEINR Switch", ROMIXSC, RMIXMUTELINEINR, 1, 0),
	SOC_DAPM_SINGLE("MIC1Booststage Switch", ROMIXSC, RMIXMUTEMIC1BOOST, 1, 0),
	SOC_DAPM_SINGLE("MIC2Booststage Switch", ROMIXSC, RMIXMUTEMIC2BOOST, 1, 0),
};

/*hp source select*/
/*0x0a:headphone input source*/
static const char *ac_hp_r_func_sel[] = {
	"DACR HPR Switch", "MIXER_R Switch"};
static const struct soc_enum ac_hp_r_func_enum =
	SOC_ENUM_SINGLE(DAC_PA_SRC, RHPIS, 2, ac_hp_r_func_sel);

static const struct snd_kcontrol_new ac_hp_r_func_controls =
	SOC_DAPM_ENUM("HP_R Mux", ac_hp_r_func_enum);

static const char *ac_hp_l_func_sel[] = {
	"DACL HPL Switch", "MIXER_L Switch"};
static const struct soc_enum ac_hp_l_func_enum =
	SOC_ENUM_SINGLE(DAC_PA_SRC, LHPIS, 2, ac_hp_l_func_sel);

static const struct snd_kcontrol_new ac_hp_l_func_controls =
	SOC_DAPM_ENUM("HP_L Mux", ac_hp_l_func_enum);

/*0x05:Lineout source select*/
static const char *ac_rspks_func_sel[] = {
	"MIXER_R Switch", "Lineout_l for diff Switch"};
static const struct soc_enum ac_rspks_func_enum =
	SOC_ENUM_SINGLE(MIC2_CTRL, RIGHTLINEOUTSRC, 2, ac_rspks_func_sel);

static const struct snd_kcontrol_new ac_rspks_func_controls =
	SOC_DAPM_ENUM("SPK_R Mux", ac_rspks_func_enum);

static const char *ac_lspks_l_func_sel[] = {
	 "MIXER_L Switch", "MIXR+MIXL"};
static const struct soc_enum ac_lspks_func_enum =
	SOC_ENUM_SINGLE(MIC2_CTRL, LEFTLINEOUTSRC, 2, ac_lspks_l_func_sel);

static const struct snd_kcontrol_new ac_lspks_func_controls =
	SOC_DAPM_ENUM("SPK_L Mux", ac_lspks_func_enum);

/*mic2 source select*/
static const char *mic2src_text[] = {
	"MIC3", "MIC2"
};

static const struct soc_enum mic2src_enum =
SOC_ENUM_SINGLE(BIAS_MIC_CTRL, MIC2_SS, 2, mic2src_text);

static const struct snd_kcontrol_new mic2src_mux =
SOC_DAPM_ENUM("MIC2 SRC", mic2src_enum);

/*
* LADC SOURCE SELECT
* 0x0c:defined left input adc mixer
*/
static const struct snd_kcontrol_new ac_ladcmix_controls[] = {
	SOC_DAPM_SINGLE("r_output mixer Switch", LADC_MIX_MUTE, LADCMIXMUTEROUTPUT, 1, 0),
	SOC_DAPM_SINGLE("l_output mixer Switch", LADC_MIX_MUTE, LADCMIXMUTELOUTPUT, 1, 0),
	SOC_DAPM_SINGLE("LINEINL Switch", LADC_MIX_MUTE, LADCMIXMUTELINEINL, 1, 0),
	SOC_DAPM_SINGLE("MIC1 boost Switch", LADC_MIX_MUTE, LADCMIXMUTEMIC1BOOST, 1, 0),
	SOC_DAPM_SINGLE("MIC2 boost Switch", LADC_MIX_MUTE, LADCMIXMUTEMIC2BOOST, 1, 0),
};
/*
* RADC SOURCE SELECT
* 0x0d:defined  right input adc mixer
*/
static const struct snd_kcontrol_new ac_radcmix_controls[] = {
	SOC_DAPM_SINGLE("r_output mixer Switch", RADC_MIX_MUTE, RADCMIXMUTEROUTPUT, 1, 0),
	SOC_DAPM_SINGLE("l_output mixer Switch", RADC_MIX_MUTE, RADCMIXMUTELOUTPUT, 1, 0),
	SOC_DAPM_SINGLE("LINEINR Switch", RADC_MIX_MUTE, RADCMIXMUTELINEINR, 1, 0),
	SOC_DAPM_SINGLE("MIC1 boost Switch", RADC_MIX_MUTE, RADCMIXMUTEMIC1BOOST, 1, 0),
	SOC_DAPM_SINGLE("MIC2 boost Switch", RADC_MIX_MUTE, RADCMIXMUTEMIC2BOOST, 1, 0),
};

/*built widget*/
static const struct snd_soc_dapm_widget ac_dapm_widgets[] = {
	SND_SOC_DAPM_AIF_IN_E("DAC_L", "Playback", 0, DAC_PA_SRC, DACALEN, 0, late_enable_dac, SND_SOC_DAPM_PRE_PMU|SND_SOC_DAPM_POST_PMD),
	SND_SOC_DAPM_AIF_IN_E("DAC_R", "Playback", 0, DAC_PA_SRC, DACAREN, 0, late_enable_dac, SND_SOC_DAPM_PRE_PMU|SND_SOC_DAPM_POST_PMD),

	/*0x0a*/
	SND_SOC_DAPM_MIXER("Left Output Mixer", DAC_PA_SRC, LMIXEN, 0,
			ac_loutmix_controls, ARRAY_SIZE(ac_loutmix_controls)),
	SND_SOC_DAPM_MIXER("Right Output Mixer", DAC_PA_SRC, RMIXEN, 0,
			ac_routmix_controls, ARRAY_SIZE(ac_routmix_controls)),

	SND_SOC_DAPM_MUX_E("HP_R Mux", SND_SOC_NOPM, 0, 0, &ac_hp_r_func_controls,late_enable_dac, SND_SOC_DAPM_PRE_PMU|SND_SOC_DAPM_POST_PMD),
	SND_SOC_DAPM_MUX_E("HP_L Mux", SND_SOC_NOPM, 0, 0, &ac_hp_l_func_controls,late_enable_dac, SND_SOC_DAPM_PRE_PMU|SND_SOC_DAPM_POST_PMD),

	/*0x05*/
	SND_SOC_DAPM_MUX("SPK_R Mux", SND_SOC_NOPM, 0, 0, &ac_rspks_func_controls),
	SND_SOC_DAPM_MUX("SPK_L Mux", SND_SOC_NOPM, 0, 0, &ac_lspks_func_controls),

	SND_SOC_DAPM_PGA("SPK_LR Adder", SND_SOC_NOPM, 0, 0, NULL, 0),

	/*output widget*/
	SND_SOC_DAPM_OUTPUT("HPOUTL"),
	SND_SOC_DAPM_OUTPUT("HPOUTR"),

	SND_SOC_DAPM_OUTPUT("SPKL"),
	SND_SOC_DAPM_OUTPUT("SPKR"),

	/*headphone*/
	SND_SOC_DAPM_HP("Headphone", ac_headphone_event),
	/*speaker*/
	SND_SOC_DAPM_SPK("External Speaker", ac_speaker_event),

	SND_SOC_DAPM_AIF_OUT("ADC_L", "Capture", 0, SND_SOC_NOPM, 0, 0),
	SND_SOC_DAPM_AIF_OUT("ADC_R", "Capture", 0, SND_SOC_NOPM, 0, 0),

	SND_SOC_DAPM_MUX("MIC2 SRC", SND_SOC_NOPM, 0, 0, &mic2src_mux),

        SND_SOC_DAPM_MIC("External MainMic", NULL),
	SND_SOC_DAPM_MIC("HeadphoneMic", NULL),
	/*INPUT widget*/
	SND_SOC_DAPM_INPUT("MIC1"),

	SND_SOC_DAPM_INPUT("MIC2"),
	SND_SOC_DAPM_INPUT("MIC3"),

	SND_SOC_DAPM_INPUT("LINEINR"),
	SND_SOC_DAPM_INPUT("LINEINL"),
	/*ADC_A_CTR*/
	SND_SOC_DAPM_MIXER_E("LADC input Mixer", AC_ADC_CTRL, ADCLEN, 0,
		ac_ladcmix_controls, ARRAY_SIZE(ac_ladcmix_controls),late_enable_adc, SND_SOC_DAPM_PRE_PMU|SND_SOC_DAPM_POST_PMD),
	SND_SOC_DAPM_MIXER_E("RADC input Mixer", AC_ADC_CTRL, ADCREN, 0,
		ac_radcmix_controls, ARRAY_SIZE(ac_radcmix_controls),late_enable_adc, SND_SOC_DAPM_PRE_PMU|SND_SOC_DAPM_POST_PMD),
	/*mic1 reference*/
	SND_SOC_DAPM_PGA("MIC1 PGA", BIAS_MIC_CTRL, MIC1AMPEN, 0, NULL, 0),
	SND_SOC_DAPM_PGA("MIC2 PGA", MIC2_CTRL, MIC2AMPEN, 0, NULL, 0),

	/*Microphone Bias Control Register*/
	SND_SOC_DAPM_MICBIAS("MainMic Bias", BIAS_MIC_CTRL, MMICBIASEN, 0),
	SND_SOC_DAPM_MICBIAS("HMic Bias", BIAS_MIC_CTRL, HMICBIASEN, 0),

};

static const struct snd_soc_dapm_route ac_dapm_routes[] = {
	/*PLAYBACK*/
	{"Left Output Mixer", "DACL Switch", "DAC_L"},
	{"Left Output Mixer", "DACR Switch", "DAC_R"},
	{"Left Output Mixer", "LINEINL Switch",	"LINEINL"},
	{"Left Output Mixer", "MIC1Booststage Switch", "MIC1 PGA"},
	{"Left Output Mixer", "MIC2Booststage Switch", "MIC2 PGA"},

	{"Right Output Mixer", "DACR Switch", "DAC_R"},
	{"Right Output Mixer", "DACL Switch", "DAC_L"},
	{"Right Output Mixer", "LINEINR Switch", "LINEINR"},
	{"Right Output Mixer", "MIC1Booststage Switch",	"MIC1 PGA"},
	{"Right Output Mixer", "MIC2Booststage Switch",	"MIC2 PGA"},

	/*hp mux*/
	{"HP_R Mux", "DACR HPR Switch",	"DAC_R"},
	{"HP_R Mux", "MIXER_R Switch",	"Right Output Mixer"},

	{"HP_L Mux", "DACL HPL Switch",	"DAC_L"},
	{"HP_L Mux", "MIXER_L Switch", "Left Output Mixer"},

	/*hp endpoint*/
	{"HPOUTR", NULL, "HP_R Mux"},
	{"HPOUTL", NULL, "HP_L Mux"},

	{"Headphone", NULL, "HPOUTR"},
	{"Headphone", NULL, "HPOUTL"},

	/*spk mux*/
	{"SPK_LR Adder", NULL, "Right Output Mixer"},
	{"SPK_LR Adder", NULL, "Left Output Mixer"},

	{"SPK_L Mux", "MIXR+MIXL", "SPK_LR Adder"},
	{"SPK_L Mux", "MIXER_L Switch", "Left Output Mixer"},

	{"SPK_R Mux", "Lineout_l for diff Switch", "SPK_LR Adder"},
	{"SPK_R Mux", "MIXER_R Switch",	"Right Output Mixer"},

	{"SPKR", NULL, "SPK_R Mux"},
	{"SPKL", NULL, "SPK_L Mux"},

	{"External Speaker", NULL, "SPKL"},
	{"External Speaker", NULL, "SPKR"},

        {"MainMic Bias", NULL, "External MainMic"},
        {"MIC1", NULL, "MainMic Bias"},
        {"MIC3", NULL, "MainMic Bias"},

	{"MIC1 PGA", NULL, "MIC1"},

	{"HMic Bias", NULL, "HeadphoneMic"},
	{"MIC2", NULL, "HMic Bias"},

	{"MIC2 SRC", "MIC2", "MIC2"},
	{"MIC2 SRC", "MIC3", "MIC3"},

	{"MIC2 PGA", NULL, "MIC2 SRC"},

	/*LADC SOURCE mixer*/
	{"LADC input Mixer", "MIC1 boost Switch", "MIC1 PGA"},
	{"LADC input Mixer", "MIC2 boost Switch", "MIC2 PGA"},
	{"LADC input Mixer", "LINEINL Switch", "LINEINL"},
	{"LADC input Mixer", "l_output mixer Switch", "Left Output Mixer"},
	{"LADC input Mixer", "r_output mixer Switch", "Right Output Mixer"},

	/*LADC SOURCE mixer*/
	{"RADC input Mixer", "MIC1 boost Switch", "MIC1 PGA"},
	{"RADC input Mixer", "MIC2 boost Switch", "MIC2 PGA"},
	{"RADC input Mixer", "LINEINR Switch", "LINEINR"},
	{"RADC input Mixer", "l_output mixer Switch", "Left Output Mixer"},
	{"RADC input Mixer", "r_output mixer Switch", "Right Output Mixer"},

	/*ADC--ADCMUX*/
	{"ADC_L", NULL, "LADC input Mixer"},
	/*ADC--ADCMUX*/
	{"ADC_R", NULL, "RADC input Mixer"},
};


static int codec_start(struct snd_pcm_substream *substream, struct snd_soc_dai *codec_dai)
{
	struct snd_soc_codec *codec = codec_dai->codec;
	struct sunxi_codec *sunxi_internal_codec = snd_soc_codec_get_drvdata(codec);
	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
		if (sunxi_internal_codec->hwconfig.dacdrc_cfg)
			dacdrc_enable(codec, 1);
		if (sunxi_internal_codec->hwconfig.dachpf_cfg)
			dachpf_enable(codec, 1);
	} else {
		if (sunxi_internal_codec->hwconfig.adcagc_cfg)
			adcagc_enable(codec, 1);

		if (sunxi_internal_codec->hwconfig.adcdrc_cfg)
			adcdrc_enable(codec, 1);

		if (sunxi_internal_codec->hwconfig.adchpf_cfg)
			adchpf_enable(codec, 1);
	}
	return 0;
}
static int codec_mute(struct snd_soc_dai *codec_dai, int mute)
{
	struct snd_soc_codec *codec = codec_dai->codec;
	struct sunxi_codec *sunxi_internal_codec = snd_soc_codec_get_drvdata(codec);

	if(sunxi_internal_codec->spkenable == true)
		msleep(sunxi_internal_codec->pa_sleep_time);

	return 0;
}

static void codec_shutdown(struct snd_pcm_substream *substream,
	struct snd_soc_dai *codec_dai)
{
	struct snd_soc_codec *codec = codec_dai->codec;
	struct sunxi_codec *sunxi_internal_codec = snd_soc_codec_get_drvdata(codec);

	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
		if (sunxi_internal_codec->hwconfig.dacdrc_cfg)
			dacdrc_enable(codec, 0);
		if (sunxi_internal_codec->hwconfig.dachpf_cfg)
			dachpf_enable(codec, 0);
	} else {
		if (sunxi_internal_codec->hwconfig.adcagc_cfg)
			adcagc_enable(codec, 0);

		if (sunxi_internal_codec->hwconfig.adcdrc_cfg)
			adcdrc_enable(codec, 0);

		if (sunxi_internal_codec->hwconfig.adchpf_cfg)
			adchpf_enable(codec, 0);
	}
}

#if 0
static int codec_trigger(struct snd_pcm_substream *substream,
                              int cmd, struct snd_soc_dai *dai)
{
	struct snd_soc_codec *codec = dai->codec;
	uint value = 0 ;
	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
		switch (cmd) {
			case SNDRV_PCM_TRIGGER_START:
			case SNDRV_PCM_TRIGGER_RESUME:
			case SNDRV_PCM_TRIGGER_PAUSE_RELEASE:
				snd_soc_update_bits(codec, SUNXI_DAC_FIFOC,
					(0x1<<DAC_FIFO_FLUSH), (0x1<<DAC_FIFO_FLUSH));
				/*enable dac drq*/
				snd_soc_update_bits(codec, SUNXI_DAC_FIFOC,
					(0x1<<DAC_DRQ), (0x1<<DAC_DRQ));
				return 0;
			case SNDRV_PCM_TRIGGER_SUSPEND:
			case SNDRV_PCM_TRIGGER_STOP:
			case SNDRV_PCM_TRIGGER_PAUSE_PUSH:
				snd_soc_update_bits(codec, SUNXI_DAC_FIFOC,
					(0x1<<DAC_DRQ), (0x0<<DAC_DRQ));
				return 0;
			default:
				return -EINVAL;
			}
	} else {
		switch (cmd) {
		case SNDRV_PCM_TRIGGER_START:
		case SNDRV_PCM_TRIGGER_RESUME:
		case SNDRV_PCM_TRIGGER_PAUSE_RELEASE:
			snd_soc_update_bits(codec, SUNXI_ADC_FIFOC,
					(0x1<<ADC_FIFO_FLUSH), (0x1<<ADC_FIFO_FLUSH));
			snd_soc_update_bits(codec, SUNXI_ADC_FIFOC,
					(0x1<<ADC_DRQ), (0x1<<ADC_DRQ));
			return 0;
		case SNDRV_PCM_TRIGGER_SUSPEND:
		case SNDRV_PCM_TRIGGER_STOP:
		case SNDRV_PCM_TRIGGER_PAUSE_PUSH:
			snd_soc_update_bits(codec, SUNXI_ADC_FIFOC,
					(0x1<<ADC_DRQ), (0x0<<ADC_DRQ));
			return 0;
		default:
			pr_err("error:%s,%d\n", __func__, __LINE__);
			return -EINVAL;
		}
	}
	return 0;
}
#endif
static int codec_hw_params(struct snd_pcm_substream *substream,
	struct snd_pcm_hw_params *params,
	struct snd_soc_dai *codec_dai)
{
	int i = 0;
	struct snd_soc_codec *codec = codec_dai->codec;
	struct snd_soc_pcm_runtime *rtd = substream->private_data;
	struct sunxi_dma_params *dma_data;

	for (i = 0; i < ARRAY_SIZE(codec_sr_s); i++) {
		if (codec_sr_s[i].samplerate ==  params_rate(params)) {
			if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
				dma_data = &sunxi_pcm_pcm_stereo_out;
				snd_soc_update_bits(codec, SUNXI_DAC_FIFOC,
				(0x7<<DAC_FS), (codec_sr_s[i].srbit<<DAC_FS));
				snd_soc_update_bits(codec, SUNXI_DAC_FIFOC,
				(0x7<<DAC_FS), (codec_sr_s[i].srbit<<DAC_FS));
			} else {
				dma_data = &sunxi_pcm_pcm_stereo_in;
				snd_soc_update_bits(codec, SUNXI_ADC_FIFOC,
				(0x7<<ADFS), (codec_sr_s[i].srbit<<ADFS));
				snd_soc_update_bits(codec, SUNXI_ADC_FIFOC,
				(0x7<<ADFS), (codec_sr_s[i].srbit<<ADFS));
			}
			break;
		}
	}

	switch (params_format(params)) {
	case SNDRV_PCM_FORMAT_S24_LE:
	case SNDRV_PCM_FORMAT_S32_LE:
		if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
			/*set TX FIFO MODE:24bit*/
			snd_soc_update_bits(codec, SUNXI_DAC_FIFOC,
				(0x3<<TX_FIFO_MODE), (0x2<<TX_FIFO_MODE));
			snd_soc_update_bits(codec, SUNXI_DAC_FIFOC,
				(0x1<<TASR), (0x1<<TASR));
		} else {
			/*set RX FIFO MODE:24bit*/
			snd_soc_update_bits(codec, SUNXI_ADC_FIFOC,
				(0x1<<RX_FIFO_MODE), (0x0<<RX_FIFO_MODE));
			snd_soc_update_bits(codec, SUNXI_ADC_FIFOC,
				(0x1<<RASR), (0x1<<RASR));
		}
		break;
	case SNDRV_PCM_FORMAT_S16_LE:
	default:
		if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
			/*set TX FIFO MODE:16bit*/
			snd_soc_update_bits(codec, SUNXI_DAC_FIFOC,
				(0x3<<TX_FIFO_MODE), (0x3<<TX_FIFO_MODE));
			snd_soc_update_bits(codec, SUNXI_DAC_FIFOC,
				(0x1<<TASR), (0x0<<TASR));
		} else {
			/*set RX FIFO MODE:16bit*/
			snd_soc_update_bits(codec, SUNXI_ADC_FIFOC,
				(0x1<<RX_FIFO_MODE), (0x1<<RX_FIFO_MODE));
			snd_soc_update_bits(codec, SUNXI_ADC_FIFOC,
				(0x1<<RASR), (0x0<<RASR));
		}
		break;
	}

	if (params_channels(params)==1) {
		if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
			snd_soc_update_bits(codec, SUNXI_DAC_FIFOC,
					(0x1<<DAC_MONO_EN), (0x1<<DAC_MONO_EN));
		} else {
			snd_soc_update_bits(codec, SUNXI_ADC_FIFOC,
					(0x1<<ADC_MONO_EN), (0x1<<ADC_MONO_EN));
		}
	} else {
		if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
			snd_soc_update_bits(codec, SUNXI_DAC_FIFOC,
					(0x1<<DAC_MONO_EN), (0x0<<DAC_MONO_EN));
		} else {
			snd_soc_update_bits(codec, SUNXI_ADC_FIFOC,
					(0x1<<ADC_MONO_EN), (0x0<<ADC_MONO_EN));
		}
	}

	snd_soc_dai_set_dma_data(rtd->cpu_dai, substream, dma_data);
	return 0;
}

static int codec_set_dai_fmt(struct snd_soc_dai *codec_dai,
			       unsigned int fmt)
{
	return 0;
}

static int codec_set_dai_sysclk(struct snd_soc_dai *codec_dai,
				  int clk_id, unsigned int freq, int dir)
{
	struct snd_soc_codec *codec = codec_dai->codec;
	struct sunxi_codec *sunxi_internal_codec = snd_soc_codec_get_drvdata(codec);

	if (clk_set_rate(sunxi_internal_codec->pllclk, freq)) {
		pr_err("[audio-cpudai]try to set the pll clk rate failed!\n");
	}

	return 0;
}

static int codec_set_bias_level(struct snd_soc_codec *codec,
				      enum snd_soc_bias_level level)
{
	codec->component.dapm.bias_level = level;
	return 0;
}

static const struct snd_soc_dai_ops codec_dai_ops = {
	.startup	= codec_start,
	.set_fmt	= codec_set_dai_fmt,
	.hw_params	= codec_hw_params,
	.shutdown	= codec_shutdown,
	.digital_mute	= codec_mute,
	.set_sysclk	= codec_set_dai_sysclk,
};

static struct snd_soc_dai_driver codec_dai[] = {
	{
		.name = "sndcodec",
		.id = 1,
		.playback = {
			.stream_name = "Playback",
			.channels_min = 1,
			.channels_max = 2,
			.rates = SNDRV_PCM_RATE_8000_192000,
			.formats = SNDRV_PCM_FMTBIT_S16_LE | SNDRV_PCM_FMTBIT_S24_LE | SNDRV_PCM_FMTBIT_S32_LE,
		},
		.capture = {
			.stream_name = "Capture",
			.channels_min = 1,
			.channels_max = 2,
			.rates = SNDRV_PCM_RATE_8000_48000,
			.formats = SNDRV_PCM_FMTBIT_S16_LE | SNDRV_PCM_FMTBIT_S24_LE | SNDRV_PCM_FMTBIT_S32_LE,
		 },
		.ops = &codec_dai_ops,
	},
};

static int codec_soc_probe(struct snd_soc_codec *codec)
{
	int ret = 0;
	struct snd_soc_dapm_context *dapm = &codec->component.dapm;
	struct sunxi_codec *sunxi_internal_codec = snd_soc_codec_get_drvdata(codec);

	sunxi_internal_codec->codec = codec;
	sunxi_internal_codec->dac_enable = 0;
	sunxi_internal_codec->adc_enable = 0;
	mutex_init(&sunxi_internal_codec->dac_mutex);
	mutex_init(&sunxi_internal_codec->adc_mutex);

	/* Add virtual switch */
	ret = snd_soc_add_codec_controls(codec, sunxi_codec_controls,
					ARRAY_SIZE(sunxi_codec_controls));
	if (ret) {
		pr_err("[audio-codec] Failed to register audio mode control, "
				"will continue without it.\n");
	}

	snd_soc_dapm_new_controls(dapm, ac_dapm_widgets, ARRAY_SIZE(ac_dapm_widgets));
 	snd_soc_dapm_add_routes(dapm, ac_dapm_routes, ARRAY_SIZE(ac_dapm_routes));

	codec_init(sunxi_internal_codec);

	return 0;
}

int audio_gpio_iodisable(u32 gpio)
{
	char pin_name[8];
	u32 config,ret;
	sunxi_gpio_to_name(gpio, pin_name);
	config = (((7) << 16) | (0 & 0xFFFF));
	ret = pin_config_set(SUNXI_PINCTRL, pin_name, config);
	return ret;
}

static int codec_suspend(struct snd_soc_codec *codec)
{
	struct sunxi_codec *sunxi_internal_codec = snd_soc_codec_get_drvdata(codec);
	pr_debug("[audio codec]:suspend start.\n");

	snd_soc_update_bits(codec, HP_CTRL, (0x1<<HPPAEN), (0x0<<HPPAEN));
	if (gpio_is_valid(sunxi_internal_codec->audio_pa_ctrl)) {
		audio_gpio_iodisable(sunxi_internal_codec->audio_pa_ctrl);
	}
	if (sunxi_internal_codec->moduleclk != NULL) {
		clk_disable(sunxi_internal_codec->moduleclk);
	}
	if (sunxi_internal_codec->pllclk != NULL) {
		clk_disable(sunxi_internal_codec->pllclk);
	}

	if (!IS_ERR_OR_NULL(sunxi_internal_codec->vol_supply.hp_ldo)) {
		regulator_disable(sunxi_internal_codec->vol_supply.hp_ldo);
	}


	pr_debug("[audio codec]:suspend end..\n");

	return 0;
}

static int codec_resume(struct snd_soc_codec *codec)
{
	int ret ;
	struct sunxi_codec *sunxi_internal_codec = snd_soc_codec_get_drvdata(codec);
	pr_debug("[audio codec]:resume start\n");

	if (!IS_ERR_OR_NULL(sunxi_internal_codec->vol_supply.hp_ldo)) {
		ret = regulator_enable(sunxi_internal_codec->vol_supply.hp_ldo);
		if (ret) {
			pr_err("[%s]: cpvdd:regulator_enable() failed!\n",__func__);
		}
	}

	if (sunxi_internal_codec->pllclk != NULL) {
		if (clk_prepare_enable(sunxi_internal_codec->pllclk)) {
			pr_err("open sunxi_internal_codec->pllclk failed! line = %d\n", __LINE__);
		}
	}

	if (sunxi_internal_codec->moduleclk != NULL) {
		if (clk_prepare_enable(sunxi_internal_codec->moduleclk)) {
			pr_err("open sunxi_internal_codec->moduleclk failed! line = %d\n", __LINE__);
		}
	}

	codec_init(sunxi_internal_codec);
	if (gpio_is_valid(sunxi_internal_codec->audio_pa_ctrl)) {
		gpio_direction_output(sunxi_internal_codec->audio_pa_ctrl, 1);
		gpio_set_value(sunxi_internal_codec->audio_pa_ctrl, 0);
	}

	pr_debug("[audio codec]:resume end..\n");
	return 0;
}
static unsigned int codec_read(struct snd_soc_codec *codec, unsigned int reg)
{
	struct sunxi_codec *sunxi_internal_codec = snd_soc_codec_get_drvdata(codec);
	unsigned int analog_reg;
	unsigned int value = 0;
	if (reg >= ANALOG_FLAG) {
		/*analog reg */
		analog_reg = reg - ANALOG_FLAG;
		return read_prcm_wvalue(analog_reg, sunxi_internal_codec->codec_abase);
	} else {
		/*digital reg */
		value =  readl(sunxi_internal_codec->codec_dbase + reg);
		return value ;
	}
}

static int codec_write(struct snd_soc_codec *codec,
		       unsigned int reg, unsigned int value)
{
	unsigned int analog_reg;
	struct sunxi_codec *sunxi_internal_codec = snd_soc_codec_get_drvdata(codec);
	if (reg >= ANALOG_FLAG) {
		/*analog reg */
		analog_reg = reg - ANALOG_FLAG;
		write_prcm_wvalue(analog_reg, value, sunxi_internal_codec->codec_abase);
	} else {
		/*digital reg */
		writel(value, sunxi_internal_codec->codec_dbase + reg);
	}
	return 0;
}

/* power down chip */
static int codec_soc_remove(struct snd_soc_codec *codec)
{
	return 0;
}

static struct snd_soc_codec_driver soc_codec_dev_codec = {
	.probe 	 = codec_soc_probe,
	.remove  = codec_soc_remove,
	.suspend = codec_suspend,
	.resume  = codec_resume,
	.set_bias_level = codec_set_bias_level,
	.read 	 = codec_read,
	.write 	 = codec_write,
	.ignore_pmdown_time = 1,
};

static ssize_t show_audio_reg(struct device *dev, struct device_attribute *attr,
			      char *buf)
{
	int count = 0;
	int i = 0;
	int reg_group = 0;
	printk("%s,line:%d\n", __func__, __LINE__);

	count += sprintf(buf, "dump audio reg:\n");

	while (reg_labels[i].name != NULL) {
		if ((reg_labels[i].value & (~ANALOG_FLAG)) == 0) {
			reg_group++;
		}
		if (reg_group == 1) {
			count +=
			    sprintf(buf + count, "%s 0x%p: 0x%x\n",
				    reg_labels[i].name,
				    (codec_digitaladress + reg_labels[i].value),
				    readl(codec_digitaladress + reg_labels[i].value));
		} else if (reg_group == 2) {
			count +=
			    sprintf(buf + count, "%s 0x%x: 0x%x\n",
				    reg_labels[i].name, (reg_labels[i].value & (~ANALOG_FLAG)),
				    read_prcm_wvalue(reg_labels[i].value & (~ANALOG_FLAG), codec_analogadress));
		}
		i++;
	}

	return count;
}

/* ex:
	read:
		echo 0,1,0x00> audio_reg
		echo 0,2,0x00> audio_reg
	write:
		echo 1,1,0x00,0xa > audio_reg
		echo 1,2,0x00,0xff > audio_reg
*/
static ssize_t store_audio_reg(struct device *dev,
			       struct device_attribute *attr, const char *buf,
			       size_t count)
{
	int ret;
	int input_reg_group = 0;
	unsigned int input_reg_offset = 0;
	unsigned int input_reg_val = 0;
	int reg_val_read;
	int rw_flag;

	printk("%s,line:%d\n", __func__, __LINE__);
	ret =
	    sscanf(buf, "%d,%d,0x%x,0x%x", &rw_flag, &input_reg_group,
		   &input_reg_offset, &input_reg_val);
	printk("ret:%d, reg_group:%d, reg_offset:%d, reg_val:0x%x\n", ret,
	       input_reg_group, input_reg_offset, input_reg_val);

	if (!(input_reg_group == 1 || input_reg_group == 2)) {
		printk("not exist reg group\n");
		ret = count;
		goto out;
	}
	if (!(rw_flag == 1 || rw_flag == 0)) {
		printk("not rw_flag\n");
		ret = count;
		goto out;
	}
	if (input_reg_group == 1) {
		if (rw_flag) {
			writel(input_reg_val, codec_digitaladress + input_reg_offset);
		} else {
			reg_val_read = readl(codec_digitaladress + input_reg_offset);
			printk("\n\n Reg[0x%x] : 0x%x\n\n", input_reg_offset,
			       reg_val_read);
		}
	} else if (input_reg_group == 2) {
		if (rw_flag) {
			write_prcm_wvalue(input_reg_offset,
					  input_reg_val & 0xff, codec_analogadress);
		} else {
			reg_val_read = read_prcm_wvalue(input_reg_offset, codec_analogadress);
			printk("\n\n Reg[0x%x] : 0x%x\n\n", input_reg_offset,
			       reg_val_read);
		}
	}

	ret = count;

      out:
	return ret;
}

static DEVICE_ATTR(audio_reg, 0644, show_audio_reg, store_audio_reg);

static struct attribute *audio_debug_attrs[] = {
	&dev_attr_audio_reg.attr,
	NULL,
};

static struct attribute_group audio_debug_attr_group = {
	.name   = "audio_reg_debug",
	.attrs  = audio_debug_attrs,
};
static const struct of_device_id sunxi_internal_codec_of_match[] = {
	{ .compatible = "allwinner,sunxi-internal-codec", },
	{},
};
MODULE_DEVICE_TABLE(of, sunxi_internal_codec_of_match);

static int  sunxi_internal_codec_probe(struct platform_device *pdev)
{
	s32 ret = 0;
	struct sunxi_codec *sunxi_internal_codec;
	int req_status;
	const struct of_device_id *device;
	struct device_node *node = pdev->dev.of_node;
	u32 temp_val;
	if (!node) {
		dev_err(&pdev->dev,
			"can not get dt node for this device.\n");
		ret = -EINVAL;
		goto err0;
	}

	sunxi_internal_codec = devm_kzalloc(&pdev->dev, sizeof(struct sunxi_codec), GFP_KERNEL);
	if (!sunxi_internal_codec) {
		dev_err(&pdev->dev, "Can't allocate sunxi_codec\n");
		ret = -ENOMEM;
		goto err0;
	}
	dev_set_drvdata(&pdev->dev, sunxi_internal_codec);
	device = of_match_device(sunxi_internal_codec_of_match, &pdev->dev);
	if (!device) {
		ret = -ENODEV;
		goto err1;
	}
	/* codec_pll2clk */
	sunxi_internal_codec->pllclk = of_clk_get(node, 0);
	if ((!sunxi_internal_codec->pllclk)||(IS_ERR(sunxi_internal_codec->pllclk))) {
		pr_err("try to get pllclk failed!\n");
		goto err1;
	}
	if (clk_set_rate(sunxi_internal_codec->pllclk, 24576000)) {
		pr_err("set pllclk rate fail\n");
		goto err1;
	}
	if (clk_prepare_enable(sunxi_internal_codec->pllclk)) {
		pr_err("enable pllclk failed; \n");
		goto err1;
	}
	/* codec_moduleclk */
	sunxi_internal_codec->moduleclk = of_clk_get(node, 1);
	if ((!sunxi_internal_codec->moduleclk)||(IS_ERR(sunxi_internal_codec->moduleclk))) {
		pr_err("try to get codec_moduleclk failed!\n");
		goto err1;
	}
	if (clk_set_parent(sunxi_internal_codec->moduleclk, sunxi_internal_codec->pllclk)) {
		pr_err("err:try to set parent of codec_moduleclk to codec_pll2clk failed!\n");
		goto err1;
	}
	if (clk_set_rate(sunxi_internal_codec->moduleclk, 24576000)) {
		pr_err("err:set codec_moduleclk clock freq 24576000 failed!\n");
		goto err1;
	}
	if (clk_prepare_enable(sunxi_internal_codec->moduleclk)) {
		pr_err("err:open codec_moduleclk failed; \n");
		goto err1;
	}

	ret = of_property_read_u32(node, "headphone_vol", &temp_val);
	if (ret < 0) {
		pr_err("[audio-codec]headphonevol configurations missing or invalid.\n");
		ret = -EINVAL;
		goto err1;
	} else {
		sunxi_internal_codec->gain_config.headphonevol = temp_val;
	}
	sunxi_internal_codec->codec_abase = NULL;
	sunxi_internal_codec->codec_dbase = NULL;
	sunxi_internal_codec->codec_dbase = of_iomap(node, 0);
	if (sunxi_internal_codec->codec_dbase == NULL) {
		pr_err("[audio-codec]Can't map codec digital registers\n");
	} else {
		codec_digitaladress = sunxi_internal_codec->codec_dbase;
	}
	sunxi_internal_codec->codec_abase = of_iomap(node, 1);
	if (sunxi_internal_codec->codec_abase == NULL) {
		pr_err("[audio-codec]Can't map codec analog registers\n");
	} else {
		codec_analogadress = sunxi_internal_codec->codec_abase;
	}

	ret = of_get_named_gpio(node, "audio_pa_ctrl", 0);
	if (ret >= 0) {
		sunxi_internal_codec->audio_pa_ctrl = ret;
		if (!gpio_is_valid(sunxi_internal_codec->audio_pa_ctrl)) {
			dev_err(&pdev->dev, "gpio-pa is valid\n");
			ret = -EINVAL;
		} else {
			ret = devm_gpio_request(&pdev->dev,
					sunxi_internal_codec->audio_pa_ctrl, "codec-gpio-pa");
			if (ret) {
				dev_err(&pdev->dev, "failed to request gpio-spk gpio\n");
				ret = -EBUSY;
			} else {
				gpio_direction_output(sunxi_internal_codec->audio_pa_ctrl, 1);
				gpio_set_value(sunxi_internal_codec->audio_pa_ctrl, 0);
			}
		}
	} else {
		sunxi_internal_codec->audio_pa_ctrl = -1;
	}

	ret = of_property_read_u32(node, "spker_vol", &temp_val);
	if (ret < 0) {
		pr_err("[audio-codec]headphonevol configurations missing or invalid.\n");
		ret = -EINVAL;
	} else {
		sunxi_internal_codec->gain_config.speakervol = temp_val;
	}

	ret = of_property_read_u32(node, "main_mic_vol", &temp_val);
	if (ret < 0) {
		pr_err("[audiocodec] main_mic_vol type err!\n");
	} else {
		sunxi_internal_codec->gain_config.maingain = temp_val;
	}

	ret = of_property_read_u32(node, "headset_mic_vol", &temp_val);
	if (ret < 0) {
		pr_err("[audiocodec] headset_mic_vol  type err!\n");
	} else {
		sunxi_internal_codec->gain_config.headsetmicgain = temp_val;
	}

	ret = of_property_read_u32(node, "adcagc_used", &temp_val);
	if (ret < 0) {
		pr_err("[audiocodec] adcagc_used type err!\n");
	} else {
		sunxi_internal_codec->hwconfig.adcagc_cfg = temp_val;
	}

	ret = of_property_read_u32(node, "adcdrc_used", &temp_val);
	if (ret < 0) {
		pr_err("[audiocodec] adcdrc_used type err!\n");
	} else {
		sunxi_internal_codec->hwconfig.adcdrc_cfg = temp_val;
	}

	ret = of_property_read_u32(node, "dacdrc_used", &temp_val);
	if (ret < 0) {
		pr_err("[audiocodec] dacdrc_used type err!\n");
	} else {
		sunxi_internal_codec->hwconfig.dacdrc_cfg = temp_val;
	}

	ret = of_property_read_u32(node, "adchpf_used", &temp_val);
	if (ret < 0) {
		pr_err("[audiocodec] adchpf_used type err!\n");
	} else {
		sunxi_internal_codec->hwconfig.adchpf_cfg = temp_val;
	}

	ret = of_property_read_u32(node, "dachpf_used", &temp_val);
	if (ret < 0) {
		pr_err("[audiocodec] dachpf_used type err!\n");
	} else {
		sunxi_internal_codec->hwconfig.dachpf_cfg = temp_val;
	}

	pr_err("before snd_soc_register_codec \n");
	ret = snd_soc_register_codec(&pdev->dev, &soc_codec_dev_codec, codec_dai, ARRAY_SIZE(codec_dai));
	if(ret < 0)
		pr_err("snd_soc_register_codec fail \n");
	ret  = sysfs_create_group(&pdev->dev.kobj, &audio_debug_attr_group);
	if (ret){
		pr_err("[audio-codec]failed to create attr group\n");
	}
	return 0;
err1:
	devm_kfree(&pdev->dev, sunxi_internal_codec);
err0:
	return ret;
}

static int __exit sunxi_internal_codec_remove(struct platform_device *pdev)
{
	sysfs_remove_group(&pdev->dev.kobj, &audio_debug_attr_group);
	snd_soc_unregister_codec(&pdev->dev);
	return 0;
}

static void sunxi_internal_codec_shutdown(struct platform_device *pdev)
{
	struct sunxi_codec *sunxi_internal_codec = dev_get_drvdata(&pdev->dev);

	if (gpio_is_valid(sunxi_internal_codec->audio_pa_ctrl)) {
		gpio_set_value(sunxi_internal_codec->audio_pa_ctrl, 0);
	}
	usleep_range(2000, 3000);

	return;
}

#if 0
static struct platform_device sunxi_internal_codec_device = {
	.name = "sunxi-pcm-codec",
	.id = -1,
};
#endif
static struct platform_driver sunxi_internal_codec_driver = {
	.driver = {
		   .name = "sunxi-internal-codec",
		   .owner = THIS_MODULE,
		   .of_match_table = sunxi_internal_codec_of_match,
	},
	.probe = sunxi_internal_codec_probe,
	.remove = __exit_p(sunxi_internal_codec_remove),
	.shutdown = sunxi_internal_codec_shutdown,
};
module_platform_driver(sunxi_internal_codec_driver);

#if 0
static int __init sndpcm_codec_init(void)
{
	int err = 0;
	err = platform_device_register(&sunxi_internal_codec_device);
	if (err < 0)
		return err;

	err = platform_driver_register(&sunxi_internal_codec_driver);
	if (err < 0)
		return err;

	return 0;
}

module_init(sndpcm_codec_init);

static void __exit sndpcm_codec_exit(void)
{
	platform_driver_unregister(&sunxi_internal_codec_driver);
}
module_exit(sndpcm_codec_exit);
#endif


MODULE_DESCRIPTION("codec ALSA soc codec driver");
MODULE_AUTHOR("guoyingyang<guoyingyang@allwinnertech.com>");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:sunxi-pcm-codec");

