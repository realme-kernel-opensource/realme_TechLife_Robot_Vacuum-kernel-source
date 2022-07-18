/*
 * sound\soc\sunxi\sun8iw16-codec.c
 * (C) Copyright 2014-2018
 * Reuuimlla Technology Co., Ltd. <www.allwinnertech.com>
 * huangxin <huangxin@allwinnertech.com>
 * Liu shaohua <liushaohua@allwinnertech.com>
 * yumingfeng <yumingfeng@allwinnertech.com>
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
#include <sound/tlv.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/pm.h>
#include <linux/of_gpio.h>
#include <linux/sunxi-gpio.h>
#include "sun8iw16-codec.h"
#include "sunxi_rw_func.h"

#ifdef CONFIG_SUNXI_MPP_AIO
#include "sunxi-aio/mpp-aio.h"
extern struct sunxi_audio_mpp_debugfs *mpp_audio_debugfs;
#endif

#define codec_RATES (SNDRV_PCM_RATE_8000_192000 | SNDRV_PCM_RATE_KNOT)
#define codec_FORMATS (SNDRV_PCM_FMTBIT_S8 | SNDRV_PCM_FMTBIT_S16_LE | \
	SNDRV_PCM_FMTBIT_S20_3LE | SNDRV_PCM_FMTBIT_S24_LE | \
	SNDRV_PCM_FMTBIT_S32_LE)

#define DRV_NAME "sunxi-internal-codec"

static void __iomem *codec_digitaladress;
static void __iomem *codec_analogadress;

static const DECLARE_TLV_DB_SCALE(lineout_vol_tlv, -450, 150, 0);

static const DECLARE_TLV_DB_SCALE(aif1_ad_slot0_vol_tlv, -11925, 75, 0);
static const DECLARE_TLV_DB_SCALE(aif1_ad_slot1_vol_tlv, -11925, 75, 0);
static const DECLARE_TLV_DB_SCALE(aif1_da_slot0_vol_tlv, -11925, 75, 0);
static const DECLARE_TLV_DB_SCALE(aif1_da_slot1_vol_tlv, -11925, 75, 0);
static const DECLARE_TLV_DB_SCALE(aif1_ad_slot0_mix_vol_tlv, -600, 600, 0);
static const DECLARE_TLV_DB_SCALE(aif1_ad_slot1_mix_vol_tlv, -600, 600, 0);

#ifdef CODEC_AIF2_AIF3_ENABLE
static const DECLARE_TLV_DB_SCALE(aif2_ad_vol_tlv, -11925, 75, 0);
static const DECLARE_TLV_DB_SCALE(aif2_da_vol_tlv, -11925, 75, 0);
static const DECLARE_TLV_DB_SCALE(aif2_ad_mix_vol_tlv, -600, 600, 0);
#endif

static const DECLARE_TLV_DB_SCALE(adc_vol_tlv, -11925, 75, 0);
static const DECLARE_TLV_DB_SCALE(dac_vol_tlv, -11925, 75, 0);
static const DECLARE_TLV_DB_SCALE(dac_mix_vol_tlv, -600, 600, 0);
static const DECLARE_TLV_DB_SCALE(dig_vol_tlv, -7308, 116, 0);

static const DECLARE_TLV_DB_SCALE(mic1_to_l_r_mix_vol_tlv, -450, 150, 0);
static const DECLARE_TLV_DB_SCALE(mic1_boost_vol_tlv, 0, 200, 0);
static const DECLARE_TLV_DB_SCALE(mic2_to_l_r_mix_vol_tlv, -450, 150, 0);
static const DECLARE_TLV_DB_SCALE(mic2_boost_vol_tlv, 0, 200, 0);
static const DECLARE_TLV_DB_SCALE(linein_to_l_r_mix_vol_tlv, -450, 150, 0);
static const DECLARE_TLV_DB_SCALE(adc_input_vol_tlv, -450, 150, 0);

struct aif1_fs {
	unsigned int samplerate;
	int aif1_bclk_div;
	int aif1_srbit;
};

struct aif1_lrck {
	int aif1_lrlk_div;
	int aif1_lrlk_bit;
};

struct aif1_word_size {
	int aif1_wsize_val;
	int aif1_wsize_bit;
};

static const struct aif1_fs codec_aif1_fs[] = {
	{44100, 4, 7},
	{48000, 4, 8},
	{8000, 9, 0},
	{11025, 8, 1},
	{12000, 8, 2},
	{16000, 7, 3},
	{22050, 6, 4},
	{24000, 6, 5},
	{32000, 5, 6},
	{96000, 2, 9},
	{192000, 1, 10},
};

static const struct aif1_lrck codec_aif1_lrck[] = {
	{16, 0},
	{32, 1},
	{64, 2},
	{128, 3},
	{256, 4},
};

static const struct aif1_word_size codec_aif1_wsize[] = {
	{8, 0},
	{16, 1},
	{20, 2},
	{24, 3},
};

static struct label reg_labels[] = {
	LABEL(SUNXI_DA_CTL),
	LABEL(SUNXI_DA_FAT0),
	LABEL(SUNXI_DA_FAT1),
	LABEL(SUNXI_DA_ISTA),
	LABEL(SUNXI_DA_FCTL),
	LABEL(SUNXI_DA_INT),
	LABEL(SUNXI_DA_CLKD),
	LABEL(SUNXI_DA_TXCNT),
	LABEL(SUNXI_DA_RXCNT),
	LABEL(SUNXI_SYSCLK_CTL),
	LABEL(SUNXI_MOD_CLK_ENA),
	LABEL(SUNXI_MOD_RST_CTL),
	LABEL(SUNXI_SYS_SR_CTRL),
	LABEL(SUNXI_SYS_DVC_MOD),

	LABEL(SUNXI_AIF1_CLK_CTRL),
	LABEL(SUNXI_AIF1_ADCDAT_CTRL),
	LABEL(SUNXI_AIF1_DACDAT_CTRL),
	LABEL(SUNXI_AIF1_MXR_SRC),
	LABEL(SUNXI_AIF1_VOL_CTRL1),
	LABEL(SUNXI_AIF1_VOL_CTRL2),
	LABEL(SUNXI_AIF1_VOL_CTRL3),
	LABEL(SUNXI_AIF1_VOL_CTRL4),
	LABEL(SUNXI_AIF1_MXR_GAIN),
	LABEL(SUNXI_AIF1_RXD_CTRL),
#ifdef CODEC_AIF2_AIF3_ENABLE
	LABEL(SUNXI_AIF2_CLK_CTRL),
	LABEL(SUNXI_AIF2_ADCDAT_CTRL),
	LABEL(SUNXI_AIF2_DACDAT_CTRL),
	LABEL(SUNXI_AIF2_MXR_SRC),
	LABEL(SUNXI_AIF2_VOL_CTRL1),
	LABEL(SUNXI_AIF2_VOL_CTRL2),
	LABEL(SUNXI_AIF2_MXR_GAIN),
	LABEL(SUNXI_AIF2_RXD_CTRL),
	LABEL(SUNXI_AIF3_CLK_CTRL),
	LABEL(SUNXI_AIF3_ADCDAT_CTRL),
	LABEL(SUNXI_AIF3_DACDAT_CTRL),
	LABEL(SUNXI_AIF3_SGP_CTRL),
	LABEL(SUNXI_AIF3_RXD_CTRL),
#endif
	LABEL(SUNXI_ADC_DIG_CTRL),
	LABEL(SUNXI_ADC_VOL_CTRL),
	LABEL(SUNXI_ADC_DBG_CTRL),
	LABEL(SUNXI_DAC_DIG_CTRL),
	LABEL(SUNXI_DAC_VOL_CTRL),
	LABEL(SUNXI_DAC_DBG_CTRL),
	LABEL(SUNXI_DAC_MXR_SRC),
	LABEL(SUNXI_DAC_MXR_GAIN),
	LABEL(SUNXI_AGC_ENA),
	LABEL(SUNXI_DRC_ENA),

	LABEL(OL_MIX_CTRL),
	LABEL(OR_MIX_CTRL),
	LABEL(LINEOUT_CTRL0),
	LABEL(LINEOUT_CTRL1),
	LABEL(MIC1_CTRL),
	LABEL(MIC2_CTRL),
	LABEL(LINEIN_CTRL),
	LABEL(MIX_DAC_CTRL),
	LABEL(L_ADCMIX_SRC),
	LABEL(R_ADCMIX_SRC),
	LABEL(ADC_CTRL),
	LABEL(MBIAS_CTRL),
	LABEL(APT_REG),
	LABEL(OP_BIAS_CTRL0),
	LABEL(OP_BIAS_CTRL1),
	LABEL(ZC_VOL_CTRL),
	LABEL_END,
};

#ifdef CODEC_DAP_ENABLE
static void adcagc_config(struct snd_soc_codec *codec)
{
}

static void adcdrc_config(struct snd_soc_codec *codec)
{
	snd_soc_write(codec, SUNXI_AC_DRC1_HCT, 0x5d0);
	snd_soc_write(codec, SUNXI_AC_DRC1_LCT, 0x3948);
	snd_soc_write(codec, SUNXI_AC_DRC1_HKC, 0x100);
	snd_soc_write(codec, SUNXI_AC_DRC1_HOPC, 0xfa2f);
	snd_soc_write(codec, SUNXI_AC_DRC1_LOPC, 0xc6b8);
	snd_soc_write(codec, SUNXI_AC_DRC1_HKI, 0x100);
	snd_soc_write(codec, SUNXI_AC_DRC1_LKI, 0x0);
	snd_soc_write(codec, SUNXI_AC_DRC1_HOPL, 0xfe56);
	snd_soc_write(codec, SUNXI_AC_DRC1_LOPL, 0xcb10);
	snd_soc_write(codec, SUNXI_AC_DRC1_HET, 0x6a4);
	snd_soc_write(codec, SUNXI_AC_DRC1_LET, 0xd3c0);
	snd_soc_write(codec, SUNXI_AC_DRC1_HKE, 0x200);
	snd_soc_write(codec, SUNXI_AC_DRC1_HOPE, 0xf8b1);
	snd_soc_write(codec, SUNXI_AC_DRC1_LOPE, 0x1713);
	snd_soc_write(codec, SUNXI_AC_DRC1_HKN, 0x1cc);
	snd_soc_write(codec, SUNXI_AC_DRC1_LKN, 0xcccc);
}

static void adchpf_config(struct snd_soc_codec *codec)
{
#if 0
	snd_soc_update_bits(codec, SUNXI_AC_DAPHHPFC,
			    (0x7ff << HPF_H_COEFFICIENT_SET),
			    (0xff << HPF_H_COEFFICIENT_SET));
	snd_soc_update_bits(codec, SUNXI_AC_DAPLHPFC,
			    (0xffff << HPF_L_COEFFICIENT_SET),
			    (0xfac1 << HPF_L_COEFFICIENT_SET));
#endif
}

static void dacdrc_config(struct snd_soc_codec *codec)
{
}

static void dachpf_config(struct snd_soc_codec *codec)
{
}

static void adcdrc_enable(struct snd_soc_codec *codec, bool on)
{
	if (on) {
		snd_soc_update_bits(codec, SUNXI_DRC_ENA, (0x1 << ADC_DRC1_ENA),
			(0x1 << ADC_DRC1_ENA));
		snd_soc_update_bits(codec, SUNXI_AC_DRC1_CTRL,
			(0x1 << DRC1_CTRL_DRC_LT_EN),
			(0x1 << DRC1_CTRL_DRC_LT_EN));
		snd_soc_update_bits(codec, SUNXI_AC_DRC1_CTRL,
			(0x1 << DRC1_CTRL_DRC_ET_EN),
			(0x1 << DRC1_CTRL_DRC_ET_EN));

		snd_soc_update_bits(codec, SUNXI_AC_DAC_DAPCTRL,
			(0x1 << DRC1_LEFT_CHAN_HPF_EN),
			(0x1 << DRC1_LEFT_CHAN_HPF_EN));
		snd_soc_update_bits(codec, SUNXI_AC_DAC_DAPCTRL,
			(0x1 << DRC1_RIGHT_CHAN_HPF_EN),
			(0x1 << DRC1_RIGHT_CHAN_HPF_EN));
		snd_soc_update_bits(codec, SUNXI_AC_DAC_DAPCTRL,
			(0x1 << DRC1_EN),
			(0x1 << DRC1_EN));
	} else {
		snd_soc_update_bits(codec, SUNXI_DRC_ENA, (0x1 << ADC_DRC1_ENA),
			(0x0 << ADC_DRC1_ENA));
		snd_soc_update_bits(codec, SUNXI_AC_DRC1_CTRL,
			(0x1 << DRC1_CTRL_DRC_LT_EN),
			(0x0 << DRC1_CTRL_DRC_LT_EN));
		snd_soc_update_bits(codec, SUNXI_AC_DRC1_CTRL,
			(0x1 << DRC1_CTRL_DRC_ET_EN),
			(0x0 << DRC1_CTRL_DRC_ET_EN));

		snd_soc_update_bits(codec, SUNXI_AC_DAC_DAPCTRL,
			(0x1 << DRC1_LEFT_CHAN_HPF_EN),
			(0x0 << DRC1_LEFT_CHAN_HPF_EN));
		snd_soc_update_bits(codec, SUNXI_AC_DAC_DAPCTRL,
			(0x1 << DRC1_RIGHT_CHAN_HPF_EN),
			(0x0 << DRC1_RIGHT_CHAN_HPF_EN));
		snd_soc_update_bits(codec, SUNXI_AC_DAC_DAPCTRL,
			(0x1 << DRC1_EN),
			(0x0 << DRC1_EN));
	}
}

static void dacdrc_enable(struct snd_soc_codec *codec, bool on)
{
	struct sunxi_codec *sunxi_internal_codec =
				snd_soc_codec_get_drvdata(codec);

	if (on) {
		if (sunxi_internal_codec->drc0_enable == 0) {
			snd_soc_update_bits(codec, SUNXI_MOD_CLK_ENA,
				(0x1 << HPF_DRC0_MOD_CLK_EN),
				(0x1 << HPF_DRC0_MOD_CLK_EN));
			snd_soc_update_bits(codec, SUNXI_MOD_RST_CTL,
				(0x1 << HPF_DRC0_MOD_RST_CTL),
				(0x1 << HPF_DRC0_MOD_RST_CTL));
		}
		snd_soc_update_bits(codec, SUNXI_DRC_ENA,
				(0x1 << AIF1_DAC0_DRC0_ENA),
				(0x1 << AIF1_DAC0_DRC0_ENA));
		snd_soc_update_bits(codec, SUNXI_DRC_ENA,
				(0x1 << AIF1_DAC1_DRC0_ENA),
				(0x1 << AIF1_DAC1_DRC0_ENA));

		if (sunxi_internal_codec->drc0_enable == 0) {
			snd_soc_update_bits(codec, SUNXI_DRC_ENA,
				(0x1 << DAC_DRC0_ENA),
				(0x1 << DAC_DRC0_ENA));
		}

		snd_soc_update_bits(codec, SUNXI_AC_DRC0_CTRL,
				(0x1 << DRC0_CTRL_DRC_LT_EN),
				(0x1 << DRC0_CTRL_DRC_LT_EN));
		snd_soc_update_bits(codec, SUNXI_AC_DRC0_CTRL,
				(0x1 << DRC0_CTRL_DRC_ET_EN),
				(0x1 << DRC0_CTRL_DRC_ET_EN));

		if (sunxi_internal_codec->drc0_enable == 0) {
			snd_soc_update_bits(codec, SUNXI_AC_DAC_DAPCTRL,
				(0x1 << DRC0_EN),
				(0x1 << DRC0_EN));
		}

		sunxi_internal_codec->drc0_enable++;
	} else {
		sunxi_internal_codec->drc0_enable--;
		if (sunxi_internal_codec->drc0_enable == 0) {
			snd_soc_update_bits(codec, SUNXI_MOD_CLK_ENA,
				(0x1 << HPF_DRC0_MOD_CLK_EN),
				(0x0 << HPF_DRC0_MOD_CLK_EN));
			snd_soc_update_bits(codec, SUNXI_MOD_RST_CTL,
				(0x1 << HPF_DRC0_MOD_RST_CTL),
				(0x0 << HPF_DRC0_MOD_RST_CTL));
			snd_soc_update_bits(codec, SUNXI_AC_DAC_DAPCTRL,
				(0x1 << DRC0_EN),
				(0x0 << DRC0_EN));
			snd_soc_update_bits(codec, SUNXI_DRC_ENA,
				(0x1 << DAC_DRC0_ENA),
				(0x0 << DAC_DRC0_ENA));
		}

		snd_soc_update_bits(codec, SUNXI_DRC_ENA,
				(0x1 << AIF1_DAC0_DRC0_ENA),
				(0x0 << AIF1_DAC0_DRC0_ENA));
		snd_soc_update_bits(codec, SUNXI_DRC_ENA,
				(0x1 << AIF1_DAC1_DRC0_ENA),
				(0x0 << AIF1_DAC1_DRC0_ENA));

		snd_soc_update_bits(codec, SUNXI_AC_DRC0_CTRL,
				(0x1 << DRC0_CTRL_DRC_LT_EN),
				(0x0 << DRC0_CTRL_DRC_LT_EN));
		snd_soc_update_bits(codec, SUNXI_AC_DRC0_CTRL,
				(0x1 << DRC0_CTRL_DRC_ET_EN),
				(0x0 << DRC0_CTRL_DRC_ET_EN));
	}
}

static void adcagc_enable(struct snd_soc_codec *codec, bool on)
{
}
static void dachpf_enable(struct snd_soc_codec *codec, bool on)
{
	struct sunxi_codec *sunxi_internal_codec =
				snd_soc_codec_get_drvdata(codec);

	if (on) {
		if (sunxi_internal_codec->drc0_enable == 0) {
			snd_soc_update_bits(codec, SUNXI_MOD_CLK_ENA,
				(0x1 << HPF_DRC0_MOD_CLK_EN),
				(0x1 << HPF_DRC0_MOD_CLK_EN));
			snd_soc_update_bits(codec, SUNXI_MOD_RST_CTL,
				(0x1 << HPF_DRC0_MOD_RST_CTL),
				(0x1 << HPF_DRC0_MOD_RST_CTL));
		}
		snd_soc_update_bits(codec, SUNXI_AC_DAC_DAPCTRL,
				(0x1 << RIGHT_HPF_EN),
				(0x01 << RIGHT_HPF_EN));
		snd_soc_update_bits(codec, SUNXI_AC_DAC_DAPCTRL,
				(0x1 << LEFT_HPF_EN),
				(0x01 << LEFT_HPF_EN));

		if (sunxi_internal_codec->drc0_enable == 0) {
			snd_soc_update_bits(codec, SUNXI_DRC_ENA,
				(0x1 << DAC_DRC0_ENA),
				(0x0 << DAC_DRC0_ENA));
			snd_soc_update_bits(codec, SUNXI_AC_DAC_DAPCTRL,
				(0x1 << DRC0_EN),
				(0x1 << DRC0_EN));
		}
		sunxi_internal_codec->drc0_enable++;
	} else {
		sunxi_internal_codec->drc0_enable--;
		if (sunxi_internal_codec->drc0_enable == 0) {
			snd_soc_update_bits(codec, SUNXI_MOD_CLK_ENA,
				(0x1 << HPF_DRC0_MOD_CLK_EN),
				(0x0 << HPF_DRC0_MOD_CLK_EN));
			snd_soc_update_bits(codec, SUNXI_MOD_RST_CTL,
				(0x1 << HPF_DRC0_MOD_RST_CTL),
				(0x0 << HPF_DRC0_MOD_RST_CTL));

			snd_soc_update_bits(codec, SUNXI_AC_DAC_DAPCTRL,
				(0x1 << DRC0_EN),
				(0x0 << DRC0_EN));
			snd_soc_update_bits(codec, SUNXI_DRC_ENA,
				(0x1 << DAC_DRC0_ENA),
				(0x0 << DAC_DRC0_ENA));
		}

		snd_soc_update_bits(codec, SUNXI_AC_DAC_DAPCTRL,
				(0x1 << RIGHT_HPF_EN),
				(0x0 << RIGHT_HPF_EN));
		snd_soc_update_bits(codec, SUNXI_AC_DAC_DAPCTRL,
				(0x1 << LEFT_HPF_EN),
				(0x0 << LEFT_HPF_EN));
	}
}

static void adchpf_enable(struct snd_soc_codec *codec, bool on)
{
	if (on) {
		snd_soc_update_bits(codec, SUNXI_AGC_ENA, (0x1 << ADCL_AGC_ENA),
				    (0x1 << ADCL_AGC_ENA));
		snd_soc_update_bits(codec, SUNXI_AGC_ENA, (0x1 << ADCR_AGC_ENA),
				    (0x1 << ADCR_AGC_ENA));

		snd_soc_update_bits(codec, SUNXI_MOD_CLK_ENA,
				    (0x1 << HPF_DRC1_MOD_CLK_EN),
				    (0x1 << HPF_DRC1_MOD_CLK_EN));

		snd_soc_update_bits(codec, SUNXI_MOD_RST_CTL,
				    (0x1 << HPF_DRC1_MOD_RST_CTL),
				    (0x1 << HPF_DRC1_MOD_RST_CTL));
	} else {
#if 0
		snd_soc_update_bits(codec, SUNXI_MOD_CLK_ENA,
				    (0x1 << HPF_AGC_MOD_CLK_EN),
				    (0x0 << HPF_AGC_MOD_CLK_EN));
		snd_soc_update_bits(codec, SUNXI_MOD_RST_CTL,
				    (0x1 << HPF_AGC_MOD_RST_CTL),
				    (0x0 << HPF_AGC_MOD_RST_CTL));
		snd_soc_update_bits(codec, SUNXI_AC_ADC_DAPLCTRL,
				    (0x1 << LEFT_HPF_EN),
				    (0x01 << LEFT_HPF_EN));
		snd_soc_update_bits(codec, SUNXI_AC_ADC_DAPRCTRL,
				    (0x1 << RIGHT_HPF_EN),
				    (0x00 << RIGHT_HPF_EN));
#endif
		snd_soc_update_bits(codec, SUNXI_MOD_CLK_ENA,
				    (0x1 << HPF_DRC1_MOD_CLK_EN),
				    (0x0 << HPF_DRC1_MOD_CLK_EN));

		snd_soc_update_bits(codec, SUNXI_MOD_RST_CTL,
				    (0x1 << HPF_DRC1_MOD_RST_CTL),
				    (0x0 << HPF_DRC1_MOD_RST_CTL));

		snd_soc_update_bits(codec, SUNXI_AGC_ENA, (0x1 << ADCL_AGC_ENA),
				    (0x00 << ADCL_AGC_ENA));
		snd_soc_update_bits(codec, SUNXI_AGC_ENA, (0x1 << ADCR_AGC_ENA),
				    (0x00 << ADCR_AGC_ENA));
	}
}
#endif

/*
 * enable the codec function which should be enable during system init.
 */
static int codec_init(struct sunxi_codec *sunxi_internal_codec)
{
	int ret = 0;

	sunxi_internal_codec->dac_enable = 0;
	sunxi_internal_codec->adc_enable = 0;
	sunxi_internal_codec->aif1_clken = 0;
	sunxi_internal_codec->aif2_clken = 0;
	sunxi_internal_codec->aif3_clken = 0;
	sunxi_internal_codec->sys_clken = 0;

	snd_soc_update_bits(sunxi_internal_codec->codec, LINEOUT_CTRL1,
		(0x1f << LINEOUT_VOL),
		(sunxi_internal_codec->gain_config.lineout_vol << LINEOUT_VOL));

	snd_soc_update_bits(sunxi_internal_codec->codec, MIC1_CTRL,
		(0x7 << MIC1BOOST),
		(sunxi_internal_codec->gain_config.maingain << MIC1BOOST));
	snd_soc_update_bits(sunxi_internal_codec->codec, MIC2_CTRL,
		(0x7 << MIC2BOOST),
		(sunxi_internal_codec->gain_config.headsetmicgain << MIC2BOOST));
	snd_soc_update_bits(sunxi_internal_codec->codec, MIX_DAC_CTRL,
			(0x1 << DACALEN), (1 << DACALEN));
	snd_soc_update_bits(sunxi_internal_codec->codec, MIX_DAC_CTRL,
			(0x1 << DACAREN), (1 << DACAREN));

#ifdef CODEC_DAP_ENABLE
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
#endif

#ifdef CODEC_AIF2_AIF3_ENABLE
	if (sunxi_internal_codec->aif_config.aif2config ||
	    sunxi_internal_codec->aif_config.aif3config) {
		if (!sunxi_internal_codec->pinctrl) {
			sunxi_internal_codec->pinctrl =
			    devm_pinctrl_get(sunxi_internal_codec->codec->dev);
			if (IS_ERR_OR_NULL(sunxi_internal_codec->pinctrl)) {
				pr_warn("pinctrl handle for audio failed\n");
				return -EINVAL;
			}
		}
	}

	if (sunxi_internal_codec->aif_config.aif2config) {
		if (!sunxi_internal_codec->aif2_pinstate) {
			sunxi_internal_codec->aif2_pinstate =
			    pinctrl_lookup_state(sunxi_internal_codec->pinctrl,
						 "aif2-default");
			if (IS_ERR_OR_NULL(
				sunxi_internal_codec->aif2_pinstate)) {
				pr_warn("lookup aif2-defaultstate failed\n");
				return -EINVAL;
			}
		}

		if (!sunxi_internal_codec->aif2sleep_pinstate) {
			sunxi_internal_codec->aif2sleep_pinstate =
			    pinctrl_lookup_state(sunxi_internal_codec->pinctrl,
						 "aif2-sleep");
			if (IS_ERR_OR_NULL(
				sunxi_internal_codec->aif2sleep_pinstate)) {
				pr_warn("lookup aif2-sleep state failed\n");
				return -EINVAL;
			}
		}
		ret = pinctrl_select_state(sunxi_internal_codec->pinctrl,
					   sunxi_internal_codec->aif2_pinstate);
		if (ret) {
			pr_warn(
			    "[audio-codec]select aif2-default state failed\n");
			return ret;
		}
	}
	if (sunxi_internal_codec->aif_config.aif3config) {
		if (!sunxi_internal_codec->aif3_pinstate) {
			sunxi_internal_codec->aif3_pinstate =
			    pinctrl_lookup_state(sunxi_internal_codec->pinctrl,
						 "aif3-default");
			if (IS_ERR_OR_NULL(
				sunxi_internal_codec->aif3_pinstate)) {
				pr_warn("lookup aif3-default state failed\n");
				return -EINVAL;
			}
		}

		if (!sunxi_internal_codec->aif3sleep_pinstate) {
			sunxi_internal_codec->aif3sleep_pinstate =
			    pinctrl_lookup_state(sunxi_internal_codec->pinctrl,
						 "aif3-sleep");
			if (IS_ERR_OR_NULL(
				sunxi_internal_codec->aif3sleep_pinstate)) {
				pr_warn("lookup aif3-sleep state failed\n");
				return -EINVAL;
			}
		}

		ret = pinctrl_select_state(sunxi_internal_codec->pinctrl,
					   sunxi_internal_codec->aif3_pinstate);
		if (ret) {
			pr_warn(
			    "[audio-codec]select aif3-default state failed\n");
			return ret;
		}
	}
#endif

	return ret;
}

int ac_aif1clk(struct snd_soc_dapm_widget *w, struct snd_kcontrol *kcontrol,
	       int event)
{
	struct snd_soc_codec *codec = snd_soc_dapm_to_codec(w->dapm);
	struct sunxi_codec *sunxi_internal_codec =
				snd_soc_codec_get_drvdata(codec);

	mutex_lock(&sunxi_internal_codec->aifclk_mutex);
	switch (event) {
	case SND_SOC_DAPM_PRE_PMU:
		if (sunxi_internal_codec->aif1_clken == 0) {
			/*enable AIF1CLK*/
			snd_soc_update_bits(codec, SUNXI_SYSCLK_CTL,
					    (0x1 << AIF1CLK_ENA),
					    (0x1 << AIF1CLK_ENA));
			snd_soc_update_bits(codec, SUNXI_MOD_CLK_ENA,
					    (0x1 << AIF1_MOD_CLK_EN),
					    (0x1 << AIF1_MOD_CLK_EN));
			snd_soc_update_bits(codec, SUNXI_MOD_RST_CTL,
					    (0x1 << AIF1_MOD_RST_CTL),
					    (0x1 << AIF1_MOD_RST_CTL));

			/* enable systemclk */
			if (sunxi_internal_codec->aif2_clken == 0 &&
			    sunxi_internal_codec->aif3_clken == 0) {
				snd_soc_update_bits(codec, SUNXI_SYSCLK_CTL,
						    (0x1 << SYSCLK_ENA),
						    (0x1 << SYSCLK_ENA));
				sunxi_internal_codec->sys_clken++;
			}
		}
		sunxi_internal_codec->aif1_clken++;
		break;
	case SND_SOC_DAPM_POST_PMD:
		sunxi_internal_codec->aif1_clken--;
		if (sunxi_internal_codec->aif1_clken < 0)
			sunxi_internal_codec->aif1_clken = 0;
		else if (sunxi_internal_codec->aif1_clken == 0) {
			/*disable AIF1CLK*/
			snd_soc_update_bits(codec, SUNXI_SYSCLK_CTL,
					    (0x1 << AIF1CLK_ENA),
					    (0x0 << AIF1CLK_ENA));
			snd_soc_update_bits(codec, SUNXI_MOD_CLK_ENA,
					    (0x1 << AIF1_MOD_CLK_EN),
					    (0x0 << AIF1_MOD_CLK_EN));
			snd_soc_update_bits(codec, SUNXI_MOD_RST_CTL,
					    (0x1 << AIF1_MOD_RST_CTL),
					    (0x0 << AIF1_MOD_RST_CTL));
			/*DISABLE systemclk*/
			if (sunxi_internal_codec->aif2_clken == 0 &&
				sunxi_internal_codec->aif3_clken == 0) {
				sunxi_internal_codec->sys_clken--;
				if (sunxi_internal_codec->sys_clken < 0)
					sunxi_internal_codec->sys_clken = 0;
				else if (sunxi_internal_codec->sys_clken == 0) {
					snd_soc_update_bits(codec, SUNXI_SYSCLK_CTL,
						(0x1 << SYSCLK_ENA),
						(0x0 << SYSCLK_ENA));
				}
			}
		}
		break;
	}
	mutex_unlock(&sunxi_internal_codec->aifclk_mutex);

	return 0;
}

#ifdef CODEC_AIF2_AIF3_ENABLE
int ac_aif2clk(struct snd_soc_dapm_widget *w,
		  struct snd_kcontrol *kcontrol, int event)
{
	struct snd_soc_codec *codec = snd_soc_dapm_to_codec(w->dapm);
	struct sunxi_codec *sunxi_internal_codec =
	    snd_soc_codec_get_drvdata(codec);

	mutex_lock(&sunxi_internal_codec->aifclk_mutex);
	switch (event) {
	case SND_SOC_DAPM_PRE_PMU:
		if (sunxi_internal_codec->aif2_clken == 0) {
			/*enable AIF2CLK*/
			snd_soc_update_bits(codec, SUNXI_SYSCLK_CTL,
					    (0x1 << AIF2CLK_ENA),
					    (0x1 << AIF2CLK_ENA));
			snd_soc_update_bits(codec, SUNXI_MOD_CLK_ENA,
					    (0x1 << AIF2_MOD_CLK_EN),
					    (0x1 << AIF2_MOD_CLK_EN));
			snd_soc_update_bits(codec, SUNXI_MOD_RST_CTL,
					    (0x1 << AIF2_MOD_RST_CTL),
					    (0x1 << AIF2_MOD_RST_CTL));
			/*enable systemclk*/
			if (sunxi_internal_codec->aif1_clken == 0 &&
			    sunxi_internal_codec->aif3_clken == 0) {
				snd_soc_update_bits(codec, SUNXI_SYSCLK_CTL,
						    (0x1 << SYSCLK_ENA),
						    (0x1 << SYSCLK_ENA));
				sunxi_internal_codec->sys_clken++;
			}
		}
		sunxi_internal_codec->aif2_clken++;
		break;
	case SND_SOC_DAPM_POST_PMD:
		sunxi_internal_codec->aif2_clken--;
		if (sunxi_internal_codec->aif2_clken < 0)
			sunxi_internal_codec->aif2_clken = 0;
		else if (sunxi_internal_codec->aif2_clken == 0) {
			/*disable AIF2CLK*/
			snd_soc_update_bits(codec, SUNXI_SYSCLK_CTL,
					(0x1 << AIF2CLK_ENA),
					(0x0 << AIF2CLK_ENA));
			snd_soc_update_bits(codec, SUNXI_MOD_CLK_ENA,
					(0x1 << AIF2_MOD_CLK_EN),
					(0x0 << AIF2_MOD_CLK_EN));
			snd_soc_update_bits(codec, SUNXI_MOD_RST_CTL,
					(0x1 << AIF2_MOD_RST_CTL),
					(0x0 << AIF2_MOD_RST_CTL));
			/*DISABLE systemclk*/
			if (sunxi_internal_codec->aif1_clken == 0 &&
				sunxi_internal_codec->aif3_clken == 0) {
				sunxi_internal_codec->sys_clken--;
				if (sunxi_internal_codec->sys_clken < 0)
					sunxi_internal_codec->sys_clken = 0;
				else if (sunxi_internal_codec->sys_clken == 0) {
					snd_soc_update_bits(codec, SUNXI_SYSCLK_CTL,
						(0x1 << SYSCLK_ENA),
						(0x0 << SYSCLK_ENA));
				}
			}
		}
		break;
	}
	mutex_unlock(&sunxi_internal_codec->aifclk_mutex);

	return 0;
}

int ac_aif3clk(struct snd_soc_dapm_widget *w,
		  struct snd_kcontrol *kcontrol, int event)
{
	struct snd_soc_codec *codec = snd_soc_dapm_to_codec(w->dapm);
	struct sunxi_codec *sunxi_internal_codec =
	    snd_soc_codec_get_drvdata(codec);

	mutex_lock(&sunxi_internal_codec->aifclk_mutex);
	switch (event) {
	case SND_SOC_DAPM_PRE_PMU:
		if (sunxi_internal_codec->aif2_clken == 0) {
			/*enable AIF2CLK*/
			snd_soc_update_bits(codec, SUNXI_SYSCLK_CTL,
					    (0x1 << AIF2CLK_ENA),
					    (0x1 << AIF2CLK_ENA));
			snd_soc_update_bits(codec, SUNXI_MOD_CLK_ENA,
					    (0x1 << AIF2_MOD_CLK_EN),
					    (0x1 << AIF2_MOD_CLK_EN));
			snd_soc_update_bits(codec, SUNXI_MOD_RST_CTL,
					    (0x1 << AIF2_MOD_RST_CTL),
					    (0x1 << AIF2_MOD_RST_CTL));
			/*enable systemclk*/
			if (sunxi_internal_codec->aif1_clken == 0 &&
			    sunxi_internal_codec->aif3_clken == 0) {
				snd_soc_update_bits(codec, SUNXI_SYSCLK_CTL,
						    (0x1 << SYSCLK_ENA),
						    (0x1 << SYSCLK_ENA));
				sunxi_internal_codec->sys_clken++;
			}
		}
		sunxi_internal_codec->aif2_clken++;
		if (sunxi_internal_codec->aif3_clken == 0) {
			/*enable AIF3CLK*/
			snd_soc_update_bits(codec, SUNXI_MOD_CLK_ENA,
					    (0x1 << AIF3_MOD_CLK_EN),
					    (0x1 << AIF3_MOD_CLK_EN));
			snd_soc_update_bits(codec, SUNXI_MOD_RST_CTL,
					    (0x1 << AIF3_MOD_RST_CTL),
					    (0x1 << AIF3_MOD_RST_CTL));
		}
		sunxi_internal_codec->aif3_clken++;
		break;
	case SND_SOC_DAPM_POST_PMD:
		sunxi_internal_codec->aif2_clken--;
		if (sunxi_internal_codec->aif2_clken < 0)
			sunxi_internal_codec->aif2_clken = 0;
		else if (sunxi_internal_codec->aif2_clken == 0) {
			/*disable AIF2CLK*/
			snd_soc_update_bits(codec, SUNXI_SYSCLK_CTL,
					(0x1 << AIF2CLK_ENA),
					(0x0 << AIF2CLK_ENA));
			snd_soc_update_bits(codec, SUNXI_MOD_CLK_ENA,
					(0x1 << AIF2_MOD_CLK_EN),
					(0x0 << AIF2_MOD_CLK_EN));
			snd_soc_update_bits(codec, SUNXI_MOD_RST_CTL,
					(0x1 << AIF2_MOD_RST_CTL),
					(0x0 << AIF2_MOD_RST_CTL));
			/*disable systemclk*/
			if (sunxi_internal_codec->aif1_clken == 0 &&
				sunxi_internal_codec->aif3_clken == 0) {
				sunxi_internal_codec->sys_clken--;
				if (sunxi_internal_codec->sys_clken < 0)
					sunxi_internal_codec->sys_clken = 0;
				else if (sunxi_internal_codec->sys_clken == 0) {
					snd_soc_update_bits(codec, SUNXI_SYSCLK_CTL,
						(0x1 << SYSCLK_ENA),
						(0x0 << SYSCLK_ENA));
				}
			}
		}
		sunxi_internal_codec->aif3_clken--;
		if (sunxi_internal_codec->aif3_clken < 0)
			sunxi_internal_codec->aif3_clken = 0;
		else if (sunxi_internal_codec->aif3_clken == 0) {
			/*disable AIF3CLK*/
			snd_soc_update_bits(codec, SUNXI_MOD_CLK_ENA,
						(0x1 << AIF3_MOD_CLK_EN),
						(0x0 << AIF3_MOD_CLK_EN));
			snd_soc_update_bits(codec, SUNXI_MOD_RST_CTL,
						(0x1 << AIF3_MOD_RST_CTL),
						(0x0 << AIF3_MOD_RST_CTL));
		}
		break;
	}
	mutex_unlock(&sunxi_internal_codec->aifclk_mutex);

	return 0;
}
#endif

static int late_enable_dac(struct snd_soc_dapm_widget *w,
			  struct snd_kcontrol *kcontrol, int event)
{
	struct snd_soc_codec *codec = snd_soc_dapm_to_codec(w->dapm);
	struct sunxi_codec *sunxi_internal_codec =
	    snd_soc_codec_get_drvdata(codec);

	mutex_lock(&sunxi_internal_codec->dac_mutex);
	switch (event) {
	case SND_SOC_DAPM_PRE_PMU:
		if (sunxi_internal_codec->dac_enable == 0) {
			if (sunxi_internal_codec->aif1_clken == 0) {
				snd_soc_update_bits(codec, SUNXI_SYSCLK_CTL,
					    (0x1 << AIF1CLK_ENA),
					    (0x1 << AIF1CLK_ENA));
				snd_soc_update_bits(codec, SUNXI_MOD_CLK_ENA,
					    (0x1 << AIF1_MOD_CLK_EN),
					    (0x1 << AIF1_MOD_CLK_EN));
				snd_soc_update_bits(codec, SUNXI_MOD_RST_CTL,
					    (0x1 << AIF1_MOD_RST_CTL),
					    (0x1 << AIF1_MOD_RST_CTL));
			}
			sunxi_internal_codec->aif1_clken++;

			if (sunxi_internal_codec->sys_clken == 0) {
				/*enable systemclk*/
				snd_soc_update_bits(codec, SUNXI_SYSCLK_CTL,
						    (0x1 << SYSCLK_ENA),
						    (0x1 << SYSCLK_ENA));
			}
			sunxi_internal_codec->sys_clken++;

			/*enable dac module clk*/
			snd_soc_update_bits(codec, SUNXI_MOD_CLK_ENA,
					    (0x1 << DAC_DIGITAL_MOD_CLK_EN),
					    (0x1 << DAC_DIGITAL_MOD_CLK_EN));
			snd_soc_update_bits(codec, SUNXI_MOD_RST_CTL,
					    (0x1 << DAC_DIGITAL_MOD_RST_CTL),
					    (0x1 << DAC_DIGITAL_MOD_RST_CTL));
			snd_soc_update_bits(codec, SUNXI_DAC_DIG_CTRL,
					    (0x1 << ENDA), (0x1 << ENDA));
		}
		sunxi_internal_codec->dac_enable++;
		break;
	case SND_SOC_DAPM_POST_PMD:
		sunxi_internal_codec->dac_enable--;
		if (sunxi_internal_codec->dac_enable < 0)
			sunxi_internal_codec->dac_enable = 0;
		else if (sunxi_internal_codec->dac_enable == 0) {
			snd_soc_update_bits(codec, SUNXI_DAC_DIG_CTRL,
					    (0x1 << ENDA),
					    (0x0 << ENDA));
			/*disable dac module clk*/
			snd_soc_update_bits(codec, SUNXI_MOD_CLK_ENA,
				(0x1 << DAC_DIGITAL_MOD_CLK_EN),
				(0x0 << DAC_DIGITAL_MOD_CLK_EN));
			snd_soc_update_bits(codec, SUNXI_MOD_RST_CTL,
					(0x1 << DAC_DIGITAL_MOD_RST_CTL),
					(0x0 << DAC_DIGITAL_MOD_RST_CTL));

			sunxi_internal_codec->aif1_clken--;
			if (sunxi_internal_codec->aif1_clken < 0)
				sunxi_internal_codec->aif1_clken = 0;
			else if (sunxi_internal_codec->aif1_clken == 0) {
				snd_soc_update_bits(codec, SUNXI_SYSCLK_CTL,
						(0x1 << AIF1CLK_ENA),
						(0x0 << AIF1CLK_ENA));
				snd_soc_update_bits(codec, SUNXI_MOD_CLK_ENA,
						(0x1 << AIF1_MOD_CLK_EN),
						(0x0 << AIF1_MOD_CLK_EN));
				snd_soc_update_bits(codec, SUNXI_MOD_RST_CTL,
						(0x1 << AIF1_MOD_RST_CTL),
						(0x0 << AIF1_MOD_RST_CTL));
			}

			sunxi_internal_codec->sys_clken--;
			if (sunxi_internal_codec->sys_clken < 0)
				sunxi_internal_codec->sys_clken = 0;
			else if (sunxi_internal_codec->sys_clken == 0) {
				snd_soc_update_bits(codec, SUNXI_SYSCLK_CTL,
						    (0x1 << SYSCLK_ENA),
						    (0x0 << SYSCLK_ENA));
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
	struct sunxi_codec *sunxi_internal_codec =
	    snd_soc_codec_get_drvdata(codec);

	mutex_lock(&sunxi_internal_codec->adc_mutex);
	switch (event) {
	case SND_SOC_DAPM_PRE_PMU:
		if (sunxi_internal_codec->adc_enable == 0) {
			/*enable adc module clk*/
			snd_soc_update_bits(codec, SUNXI_MOD_CLK_ENA,
					    (0x1 << ADC_DIGITAL_MOD_CLK_EN),
					    (0x1 << ADC_DIGITAL_MOD_CLK_EN));
			snd_soc_update_bits(codec, SUNXI_MOD_RST_CTL,
					    (0x1 << ADC_DIGITAL_MOD_RST_CTL),
					    (0x1 << ADC_DIGITAL_MOD_RST_CTL));
			snd_soc_update_bits(codec, SUNXI_ADC_DIG_CTRL,
					    (0x1 << ENAD), (0x1 << ENAD));
		}
		sunxi_internal_codec->adc_enable++;
		break;
	case SND_SOC_DAPM_POST_PMD:
		sunxi_internal_codec->adc_enable--;
		if (sunxi_internal_codec->adc_enable < 0)
			sunxi_internal_codec->adc_enable = 0;
		else if (sunxi_internal_codec->adc_enable == 0) {
			snd_soc_update_bits(codec, SUNXI_ADC_DIG_CTRL,
					(0x1 << ENAD),
					(0x0 << ENAD));
			/*disable adc module clk*/
			snd_soc_update_bits(codec, SUNXI_MOD_CLK_ENA,
					(0x1 << ADC_DIGITAL_MOD_CLK_EN),
					(0x0 << ADC_DIGITAL_MOD_CLK_EN));
			snd_soc_update_bits(codec, SUNXI_MOD_RST_CTL,
					(0x1 << ADC_DIGITAL_MOD_RST_CTL),
					(0x0 << ADC_DIGITAL_MOD_RST_CTL));
		}
		break;
	}
	mutex_unlock(&sunxi_internal_codec->adc_mutex);

	return 0;
}

static int ac_lineout_event(struct snd_soc_dapm_widget *w,
			struct snd_kcontrol *k,	int event)
{
	struct snd_soc_codec *codec = snd_soc_dapm_to_codec(w->dapm);
	struct sunxi_codec *sunxi_codec = snd_soc_codec_get_drvdata(codec);
	struct spk_config *spk_cfg = &(sunxi_codec->spk_config);

	switch (event) {
	case SND_SOC_DAPM_POST_PMU:
		if (spk_cfg->used) {
			gpio_set_value(spk_cfg->gpio, spk_cfg->pa_ctl_level);
		}
		break;
	case SND_SOC_DAPM_PRE_PMD:
		if (spk_cfg->used) {
			gpio_set_value(spk_cfg->gpio, !(spk_cfg->pa_ctl_level));
			msleep(spk_cfg->pa_msleep_time);
		}
		break;
	default:
		break;
	}
	return 0;
}

#ifdef CODEC_AIF2_AIF3_ENABLE
static int aif2inl_vir_event(struct snd_soc_dapm_widget *w,
			  struct snd_kcontrol *kcontrol, int event)
{
	struct snd_soc_codec *codec = snd_soc_dapm_to_codec(w->dapm);

	switch (event) {
	case SND_SOC_DAPM_PRE_PMU:
		snd_soc_update_bits(codec, SUNXI_AIF3_SGP_CTRL,
				    (0x3 << AIF2_DAC_SRC),
				    (0x1 << AIF2_DAC_SRC));
		break;
	case SND_SOC_DAPM_POST_PMD:
		snd_soc_update_bits(codec, SUNXI_AIF3_SGP_CTRL,
				    (0x3 << AIF2_DAC_SRC),
				    (0x0 << AIF2_DAC_SRC));
		break;
	}

	return 0;
}

static int aif2inr_vir_event(struct snd_soc_dapm_widget *w,
			  struct snd_kcontrol *kcontrol, int event)
{
	struct snd_soc_codec *codec = snd_soc_dapm_to_codec(w->dapm);

	switch (event) {
	case SND_SOC_DAPM_PRE_PMU:
		snd_soc_update_bits(codec, SUNXI_AIF3_SGP_CTRL,
				    (0x3 << AIF2_DAC_SRC),
				    (0x2 << AIF2_DAC_SRC));
		break;
	case SND_SOC_DAPM_POST_PMD:
		snd_soc_update_bits(codec, SUNXI_AIF3_SGP_CTRL,
				    (0x3 << AIF2_DAC_SRC),
				    (0x0 << AIF2_DAC_SRC));
		break;
	}

	return 0;
}

/*0x2c0:aif3 out, AIF3 PCM clk source select */
static const char * const aif3out_clk_text[] = {
	"AIF1_CLK", "AIF2_CLK", "AIF3_WITH_AIF1"
};

static const unsigned int aif3out_clk_values[] = {0, 1, 2};

static const struct soc_enum aif3out_clk_enum =
	SOC_VALUE_ENUM_SINGLE(SUNXI_AIF3_CLK_CTRL, AIF3_CLOC_SRC, 0x3,
			ARRAY_SIZE(aif3out_clk_text), aif3out_clk_text,
			aif3out_clk_values);
#endif

/* add mixer kcontrol for PA mute */
int sunxi_pashdn_get_data(struct snd_kcontrol *kcontrol,
		struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_component *component = snd_kcontrol_chip(kcontrol);
	struct snd_soc_codec *codec = snd_soc_component_to_codec(component);
	struct sunxi_codec *sunxi_codec = snd_soc_codec_get_drvdata(codec);
	struct spk_config *spk_cfg = &(sunxi_codec->spk_config);

	if (spk_cfg->used)
		ucontrol->value.integer.value[0] = gpio_get_value(spk_cfg->gpio);
	else
		ucontrol->value.integer.value[0] = 0;
	return 0;
}

int sunxi_pashdn_put_data(struct snd_kcontrol *kcontrol,
		struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_component *component = snd_kcontrol_chip(kcontrol);
	struct snd_soc_codec *codec = snd_soc_component_to_codec(component);
	struct sunxi_codec *sunxi_codec = snd_soc_codec_get_drvdata(codec);
	struct spk_config *spk_cfg = &(sunxi_codec->spk_config);

	if (spk_cfg->used) {
		int val = ucontrol->value.integer.value[0];
		gpio_set_value(spk_cfg->gpio, val);
	}

	return 0;
}

static const struct snd_kcontrol_new sunxi_codec_controls[] = {
	/*AIF1*/
	SOC_DOUBLE_TLV("AIF1 ADC timeslot 0 volume", SUNXI_AIF1_VOL_CTRL1,
		       AIF1_AD0L_VOL, AIF1_AD0R_VOL, 0xff, 0,
		       aif1_ad_slot0_vol_tlv),
	SOC_DOUBLE_TLV("AIF1 ADC timeslot 1 volume", SUNXI_AIF1_VOL_CTRL2,
		       AIF1_AD1L_VOL, AIF1_AD1R_VOL, 0xff, 0,
		       aif1_ad_slot1_vol_tlv),
	SOC_DOUBLE_TLV("AIF1 DAC timeslot 0 volume", SUNXI_AIF1_VOL_CTRL3,
		       AIF1_DA0L_VOL, AIF1_DA0R_VOL, 0xff, 0,
		       aif1_da_slot0_vol_tlv),
	SOC_DOUBLE_TLV("AIF1 DAC timeslot 1 volume", SUNXI_AIF1_VOL_CTRL4,
		       AIF1_DA1L_VOL, AIF1_DA1R_VOL, 0xff, 0,
		       aif1_da_slot1_vol_tlv),
	SOC_DOUBLE_TLV("AIF1 ADC timeslot 0 mixer gain", SUNXI_AIF1_MXR_GAIN,
		       AIF1_AD0L_MXR_GAIN, AIF1_AD0R_MXR_GAIN, 0xf, 0,
		       aif1_ad_slot0_mix_vol_tlv),
	SOC_DOUBLE_TLV("AIF1 ADC timeslot 1 mixer gain", SUNXI_AIF1_MXR_GAIN,
		       AIF1_AD1L_MXR_GAIN, AIF1_AD1R_MXR_GAIN, 0x3, 0,
		       aif1_ad_slot1_mix_vol_tlv),

#ifdef CODEC_AIF2_AIF3_ENABLE
	/*AIF2*/
	SOC_DOUBLE_TLV("AIF2 ADC volume", SUNXI_AIF2_VOL_CTRL1, AIF2_ADCL_VOL,
		       AIF2_ADCR_VOL, 0xff, 0, aif2_ad_vol_tlv),
	SOC_DOUBLE_TLV("AIF2 DAC volume", SUNXI_AIF2_VOL_CTRL2, AIF2_DACL_VOL,
		       AIF2_DACR_VOL, 0xff, 0, aif2_da_vol_tlv),
	SOC_DOUBLE_TLV("AIF2 ADC mixer gain", SUNXI_AIF2_MXR_GAIN,
		       AIF2_ADCL_MXR_GAIN, AIF2_ADCR_MXR_GAIN, 0xf, 0,
		       aif2_ad_mix_vol_tlv),
#endif
	/*ADC*/
	SOC_DOUBLE_TLV("ADC volume", SUNXI_ADC_VOL_CTRL, ADC_VOL_L, ADC_VOL_R,
		       0xff, 0, adc_vol_tlv),
	/*DAC*/
	SOC_DOUBLE_TLV("DAC volume", SUNXI_DAC_VOL_CTRL, DAC_VOL_L, DAC_VOL_R,
		       0xff, 0, dac_vol_tlv),
	SOC_DOUBLE_TLV("DAC mixer gain", SUNXI_DAC_MXR_GAIN, DACL_MXR_GAIN,
		       DACR_MXR_GAIN, 0xf, 0, dac_mix_vol_tlv),

	SOC_SINGLE_TLV("digital volume", SUNXI_DAC_DBG_CTRL, DVC, 0x3f, 0,
		       dig_vol_tlv),

	/*analog control*/
	SOC_SINGLE_TLV("lineout volume", LINEOUT_CTRL1, LINEOUT_VOL, 0x1f, 0,
		       lineout_vol_tlv),
	SOC_SINGLE_TLV("MIC1_G boost stage output mixer control", MIC1_CTRL,
		       MIC1G, 0x7, 0, mic1_to_l_r_mix_vol_tlv),
	SOC_SINGLE_TLV("MIC1 boost AMP gain control", MIC1_CTRL, MIC1BOOST,
		       0x7, 0, mic1_boost_vol_tlv),

	SOC_SINGLE_TLV("MIC2 BST stage to L_R outp mixer gain", MIC2_CTRL,
		       MIC2G, 0x7, 0, mic2_to_l_r_mix_vol_tlv),
	SOC_SINGLE_TLV("MIC2 boost AMP gain control", MIC2_CTRL, MIC2BOOST,
		       0x7, 0, mic2_boost_vol_tlv),

	SOC_SINGLE_TLV("LINEINL/R to L_R output mixer gain", LINEIN_CTRL,
		       LINEING, 0x7, 0, linein_to_l_r_mix_vol_tlv),
	/*ADC*/
	SOC_SINGLE_TLV("ADC input gain control", ADC_CTRL, ADCG, 0x7, 0,
		       adc_input_vol_tlv),
#ifdef SUNXI_CODEC_AIF_LOOP_DEBUG
	SOC_SINGLE("AIF1 Loopback Debug", SUNXI_AIF1_DACDAT_CTRL, AIF1_LOOP_ENA, 1, 0),
	SOC_SINGLE("AIF2 Loopback Debug", SUNXI_AIF2_DACDAT_CTRL, AIF2_LOOP_ENA, 1, 0),
	SOC_SINGLE("AIF3 Loopback Debug", SUNXI_AIF3_DACDAT_CTRL, AIF3_LOOP_ENA, 1, 0),
#endif
	/* pa shutdown */
	SOC_SINGLE_BOOL_EXT("Speaker PA shutdown pin high level", 0,
			sunxi_pashdn_get_data, sunxi_pashdn_put_data),

#ifdef CODEC_AIF2_AIF3_ENABLE
	/* 0x20c */
	SOC_ENUM("AIF3 CLOCK Src", aif3out_clk_enum),
#endif
};

/*0x244:AIF1 AD0 OUT */
static const char * const aif1out0l_text[] = {
	"AIF1_AD0L", "AIF1_AD0R",
	"SUM_AIF1AD0L_AIF1AD0R", "AVE_AIF1AD0L_AIF1AD0R"};
static const char * const aif1out0r_text[] = {
	"AIF1_AD0R", "AIF1_AD0L",
	"SUM_AIF1AD0L_AIF1AD0R", "AVE_AIF1AD0L_AIF1AD0R"};

static const struct soc_enum aif1out0l_enum =
	SOC_ENUM_SINGLE(SUNXI_AIF1_ADCDAT_CTRL, 10, 4, aif1out0l_text);

static const struct snd_kcontrol_new aif1out0l_mux =
	SOC_DAPM_ENUM("AIF1OUT0L Mux", aif1out0l_enum);

static const struct soc_enum aif1out0r_enum =
	SOC_ENUM_SINGLE(SUNXI_AIF1_ADCDAT_CTRL, 8, 4, aif1out0r_text);

static const struct snd_kcontrol_new aif1out0r_mux =
	SOC_DAPM_ENUM("AIF1OUT0R Mux", aif1out0r_enum);

/*0x244:AIF1 AD1 OUT */
static const char * const aif1out1l_text[] = {"AIF1_AD1L", "AIF1_AD1R",
				       "SUM_AIF1ADC1L_AIF1ADC1R",
				       "AVE_AIF1ADC1L_AIF1ADC1R"};
static const char *const aif1out1r_text[] = {"AIF1_AD1R", "AIF1_AD1L",
				       "SUM_AIF1ADC1L_AIF1ADC1R",
				       "AVE_AIF1ADC1L_AIF1ADC1R"};

static const struct soc_enum aif1out1l_enum =
	SOC_ENUM_SINGLE(SUNXI_AIF1_ADCDAT_CTRL, 6, 4, aif1out1l_text);

static const struct snd_kcontrol_new aif1out1l_mux =
	SOC_DAPM_ENUM("AIF1OUT1L Mux", aif1out1l_enum);

static const struct soc_enum aif1out1r_enum =
	SOC_ENUM_SINGLE(SUNXI_AIF1_ADCDAT_CTRL, 4, 4, aif1out1r_text);

static const struct snd_kcontrol_new aif1out1r_mux =
	SOC_DAPM_ENUM("AIF1OUT1R Mux", aif1out1r_enum);

/*0x248:AIF1 DA0 IN*/
static const char * const aif1in0l_text[] = {
	"AIF1_DA0L", "AIF1_DA0R",
	"SUM_AIF1DA0L_AIF1DA0R", "AVE_AIF1DA0L_AIF1DA0R"};
static const char * const aif1in0r_text[] = {
	"AIF1_DA0R", "AIF1_DA0L",
	"SUM_AIF1DA0L_AIF1DA0R", "AVE_AIF1DA0L_AIF1DA0R"};

static const struct soc_enum aif1in0l_enum =
	SOC_ENUM_SINGLE(SUNXI_AIF1_DACDAT_CTRL, 10, 4, aif1in0l_text);

static const struct snd_kcontrol_new aif1in0l_mux =
	SOC_DAPM_ENUM("AIF1IN0L Mux", aif1in0l_enum);

static const struct soc_enum aif1in0r_enum =
	SOC_ENUM_SINGLE(SUNXI_AIF1_DACDAT_CTRL, 8, 4, aif1in0r_text);

static const struct snd_kcontrol_new aif1in0r_mux =
	SOC_DAPM_ENUM("AIF1IN0R Mux", aif1in0r_enum);

/*0x248:AIF1 DA1 IN*/
static const char * const aif1in1l_text[] = {
	"AIF1_DA1L", "AIF1_DA1R",
	"SUM_AIF1DA1L_AIF1DA1R", "AVE_AIF1DA1L_AIF1DA1R"};
static const char * const aif1in1r_text[] = {
	"AIF1_DA1R", "AIF1_DA1L",
	"SUM_AIF1DA1L_AIF1DA1R", "AVE_AIF1DA1L_AIF1DA1R"};

static const struct soc_enum aif1in1l_enum =
	SOC_ENUM_SINGLE(SUNXI_AIF1_DACDAT_CTRL, 6, 4, aif1in1l_text);

static const struct snd_kcontrol_new aif1in1l_mux =
	SOC_DAPM_ENUM("AIF1IN1L Mux", aif1in1l_enum);

static const struct soc_enum aif1in1r_enum =
	SOC_ENUM_SINGLE(SUNXI_AIF1_DACDAT_CTRL, 4, 4, aif1in1r_text);

static const struct snd_kcontrol_new aif1in1r_mux =
	SOC_DAPM_ENUM("AIF1IN1R Mux", aif1in1r_enum);

/*0x24c:AIF1 ADC0 MIXER SOURCE*/
static const struct snd_kcontrol_new aif1_ad0l_mxr_src_ctl[] = {
	SOC_DAPM_SINGLE("AIF1 DA0L Switch", SUNXI_AIF1_MXR_SRC,
		    AIF1_AD0L_MXL_SRC_AIF1DA0L, 1, 0),
	SOC_DAPM_SINGLE("AIF2 DACL Switch", SUNXI_AIF1_MXR_SRC,
		    AIF1_AD0L_MXL_SRC_AIF2DACL, 1, 0),
	SOC_DAPM_SINGLE("ADCL Switch", SUNXI_AIF1_MXR_SRC,
		AIF1_AD0L_MXL_SRC_ADCL, 1, 0),
	SOC_DAPM_SINGLE("AIF2 DACR Switch", SUNXI_AIF1_MXR_SRC,
		    AIF1_AD0L_MXL_SRC_AIF2DACR, 1, 0),
};

static const struct snd_kcontrol_new aif1_ad0r_mxr_src_ctl[] = {
	SOC_DAPM_SINGLE("AIF1 DA0R Switch", SUNXI_AIF1_MXR_SRC,
			AIF1_AD0R_MXR_SRC_AIF1DA0R, 1, 0),
	SOC_DAPM_SINGLE("AIF2 DACR Switch", SUNXI_AIF1_MXR_SRC,
			AIF1_AD0R_MXR_SRC_AIF2DACR, 1, 0),
	SOC_DAPM_SINGLE("ADCR Switch", SUNXI_AIF1_MXR_SRC,
			AIF1_AD0R_MXR_SRC_ADCR, 1, 0),
	SOC_DAPM_SINGLE("AIF2 DACL Switch", SUNXI_AIF1_MXR_SRC,
			AIF1_AD0R_MXR_SRC_AIF2DACL, 1, 0),
};

/*0x24c:AIF1 ADC1 MIXER SOURCE*/
static const struct snd_kcontrol_new aif1_ad1l_mxr_src_ctl[] = {
	SOC_DAPM_SINGLE("AIF2 DACL Switch", SUNXI_AIF1_MXR_SRC,
			AIF1_AD1L_MXR_AIF2_DACL, 1, 0),
	SOC_DAPM_SINGLE("ADCL Switch", SUNXI_AIF1_MXR_SRC, AIF1_AD1L_MXR_ADCL, 1
			, 0),
};

static const struct snd_kcontrol_new aif1_ad1r_mxr_src_ctl[] = {
	SOC_DAPM_SINGLE("AIF2 DACR Switch", SUNXI_AIF1_MXR_SRC,
		    AIF1_AD1R_MXR_AIF2_DACR, 1, 0),
	SOC_DAPM_SINGLE("ADCR Switch", SUNXI_AIF1_MXR_SRC, AIF1_AD1R_MXR_ADCR,
			1, 0),
};

/*0x330 dac digital mixer source select*/
static const struct snd_kcontrol_new dacl_mxr_src_controls[] = {
	SOC_DAPM_SINGLE("ADCL Switch", SUNXI_DAC_MXR_SRC, DACL_MXR_SRC_ADCL,
			1, 0),
	SOC_DAPM_SINGLE("AIF2DACL Switch", SUNXI_DAC_MXR_SRC,
		DACL_MXR_SRC_AIF2DACL, 1, 0),
	SOC_DAPM_SINGLE("AIF1DA1L Switch", SUNXI_DAC_MXR_SRC,
		DACL_MXR_SRC_AIF1DA1L, 1, 0),
	SOC_DAPM_SINGLE("AIF1DA0L Switch", SUNXI_DAC_MXR_SRC,
		DACL_MXR_SRC_AIF1DA0L, 1, 0),
};

static const struct snd_kcontrol_new dacr_mxr_src_controls[] = {
	SOC_DAPM_SINGLE("ADCR Switch", SUNXI_DAC_MXR_SRC,
					DACR_MXR_SRC_ADCR, 1, 0),
	SOC_DAPM_SINGLE("AIF2DACR Switch",
			SUNXI_DAC_MXR_SRC, DACR_MXR_SRC_AIF2DACR, 1, 0),
	SOC_DAPM_SINGLE("AIF1DA1R Switch", SUNXI_DAC_MXR_SRC,
			DACR_MXR_SRC_AIF1DA1R, 1, 0),
	SOC_DAPM_SINGLE("AIF1DA0R Switch", SUNXI_DAC_MXR_SRC,
			DACR_MXR_SRC_AIF1DA0R, 1, 0),
};

/*output mixer source select*/
/*analog:0x01:defined left output mixer*/
static const struct snd_kcontrol_new ac_loutmix_controls[] = {
	SOC_DAPM_SINGLE("DACR Switch", OL_MIX_CTRL, LMIXMUTEDACR, 1, 0),
	SOC_DAPM_SINGLE("DACL Switch", OL_MIX_CTRL, LMIXMUTEDACL, 1, 0),
	SOC_DAPM_SINGLE("LINEINL Switch", OL_MIX_CTRL, LMIXMUTELINEINL, 1, 0),
	SOC_DAPM_SINGLE("MIC2Booststage Switch", OL_MIX_CTRL,
					LMIXMUTEMIC2BOOST, 1, 0),
	SOC_DAPM_SINGLE("MIC1Booststage Switch", OL_MIX_CTRL,
					LMIXMUTEMIC1BOOST, 1, 0),
};

/*analog:0x02:defined right output mixer*/
static const struct snd_kcontrol_new ac_routmix_controls[] = {
	SOC_DAPM_SINGLE("DACL Switch", OR_MIX_CTRL, RMIXMUTEDACL, 1, 0),
	SOC_DAPM_SINGLE("DACR Switch", OR_MIX_CTRL, RMIXMUTEDACR, 1, 0),
	SOC_DAPM_SINGLE("LINEINR Switch", OR_MIX_CTRL, RMIXMUTELINEINR, 1, 0),
	SOC_DAPM_SINGLE("MIC2Booststage Switch", OR_MIX_CTRL,
					RMIXMUTEMIC2BOOST, 1, 0),
	SOC_DAPM_SINGLE("MIC1Booststage Switch", OR_MIX_CTRL,
					RMIXMUTEMIC1BOOST, 1, 0),
};

/*lineout output source*/
static const char * const left_lineout_text[] = {
	"LOMIX", "OMIX_LR_SUM",
};
static const struct soc_enum left_lineout_enum =
	SOC_ENUM_SINGLE(LINEOUT_CTRL0, LINEOUTL_SRC,
			ARRAY_SIZE(left_lineout_text), left_lineout_text);
static const struct snd_kcontrol_new left_lineout_mux =
	SOC_DAPM_ENUM("LINEOUTL Mux", left_lineout_enum);

static const char * const right_lineout_text[] = {
	"ROMIX", "OMIX_LR_SUM",
};
static const struct soc_enum right_lineout_enum =
	SOC_ENUM_SINGLE(LINEOUT_CTRL0, LINEOUTR_SRC,
			ARRAY_SIZE(right_lineout_text), right_lineout_text);
static const struct snd_kcontrol_new right_lineout_mux =
	SOC_DAPM_ENUM("LINEOUTR Mux", right_lineout_enum);

/*0x05:lineout source select*/
static const char * const ac_lineout_func_sel[] = {
	"Right Analog Mixer", "Left Analog Mixer"};
static const struct soc_enum ac_lineout_func_enum =
	SOC_ENUM_SINGLE(LINEOUT_CTRL0, LINEOUTR_SRC, 2, ac_lineout_func_sel);

static const struct snd_kcontrol_new ac_lineout_func_controls =
	SOC_DAPM_ENUM("LINEOUT Mux", ac_lineout_func_enum);

#ifdef CODEC_AIF2_AIF3_ENABLE
/*0x284:AIF2 out*/
static const char * const aif2outl_text[] = {
	"AIF2_ADCL", "AIF2_ADCR", "SUM_AIF2_ADCL_AIF2_ADCR",
	"AVE_AIF2_ADCL_AIF2_ADCR"
};
static const char * const aif2outr_text[] = {
	"AIF2_ADCR", "AIF2_ADCL", "SUM_AIF2_ADCL_AIF2_ADCR",
	"AVE_AIF2_ADCL_AIF2_ADCR"
};

static const struct soc_enum aif2outl_enum =
	SOC_ENUM_SINGLE(SUNXI_AIF2_ADCDAT_CTRL, 10, 4, aif2outl_text);

static const struct snd_kcontrol_new aif2outl_mux =
	SOC_DAPM_ENUM("AIF2OUTL Mux", aif2outl_enum);

static const struct soc_enum aif2outr_enum =
	SOC_ENUM_SINGLE(SUNXI_AIF2_ADCDAT_CTRL, 8, 4, aif2outr_text);

static const struct snd_kcontrol_new aif2outr_mux =
	SOC_DAPM_ENUM("AIF2OUTR Mux", aif2outr_enum);

/*0x288:AIF2 IN*/
static const char * const aif2inl_text[] = {
	"AIF2_DACL", "AIF2_DACR", "SUM_AIF2DACL_AIF2DACR",
	"AVE_AIF2DACL_AIF2DACR"
};
static const char * const aif2inr_text[] = {
	"AIF2_DACR", "AIF2_DACL", "SUM_AIF2DACL_AIF2DACR",
	"AVE_AIF2DACL_AIF2DACR"
};

static const struct soc_enum aif2inl_enum =
	SOC_ENUM_SINGLE(SUNXI_AIF2_DACDAT_CTRL, 10, 4, aif2inl_text);
static const struct snd_kcontrol_new aif2inl_mux =
	SOC_DAPM_ENUM("AIF2INL Mux", aif2inl_enum);

static const struct soc_enum aif2inr_enum =
	SOC_ENUM_SINGLE(SUNXI_AIF2_DACDAT_CTRL, 8, 4, aif2inr_text);
static const struct snd_kcontrol_new aif2inr_mux =
	SOC_DAPM_ENUM("AIF2INR Mux", aif2inr_enum);

/*0x28c:AIF2 source select*/
static const struct snd_kcontrol_new aif2_adcl_mxr_src_controls[] = {
	SOC_DAPM_SINGLE("AIF1 DA0L Switch", SUNXI_AIF2_MXR_SRC,
				AIF2_ADCL_MXR_SRC_AIF1DA0L, 1, 0),
	SOC_DAPM_SINGLE("AIF1 DA1L Switch", SUNXI_AIF2_MXR_SRC,
				AIF2_ADCL_MXR_SRC_AIF1DA1L, 1, 0),
	SOC_DAPM_SINGLE("AIF2 DACR Switch", SUNXI_AIF2_MXR_SRC,
				AIF2_ADCL_MXR_SRC_AIF2DACR, 1, 0),
	SOC_DAPM_SINGLE("ADCL Switch", SUNXI_AIF2_MXR_SRC,
					AIF2_ADCL_MXR_SRC_ADCL, 1, 0),
};

static const struct snd_kcontrol_new aif2_adcr_mxr_src_controls[] = {
	SOC_DAPM_SINGLE("AIF1 DA0R Switch", SUNXI_AIF2_MXR_SRC,
				AIF2_ADCR_MXR_SRC_AIF1DA0R, 1, 0),
	SOC_DAPM_SINGLE("AIF1 DA1R Switch", SUNXI_AIF2_MXR_SRC,
				AIF2_ADCR_MXR_SRC_AIF1DA1R, 1, 0),
	SOC_DAPM_SINGLE("AIF2 DACL Switch", SUNXI_AIF2_MXR_SRC,
				AIF2_ADCR_MXR_SRC_AIF2DACL, 1, 0),
	SOC_DAPM_SINGLE("ADCR Switch", SUNXI_AIF2_MXR_SRC,
				AIF2_ADCR_MXR_SRC_ADCR, 1, 0),
};

/*0x2cc:aif3 out, AIF3 PCM output source select*/
static const char * const aif3out_text[] = {
	"NULL", "AIF2_ADC_Left_Channel", "AIF2_ADC_Right_Channel"
};

static const unsigned int aif3out_values[] = {0, 1, 2};

static const struct soc_enum aif3out_enum =
		SOC_VALUE_ENUM_SINGLE(SUNXI_AIF3_SGP_CTRL, AIF3_ADC_SRC, 3,
		ARRAY_SIZE(aif3out_text), aif3out_text, aif3out_values);

static const struct snd_kcontrol_new aif3out_mux =
	SOC_DAPM_ENUM("AIF3OUT Mux", aif3out_enum);
#endif

/*ADC SOURCE SELECT*/
/*0x0b:defined left input adc mixer*/
static const struct snd_kcontrol_new ac_ladcmix_controls[] = {
	SOC_DAPM_SINGLE("MIC1 boost Switch", L_ADCMIX_SRC,
				LADCMIXMUTEMIC1BOOST, 1, 0),
	SOC_DAPM_SINGLE("MIC2 boost Switch", L_ADCMIX_SRC,
				LADCMIXMUTEMIC2BOOST, 1, 0),
	SOC_DAPM_SINGLE("LINEINL Switch", L_ADCMIX_SRC,
					LADCMIXMUTELINEINL, 1, 0),
	SOC_DAPM_SINGLE("l_output mixer Switch", L_ADCMIX_SRC,
					LADCMIXMUTELOUTPUT, 1, 0),
	SOC_DAPM_SINGLE("r_output mixer Switch", L_ADCMIX_SRC,
					LADCMIXMUTEROUTPUT, 1, 0),
};

/*0x0c:defined right input adc mixer*/
static const struct snd_kcontrol_new ac_radcmix_controls[] = {
	SOC_DAPM_SINGLE("MIC1 boost Switch", R_ADCMIX_SRC,
				RADCMIXMUTEMIC1BOOST, 1, 0),
	SOC_DAPM_SINGLE("MIC2 boost Switch", R_ADCMIX_SRC,
				RADCMIXMUTEMIC2BOOST, 1, 0),
	SOC_DAPM_SINGLE("LINEINR Switch", R_ADCMIX_SRC,
				RADCMIXMUTELINEINR, 1, 0),
	SOC_DAPM_SINGLE("r_output mixer Switch", R_ADCMIX_SRC,
				RADCMIXMUTEROUTPUT, 1, 0),
	SOC_DAPM_SINGLE("l_output mixer Switch", R_ADCMIX_SRC,
				RADCMIXMUTELOUTPUT, 1, 0),
};

static const struct snd_kcontrol_new aif2inl_aif2switch =
	SOC_DAPM_SINGLE("aif2inl aif2", SUNXI_AIF1_RXD_CTRL, 8, 1, 0);
static const struct snd_kcontrol_new aif2inr_aif2switch =
	SOC_DAPM_SINGLE("aif2inr aif2", SUNXI_AIF1_RXD_CTRL, 9, 1, 0);

static const struct snd_kcontrol_new aif2inl_aif3switch =
	SOC_DAPM_SINGLE("aif2inl aif3", SUNXI_AIF1_RXD_CTRL, 10, 1, 0);
static const struct snd_kcontrol_new aif2inr_aif3switch =
	SOC_DAPM_SINGLE("aif2inr aif3", SUNXI_AIF1_RXD_CTRL, 11, 1, 0);

/*built widget*/
static const struct snd_soc_dapm_widget ac_dapm_widgets[] = {

#ifdef CODEC_AIF2_AIF3_ENABLE
	SND_SOC_DAPM_SWITCH("AIF2INL Mux switch", SND_SOC_NOPM, 0, 1,
			    &aif2inl_aif2switch),
	SND_SOC_DAPM_SWITCH("AIF2INR Mux switch", SND_SOC_NOPM, 0, 1,
			    &aif2inr_aif2switch),

	SND_SOC_DAPM_SWITCH("AIF2INL Mux VIR switch", SND_SOC_NOPM, 0, 1,
			    &aif2inl_aif3switch),
	SND_SOC_DAPM_SWITCH("AIF2INR Mux VIR switch", SND_SOC_NOPM, 0, 1,
			    &aif2inr_aif3switch),
#endif

	/*0x244*/
	SND_SOC_DAPM_MUX("AIF1OUT0L Mux", SUNXI_AIF1_ADCDAT_CTRL,
						15, 0, &aif1out0l_mux),
	SND_SOC_DAPM_MUX("AIF1OUT0R Mux", SUNXI_AIF1_ADCDAT_CTRL,
						14, 0, &aif1out0r_mux),
	SND_SOC_DAPM_MUX("AIF1OUT1L Mux", SUNXI_AIF1_ADCDAT_CTRL,
						13, 0, &aif1out1l_mux),
	SND_SOC_DAPM_MUX("AIF1OUT1R Mux", SUNXI_AIF1_ADCDAT_CTRL,
						12, 0, &aif1out1r_mux),
	/* 0x248 */
	SND_SOC_DAPM_MUX("AIF1IN0L Mux", SUNXI_AIF1_DACDAT_CTRL,
						15, 0, &aif1in0l_mux),
	SND_SOC_DAPM_MUX("AIF1IN0R Mux", SUNXI_AIF1_DACDAT_CTRL,
						14, 0, &aif1in0r_mux),
	SND_SOC_DAPM_MUX("AIF1IN1L Mux", SUNXI_AIF1_DACDAT_CTRL,
						13, 0, &aif1in1l_mux),
	SND_SOC_DAPM_MUX("AIF1IN1R Mux", SUNXI_AIF1_DACDAT_CTRL,
						12, 0, &aif1in1r_mux),
	/*0x24c*/
#ifdef AIF1_FPGA_LOOPBACK_TEST
	SND_SOC_DAPM_MIXER_E("AIF1 AD0L Mixer", SND_SOC_NOPM, 0, 0,
		aif1_ad0l_mxr_src_ctl, ARRAY_SIZE(aif1_ad0l_mxr_src_ctl),
		late_enable_adc, SND_SOC_DAPM_PRE_PMU|SND_SOC_DAPM_POST_PMD),
	SND_SOC_DAPM_MIXER_E("AIF1 AD0R Mixer", SND_SOC_NOPM, 0, 0,
		aif1_ad0r_mxr_src_ctl, ARRAY_SIZE(aif1_ad0r_mxr_src_ctl),
		late_enable_adc, SND_SOC_DAPM_PRE_PMU|SND_SOC_DAPM_POST_PMD),
#else
	SND_SOC_DAPM_MIXER("AIF1 AD0L Mixer", SND_SOC_NOPM, 0, 0,
		aif1_ad0l_mxr_src_ctl, ARRAY_SIZE(aif1_ad0l_mxr_src_ctl)),
	SND_SOC_DAPM_MIXER("AIF1 AD0R Mixer", SND_SOC_NOPM, 0, 0,
		aif1_ad0r_mxr_src_ctl, ARRAY_SIZE(aif1_ad0r_mxr_src_ctl)),
#endif
	SND_SOC_DAPM_MIXER("AIF1 AD1L Mixer", SND_SOC_NOPM, 0, 0,
		aif1_ad1l_mxr_src_ctl, ARRAY_SIZE(aif1_ad1l_mxr_src_ctl)),
	SND_SOC_DAPM_MIXER("AIF1 AD1R Mixer", SND_SOC_NOPM, 0, 0,
		aif1_ad1r_mxr_src_ctl, ARRAY_SIZE(aif1_ad1r_mxr_src_ctl)),
	/*analog:0x0a*/
	SND_SOC_DAPM_MIXER_E("DACL Mixer", SND_SOC_NOPM, 0, 0,
		dacl_mxr_src_controls, ARRAY_SIZE(dacl_mxr_src_controls),
		late_enable_dac, SND_SOC_DAPM_PRE_PMU|SND_SOC_DAPM_POST_PMD),
	SND_SOC_DAPM_MIXER_E("DACR Mixer", SND_SOC_NOPM, 0, 0,
		dacr_mxr_src_controls, ARRAY_SIZE(dacr_mxr_src_controls),
		late_enable_dac, SND_SOC_DAPM_PRE_PMU|SND_SOC_DAPM_POST_PMD),

	/*0x0a*/
	SND_SOC_DAPM_MIXER("Left Output Mixer", MIX_DAC_CTRL, LMIXEN, 0,
			ac_loutmix_controls, ARRAY_SIZE(ac_loutmix_controls)),
	SND_SOC_DAPM_MIXER("Right Output Mixer", MIX_DAC_CTRL, RMIXEN, 0,
			ac_routmix_controls, ARRAY_SIZE(ac_routmix_controls)),
	SND_SOC_DAPM_MUX("LINEOUTL Mux", LINEOUT_CTRL0, LINEOUTL_EN,
					0, &left_lineout_mux),
	SND_SOC_DAPM_MUX("LINEOUTR Mux", LINEOUT_CTRL0, LINEOUTR_EN,
					0, &right_lineout_mux),

	SND_SOC_DAPM_OUTPUT("LINEOUTL"),
	SND_SOC_DAPM_OUTPUT("LINEOUTR"),

#ifdef CODEC_AIF2_AIF3_ENABLE
	/*0x284*/
	SND_SOC_DAPM_MUX("AIF2OUTL Mux", SUNXI_AIF2_ADCDAT_CTRL, AIF2_ADCL_EN,
					0, &aif2outl_mux),
	SND_SOC_DAPM_MUX("AIF2OUTR Mux", SUNXI_AIF2_ADCDAT_CTRL, AIF2_ADCR_EN,
					0, &aif2outr_mux),
	/*0x288*/
	SND_SOC_DAPM_MUX("AIF2INL Mux", SUNXI_AIF2_DACDAT_CTRL, AIF2_DACL_ENA,
					0, &aif2inl_mux),
	SND_SOC_DAPM_MUX("AIF2INR Mux", SUNXI_AIF2_DACDAT_CTRL, AIF2_DACR_ENA,
					0, &aif2inr_mux),

	SND_SOC_DAPM_PGA("AIF2INL_VIR", SUNXI_AIF2_ADCDAT_CTRL,
				AIF2_ADCL_EN, 0, NULL, 0),
	SND_SOC_DAPM_PGA("AIF2INR_VIR", SUNXI_AIF2_ADCDAT_CTRL,
				AIF2_ADCR_EN, 0, NULL, 0),
	/*0x28c*/
	SND_SOC_DAPM_MIXER("AIF2 ADL Mixer", SND_SOC_NOPM, 0, 0,
	aif2_adcl_mxr_src_controls, ARRAY_SIZE(aif2_adcl_mxr_src_controls)),
	SND_SOC_DAPM_MIXER("AIF2 ADR Mixer", SND_SOC_NOPM, 0, 0,
	aif2_adcr_mxr_src_controls, ARRAY_SIZE(aif2_adcr_mxr_src_controls)),
	/*0x2cc*/
	SND_SOC_DAPM_MUX("AIF3OUT Mux", SND_SOC_NOPM, 0, 0, &aif3out_mux),

	/*0x2cc virtual widget*/
	SND_SOC_DAPM_PGA_E("AIF2INL Mux VIR", SUNXI_AIF2_DACDAT_CTRL,
		AIF2_DACL_ENA, 0, NULL, 0,
		aif2inl_vir_event, SND_SOC_DAPM_PRE_PMU|SND_SOC_DAPM_POST_PMD),
	SND_SOC_DAPM_PGA_E("AIF2INR Mux VIR", SUNXI_AIF2_DACDAT_CTRL,
		AIF2_DACR_ENA, 0, NULL, 0,
		aif2inr_vir_event, SND_SOC_DAPM_PRE_PMU|SND_SOC_DAPM_POST_PMD),
#endif

#ifdef AIF1_FPGA_LOOPBACK_TEST
	/*0x0d 0x0b 0x0c ADC_CTRL*/
	SND_SOC_DAPM_MIXER("LADC input Mixer", ADC_CTRL, ADCLEN, 0,
			ac_ladcmix_controls, ARRAY_SIZE(ac_ladcmix_controls)),
	SND_SOC_DAPM_MIXER("RADC input Mixer", ADC_CTRL, ADCREN, 0,
			ac_radcmix_controls, ARRAY_SIZE(ac_radcmix_controls)),
#else
	/*0x0d 0x0b 0x0c ADC_CTRL*/
	SND_SOC_DAPM_MIXER_E("LADC input Mixer", ADC_CTRL, ADCLEN, 0,
		ac_ladcmix_controls, ARRAY_SIZE(ac_ladcmix_controls),
		late_enable_adc, SND_SOC_DAPM_PRE_PMU|SND_SOC_DAPM_POST_PMD),
	SND_SOC_DAPM_MIXER_E("RADC input Mixer", ADC_CTRL, ADCREN, 0,
		ac_radcmix_controls, ARRAY_SIZE(ac_radcmix_controls),
		late_enable_adc, SND_SOC_DAPM_PRE_PMU|SND_SOC_DAPM_POST_PMD),
#endif
	/*0x07 mic1 reference*/
	SND_SOC_DAPM_PGA("MIC1 PGA", MIC1_CTRL, MIC1AMPEN, 0, NULL, 0),
	/*0x08 mic2 reference*/
	SND_SOC_DAPM_PGA("MIC2 PGA", MIC2_CTRL, MIC2AMPEN, 0, NULL, 0),

	/*INPUT widget*/
	SND_SOC_DAPM_INPUT("MIC1P"),
	SND_SOC_DAPM_INPUT("MIC1N"),
	/*0x0e Headset Microphone Bias Control Register*/
	SND_SOC_DAPM_MICBIAS("MainMic Bias", MBIAS_CTRL, MMICBIASEN, 0),
	SND_SOC_DAPM_INPUT("MIC2P"),
	SND_SOC_DAPM_INPUT("MIC2N"),

	SND_SOC_DAPM_INPUT("LINEINP"),
	SND_SOC_DAPM_INPUT("LINEINN"),

	/*aif1 interface*/
	SND_SOC_DAPM_AIF_IN_E("AIF1DACL", "AIF1 Playback", 0,
			SND_SOC_NOPM, 0, 0, ac_aif1clk,
			SND_SOC_DAPM_PRE_PMU|SND_SOC_DAPM_POST_PMD),
	SND_SOC_DAPM_AIF_IN_E("AIF1DACR", "AIF1 Playback", 0,
			SND_SOC_NOPM, 0, 0, ac_aif1clk,
			SND_SOC_DAPM_PRE_PMU|SND_SOC_DAPM_POST_PMD),

	SND_SOC_DAPM_AIF_OUT_E("AIF1ADCL", "AIF1 Capture", 0, SND_SOC_NOPM, 0,
			0, ac_aif1clk,
			SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMD),
	SND_SOC_DAPM_AIF_OUT_E("AIF1ADCR", "AIF1 Capture", 0, SND_SOC_NOPM,
			0, 0, ac_aif1clk,
			SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMD),

#ifdef CODEC_AIF2_AIF3_ENABLE
	/*aif2 interface*/
	SND_SOC_DAPM_AIF_IN_E("AIF2DACL", "AIF2 Playback", 0, SND_SOC_NOPM,
			0, 0, ac_aif2clk,
			SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMD),

	SND_SOC_DAPM_AIF_IN_E("AIF2DACR", "AIF2 Playback", 0, SND_SOC_NOPM,
			0, 0, ac_aif2clk,
			SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMD),

	SND_SOC_DAPM_AIF_OUT_E("AIF2ADCL", "AIF2 Capture", 0, SND_SOC_NOPM,
			0, 0, ac_aif2clk,
			SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMD),
	SND_SOC_DAPM_AIF_OUT_E("AIF2ADCR", "AIF2 Capture", 0, SND_SOC_NOPM,
			0, 0, ac_aif2clk,
			SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMD),

	/*aif3 interface*/
	SND_SOC_DAPM_AIF_OUT_E("AIF3OUT", "AIF3 Capture", 0, SND_SOC_NOPM, 0,
			0, ac_aif3clk,
			SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMD),
	SND_SOC_DAPM_AIF_IN_E("AIF3IN", "AIF3 Playback", 0, SND_SOC_NOPM,
			0, 0, ac_aif3clk,
			SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMD),
#endif
	/* LINEOUT */
	SND_SOC_DAPM_LINE("Lineout", ac_lineout_event),
};

static const struct snd_soc_dapm_route ac_dapm_routes[] = {
	{"AIF1ADCL", NULL, "AIF1OUT0L Mux"},
	{"AIF1ADCR", NULL, "AIF1OUT0R Mux"},

	{"AIF1ADCL", NULL, "AIF1OUT1L Mux"},
	{"AIF1ADCR", NULL, "AIF1OUT1R Mux"},

	/* aif1out0 mux 11---13*/
	{"AIF1OUT0L Mux", "AIF1_AD0L", "AIF1 AD0L Mixer"},
	{"AIF1OUT0L Mux", "AIF1_AD0R", "AIF1 AD0R Mixer"},

	{"AIF1OUT0R Mux", "AIF1_AD0R", "AIF1 AD0R Mixer"},
	{"AIF1OUT0R Mux", "AIF1_AD0L", "AIF1 AD0L Mixer"},

	/*AIF1OUT1 mux 11--13 */
	{"AIF1OUT1L Mux", "AIF1_AD1L", "AIF1 AD1L Mixer"},
	{"AIF1OUT1L Mux", "AIF1_AD1R", "AIF1 AD1R Mixer"},

	{"AIF1OUT1R Mux", "AIF1_AD1R", "AIF1 AD1R Mixer"},
	{"AIF1OUT1R Mux", "AIF1_AD1L", "AIF1 AD1L Mixer"},

	/*AIF1 AD0L Mixer*/
	{"AIF1 AD0L Mixer", "AIF1 DA0L Switch", "AIF1IN0L Mux"},
	{"AIF1 AD0L Mixer", "AIF2 DACL Switch", "AIF2INL_VIR"},
	#ifdef AIF1_FPGA_LOOPBACK_TEST
	{"AIF1 AD0L Mixer", "ADCL Switch", "MIC1P"},
	#else
	{"AIF1 AD0L Mixer", "ADCL Switch", "LADC input Mixer"},
	#endif
	{"AIF1 AD0L Mixer", "AIF2 DACR Switch", "AIF2INR_VIR"},

	/*AIF1 AD0R Mixer*/
	{"AIF1 AD0R Mixer", "AIF1 DA0R Switch", "AIF1IN0R Mux"},
	{"AIF1 AD0R Mixer", "AIF2 DACR Switch", "AIF2INR_VIR"},

	#ifdef AIF1_FPGA_LOOPBACK_TEST
	{"AIF1 AD0R Mixer", "ADCR Switch", "MIC1N"},
	#else
	{"AIF1 AD0R Mixer", "ADCR Switch", "RADC input Mixer"},
	#endif
	{"AIF1 AD0R Mixer", "AIF2 DACL Switch", "AIF2INL_VIR"},

	/*AIF1 AD1L Mixer*/
	{"AIF1 AD1L Mixer", "AIF2 DACL Switch", "AIF2INL_VIR"},
	{"AIF1 AD1L Mixer", "ADCL Switch", "LADC input Mixer"},

	/*AIF1 AD1R Mixer*/
	{"AIF1 AD1R Mixer", "AIF2 DACR Switch", "AIF2INR_VIR"},
	{"AIF1 AD1R Mixer", "ADCR Switch", "RADC input Mixer"},

	/*AIF1 DA0 IN 12h*/
	{"AIF1IN0L Mux", "AIF1_DA0L", "AIF1DACL"},
	{"AIF1IN0L Mux", "AIF1_DA0R", "AIF1DACR"},

	{"AIF1IN0R Mux", "AIF1_DA0R", "AIF1DACR"},
	{"AIF1IN0R Mux", "AIF1_DA0L", "AIF1DACL"},

	/*AIF1 DA1 IN 12h*/
	{"AIF1IN1L Mux", "AIF1_DA1L", "AIF1DACL"},
	{"AIF1IN1L Mux", "AIF1_DA1R", "AIF1DACR"},

	{"AIF1IN1R Mux", "AIF1_DA1R", "AIF1DACR"},
	{"AIF1IN1R Mux", "AIF1_DA1L", "AIF1DACL"},

#ifdef CODEC_AIF2_AIF3_ENABLE
	/*aif2 virtual*/
	{"AIF2INL Mux switch", "aif2inl aif2", "AIF2INL Mux"},
	{"AIF2INR Mux switch", "aif2inr aif2", "AIF2INR Mux"},

	{"AIF2INL_VIR", NULL, "AIF2INL Mux switch"},
	{"AIF2INR_VIR", NULL, "AIF2INR Mux switch"},

	{"AIF2INL_VIR", NULL, "AIF2INL Mux VIR"},
	{"AIF2INR_VIR", NULL, "AIF2INR Mux VIR"},
#endif

	/*4c*/
	{"DACL Mixer", "AIF1DA0L Switch", "AIF1IN0L Mux"},
	{"DACL Mixer", "AIF1DA1L Switch", "AIF1IN1L Mux"},

	{"DACL Mixer", "ADCL Switch", "LADC input Mixer"},
	{"DACL Mixer", "AIF2DACL Switch", "AIF2INL_VIR"},

	{"DACR Mixer", "AIF1DA0R Switch", "AIF1IN0R Mux"},
	{"DACR Mixer", "AIF1DA1R Switch", "AIF1IN1R Mux"},

	{"DACR Mixer", "ADCR Switch", "RADC input Mixer"},
	{"DACR Mixer", "AIF2DACR Switch", "AIF2INR_VIR"},

	{"Right Output Mixer", "DACR Switch", "DACR Mixer"},
	{"Right Output Mixer", "DACL Switch", "DACL Mixer"},

	{"Right Output Mixer", "LINEINR Switch", "LINEINN"},
	{"Right Output Mixer", "MIC2Booststage Switch", "MIC2 PGA"},
	{"Right Output Mixer", "MIC1Booststage Switch", "MIC1 PGA"},

	{"Left Output Mixer", "DACL Switch", "DACL Mixer"},
	{"Left Output Mixer", "DACR Switch", "DACR Mixer"},

	{"Left Output Mixer", "LINEINL Switch", "LINEINP"},
	{"Left Output Mixer", "MIC2Booststage Switch", "MIC2 PGA"},
	{"Left Output Mixer", "MIC1Booststage Switch", "MIC1 PGA"},

	/*lineout mux*/
	{"LINEOUTL Mux", "LOMIX", "Left Output Mixer"},
	{"LINEOUTL Mux", "OMIX_LR_SUM", "Left Output Mixer"},
	{"LINEOUTL Mux", "OMIX_LR_SUM", "Right Output Mixer"},
	{"LINEOUTR Mux", "ROMIX", "Right Output Mixer"},
	{"LINEOUTR Mux", "OMIX_LR_SUM", "Left Output Mixer"},
	{"LINEOUTR Mux", "OMIX_LR_SUM", "Right Output Mixer"},
	{"LINEOUTL", NULL, "LINEOUTL Mux"},
	{"LINEOUTR", NULL, "LINEOUTR Mux"},
	{"Lineout", NULL, "LINEOUTL"},
	{"Lineout", NULL, "LINEOUTR"},

	/*LADC SOURCE mixer*/
	{"LADC input Mixer", "MIC1 boost Switch", "MIC1 PGA"},
	{"LADC input Mixer", "MIC2 boost Switch", "MIC2 PGA"},
	{"LADC input Mixer", "LINEINL Switch", "LINEINN"},
	{"LADC input Mixer", "l_output mixer Switch", "Left Output Mixer"},
	{"LADC input Mixer", "r_output mixer Switch", "Right Output Mixer"},

	/*RADC SOURCE mixer*/
	{"RADC input Mixer", "MIC1 boost Switch", "MIC1 PGA"},
	{"RADC input Mixer", "MIC2 boost Switch", "MIC2 PGA"},
	{"RADC input Mixer", "LINEINR Switch", "LINEINP"},
	{"RADC input Mixer", "r_output mixer Switch", "Right Output Mixer"},
	{"RADC input Mixer", "l_output mixer Switch", "Left Output Mixer"},

	{"MIC1 PGA", NULL, "MIC1P"},
	{"MIC1 PGA", NULL, "MIC1N"},

	{"MIC2 PGA", NULL, "MIC2P"},
	{"MIC2 PGA", NULL, "MIC2N"},

#ifdef CODEC_AIF2_AIF3_ENABLE
	/*AIF2 out */
	{"AIF2ADCL", NULL, "AIF2OUTL Mux"},
	{"AIF2ADCR", NULL, "AIF2OUTR Mux"},

	{"AIF2OUTL Mux", "AIF2_ADCL", "AIF2 ADL Mixer"},
	{"AIF2OUTL Mux", "AIF2_ADCR", "AIF2 ADR Mixer"},

	{"AIF2OUTR Mux", "AIF2_ADCR", "AIF2 ADR Mixer"},
	{"AIF2OUTR Mux", "AIF2_ADCL", "AIF2 ADL Mixer"},

	/*23*/
	{"AIF2 ADL Mixer", "AIF1 DA0L Switch", "AIF1IN0L Mux"},
	{"AIF2 ADL Mixer", "AIF1 DA1L Switch", "AIF1IN1L Mux"},
	{"AIF2 ADL Mixer", "AIF2 DACR Switch", "AIF2INR_VIR"},
	{"AIF2 ADL Mixer", "ADCL Switch", "LADC input Mixer"},

	{"AIF2 ADR Mixer", "AIF1 DA0R Switch", "AIF1IN0R Mux"},
	{"AIF2 ADR Mixer", "AIF1 DA1R Switch", "AIF1IN1R Mux"},
	{"AIF2 ADR Mixer", "AIF2 DACL Switch", "AIF2INL_VIR"},
	{"AIF2 ADR Mixer", "ADCR Switch", "RADC input Mixer"},

	/*aif2*/
	{"AIF2INL Mux", "AIF2_DACL", "AIF2DACL"},
	{"AIF2INL Mux", "AIF2_DACR", "AIF2DACR"},

	{"AIF2INR Mux", "AIF2_DACR", "AIF2DACR"},
	{"AIF2INR Mux", "AIF2_DACL", "AIF2DACL"},

	/*aif3*/
	{"AIF2INL Mux VIR switch", "aif2inl aif3", "AIF3IN"},
	{"AIF2INR Mux VIR switch", "aif2inr aif3", "AIF3IN"},

	{"AIF2INL Mux VIR", NULL, "AIF2INL Mux VIR switch"},
	{"AIF2INR Mux VIR", NULL, "AIF2INR Mux VIR switch"},

	{"AIF3OUT", NULL, "AIF3OUT Mux"},
	{"AIF3OUT Mux", "AIF2_ADC_Left_Channel", "AIF2 ADL Mixer"},
	{"AIF3OUT Mux", "AIF2_ADC_Right_Channel", "AIF2 ADR Mixer"},
#endif
};

static int codec_start(struct snd_pcm_substream *substream,
				struct snd_soc_dai *codec_dai)
{
#ifdef CODEC_DAP_ENABLE
	struct snd_soc_codec *codec = codec_dai->codec;
	struct sunxi_codec *sunxi_internal_codec =
			snd_soc_codec_get_drvdata(codec);

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
#endif
	return 0;
}

static int codec_aif_mute(struct snd_soc_dai *codec_dai, int mute)
{
#if 0
	struct snd_soc_codec *codec = codec_dai->codec;
	struct sunxi_codec *sunxi_codec = snd_soc_codec_get_drvdata(codec);
	struct spk_config *spk_cfg = &(sunxi_codec->spk_config);

	if (mute) {
		if (spk_cfg->used) {
			gpio_set_value(spk_cfg->gpio, !(spk_cfg->pa_ctl_level));
		}
	} else {
		if (spk_cfg->used) {
			gpio_set_value(spk_cfg->gpio, spk_cfg->pa_ctl_level);
			snd_soc_read(codec, SUNXI_DA_CTL);
		}
	}
	if (spk_cfg->used)
		msleep(sunxi_codec->pa_msleep_time);
#endif
	return 0;
}

static void codec_aif_shutdown(struct snd_pcm_substream *substream,
	struct snd_soc_dai *codec_dai)
{
#ifdef CODEC_DAP_ENABLE
	struct snd_soc_codec *codec = codec_dai->codec;
	struct sunxi_codec *sunxi_internal_codec =
		snd_soc_codec_get_drvdata(codec);

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
#endif
}

static int codec_hw_params(struct snd_pcm_substream *substream,
	struct snd_pcm_hw_params *params,
	struct snd_soc_dai *codec_dai)
{
	int i = 0;
	int AIF_CLK_CTRL = 0;
	int aif1_word_size = 16;
	int aif1_lrlk_div = 64;
	int bclk_div_factor = 0;
	struct snd_soc_codec *codec = codec_dai->codec;
	struct sunxi_codec *sunxi_internal_codec =
			snd_soc_codec_get_drvdata(codec);

	switch (codec_dai->id) {
	case 1:
		AIF_CLK_CTRL = SUNXI_AIF1_CLK_CTRL;
		if (sunxi_internal_codec->aif1_lrlk_div == 0)
			aif1_lrlk_div = 64;
		else
			aif1_lrlk_div = sunxi_internal_codec->aif1_lrlk_div;
		break;
	case 2:
			AIF_CLK_CTRL = SUNXI_AIF2_CLK_CTRL;
		if (sunxi_internal_codec->aif2_lrlk_div == 0)
			aif1_lrlk_div = 64;
		else
			aif1_lrlk_div = sunxi_internal_codec->aif2_lrlk_div;
		break;
	default:
		return -EINVAL;
	}

	/* FIXME make up the codec_aif1_lrck factor
	 * adjust for more working scene
	 */
	switch (aif1_lrlk_div) {
	case	16:
		bclk_div_factor = 4;
		break;
	case	32:
		bclk_div_factor = 2;
		break;
	case	64:
		bclk_div_factor = 0;
		break;
	case	128:
		bclk_div_factor = -2;
		break;
	case	256:
		bclk_div_factor = -4;
		break;
	default:
		pr_err("invalid lrlk_div setting in sysconfig!\n");
		return -EINVAL;
	}

	for (i = 0; i < ARRAY_SIZE(codec_aif1_lrck); i++) {
		if (codec_aif1_lrck[i].aif1_lrlk_div == aif1_lrlk_div) {
			snd_soc_update_bits(codec, AIF_CLK_CTRL,
				(0x7<<AIF1_LRCK_DIV),
			((codec_aif1_lrck[i].aif1_lrlk_bit)<<AIF1_LRCK_DIV));
			break;
		}
	}

	for (i = 0; i < ARRAY_SIZE(codec_aif1_fs); i++) {
		if (codec_aif1_fs[i].samplerate ==  params_rate(params)) {
			snd_soc_update_bits(codec, SUNXI_SYS_SR_CTRL,
				(0xf<<AIF1_FS),
				((codec_aif1_fs[i].aif1_srbit)<<AIF1_FS));
			snd_soc_update_bits(codec, SUNXI_SYS_SR_CTRL,
				(0xf<<AIF2_FS),
				((codec_aif1_fs[i].aif1_srbit)<<AIF2_FS));
			bclk_div_factor += codec_aif1_fs[i].aif1_bclk_div;
			snd_soc_update_bits(codec, AIF_CLK_CTRL,
						(0xf<<AIF1_BCLK_DIV),
				((bclk_div_factor)<<AIF1_BCLK_DIV));
			break;
		}
	}
	switch (params_format(params)) {
	case SNDRV_PCM_FORMAT_S24_LE:
	case SNDRV_PCM_FORMAT_S32_LE:
		aif1_word_size = 24;
		break;
	case SNDRV_PCM_FORMAT_S16_LE:
		break;
	default:
			aif1_word_size = 16;
		break;
	}

	if (params_channels(params) == 1 &&
		(AIF_CLK_CTRL == SUNXI_AIF2_CLK_CTRL))
		snd_soc_update_bits(codec, AIF_CLK_CTRL,
				    (0x1<<DSP_MONO_PCM), (0x1<<DSP_MONO_PCM));
	else
		snd_soc_update_bits(codec, AIF_CLK_CTRL,
				    (0x1<<DSP_MONO_PCM), (0x0<<DSP_MONO_PCM));

	for (i = 0; i < ARRAY_SIZE(codec_aif1_wsize); i++) {
		if (codec_aif1_wsize[i].aif1_wsize_val == aif1_word_size) {
			snd_soc_update_bits(codec, AIF_CLK_CTRL,
				(0x3<<AIF1_WORD_SIZ),
			((codec_aif1_wsize[i].aif1_wsize_bit)<<AIF1_WORD_SIZ));
			break;
		}
	}

#ifdef CONFIG_SUNXI_MPP_AIO
	if (mpp_audio_debugfs) {
		if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
			mpp_aio_info_set(mpp_audio_debugfs->ao_devenable, 32, 1);
			mpp_aio_info_set(mpp_audio_debugfs->ao_cardtype, 64, 0);
			mpp_aio_info_set(mpp_audio_debugfs->ao_samplerate, 32, params_rate(params));
			mpp_aio_info_set(mpp_audio_debugfs->ao_bitwidth, 32, aif1_word_size);
		} else {
			mpp_aio_info_set(mpp_audio_debugfs->ai_devenable, 32, 1);
			mpp_aio_info_set(mpp_audio_debugfs->ai_samplerate, 32, params_rate(params));
			mpp_aio_info_set(mpp_audio_debugfs->ai_bitwidth, 32, aif1_word_size);
		}
	}
#endif
	return 0;
}

static int codec_set_dai_sysclk(struct snd_soc_dai *codec_dai,
				  int clk_id, unsigned int freq, int dir)
{
	struct snd_soc_codec *codec = codec_dai->codec;

	switch (clk_id) {
	case AIF1_CLK:
		/*system clk from aif1*/
		snd_soc_update_bits(codec, SUNXI_SYSCLK_CTL,
				    (0x1<<SYSCLK_SRC), (0x0<<SYSCLK_SRC));
		break;
	case AIF2_CLK:
		/*system clk from aif2*/
		snd_soc_update_bits(codec, SUNXI_SYSCLK_CTL,
				    (0x1<<SYSCLK_SRC), (0x1<<SYSCLK_SRC));
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int codec_set_dai_fmt(struct snd_soc_dai *codec_dai,
			       unsigned int fmt)
{
	int reg_val;
	int AIF_CLK_CTRL = 0;
	struct snd_soc_codec *codec = codec_dai->codec;

	switch (codec_dai->id) {
	case 1:
		AIF_CLK_CTRL = SUNXI_AIF1_CLK_CTRL;
		break;
	case 2:
		AIF_CLK_CTRL = SUNXI_AIF2_CLK_CTRL;
		break;
	default:
		return -EINVAL;
	}

	/*
	 * master or slave selection
	 * 0 = Master mode
	 * 1 = Slave mode
	 */
	reg_val = snd_soc_read(codec, AIF_CLK_CTRL);
	reg_val &= ~(0x1<<AIF1_MSTR_MOD);
	switch (fmt & SND_SOC_DAIFMT_MASTER_MASK) {
	case SND_SOC_DAIFMT_CBM_CFM:   /* codec clk & frm master, ap is slave*/
		reg_val |= (0x0<<AIF1_MSTR_MOD);
		break;
	case SND_SOC_DAIFMT_CBS_CFS:   /* codec clk & frm slave,ap is master*/
		reg_val |= (0x1<<AIF1_MSTR_MOD);
		break;
	default:
		pr_err("unknwon master/slave format\n");
		return -EINVAL;
	}
	snd_soc_write(codec, AIF_CLK_CTRL, reg_val);

	/* i2s mode selection */
	reg_val = snd_soc_read(codec, AIF_CLK_CTRL);
	reg_val &= ~(3<<AIF1_DATA_FMT);
	switch (fmt & SND_SOC_DAIFMT_FORMAT_MASK) {
	case SND_SOC_DAIFMT_I2S:        /* I2S1 mode */
		reg_val |= (0x0<<AIF1_DATA_FMT);
		break;
	case SND_SOC_DAIFMT_RIGHT_J:    /* Right Justified mode */
		reg_val |= (0x2<<AIF1_DATA_FMT);
		break;
	case SND_SOC_DAIFMT_LEFT_J:     /* Left Justified mode */
		reg_val |= (0x1<<AIF1_DATA_FMT);
		break;
	case SND_SOC_DAIFMT_DSP_A:      /* L reg_val msb after FRM LRC */
		reg_val |= (0x3<<AIF1_DATA_FMT);
		break;
	default:
		pr_err("%s, line:%d\n", __func__, __LINE__);
		return -EINVAL;
	}
	snd_soc_write(codec, AIF_CLK_CTRL, reg_val);

	/* DAI signal inversions */
	reg_val = snd_soc_read(codec, AIF_CLK_CTRL);
	switch (fmt & SND_SOC_DAIFMT_INV_MASK) {
	case SND_SOC_DAIFMT_NB_NF:     /* normal bit clock + nor frame */
		reg_val &= ~(0x1<<AIF1_LRCK_INV);
		reg_val &= ~(0x1<<AIF1_BCLK_INV);
		break;
	case SND_SOC_DAIFMT_NB_IF:     /* normal bclk + inv frm */
		reg_val |= (0x1<<AIF1_LRCK_INV);
		reg_val &= ~(0x1<<AIF1_BCLK_INV);
		break;
	case SND_SOC_DAIFMT_IB_NF:     /* invert bclk + nor frm */
		reg_val &= ~(0x1<<AIF1_LRCK_INV);
		reg_val |= (0x1<<AIF1_BCLK_INV);
		break;
	case SND_SOC_DAIFMT_IB_IF:     /* invert bclk + inv frm */
		reg_val |= (0x1<<AIF1_LRCK_INV);
		reg_val |= (0x1<<AIF1_BCLK_INV);
		break;
	}
	snd_soc_write(codec, AIF_CLK_CTRL, reg_val);

	return 0;
}

static int codec_set_fll(struct snd_soc_dai *codec_dai, int pll_id, int source,
				unsigned int freq_in, unsigned int freq_out)
{
	struct snd_soc_codec *codec = codec_dai->codec;

	if (!freq_out)
		return 0;
	if ((freq_in < 128000) || (freq_in > 24576000)) {
		return -EINVAL;
	} else if ((freq_in == 24576000) || (freq_in == 22579200)) {
		switch (pll_id) {
		case PLLCLK:
			/*select aif1/aif2 clk source from pll*/
			snd_soc_update_bits(codec, SUNXI_SYSCLK_CTL,
				(0x3<<AIF1CLK_SRC), (0x3<<AIF1CLK_SRC));
			snd_soc_update_bits(codec, SUNXI_SYSCLK_CTL,
				(0x3<<AIF2CLK_SRC), (0x3<<AIF2CLK_SRC));
			break;
		case MCLK:
			snd_soc_update_bits(codec, SUNXI_SYSCLK_CTL,
				(0x3<<AIF1CLK_SRC), (0x0<<AIF1CLK_SRC));
			snd_soc_update_bits(codec, SUNXI_SYSCLK_CTL,
				(0x3<<AIF2CLK_SRC), (0x0<<AIF2CLK_SRC));
		default:
			return -EINVAL;
		}
		return 0;
	}

	return 0;
}

#ifdef CODEC_AIF2_AIF3_ENABLE
static int codec_aif3_set_dai_fmt(struct snd_soc_dai *codec_dai,
			       unsigned int fmt)
{
	int reg_val;
	struct snd_soc_codec *codec = codec_dai->codec;

	/* DAI signal inversions */
	reg_val = snd_soc_read(codec, SUNXI_AIF3_CLK_CTRL);
	switch (fmt & SND_SOC_DAIFMT_INV_MASK) {
	case SND_SOC_DAIFMT_NB_NF:     /* normal bit clock + nor frame */
		reg_val &= ~(0x1<<AIF3_LRCK_INV);
		reg_val &= ~(0x1<<AIF3_BCLK_INV);
		break;
	case SND_SOC_DAIFMT_NB_IF:     /* normal bclk + inv frm */
		reg_val |= (0x1<<AIF3_LRCK_INV);
		reg_val &= ~(0x1<<AIF3_BCLK_INV);
		break;
	case SND_SOC_DAIFMT_IB_NF:     /* invert bclk + nor frm */
		reg_val &= ~(0x1<<AIF3_LRCK_INV);
		reg_val |= (0x1<<AIF3_BCLK_INV);
		break;
	case SND_SOC_DAIFMT_IB_IF:     /* invert bclk + inv frm */
		reg_val |= (0x1<<AIF3_LRCK_INV);
		reg_val |= (0x1<<AIF3_BCLK_INV);
		break;
	}
	snd_soc_write(codec, SUNXI_AIF3_CLK_CTRL, reg_val);

	return 0;
}

static int codec_aif3_hw_params(struct snd_pcm_substream *substream,
	struct snd_pcm_hw_params *params,
	struct snd_soc_dai *codec_dai)
{
	int aif3_word_size = 0;
	int aif3_size = 0;
	int i = 0;
	int aif2_lrlk_div = 64;
	int bclk_div_factor = 0;
	struct snd_soc_codec *codec = codec_dai->codec;
	struct sunxi_codec *sunxi_codec = snd_soc_codec_get_drvdata(codec);

	if (sunxi_codec->aif2_lrlk_div == 0)
		aif2_lrlk_div = 64;
	else
		aif2_lrlk_div = sunxi_codec->aif2_lrlk_div;

	/* FIXME make up the codec_aif2_lrck factor
	 * adjust for more working scene
	 */
	switch (aif2_lrlk_div) {
	case	16:
		bclk_div_factor = 4;
		break;
	case	32:
		bclk_div_factor = 2;
		break;
	case	64:
		bclk_div_factor = 0;
		break;
	case	128:
		bclk_div_factor = -2;
		break;
	case	256:
		bclk_div_factor = -4;
		break;
	default:
		pr_err("invalid lrlk_div setting in sysconfig!\n");
		return -EINVAL;
	}

	for (i = 0; i < ARRAY_SIZE(codec_aif1_lrck); i++) {
		if (codec_aif1_lrck[i].aif1_lrlk_div == aif2_lrlk_div) {
			snd_soc_update_bits(codec, SUNXI_AIF2_CLK_CTRL,
				(0x7 << AIF2_LRCK_DIV),
			((codec_aif1_lrck[i].aif1_lrlk_bit) << AIF2_LRCK_DIV));
			break;
		}
	}

	for (i = 0; i < ARRAY_SIZE(codec_aif1_fs); i++) {
		if (codec_aif1_fs[i].samplerate ==  params_rate(params)) {
			snd_soc_update_bits(codec, SUNXI_SYS_SR_CTRL,
				(0xf << AIF2_FS),
				((codec_aif1_fs[i].aif1_srbit) << AIF2_FS));
			bclk_div_factor += codec_aif1_fs[i].aif1_bclk_div;
			snd_soc_update_bits(codec, SUNXI_AIF2_CLK_CTRL,
				(0xf << AIF2_BCLK_DIV),
				((bclk_div_factor) << AIF2_BCLK_DIV));
			break;
		}
	}

	switch (params_format(params)) {
	case SNDRV_PCM_FORMAT_S24_LE:
		aif3_word_size = 24;
		aif3_size = 3;
		break;
	case SNDRV_PCM_FORMAT_S16_LE:
	default:
		aif3_word_size = 16;
		aif3_size = 1;
		break;
	}
	snd_soc_update_bits(codec, SUNXI_AIF3_CLK_CTRL, (0x3<<AIF3_WORD_SIZ),
						aif3_size<<AIF3_WORD_SIZ);

	return 0;
}
#endif

#ifdef CONFIG_SUNXI_MPP_AIO
static void ac_mpp_debugfs_update_adc_cardtype(struct snd_soc_codec *codec)
{
	if (mpp_audio_debugfs != NULL) {
		if ((snd_soc_read(codec, MBIAS_CTRL) >> MMICBIASEN) & 0x1)
			mpp_aio_info_set(mpp_audio_debugfs->ai_cardtype, 64, 0);

		if ((snd_soc_read(codec, L_ADCMIX_SRC) >>
			LADCMIXMUTELINEINL) & 0x1)
			mpp_aio_info_set(mpp_audio_debugfs->ai_cardtype, 64, 1);
		else if ((snd_soc_read(codec, R_ADCMIX_SRC) >>
				RADCMIXMUTELINEINR) & 0x1) {
			mpp_aio_info_set(mpp_audio_debugfs->ai_cardtype, 64, 1);
		} else {
			mpp_aio_info_set(mpp_audio_debugfs->ai_cardtype, 64, 0);
		}
	}
}
#endif

static int codec_set_bias_level(struct snd_soc_codec *codec,
				      enum snd_soc_bias_level level)
{
	switch (level) {
	case SND_SOC_BIAS_ON:
#ifdef CONFIG_SUNXI_MPP_AIO
		ac_mpp_debugfs_update_adc_cardtype(codec);
#endif
		pr_debug("[%s] SND_SOC_BIAS_ON\n", __func__);
		break;
	case SND_SOC_BIAS_PREPARE:
		pr_debug("[%s] SND_SOC_BIAS_PREPARE\n", __func__);
		break;
	case SND_SOC_BIAS_STANDBY:
		/*on*/
		/*switch_hw_config(codec);*/
#ifdef CONFIG_SUNXI_MPP_AIO
		ac_mpp_debugfs_update_adc_cardtype(codec);
#endif
		pr_debug("[%s] SND_SOC_BIAS_STANDBY\n", __func__);
		break;
	case SND_SOC_BIAS_OFF:
		/*off*/
		pr_debug("[%s] SND_SOC_BIAS_OFF\n", __func__);
		break;
	}
	codec->component.dapm.bias_level = level;
	return 0;
}

static const struct snd_soc_dai_ops codec_aif1_dai_ops = {
	.startup	= codec_start,
	.set_sysclk	= codec_set_dai_sysclk,
	.set_fmt	= codec_set_dai_fmt,
	.hw_params	= codec_hw_params,
	.shutdown	= codec_aif_shutdown,
	.digital_mute	= codec_aif_mute,
	.set_pll	= codec_set_fll,
};

#ifdef CODEC_AIF2_AIF3_ENABLE
static const struct snd_soc_dai_ops codec_aif2_dai_ops = {
	.set_sysclk	= codec_set_dai_sysclk,
	.set_fmt	= codec_set_dai_fmt,
	.hw_params	= codec_hw_params,
	/*.shutdown	= codec_aif_shutdown,*/
	.set_pll	= codec_set_fll,
};

static const struct snd_soc_dai_ops codec_aif3_dai_ops = {
	.hw_params	= codec_aif3_hw_params,
	.set_fmt	= codec_aif3_set_dai_fmt,
};
#endif

static struct snd_soc_dai_driver codec_dai[] = {
	{
		.name = "codec-aif1",
		.id = 1,
		.playback = {
			.stream_name = "AIF1 Playback",
			.channels_min = 1,
			.channels_max = 2,
			.rates = codec_RATES,
			.formats = codec_FORMATS,
		},
		.capture = {
			.stream_name = "AIF1 Capture",
			.channels_min = 1,
			.channels_max = 2,
			.rates = codec_RATES,
			.formats = codec_FORMATS,
		 },
		.ops = &codec_aif1_dai_ops,
	},
#ifdef CODEC_AIF2_AIF3_ENABLE
	{
		.name = "codec-aif2",
		.id = 2,
		.playback = {
			.stream_name = "AIF2 Playback",
			.channels_min = 1,
			.channels_max = 2,
			.rates = codec_RATES,
			.formats = codec_FORMATS,
		},
		.capture = {
			.stream_name = "AIF2 Capture",
			.channels_min = 1,
			.channels_max = 2,
			.rates = codec_RATES,
			.formats = codec_FORMATS,
		},
		.ops = &codec_aif2_dai_ops,
	},
	{
		.name = "codec-aif3",
		.id = 3,
		.playback = {
			.stream_name = "AIF3 Playback",
			.channels_min = 1,
			.channels_max = 1,
			.rates = codec_RATES,
			.formats = codec_FORMATS,
		},
		.capture = {
			.stream_name = "AIF3 Capture",
			.channels_min = 1,
			.channels_max = 1,
			.rates = codec_RATES,
			.formats = codec_FORMATS,
		 },
		.ops = &codec_aif3_dai_ops,
	}
#endif
};

static int codec_soc_probe(struct snd_soc_codec *codec)
{
	int ret = 0;
	struct snd_soc_dapm_context *dapm = &codec->component.dapm;
	struct sunxi_codec *sunxi_internal_codec =
			snd_soc_codec_get_drvdata(codec);

	sunxi_internal_codec->codec = codec;
	mutex_init(&sunxi_internal_codec->dac_mutex);
	mutex_init(&sunxi_internal_codec->adc_mutex);
	mutex_init(&sunxi_internal_codec->aifclk_mutex);
	/* Add virtual switch */
	ret = snd_soc_add_codec_controls(codec, sunxi_codec_controls,
					ARRAY_SIZE(sunxi_codec_controls));
	if (ret)
		pr_err("Failed to register will continue without it.\n");

	snd_soc_dapm_new_controls(dapm, ac_dapm_widgets,
				ARRAY_SIZE(ac_dapm_widgets));
	snd_soc_dapm_add_routes(dapm, ac_dapm_routes,
				ARRAY_SIZE(ac_dapm_routes));
	codec_init(sunxi_internal_codec);

	/* ADC use FIR32*/
	snd_soc_update_bits(codec, SUNXI_ADC_DIG_CTRL,
				(0x1 << ADFIR32), (0x1 << ADFIR32));

	return 0;
}

int audio_gpio_iodisable(u32 gpio)
{
	char pin_name[8];
	u32 config, ret;

	sunxi_gpio_to_name(gpio, pin_name);
	config = (((7) << 16) | (0 & 0xFFFF));
	ret = pin_config_set(SUNXI_PINCTRL, pin_name, config);
	return ret;
}

static int save_audio_reg(void)
{
	int i = 0;
	int reg_group = 0;

	while (reg_labels[i].name != NULL) {
		if (reg_labels[i].address == AREG_MIN_NUM)
			reg_group++;
		if (reg_group != 1) {
			reg_labels[i].value = readl(codec_digitaladress + reg_labels[i].address);
		} else if (reg_group == 1) {
			reg_labels[i].value = read_prcm_wvalue(reg_labels[i].address, codec_analogadress);
		}
		i++;
	}

	return i;
}

static int echo_audio_reg(void)
{
	int i = 0;
	int reg_group = 0;

	while (reg_labels[i].name != NULL) {
		if (reg_labels[i].address == AREG_MIN_NUM)
			reg_group++;
		if (reg_group != 1) {
			writel(reg_labels[i].value,
				codec_digitaladress + reg_labels[i].address);
		} else if (reg_group == 1) {
			write_prcm_wvalue(reg_labels[i].address,
				reg_labels[i].value & 0xff, codec_analogadress);
		}
		i++;
	}

	return i;
}

static int codec_suspend(struct snd_soc_codec *codec)
{
	struct sunxi_codec *sunxi_internal_codec =
			snd_soc_codec_get_drvdata(codec);
	struct spk_config *spk_cfg = &(sunxi_internal_codec->spk_config);
#ifdef CODEC_AIF2_AIF3_ENABLE
	int ret = 0;
#endif

	save_audio_reg();

#ifdef CODEC_AIF2_AIF3_ENABLE
	if (sunxi_internal_codec->aif_config.aif3config) {
		ret = pinctrl_select_state(sunxi_internal_codec->pinctrl,
				sunxi_internal_codec->aif3sleep_pinstate);
		if (ret) {
			pr_warn("[audio-codec] aif3-sleep state failed\n");
			return ret;
		}
	}
	if (sunxi_internal_codec->aif_config.aif2config) {
		ret = pinctrl_select_state(sunxi_internal_codec->pinctrl,
				sunxi_internal_codec->aif2sleep_pinstate);
		if (ret) {
			pr_warn("[audio-codec]select aif2-sleep state failed\n");
			return ret;
		}
	}

	if (sunxi_internal_codec->aif_config.aif2config ||
	    sunxi_internal_codec->aif_config.aif3config){
		devm_pinctrl_put(sunxi_internal_codec->pinctrl);
		sunxi_internal_codec->pinctrl = NULL;
		sunxi_internal_codec->aif3_pinstate = NULL;
		sunxi_internal_codec->aif2_pinstate = NULL;
		sunxi_internal_codec->aif3sleep_pinstate = NULL;
		sunxi_internal_codec->aif2sleep_pinstate = NULL;
	}
#endif
	if (spk_cfg->used)
		/*audio_gpio_iodisable(spk_cfg->gpio);*/
		gpio_set_value(spk_cfg->gpio, !(spk_cfg->pa_ctl_level));


	if (sunxi_internal_codec->vol_supply.avcc)
		regulator_disable(sunxi_internal_codec->vol_supply.avcc);

	if (sunxi_internal_codec->pllclk != NULL)
		clk_disable(sunxi_internal_codec->pllclk);

	if (sunxi_internal_codec->moduleclk != NULL)
		clk_disable(sunxi_internal_codec->moduleclk);

	return 0;
}

static int codec_resume(struct snd_soc_codec *codec)
{
	int ret;
	struct sunxi_codec *sunxi_internal_codec =
				snd_soc_codec_get_drvdata(codec);
	struct spk_config *spk_cfg = &(sunxi_internal_codec->spk_config);

	if (sunxi_internal_codec->vol_supply.avcc) {
		ret = regulator_enable(sunxi_internal_codec->vol_supply.avcc);
		if (ret)
			pr_err("[%s]: avcc:enable() failed!\n", __func__);
	}

	if (sunxi_internal_codec->pllclk != NULL)
		clk_prepare_enable(sunxi_internal_codec->pllclk);

	if (sunxi_internal_codec->moduleclk != NULL)
		clk_prepare_enable(sunxi_internal_codec->moduleclk);

	msleep(100);
	codec_init(sunxi_internal_codec);
	echo_audio_reg();
	/* ADC use FIR32*/
	snd_soc_update_bits(codec, SUNXI_ADC_DIG_CTRL,
				(0x1 << ADFIR32), (0x1 << ADFIR32));
	if (spk_cfg->used) {
		gpio_direction_output(spk_cfg->gpio, 1);
		gpio_set_value(spk_cfg->gpio, !(spk_cfg->pa_ctl_level));
	}

	return 0;
}

/* power down chip */
static int codec_soc_remove(struct snd_soc_codec *codec)
{
	return 0;
}

static unsigned int codec_read(struct snd_soc_codec *codec,
					  unsigned int reg)
{
	struct sunxi_codec *sunxi_internal_codec =
			snd_soc_codec_get_drvdata(codec);

	if (reg <= AREG_MAX_NUM)
		/*analog reg*/
		return read_prcm_wvalue(reg, sunxi_internal_codec->codec_abase);
	else
		/*digital reg*/
		return codec_rdreg(sunxi_internal_codec->codec_dbase + reg);
}

static int codec_write(struct snd_soc_codec *codec,
				  unsigned int reg, unsigned int value)
{
	struct sunxi_codec *sunxi_internal_codec =
			snd_soc_codec_get_drvdata(codec);

	if (reg <= AREG_MAX_NUM) {
		/*analog reg*/
		write_prcm_wvalue(reg, value,
				  sunxi_internal_codec->codec_abase);
	} else {
		/*digital reg*/
		codec_wrreg(sunxi_internal_codec->codec_dbase + reg, value);
	}
	return 0;
}

static struct snd_soc_codec_driver soc_codec_dev_codec = {
	.probe	= codec_soc_probe,
	.remove	= codec_soc_remove,
	.suspend	= codec_suspend,
	.resume	= codec_resume,
	.set_bias_level	= codec_set_bias_level,
	.read	= codec_read,
	.write	= codec_write,
	.ignore_pmdown_time	= 1,
};

static ssize_t show_audio_reg(struct device *dev, struct device_attribute *attr,
		char *buf)
{
	int count = 0;
	int i = 0;
	int reg_group = 0;

	count += sprintf(buf, "dump audio reg:\n");

	while (reg_labels[i].name != NULL) {
		if (reg_labels[i].address == AREG_MIN_NUM)
			reg_group++;
		if (reg_group != 1) {
			count += sprintf(buf + count, "[%s] 0x%p: 0x%x; Save: 0x%x\n",
			reg_labels[i].name,
			(codec_digitaladress + reg_labels[i].address),
			readl(codec_digitaladress + reg_labels[i].address),
			reg_labels[i].value);
		} else if (reg_group == 1) {
			count += sprintf(buf + count, "[%s] 0x%x: 0x%x; Save: 0x%x\n",
			reg_labels[i].name, (reg_labels[i].address),
			read_prcm_wvalue(reg_labels[i].address, codec_analogadress),
			reg_labels[i].value);
		}
		i++;
	}

	return count;
}

/*
 * ex:
 * param 1: 0 read;1 write
 * param 2: 1 digital reg; 2 analog reg
 * param 3: reg value;
 * param 4: write value;
 * read:
 * echo 0,1,0x00> audio_reg
 * echo 0,2,0x00> audio_reg
 * write:
 * echo 1,1,0x00,0xa > audio_reg
 * echo 1,2,0x00,0xff > audio_reg
 */
static ssize_t store_audio_reg(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	int ret;
	int rw_flag;
	int reg_val_read;
	unsigned int input_reg_val = 0;
	int input_reg_group = 0;
	unsigned int input_reg_offset = 0;

	ret = sscanf(buf, "%d,%d,0x%x,0x%x", &rw_flag, &input_reg_group,
		     &input_reg_offset, &input_reg_val);
	printk("ret:%d, reg_group:%d, reg_offset:%d, reg_val:0x%x\n",
	       ret, input_reg_group, input_reg_offset, input_reg_val);

	if (!(input_reg_group == 1 || input_reg_group == 2)) {
		pr_err("not exist reg group\n");
		ret = count;
		goto out;
	}
	if (!(rw_flag == 1 || rw_flag == 0)) {
		pr_err("not rw_flag\n");
		ret = count;
		goto out;
	}
	if (input_reg_group == 1) {
		if (rw_flag) {
			writel(input_reg_val,
			       codec_digitaladress + input_reg_offset);
		} else {
			reg_val_read = readl(codec_digitaladress +
							input_reg_offset);
			pr_alert("\n\n Reg[0x%x] : 0x%x\n\n",
					input_reg_offset, reg_val_read);
		}
	} else if (input_reg_group == 2) {
		if (rw_flag)
			write_prcm_wvalue(input_reg_offset,
				input_reg_val & 0xff, codec_analogadress);
		else {
			 reg_val_read = read_prcm_wvalue(input_reg_offset,
							 codec_analogadress);
			 pr_alert("\n\n Reg[0x%x] : 0x%x\n\n",
					input_reg_offset, reg_val_read);
		}
	}

	ret = count;

out:
	return ret;
}

DEVICE_ATTR(audio_reg, 0644, show_audio_reg, store_audio_reg);

static struct attribute *audio_debug_attrs[] = {
	&dev_attr_audio_reg.attr,
	NULL,
};

static struct attribute_group audio_debug_attr_group = {
	.name   = "audio_reg_debug",
	.attrs  = audio_debug_attrs,
};
static const struct of_device_id sunxi_codec_of_match[] = {
	{ .compatible = "allwinner,sunxi-internal-codec", },
	{},
};

static int sunxi_internal_codec_probe(struct platform_device *pdev)
{
	s32 ret = 0;
	u32 temp_val;
	struct gpio_config config;
	const struct of_device_id *device;
	struct sunxi_codec *sunxi_internal_codec;
	struct device_node *node = pdev->dev.of_node;
	struct spk_config *spk_cfg;

	if (!node) {
		dev_err(&pdev->dev,
			"can not get dt node for this device.\n");
		ret = -EINVAL;
		goto err0;
	}
	sunxi_internal_codec = devm_kzalloc(&pdev->dev,
					sizeof(struct sunxi_codec), GFP_KERNEL);
	if (!sunxi_internal_codec) {
		dev_err(&pdev->dev, "Can't allocate sunxi_codec\n");
		ret = -ENOMEM;
		goto err0;
	}
	dev_set_drvdata(&pdev->dev, sunxi_internal_codec);
	device = of_match_device(sunxi_codec_of_match, &pdev->dev);
	if (!device) {
		ret = -ENODEV;
		goto err_put_mem;
	}

	sunxi_internal_codec->vol_supply.avcc = regulator_get(NULL, "avcc");
	if (IS_ERR(sunxi_internal_codec->vol_supply.avcc)) {
		pr_err("[%s]:get audio avcc failed\n", __func__);
		ret = -EFAULT;
		goto err_put_mem;
	} else {
		ret = regulator_enable(sunxi_internal_codec->vol_supply.avcc);
		if (ret) {
			pr_err("[%s]: avcc:enable() failed!\n", __func__);
			goto err_put_regulator;
		}
	}

	sunxi_internal_codec->codec_dbase = of_iomap(node, 0);
	if (sunxi_internal_codec->codec_dbase == NULL) {
		pr_err("[audio-codec]Can't map codec digital registers\n");
		ret = -ENOMEM;
		goto err_put_regulator;
	} else
		codec_digitaladress = sunxi_internal_codec->codec_dbase;

	sunxi_internal_codec->codec_abase = of_iomap(node, 1);
	if (sunxi_internal_codec->codec_abase == NULL) {
		pr_err("[audio-codec]Can't map codec analog registers\n");
		ret = -ENOMEM;
		goto err_put_iomem1;
	} else
		codec_analogadress = sunxi_internal_codec->codec_abase;

	sunxi_internal_codec->pllclk = of_clk_get(node, 0);
	if (IS_ERR(sunxi_internal_codec->pllclk)) {
		dev_err(&pdev->dev, "audio codec get pll clk failed !\n");
		ret = PTR_ERR(sunxi_internal_codec->pllclk);
		goto err_put_iomem2;
	}
	sunxi_internal_codec->moduleclk = of_clk_get(node, 1);
	if (IS_ERR(sunxi_internal_codec->moduleclk)) {
		dev_err(&pdev->dev, "[audio-codec]Can't get module clocks\n");
		ret = PTR_ERR(sunxi_internal_codec->moduleclk);
		goto err_put_clk;
	}
	if (clk_set_parent(sunxi_internal_codec->moduleclk, sunxi_internal_codec->pllclk))
		pr_err("try to set pllclk as parent of modulepll failed!\n");

	clk_prepare_enable(sunxi_internal_codec->pllclk);
	clk_prepare_enable(sunxi_internal_codec->moduleclk);

	/*initial speaker gpio */
	spk_cfg = &(sunxi_internal_codec->spk_config);

	ret = of_property_read_u32(node, "pa_ctl_level", &temp_val);
	if (ret < 0) {
		pr_err("[audio-codec] pa_ctl_level  missing or invalid.\n");
		spk_cfg->pa_ctl_level = 1;
	} else {
		spk_cfg->pa_ctl_level = temp_val;
	}

	spk_cfg->gpio = of_get_named_gpio_flags(node, "gpio-spk", 0,
						(enum of_gpio_flags *)&config);
	if (!gpio_is_valid(spk_cfg->gpio)) {
		pr_err("failed to get gpio-spk gpio from dts,spk_cfg:%d\n",
							spk_cfg->gpio);
		spk_cfg->used = 0;
	} else {
		ret = devm_gpio_request(&pdev->dev, spk_cfg->gpio, "Speaker");
		if (ret) {
			spk_cfg->used = 0;
			pr_err("failed to request gpio-spk gpio\n");
			goto err_put_clk;
		} else {
			pr_err("gpio-spk setting ok");
			spk_cfg->used = 1;
			gpio_direction_output(spk_cfg->gpio, 1);
			gpio_set_value(spk_cfg->gpio, !(spk_cfg->pa_ctl_level));
		}
	}

	if (spk_cfg->used) {
		ret = of_property_read_u32(node, "pa_msleep_time", &temp_val);
		if (ret < 0) {
			pr_err("[audio-codec] pa_msleep_time missing or invalid.\n");
			ret = -EINVAL;
			goto err_put_gpio;
		} else
			spk_cfg->pa_msleep_time = temp_val;
	}

	ret = of_property_read_u32(node, "lineoutvol", &temp_val);
	if (ret < 0) {
		pr_err("[audio-codec] lineout vol  missing or invalid.\n");
		ret = -EINVAL;
		goto err_put_gpio;
	} else {
		sunxi_internal_codec->gain_config.lineout_vol = temp_val;
	}
	ret = of_property_read_u32(node, "maingain", &temp_val);
	if (ret < 0) {
		pr_err("[audio-codec]maingain  missing or invalid.\n");
		ret = -EINVAL;
		goto err_put_gpio;
	} else {
		sunxi_internal_codec->gain_config.maingain = temp_val;
	}

	ret = of_property_read_u32(node, "headsetmicgain", &temp_val);
	if (ret < 0) {
		pr_err("[audio-codec]headsetmicgain missing or invalid.\n");
		ret = -EINVAL;
		goto err_put_gpio;
	} else {
		sunxi_internal_codec->gain_config.headsetmicgain = temp_val;
	}

	ret = of_property_read_u32(node, "adcagc_cfg", &temp_val);
	if (ret < 0) {
		pr_err("[audio-codec]adcagc_cfg missing or invalid.\n");
		ret = -EINVAL;
		goto err_put_gpio;
	} else {
		sunxi_internal_codec->hwconfig.adcagc_cfg = temp_val;
	}

	ret = of_property_read_u32(node, "adcdrc_cfg", &temp_val);
	if (ret < 0) {
		pr_err("[audio-codec]adcdrc_cfg missing or invalid.\n");
		ret = -EINVAL;
		goto err_put_gpio;
	} else {
		sunxi_internal_codec->hwconfig.adcdrc_cfg = temp_val;
	}

	ret = of_property_read_u32(node, "adchpf_cfg", &temp_val);
	if (ret < 0) {
		pr_err("[audio-codec]adchpf_cfg missing or invalid.\n");
		ret = -EINVAL;
		goto err_put_gpio;
	} else {
		sunxi_internal_codec->hwconfig.adchpf_cfg = temp_val;
	}

	ret = of_property_read_u32(node, "dacdrc_cfg", &temp_val);
	if (ret < 0) {
		pr_err("[audio-codec]dacdrc_cfg missing or invalid.\n");
		ret = -EINVAL;
		goto err_put_gpio;
	} else {
		sunxi_internal_codec->hwconfig.dacdrc_cfg = temp_val;
	}

	ret = of_property_read_u32(node, "dachpf_cfg", &temp_val);
	if (ret < 0) {
		pr_err("[audio-codec]dachpf_cfg missing or invalid.\n");
		ret = -EINVAL;
		goto err_put_gpio;
	} else {
		sunxi_internal_codec->hwconfig.dachpf_cfg = temp_val;
	}

	ret = of_property_read_u32(node, "aif2config", &temp_val);
	if (ret < 0) {
		pr_err("[audio-codec]aif2config missing or invalid.\n");
		ret = -EINVAL;
		goto err_put_gpio;
	} else {
		sunxi_internal_codec->aif_config.aif2config = temp_val;
	}

	ret = of_property_read_u32(node, "aif3config", &temp_val);
	if (ret < 0) {
		pr_err("[audio-codec]aif3config missing or invalid.\n");
		ret = -EINVAL;
		goto err_put_gpio;
	} else {
		sunxi_internal_codec->aif_config.aif3config = temp_val;
	}

	ret = of_property_read_u32(node, "aif1_lrlk_div", &temp_val);
	if (ret < 0) {
		pr_err("[audio-codec]aif1_lrlk_div missing or invalid.\n");
		ret = -EINVAL;
		goto err_put_gpio;
	} else {
		sunxi_internal_codec->aif1_lrlk_div = temp_val;
	}
	ret = of_property_read_u32(node, "aif2_lrlk_div", &temp_val);
	if (ret < 0) {
		pr_err("[audio-codec]aif2_lrlk_div missing or invalid.\n");
		ret = -EINVAL;
		goto err_put_gpio;
	} else {
		sunxi_internal_codec->aif2_lrlk_div = temp_val;
	}

	ret = of_property_read_u32(node, "dac_digital_vol", &temp_val);
	if (ret < 0) {
		pr_err("[audio-codec]dac_digital_vol missing or invalid.\n");
		ret = -EINVAL;
		goto err_put_gpio;
	} else {
		sunxi_internal_codec->gain_config.dac_digital_vol = temp_val;
	}

	snd_soc_register_codec(&pdev->dev, &soc_codec_dev_codec,
				codec_dai, ARRAY_SIZE(codec_dai));

	ret  = sysfs_create_group(&pdev->dev.kobj, &audio_debug_attr_group);
	if (ret)
		pr_err("[audio-codec]failed to create attr group\n");
	else
		sunxi_internal_codec->attr_flag = 1;
	return 0;

err_put_gpio:
	devm_gpio_free(&pdev->dev, spk_cfg->gpio);

err_put_clk:
	if (sunxi_internal_codec->pllclk)
		clk_put(sunxi_internal_codec->pllclk);
	if (sunxi_internal_codec->moduleclk)
		clk_put(sunxi_internal_codec->moduleclk);
err_put_iomem2:
	iounmap(sunxi_internal_codec->codec_abase);
err_put_iomem1:
	iounmap(sunxi_internal_codec->codec_dbase);
err_put_regulator:
	regulator_disable(sunxi_internal_codec->vol_supply.avcc);
	regulator_put(sunxi_internal_codec->vol_supply.avcc);
err_put_mem:
	devm_kfree(&pdev->dev, sunxi_internal_codec);
err0:
	return ret;
}

static int __exit sunxi_internal_codec_remove(struct platform_device *pdev)
{
	struct sunxi_codec *sunxi_internal_codec = dev_get_drvdata(&pdev->dev);

	if (sunxi_internal_codec->attr_flag)
		sysfs_remove_group(&pdev->dev.kobj, &audio_debug_attr_group);
	snd_soc_unregister_codec(&pdev->dev);
	return 0;
}

static void sunxi_internal_codec_shutdown(struct platform_device *pdev)
{
	struct sunxi_codec *sunxi_internal_codec = dev_get_drvdata(&pdev->dev);
	struct spk_config *spk_cfg = &(sunxi_internal_codec->spk_config);

	if (spk_cfg->used)
		gpio_set_value(spk_cfg->gpio, !(spk_cfg->pa_ctl_level));
}

static struct platform_driver sunxi_internal_codec_driver = {
	.driver = {
		.name = DRV_NAME,
		.owner = THIS_MODULE,
		.of_match_table = sunxi_codec_of_match,
	},
	.probe = sunxi_internal_codec_probe,
	.remove = __exit_p(sunxi_internal_codec_remove),
	.shutdown = sunxi_internal_codec_shutdown,
};

module_platform_driver(sunxi_internal_codec_driver);

MODULE_DESCRIPTION("codec ALSA soc codec driver");
MODULE_AUTHOR("huanxin<huanxin@allwinnertech.com>");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:sunxi-pcm-codec");
