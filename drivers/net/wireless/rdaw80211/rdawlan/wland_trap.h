
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
#ifndef _WLAND_TRAP_H_
#define _WLAND_TRAP_H_
#include <linux/kernel.h>

extern int wland_download_codefile(struct wland_if *ifp);
extern int wland_download_datafile(struct wland_if *ifp);
extern int wland_run_firmware(struct wland_if *ifp, u32 addr);
extern s32 wland_assoc_power_save(struct wland_private *priv);
extern s32 wland_set_phy_timeout(struct wland_private *priv,
	u32 cipher_pairwise, u32 cipher_group);

#endif /*_WLAND_TRAP_H_ */
