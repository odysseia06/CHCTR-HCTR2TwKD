/*
 * Copyright 2026 CHCTR-HCTR2TwKD authors
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 *
 * Internal repository header -- no ABI stability promise.
 */
#pragma once

#include "hctr2.h"
#include "polyval_xor.h"

struct chctr2_ctx {
	struct aes_ctx aes1, aes2;
	struct polyval_xor_key hx; /* hx.h1 / hx.h2 double as the layer 1/3 keys */
	u8 L1[BLOCKCIPHER_BLOCK_SIZE], L2[BLOCKCIPHER_BLOCK_SIZE];
	unsigned int default_tweak_len;
	/* [0] = message not block-aligned (+3), [1] = aligned (+2),
	 * matching hctr2.c's initial_states convention; layers 1 and 3
	 * only -- the middle layer is one-shot (see polyval_xor.h). */
	struct polyval_state init1[2], init2[2];
};

void chctr2_setkey(struct chctr2_ctx *ctx, const u8 *key, bool simd);
void chctr2_crypt(const struct chctr2_ctx *ctx, u8 *dst, const u8 *src,
		  size_t nbytes, const u8 *tweak, size_t tweak_len,
		  bool encrypt, bool simd);
