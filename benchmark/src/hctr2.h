/*
 * Copyright 2021 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */
#pragma once

#include "aes.h"
#include "polyval.h"

#define HCTR2_DEFAULT_TWEAK_LEN 16
#define BLOCKCIPHER_BLOCK_SIZE 16

struct hctr2_ctx {
	struct aes_ctx aes_ctx;
	unsigned int default_tweak_len;
	struct polyval_key polyval_key;
	u8 L[BLOCKCIPHER_BLOCK_SIZE];
	struct polyval_state initial_states[2];
};

void hctr2_setkey(struct hctr2_ctx *ctx, const u8 *key, size_t key_len,
		  bool simd);
void hctr2_crypt(const struct hctr2_ctx *ctx, u8 *dst, const u8 *src,
		 size_t nbytes, const u8 *tweak, size_t tweak_len, bool encrypt,
		 bool simd);
void hctr2_change_tweak_len(struct hctr2_ctx *ctx, const size_t tweak_len,
			    bool simd);
