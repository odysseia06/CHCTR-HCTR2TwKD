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

#define TWKD_TWEAK_LEN 16

struct hctr2_twkd_ctx {
	struct aes_ctx kdf_aes;
};

void twkd_setkey(struct hctr2_twkd_ctx *ctx, const u8 *key);
/* F_L(T0) = (E(00||T0)^E(01||T0)) || (E(00||T0)^E(10||T0)).  T0 must be
 * canonical (tweak[0] & 0xc0 == 0); a noncanonical T0 fails an ASSERT. */
void twkd_derive(const struct hctr2_twkd_ctx *ctx, const u8 *tweak,
		 u8 subkey[32], bool simd);
void twkd_crypt(const struct hctr2_twkd_ctx *ctx, u8 *dst, const u8 *src,
		size_t nbytes, const u8 *tweak, bool encrypt, bool simd);
