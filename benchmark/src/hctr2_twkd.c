/*
 * Copyright 2026 CHCTR-HCTR2TwKD authors
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 *
 * HCTR2-TwKD (ePrint 2026/085 Sec. 3.4): HCTR2 whose key is derived from
 * the tweak with the CENC-based KDF of Sec. 8.  T0 = the 126-bit tweak,
 * encoded in 16 bytes with the top two bits of byte 0 zero (those bits
 * carry the KDF's 00/01/10 prefix); the inner HCTR2 tweak is empty.
 */

#include "hctr2.h"
#include "hctr2_twkd.h"
#include "util.h"

void twkd_setkey(struct hctr2_twkd_ctx *ctx, const u8 *key)
{
	aes_setkey(&ctx->kdf_aes, key, AES_KEYSIZE_256);
}

/* F_L(T0) = (E(00||T0)^E(01||T0)) || (E(00||T0)^E(10||T0)) */
void twkd_derive(const struct hctr2_twkd_ctx *ctx, const u8 *tweak,
		 u8 subkey[32], bool simd)
{
	u8 in[16], e0[16], e1[16], e2[16];

	/* A noncanonical T0 would collide with T0 & 0x3f..: reject it rather
	 * than silently mask it. */
	ASSERT((tweak[0] & 0xc0) == 0);
	memcpy(in, tweak, 16);
	aes_encrypt(&ctx->kdf_aes, e0, in, simd);
	in[0] = (in[0] & 0x3f) | 0x40;
	aes_encrypt(&ctx->kdf_aes, e1, in, simd);
	in[0] = (in[0] & 0x3f) | 0x80;
	aes_encrypt(&ctx->kdf_aes, e2, in, simd);
	xor(subkey, e0, e1, 16);
	xor(subkey + 16, e0, e2, 16);
}

void twkd_crypt(const struct hctr2_twkd_ctx *ctx, u8 *dst, const u8 *src,
		size_t nbytes, const u8 *tweak, bool encrypt, bool simd)
{
	/* Per-call locals: no derived state is shared between calls, so
	 * concurrent valid calls on one master context are independent.
	 * Secure erasure is deliberately not claimed in this milestone. */
	struct hctr2_ctx hctr2;
	u8 subkey[32];

	twkd_derive(ctx, tweak, subkey, simd);
	hctr2_setkey(&hctr2, subkey, 32, simd);
	hctr2_crypt(&hctr2, dst, src, nbytes, tweak, 0, encrypt, simd);
}
