/*
 * Copyright 2026 CHCTR-HCTR2TwKD authors
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 *
 * CHCTR2 (ePrint 2026/085): HCTR2 cascaded with two independent AES-256
 * keys, in the optimized single-pass form -- the two middle hash layers are
 * merged into one polyval_xor pass.  Cost: 2 BC + 3 FMUL per block.
 */

#include "chctr2.h"
#include "hctr2.h"
#include "hctr2_format.h"
#include "polyval_xor.h"
#include "xctr.h"
#include "util.h"

void chctr2_setkey(struct chctr2_ctx *ctx, const u8 *key, bool simd)
{
	u8 h1_raw[16], h2_raw[16];
	le128 tmp;
	int i;

	aes_setkey(&ctx->aes1, key, AES_KEYSIZE_256);
	aes_setkey(&ctx->aes2, key + 32, AES_KEYSIZE_256);

	memset(h1_raw, 0, 16);
	aes_encrypt(&ctx->aes1, h1_raw, h1_raw, simd);
	memset(h2_raw, 0, 16);
	aes_encrypt(&ctx->aes2, h2_raw, h2_raw, simd);

	memset(ctx->L1, 0, 16);
	ctx->L1[0] = 0x01;
	aes_encrypt(&ctx->aes1, ctx->L1, ctx->L1, simd);
	memset(ctx->L2, 0, 16);
	ctx->L2[0] = 0x01;
	aes_encrypt(&ctx->aes2, ctx->L2, ctx->L2, simd);

	polyval_xor_setkey(&ctx->hx, h1_raw, h2_raw, simd);

	ctx->default_tweak_len = HCTR2_DEFAULT_TWEAK_LEN;
	for (i = 0; i < 2; i++) {
		polyval_init(&ctx->init1[i]);
		polyval_init(&ctx->init2[i]);
		hctr2_format_length_block(&tmp, ctx->default_tweak_len, i != 0);
		polyval_update(&ctx->init1[i], &ctx->hx.h1, (u8 *)&tmp, 1, simd);
		polyval_update(&ctx->init2[i], &ctx->hx.h2, (u8 *)&tmp, 1, simd);
	}
}

/* H_Hi(T, msg) with hctr2.c's padding; init = the layer's cached states. */
static void chctr2_hash(const struct chctr2_ctx *ctx,
			const struct polyval_key *pk,
			const struct polyval_state init[2], const u8 *tweak,
			size_t tweak_len, const u8 *msg, size_t nbytes,
			u8 digest[16], bool simd)
{
	struct polyval_state st;
	u8 block[16];
	le128 tmp;
	bool mdiv = nbytes % 16 == 0;

	if (tweak_len == ctx->default_tweak_len) {
		st = init[mdiv ? 1 : 0];
	} else {
		polyval_init(&st);
		hctr2_format_length_block(&tmp, tweak_len, mdiv);
		polyval_update(&st, pk, (u8 *)&tmp, 1, simd);
	}

	polyval_update(&st, pk, tweak, tweak_len / 16, simd);
	if (hctr2_format_partial_block(block, tweak, tweak_len, false))
		polyval_update(&st, pk, block, 1, simd);
	polyval_update(&st, pk, msg, nbytes / 16, simd);
	if (hctr2_format_partial_block(block, msg, nbytes, true))
		polyval_update(&st, pk, block, 1, simd);
	polyval_emit(&st, digest, simd);
}

void chctr2_crypt(const struct chctr2_ctx *ctx, u8 *dst, const u8 *src,
		  size_t nbytes, const u8 *tweak, size_t tweak_len,
		  bool encrypt, bool simd)
{
	u8 digest[16], x10[16], y10[16], x20[16], y20[16], stream_iv[16];
	const u8 *right_src = src + BLOCKCIPHER_BLOCK_SIZE;
	u8 *right_dst = dst + BLOCKCIPHER_BLOCK_SIZE;
	size_t right_len = nbytes - BLOCKCIPHER_BLOCK_SIZE;

	ASSERT(nbytes >= BLOCKCIPHER_BLOCK_SIZE);

	if (encrypt) {
		chctr2_hash(ctx, &ctx->hx.h1, ctx->init1, tweak, tweak_len,
			    right_src, right_len, digest, simd);
		xor(x10, src, digest, 16);
		aes_encrypt(&ctx->aes1, y10, x10, simd);
		xor(stream_iv, x10, y10, 16);
		xor(stream_iv, stream_iv, ctx->L1, 16);
		xctr_crypt(&ctx->aes1, right_dst, right_src, right_len, stream_iv,
			   simd); /* right_dst = R */

		polyval_xor_hash(&ctx->hx, tweak, tweak_len, right_dst,
				 right_len, digest, simd);
		xor(x20, y10, digest, 16);
		aes_encrypt(&ctx->aes2, y20, x20, simd);
		xor(stream_iv, x20, y20, 16);
		xor(stream_iv, stream_iv, ctx->L2, 16);
		xctr_crypt(&ctx->aes2, right_dst, right_dst, right_len, stream_iv,
			   simd); /* right_dst = C* */

		chctr2_hash(ctx, &ctx->hx.h2, ctx->init2, tweak, tweak_len,
			    right_dst, right_len, digest, simd);
		xor(dst, y20, digest, 16); /* C_0 = Y_{2,0} ^ Z_2 */
	} else {
		chctr2_hash(ctx, &ctx->hx.h2, ctx->init2, tweak, tweak_len,
			    right_src, right_len, digest, simd);
		xor(y20, src, digest, 16);
		aes_decrypt(&ctx->aes2, x20, y20, simd);
		xor(stream_iv, x20, y20, 16);
		xor(stream_iv, stream_iv, ctx->L2, 16);
		xctr_crypt(&ctx->aes2, right_dst, right_src, right_len, stream_iv,
			   simd); /* right_dst = R */

		polyval_xor_hash(&ctx->hx, tweak, tweak_len, right_dst,
				 right_len, digest, simd);
		xor(y10, x20, digest, 16);
		aes_decrypt(&ctx->aes1, x10, y10, simd);
		xor(stream_iv, x10, y10, 16);
		xor(stream_iv, stream_iv, ctx->L1, 16);
		xctr_crypt(&ctx->aes1, right_dst, right_dst, right_len, stream_iv,
			   simd); /* right_dst = M* */

		chctr2_hash(ctx, &ctx->hx.h1, ctx->init1, tweak, tweak_len,
			    right_dst, right_len, digest, simd);
		xor(dst, x10, digest, 16); /* M_0 = X_{1,0} ^ Z_1 */
	}
}
