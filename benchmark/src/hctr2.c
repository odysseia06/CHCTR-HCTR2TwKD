/*
 * Copyright 2021 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

#include "aes.h"
#include "aes_linux.h"
#include "xctr.h"
#include "polyval.h"
#include "util.h"
#include "hctr2.h"
#include "hctr2_format.h"

/*
 * Precomputes the first block of the polynomial hash function. This block is
 * fixed for any message with the same key and tweak length.
 *
 * The two computed states are used as the polynomial hash function's initial
 * state.
 */
void hctr2_change_tweak_len(struct hctr2_ctx *ctx, const size_t tweak_len,
			    bool simd)
{
	le128 tmp;

	polyval_init(&ctx->initial_states[0]);
	hctr2_format_length_block(&tmp, tweak_len, false);
	polyval_update(&ctx->initial_states[0], &ctx->polyval_key, (u8 *)&tmp,
		       1, simd);

	polyval_init(&ctx->initial_states[1]);
	hctr2_format_length_block(&tmp, tweak_len, true);
	polyval_update(&ctx->initial_states[1], &ctx->polyval_key, (u8 *)&tmp,
		       1, simd);
}

void hctr2_setkey(struct hctr2_ctx *ctx, const u8 *key, size_t key_len,
		  bool simd)
{
	u8 hbar[BLOCKCIPHER_BLOCK_SIZE];

	aesti_expand_key(&ctx->aes_ctx.aes_ctx, key, key_len);
	ctx->default_tweak_len = HCTR2_DEFAULT_TWEAK_LEN;

	memset(hbar, 0, BLOCKCIPHER_BLOCK_SIZE);
	aes_encrypt(&ctx->aes_ctx, hbar, hbar, simd);
	memset(ctx->L, 0, BLOCKCIPHER_BLOCK_SIZE);
	ctx->L[0] = 0x01;
	aes_encrypt(&ctx->aes_ctx, ctx->L, ctx->L, simd);

	polyval_setkey(&ctx->polyval_key, hbar, simd);
	hctr2_change_tweak_len(ctx, ctx->default_tweak_len, simd);
}

static void hctr2_hash_tweak(const struct hctr2_ctx *ctx,
			     struct polyval_state *state, const u8 *data,
			     size_t nbytes, bool simd)
{
	u8 padded_final[POLYVAL_BLOCK_SIZE];
	size_t nblocks = nbytes / POLYVAL_BLOCK_SIZE;

	polyval_update(state, &ctx->polyval_key, data, nblocks, simd);
	if (hctr2_format_partial_block(padded_final, data, nbytes, false))
		polyval_update(state, &ctx->polyval_key, padded_final, 1, simd);
}

static void hctr2_hash_message(const struct hctr2_ctx *ctx,
			       struct polyval_state *state, const u8 *data,
			       size_t nbytes, bool simd)
{
	u8 padded_final[POLYVAL_BLOCK_SIZE];
	size_t nblocks = nbytes / POLYVAL_BLOCK_SIZE;

	polyval_update(state, &ctx->polyval_key, data, nblocks, simd);
	if (hctr2_format_partial_block(padded_final, data, nbytes, true))
		polyval_update(state, &ctx->polyval_key, padded_final, 1, simd);
}

void hctr2_crypt(const struct hctr2_ctx *ctx, u8 *dst, const u8 *src,
		 size_t nbytes, const u8 *tweak, size_t tweak_len, bool encrypt,
		 bool simd)
{
	struct polyval_state polystate1;
	struct polyval_state polystate2;
	u8 digest[POLYVAL_DIGEST_SIZE];
	u8 MM[BLOCKCIPHER_BLOCK_SIZE];
	u8 UU[BLOCKCIPHER_BLOCK_SIZE];
	u8 S[BLOCKCIPHER_BLOCK_SIZE];
	const u8 *M;
	const u8 *N;
	u8 *U;
	u8 *V;
	size_t M_bytes;
	size_t N_bytes;
	bool mdiv;
	le128 tmp;

	ASSERT(nbytes >= BLOCKCIPHER_BLOCK_SIZE);
	M_bytes = BLOCKCIPHER_BLOCK_SIZE;
	N_bytes = nbytes - M_bytes;
	M = src;
	N = src + BLOCKCIPHER_BLOCK_SIZE;
	U = dst;
	V = dst + BLOCKCIPHER_BLOCK_SIZE;

	mdiv = N_bytes % POLYVAL_BLOCK_SIZE == 0;
	// Reuse the precomputed first block if tweak_len is the same
	// as the context's default_tweak_len.
	if (tweak_len == ctx->default_tweak_len) {
		// Pick the appropriate precomputed first block based on whether
		// the message divides the block size.
		polystate1 = ctx->initial_states[mdiv ? 1 : 0];
	} else {
		// Recompute the initial state if we're using a different
		// tweak_len.
		polyval_init(&polystate1);
		hctr2_format_length_block(&tmp, tweak_len, mdiv);
		polyval_update(&polystate1, &ctx->polyval_key, (u8 *)&tmp, 1,
			       simd);
	}

	hctr2_hash_tweak(ctx, &polystate1, tweak, tweak_len, simd);
	// Since the tweak is the same for both hashes, save the state
	// for later to avoid re-computing the same partial hash.
	polystate2 = polystate1;
	hctr2_hash_message(ctx, &polystate1, N, N_bytes, simd);
	polyval_emit(&polystate1, digest, simd);

	xor(&MM, M, digest, BLOCKCIPHER_BLOCK_SIZE);

	if (encrypt)
		aes_encrypt(&ctx->aes_ctx, UU, MM, simd);
	else
		aes_decrypt(&ctx->aes_ctx, UU, MM, simd);

	xor(&S, &MM, &UU, BLOCKCIPHER_BLOCK_SIZE);
	xor(&S, &ctx->L, &S, BLOCKCIPHER_BLOCK_SIZE);

	xctr_crypt(&ctx->aes_ctx, V, N, N_bytes, S, simd);

	// Use the saved partial hash state.
	hctr2_hash_message(ctx, &polystate2, V, N_bytes, simd);
	polyval_emit(&polystate2, digest, simd);

	xor(U, &UU, digest, BLOCKCIPHER_BLOCK_SIZE);
}
