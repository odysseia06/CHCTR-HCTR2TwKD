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

#ifdef __x86_64__
asmlinkage void aes_xctr_enc_128_avx_by8(const u8 *in, const u8 *iv,
	const void *keys, u8 *out, unsigned int num_bytes,
	unsigned int byte_ctr);

asmlinkage void aes_xctr_enc_192_avx_by8(const u8 *in, const u8 *iv,
	const void *keys, u8 *out, unsigned int num_bytes,
	unsigned int byte_ctr);

asmlinkage void aes_xctr_enc_256_avx_by8(const u8 *in, const u8 *iv,
	const void *keys, u8 *out, unsigned int num_bytes,
	unsigned int byte_ctr);
#elif defined(__aarch64__)
asmlinkage void ce_aes_xctr_encrypt(u8 out[], u8 const in[], u32 const rk[],
				    int rounds, int bytes, u8 ctr[],
				    int byte_ctr);
#else
#error Unsupported architecture.
#endif

static void xctr_crypt_simd(const struct aes_ctx *ctx, u8 *dst, const u8 *src,
			    size_t nbytes, const u8 *iv)
{
#ifdef __x86_64__
	unsigned int remainder = nbytes % XCTR_BLOCK_SIZE;
	unsigned int aligned_len = nbytes - remainder;
	__le64 block[2];

	if (ctx->aes_ctx.key_length == AES_KEYSIZE_128)
		aes_xctr_enc_128_avx_by8(src, iv, ctx, dst, aligned_len, 0);
	else if (ctx->aes_ctx.key_length == AES_KEYSIZE_192)
		aes_xctr_enc_192_avx_by8(src, iv, ctx, dst, aligned_len, 0);
	else
		aes_xctr_enc_256_avx_by8(src, iv, ctx, dst, aligned_len, 0);

	if (remainder) {
		memcpy(block, iv, XCTR_BLOCK_SIZE);
		block[0] ^= cpu_to_le64(1 + aligned_len / XCTR_BLOCK_SIZE);
		aes_encrypt(ctx, (u8 *)&block, (u8 *)&block, true);
		xor(dst + aligned_len, src + aligned_len, block, remainder);
	}
#elif defined(__aarch64__)
	if (nbytes >= XCTR_BLOCK_SIZE) {
		ce_aes_xctr_encrypt(dst, src, ctx->aes_ctx.key_enc,
				    aes_nrounds(ctx), nbytes, (u8 *)iv, 0);
	} else {
		u8 tmpbuf[XCTR_BLOCK_SIZE];
		u8 *p = &tmpbuf[XCTR_BLOCK_SIZE - nbytes];

		memcpy(p, src, nbytes);
		ce_aes_xctr_encrypt(p, p, ctx->aes_ctx.key_enc,
				    aes_nrounds(ctx), nbytes, (u8 *)iv, 0);
		memcpy(dst, p, nbytes);
	}
#else
#error Unsupported architecture.
#endif
}

static void xctr_crypt_generic(const struct aes_ctx *ctx, u8 *dst,
			       const u8 *src, size_t nbytes, const u8 *iv)
{
	int i;
	int nblocks;
	size_t offset;
	le128 ctr;
	le128 ks;

	nblocks = nbytes / XCTR_BLOCK_SIZE;
	for (i = 0; i < nblocks; i++) {
		ctr.a = 0;
		ctr.b = cpu_to_le64(i + 1);
		xor(&ctr, &ctr, iv, XCTR_BLOCK_SIZE);
		aes_encrypt(ctx, (u8 *)&ks, (u8 *)&ctr, false);
		xor(&dst[i * XCTR_BLOCK_SIZE], (u8 *)&ks,
		    &src[i * XCTR_BLOCK_SIZE], XCTR_BLOCK_SIZE);
	}

	if (nbytes % XCTR_BLOCK_SIZE != 0) {
		offset = (nbytes / XCTR_BLOCK_SIZE) * XCTR_BLOCK_SIZE;
		ctr.a = 0;
		ctr.b = cpu_to_le64(nbytes / XCTR_BLOCK_SIZE + 1);
		xor(&ctr, &ctr, iv, XCTR_BLOCK_SIZE);
		aes_encrypt(ctx, (u8 *)&ctr, (u8 *)&ctr, false);
		xor(&dst[offset], (u8 *)&ctr, &src[offset],
		    nbytes % XCTR_BLOCK_SIZE);
	}
}

void xctr_crypt(const struct aes_ctx *ctx, u8 *dst, const u8 *src,
		size_t nbytes, const u8 *iv, bool simd)
{
	if (simd)
		xctr_crypt_simd(ctx, dst, src, nbytes, iv);
	else
		xctr_crypt_generic(ctx, dst, src, nbytes, iv);
}
