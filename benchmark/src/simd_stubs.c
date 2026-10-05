/*
 * Stub implementations of SIMD functions for platforms without SIMD assembly
 * (Windows/MinGW).  simd_supported() returns false there, so these are never
 * reached by the tests or the benchmark; they exist only to satisfy the
 * linker.  Each one aborts: a silent no-op would hand back unencrypted data
 * to any caller that passed simd=true.
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "aes_linux.h"
#include "polyval_xor.h"
#include "util.h"

/* Wrapper for aligned_alloc which may not be available on all MINGW versions */
#ifdef _WIN32
void *aligned_alloc(size_t alignment, size_t size)
{
	/* MINGW: just allocate normally; SIMD is not available on Windows anyway */
	(void)alignment;
	return malloc(size);
}
#endif

static __noreturn void simd_unavailable(const char *fn)
{
	fflush(stdout);
	fprintf(stderr, "%s: SIMD implementation not built on this platform\n",
		fn);
	abort();
}

/* POLYVAL stubs (prototypes as in polyval.c / polyval_xor.h) */
void clmul_polyval_mul(u8 *op1, const u8 *op2)
{
	(void)op1;
	(void)op2;
	simd_unavailable(__func__);
}

void clmul_polyval_update(const struct polyval_key *key, const u8 *in,
			  size_t nblocks, u8 *accumulator)
{
	(void)key;
	(void)in;
	(void)nblocks;
	(void)accumulator;
	simd_unavailable(__func__);
}

void polyval_xor_hash_clmul(const struct polyval_xor_key *key, const u8 *tweak,
			    size_t tweak_len, const u8 *msg, size_t msg_len,
			    u8 digest[16])
{
	(void)key;
	(void)tweak;
	(void)tweak_len;
	(void)msg;
	(void)msg_len;
	(void)digest;
	simd_unavailable(__func__);
}

/* AES stubs (prototypes as in aes_linux.h / xctr.c) */
void aesni_ecb_enc(const struct crypto_aes_ctx *ctx, u8 *dst, const u8 *src,
		   size_t len)
{
	(void)ctx;
	(void)dst;
	(void)src;
	(void)len;
	simd_unavailable(__func__);
}

void aesni_ecb_dec(const struct crypto_aes_ctx *ctx, u8 *dst, const u8 *src,
		   size_t len)
{
	(void)ctx;
	(void)dst;
	(void)src;
	(void)len;
	simd_unavailable(__func__);
}

#define XCTR_STUB(name)                                                        \
	void name(const u8 *in, const u8 *iv, const void *keys, u8 *out,      \
		  unsigned int num_bytes, unsigned int byte_ctr)               \
	{                                                                      \
		(void)in;                                                      \
		(void)iv;                                                      \
		(void)keys;                                                    \
		(void)out;                                                     \
		(void)num_bytes;                                               \
		(void)byte_ctr;                                                \
		simd_unavailable(__func__);                                    \
	}

XCTR_STUB(aes_xctr_enc_128_avx_by8)
XCTR_STUB(aes_xctr_enc_192_avx_by8)
XCTR_STUB(aes_xctr_enc_256_avx_by8)
