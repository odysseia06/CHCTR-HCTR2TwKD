/*
 * Copyright 2018 Google LLC / 2026 CHCTR-HCTR2TwKD authors
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 *
 * All benchmark registrations, benchmark-template includes, and startup
 * self-tests, moved out of the production translation units.
 */

#include "aes_linux.h"
#include "chctr2.h"
#include "conformance_vectors.h"
#include "cpu_support.h"
#include "det.h"
#include "hctr2.h"
#include "hctr2_testvecs.h"
#include "hctr2_twkd.h"
#include "polyval.h"
#include "polyval_xor.h"
#include "util.h"
#include "xctr.h"

/* ---- frozen smoke vectors: one per mode, each available implementation,
 * before any timing.  Failure aborts before benchmarks run. ---- */
static void smoke_check(const char *alg, const char *impl, const u8 *expected,
			const u8 *actual, size_t len)
{
	if (memcmp(expected, actual, len)) {
		fflush(stdout);
		fprintf(stderr, "%s smoke vector FAILED (%s)\n", alg, impl);
		exit(1);
	}
}

/* ---- HCTR2 ---- */
static void hctr2_setkey_aes128_generic(struct hctr2_ctx *ctx, const u8 *key)
{
	hctr2_setkey(ctx, key, AES_KEYSIZE_128, false);
}

static void hctr2_setkey_aes128_simd(struct hctr2_ctx *ctx, const u8 *key)
{
	hctr2_setkey(ctx, key, AES_KEYSIZE_128, true);
}

static void hctr2_setkey_aes192_generic(struct hctr2_ctx *ctx, const u8 *key)
{
	hctr2_setkey(ctx, key, AES_KEYSIZE_192, false);
}

static void hctr2_setkey_aes192_simd(struct hctr2_ctx *ctx, const u8 *key)
{
	hctr2_setkey(ctx, key, AES_KEYSIZE_192, true);
}

static void hctr2_setkey_aes256_generic(struct hctr2_ctx *ctx, const u8 *key)
{
	hctr2_setkey(ctx, key, AES_KEYSIZE_256, false);
}

static void hctr2_setkey_aes256_simd(struct hctr2_ctx *ctx, const u8 *key)
{
	hctr2_setkey(ctx, key, AES_KEYSIZE_256, true);
}

static void hctr2_encrypt_generic(const struct hctr2_ctx *ctx, u8 *dst,
				  const u8 *src, size_t nbytes, const u8 *tweak)
{
	hctr2_crypt(ctx, dst, src, nbytes, tweak, ctx->default_tweak_len, true,
		    false);
}

static void hctr2_decrypt_generic(const struct hctr2_ctx *ctx, u8 *dst,
				  const u8 *src, size_t nbytes, const u8 *tweak)
{
	hctr2_crypt(ctx, dst, src, nbytes, tweak, ctx->default_tweak_len, false,
		    false);
}

static void hctr2_encrypt_simd(const struct hctr2_ctx *ctx, u8 *dst,
			       const u8 *src, size_t nbytes, const u8 *tweak)
{
	hctr2_crypt(ctx, dst, src, nbytes, tweak, ctx->default_tweak_len, true,
		    true);
}

static void hctr2_decrypt_simd(const struct hctr2_ctx *ctx, u8 *dst,
			       const u8 *src, size_t nbytes, const u8 *tweak)
{
	hctr2_crypt(ctx, dst, src, nbytes, tweak, ctx->default_tweak_len, false,
		    true);
}

static void smoke_hctr2_vec(const struct hctr2_testvec *v, size_t key_len,
			    const char *alg)
{
	size_t len = v->plaintext.len;
	u8 out[len];
	struct hctr2_ctx ctx;
	int s;

	for (s = 0; s < 2; s++) {
		bool simd = s == 1;

		if (simd && !simd_supported())
			continue;
		hctr2_setkey(&ctx, v->key.data, key_len, simd);
		hctr2_crypt(&ctx, out, v->plaintext.data, len, v->tweak.data,
			    v->tweak.len, true, simd);
		smoke_check(alg, simd ? "simd" : "generic",
			    v->ciphertext.data, out, len);
		hctr2_crypt(&ctx, out, v->ciphertext.data, len, v->tweak.data,
			    v->tweak.len, false, simd);
		smoke_check(alg, simd ? "simd" : "generic",
			    v->plaintext.data, out, len);
	}
}

static void smoke_hctr2(void)
{
	smoke_hctr2_vec(&hctr2_aes128_tv[0], AES_KEYSIZE_128, "AES-128-HCTR2");
	smoke_hctr2_vec(&hctr2_aes192_tv[0], AES_KEYSIZE_192, "AES-192-HCTR2");
	smoke_hctr2_vec(&hctr2_aes256_tv[0], AES_KEYSIZE_256, "AES-256-HCTR2");
}

void test_hctr2(void)
{
	smoke_hctr2();
#define ALGNAME "AES-128-HCTR2"
#define KEY_BYTES AES_KEYSIZE_128
#define IV_BYTES HCTR2_DEFAULT_TWEAK_LEN
#define KEY struct hctr2_ctx
#define SETKEY hctr2_setkey_aes128_generic
#define SETKEY_SIMD hctr2_setkey_aes128_simd
#define ENCRYPT hctr2_encrypt_generic
#define DECRYPT hctr2_decrypt_generic
#define ENCRYPT_SIMD hctr2_encrypt_simd
#define DECRYPT_SIMD hctr2_decrypt_simd
#define SIMD_IMPL_NAME "simd"
#include "cipher_benchmark_template.h"

#define ALGNAME "AES-192-HCTR2"
#define KEY_BYTES AES_KEYSIZE_192
#define IV_BYTES HCTR2_DEFAULT_TWEAK_LEN
#define KEY struct hctr2_ctx
#define SETKEY hctr2_setkey_aes192_generic
#define SETKEY_SIMD hctr2_setkey_aes192_simd
#define ENCRYPT hctr2_encrypt_generic
#define DECRYPT hctr2_decrypt_generic
#define ENCRYPT_SIMD hctr2_encrypt_simd
#define DECRYPT_SIMD hctr2_decrypt_simd
#define SIMD_IMPL_NAME "simd"
#include "cipher_benchmark_template.h"

#define ALGNAME "AES-256-HCTR2"
#define KEY_BYTES AES_KEYSIZE_256
#define IV_BYTES HCTR2_DEFAULT_TWEAK_LEN
#define KEY struct hctr2_ctx
#define SETKEY hctr2_setkey_aes256_generic
#define SETKEY_SIMD hctr2_setkey_aes256_simd
#define ENCRYPT hctr2_encrypt_generic
#define DECRYPT hctr2_decrypt_generic
#define ENCRYPT_SIMD hctr2_encrypt_simd
#define DECRYPT_SIMD hctr2_decrypt_simd
#define SIMD_IMPL_NAME "simd"
#include "cipher_benchmark_template.h"
}

/* ---- CHCTR2 ---- */
static void smoke_chctr2(void)
{
	const struct conf_vec *v = &chctr2_conf_tv[0];
	struct chctr2_ctx *ctx =
		aligned_alloc(__alignof__(*ctx), sizeof(*ctx));
	u8 *out = malloc(v->len);
	int s;

	ASSERT(ctx && out);
	for (s = 0; s < 2; s++) {
		bool simd = s == 1;

		if (simd && !simd_supported())
			continue;
		chctr2_setkey(ctx, v->key, simd);
		chctr2_crypt(ctx, out, v->plaintext, v->len, v->tweak,
			     v->tweak_len, true, simd);
		smoke_check("AES-256-CHCTR2", simd ? "simd" : "generic",
			    v->ciphertext, out, v->len);
		chctr2_crypt(ctx, out, v->ciphertext, v->len, v->tweak,
			     v->tweak_len, false, simd);
		smoke_check("AES-256-CHCTR2", simd ? "simd" : "generic",
			    v->plaintext, out, v->len);
	}
	free(ctx);
	free(out);
}

static void chctr2_setkey_generic(struct chctr2_ctx *ctx, const u8 *key)
{
	chctr2_setkey(ctx, key, false);
}

static void chctr2_setkey_simd(struct chctr2_ctx *ctx, const u8 *key)
{
	chctr2_setkey(ctx, key, true);
}

static void chctr2_encrypt_generic(const struct chctr2_ctx *ctx, u8 *dst,
				   const u8 *src, size_t nbytes,
				   const u8 *tweak)
{
	chctr2_crypt(ctx, dst, src, nbytes, tweak, ctx->default_tweak_len,
		     true, false);
}

static void chctr2_decrypt_generic(const struct chctr2_ctx *ctx, u8 *dst,
				   const u8 *src, size_t nbytes,
				   const u8 *tweak)
{
	chctr2_crypt(ctx, dst, src, nbytes, tweak, ctx->default_tweak_len,
		     false, false);
}

static void chctr2_encrypt_simd(const struct chctr2_ctx *ctx, u8 *dst,
				const u8 *src, size_t nbytes, const u8 *tweak)
{
	chctr2_crypt(ctx, dst, src, nbytes, tweak, ctx->default_tweak_len,
		     true, true);
}

static void chctr2_decrypt_simd(const struct chctr2_ctx *ctx, u8 *dst,
				const u8 *src, size_t nbytes, const u8 *tweak)
{
	chctr2_crypt(ctx, dst, src, nbytes, tweak, ctx->default_tweak_len,
		     false, true);
}

void test_chctr2(void)
{
	smoke_chctr2();
#define ALGNAME "AES-256-CHCTR2"
#define KEY_BYTES 64
#define IV_BYTES HCTR2_DEFAULT_TWEAK_LEN
#define KEY struct chctr2_ctx
#define SETKEY chctr2_setkey_generic
#define SETKEY_SIMD chctr2_setkey_simd
#define ENCRYPT chctr2_encrypt_generic
#define DECRYPT chctr2_decrypt_generic
#define ENCRYPT_SIMD chctr2_encrypt_simd
#define DECRYPT_SIMD chctr2_decrypt_simd
#define SIMD_IMPL_NAME "simd"
#include "cipher_benchmark_template.h"
}

/* ---- HCTR2-TwKD ---- */
static void smoke_twkd(void)
{
	const struct conf_vec *v = &twkd_conf_tv[0];
	struct hctr2_twkd_ctx *ctx =
		aligned_alloc(__alignof__(*ctx), sizeof(*ctx));
	u8 *out = malloc(v->len);
	int s;

	ASSERT(ctx && out);
	twkd_setkey(ctx, v->key);
	for (s = 0; s < 2; s++) {
		bool simd = s == 1;

		if (simd && !simd_supported())
			continue;
		twkd_crypt(ctx, out, v->plaintext, v->len, v->tweak, true,
			   simd);
		smoke_check("AES-256-HCTR2-TwKD", simd ? "simd" : "generic",
			    v->ciphertext, out, v->len);
		twkd_crypt(ctx, out, v->ciphertext, v->len, v->tweak, false,
			   simd);
		smoke_check("AES-256-HCTR2-TwKD", simd ? "simd" : "generic",
			    v->plaintext, out, v->len);
	}
	free(ctx);
	free(out);
}

static void twkd_setkey_generic(struct hctr2_twkd_ctx *ctx, const u8 *key)
{
	twkd_setkey(ctx, key);
}

static void twkd_setkey_simd(struct hctr2_twkd_ctx *ctx, const u8 *key)
{
	twkd_setkey(ctx, key);
}

/* The template draws a random 16-byte IV, but T0 is a 126-bit value: clear
 * the two KDF prefix bits first (a 16-byte copy per call, negligible). */
static void twkd_bench_crypt(const struct hctr2_twkd_ctx *ctx, u8 *dst,
			     const u8 *src, size_t nbytes, const u8 *tweak,
			     bool encrypt, bool simd)
{
	u8 t0[TWKD_TWEAK_LEN];

	memcpy(t0, tweak, sizeof(t0));
	t0[0] &= 0x3f;
	twkd_crypt(ctx, dst, src, nbytes, t0, encrypt, simd);
}

static void twkd_encrypt_generic(const struct hctr2_twkd_ctx *ctx, u8 *dst,
				 const u8 *src, size_t nbytes, const u8 *tweak)
{
	twkd_bench_crypt(ctx, dst, src, nbytes, tweak, true, false);
}

static void twkd_decrypt_generic(const struct hctr2_twkd_ctx *ctx, u8 *dst,
				 const u8 *src, size_t nbytes, const u8 *tweak)
{
	twkd_bench_crypt(ctx, dst, src, nbytes, tweak, false, false);
}

static void twkd_encrypt_simd(const struct hctr2_twkd_ctx *ctx, u8 *dst,
			      const u8 *src, size_t nbytes, const u8 *tweak)
{
	twkd_bench_crypt(ctx, dst, src, nbytes, tweak, true, true);
}

static void twkd_decrypt_simd(const struct hctr2_twkd_ctx *ctx, u8 *dst,
			      const u8 *src, size_t nbytes, const u8 *tweak)
{
	twkd_bench_crypt(ctx, dst, src, nbytes, tweak, false, true);
}

void test_hctr2_twkd(void)
{
	smoke_twkd();
#define ALGNAME "AES-256-HCTR2-TwKD"
#define KEY_BYTES 32
#define IV_BYTES TWKD_TWEAK_LEN
#define KEY struct hctr2_twkd_ctx
#define SETKEY twkd_setkey_generic
#define SETKEY_SIMD twkd_setkey_simd
#define ENCRYPT twkd_encrypt_generic
#define DECRYPT twkd_decrypt_generic
#define ENCRYPT_SIMD twkd_encrypt_simd
#define DECRYPT_SIMD twkd_decrypt_simd
#define SIMD_IMPL_NAME "simd"
#include "cipher_benchmark_template.h"
}

/* ---- Polyval ---- */
static void _polyval(const struct polyval_key *key, const void *src,
		     unsigned int srclen, u8 *digest, bool simd)
{
	struct polyval_state polystate;
	size_t nblocks = srclen / POLYVAL_BLOCK_SIZE;

	ASSERT(srclen % POLYVAL_BLOCK_SIZE == 0);

	polyval_init(&polystate);
	polyval_update(&polystate, key, src, nblocks, simd);
	polyval_emit(&polystate, digest, simd);
}

static void _polyval_generic(const struct polyval_key *key, const void *src,
			     unsigned int srclen, u8 *digest)
{
	_polyval(key, src, srclen, digest, false);
}

static void _polyval_simd(const struct polyval_key *key, const void *src,
			  unsigned int srclen, u8 *digest)
{
	_polyval(key, src, srclen, digest, true);
}

/* NEW: 2-arg setkey wrappers for the hash template (the static
 * polyval_setkey_generic/_simd stayed in polyval.c). */
static void bench_polyval_setkey_generic(struct polyval_key *key, const u8 *raw)
{
	polyval_setkey(key, raw, false);
}

static void bench_polyval_setkey_simd(struct polyval_key *key, const u8 *raw)
{
	polyval_setkey(key, raw, true);
}

/* Primitives have no mode-level frozen vectors; their smoke is a
 * deterministic generic-vs-simd agreement check on fixed bytes. */
static void smoke_polyval(void)
{
	struct polyval_key gk, sk;
	struct polyval_state st;
	u8 raw[16], data[64], dg[16], ds[16];

	det_seed(0x506f6c79ULL);
	det_fill(raw, sizeof(raw));
	det_fill(data, sizeof(data));
	polyval_setkey(&gk, raw, false);
	polyval_init(&st);
	polyval_update(&st, &gk, data, 4, false);
	polyval_emit(&st, dg, false);
	if (simd_supported()) {
		polyval_setkey(&sk, raw, true);
		polyval_init(&st);
		polyval_update(&st, &sk, data, 4, true);
		polyval_emit(&st, ds, true);
		smoke_check("Polyval", "generic-vs-simd", dg, ds, 16);
	}
}

void test_polyval(void)
{
	smoke_polyval();
#define ALGNAME "Polyval"
#define HASH _polyval_generic
#define HASH_SIMD _polyval_simd
#define SIMD_IMPL_NAME "clmul"
#define KEY struct polyval_key
#define SETKEY bench_polyval_setkey_generic
#define SETKEY_SIMD bench_polyval_setkey_simd
#define KEY_BYTES POLYVAL_KEY_SIZE
#define DIGEST_SIZE POLYVAL_DIGEST_SIZE
#include "hash_benchmark_template.h"
}

/* ---- XCTR ---- */
/* NEW: 5-arg crypt wrappers for the cipher template (the static
 * xctr_crypt_generic/_simd stayed in xctr.c). */
static void bench_xctr_generic(const struct aes_ctx *ctx, u8 *dst,
			       const u8 *src, size_t nbytes, const u8 *iv)
{
	xctr_crypt(ctx, dst, src, nbytes, iv, false);
}

static void bench_xctr_simd(const struct aes_ctx *ctx, u8 *dst, const u8 *src,
			    size_t nbytes, const u8 *iv)
{
	xctr_crypt(ctx, dst, src, nbytes, iv, true);
}

static void xctr_aes128_setkey(struct aes_ctx *ctx, const u8 *key)
{
	aes_setkey(ctx, key, AES_KEYSIZE_128);
}

static void xctr_aes192_setkey(struct aes_ctx *ctx, const u8 *key)
{
	aes_setkey(ctx, key, AES_KEYSIZE_192);
}

static void xctr_aes256_setkey(struct aes_ctx *ctx, const u8 *key)
{
	aes_setkey(ctx, key, AES_KEYSIZE_256);
}

static void smoke_xctr(void)
{
	u8 key[32], iv[16], src[255], out[255], tmp[255];
	struct aes_ctx ctx;

	det_seed(0x58435452ULL);
	det_fill(key, sizeof(key));
	det_fill(iv, sizeof(iv));
	det_fill(src, sizeof(src));
	aes_setkey(&ctx, key, AES_KEYSIZE_256);
	xctr_crypt(&ctx, out, src, sizeof(src), iv, false);
	memcpy(tmp, src, sizeof(src));
	xctr_crypt(&ctx, tmp, tmp, sizeof(src), iv, false);
	smoke_check("AES-256-XCTR", "generic-inplace", out, tmp, sizeof(src));
	if (simd_supported()) {
		xctr_crypt(&ctx, tmp, src, sizeof(src), iv, true);
		smoke_check("AES-256-XCTR", "generic-vs-simd", out, tmp,
			    sizeof(src));
	}
}

void test_xctr(void)
{
	smoke_xctr();

#define ALGNAME "AES-128-XCTR"
#define KEY_BYTES AES_KEYSIZE_128
#define IV_BYTES XCTR_IV_SIZE
#define KEY struct aes_ctx
#define SETKEY xctr_aes128_setkey
#define SETKEY_SIMD xctr_aes128_setkey
#define ENCRYPT bench_xctr_generic
#define DECRYPT bench_xctr_generic
#define SIMD_IMPL_NAME "simd"
#define ENCRYPT_SIMD bench_xctr_simd
#define DECRYPT_SIMD bench_xctr_simd
#include "cipher_benchmark_template.h"

#define ALGNAME "AES-192-XCTR"
#define KEY_BYTES AES_KEYSIZE_192
#define IV_BYTES XCTR_IV_SIZE
#define KEY struct aes_ctx
#define SETKEY xctr_aes192_setkey
#define SETKEY_SIMD xctr_aes192_setkey
#define ENCRYPT bench_xctr_generic
#define DECRYPT bench_xctr_generic
#define SIMD_IMPL_NAME "simd"
#define ENCRYPT_SIMD bench_xctr_simd
#define DECRYPT_SIMD bench_xctr_simd
#include "cipher_benchmark_template.h"

#define ALGNAME "AES-256-XCTR"
#define KEY_BYTES AES_KEYSIZE_256
#define IV_BYTES XCTR_IV_SIZE
#define KEY struct aes_ctx
#define SETKEY xctr_aes256_setkey
#define SETKEY_SIMD xctr_aes256_setkey
#define ENCRYPT bench_xctr_generic
#define DECRYPT bench_xctr_generic
#define SIMD_IMPL_NAME "simd"
#define ENCRYPT_SIMD bench_xctr_simd
#define DECRYPT_SIMD bench_xctr_simd
#include "cipher_benchmark_template.h"
}
