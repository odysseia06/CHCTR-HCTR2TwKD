/*
 * Copyright 2026 CHCTR-HCTR2TwKD authors
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 *
 * Standalone conformance runner for the internal mode library.
 * Deterministic: no timing, no CPU-frequency probing, no rand().
 * Reports every failing case and keeps going; exits nonzero if any failed.
 */

#include <stdlib.h>

#include "aes_linux.h"
#include "chctr2.h"
#include "conformance_vectors.h"
#include "cpu_support.h"
#include "det.h"
#include "hctr2.h"
#include "hctr2_format.h"
#include "hctr2_testvecs.h"
#include "hctr2_twkd.h"
#include "polyval_xor.h"
#include "util.h"
#include "xctr.h"

static int checks, failures, skips;

__noreturn void assertion_failed(const char *expr, const char *file, int line)
{
	fflush(stdout);
	fprintf(stderr, "Assertion failed: %s at %s:%d\n", expr, file, line);
	abort();
}

static void report_diff(const char *profile, const char *id, const char *impl,
			const char *op, const u8 *expected, const u8 *actual,
			size_t len)
{
	size_t off = 0, i, start, end;

	while (off < len && expected[off] == actual[off])
		off++;
	fprintf(stderr,
		"FAIL profile=%s vector=%s impl=%s op=%s first-diff=%zu len=%zu\n",
		profile, id, impl, op, off, len);
	start = off >= 8 ? off - 8 : 0;
	end = min(len, off + 8);
	fprintf(stderr, "  expected:");
	for (i = start; i < end; i++)
		fprintf(stderr, " %02x", expected[i]);
	fprintf(stderr, "\n  actual:  ");
	for (i = start; i < end; i++)
		fprintf(stderr, " %02x", actual[i]);
	fprintf(stderr, "\n");
	failures++;
}

static void check_bytes(const char *profile, const char *id, const char *impl,
			const char *op, const u8 *expected, const u8 *actual,
			size_t len)
{
	checks++;
	if (memcmp(expected, actual, len))
		report_diff(profile, id, impl, op, expected, actual, len);
}

/* ---- hctr2_format unit checks (ported from test_hctr2_format) ---- */
static void test_format(void)
{
	u8 data[17], block[16];
	le128 length_block;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(data); i++)
		data[i] = i;

	hctr2_format_length_block(&length_block, 16, false);
	ASSERT(le64_to_cpu(length_block.b) == 16 * 8 * 2 + 3);
	ASSERT(le64_to_cpu(length_block.a) == 0);
	hctr2_format_length_block(&length_block, 16, true);
	ASSERT(le64_to_cpu(length_block.b) == 16 * 8 * 2 + 2);
	ASSERT(le64_to_cpu(length_block.a) == 0);

	ASSERT(hctr2_format_partial_block(block, data, sizeof(data), false));
	ASSERT(block[0] == data[16]);
	for (i = 1; i < ARRAY_SIZE(block); i++)
		ASSERT(block[i] == 0);

	ASSERT(hctr2_format_partial_block(block, data, sizeof(data), true));
	ASSERT(block[0] == data[16]);
	ASSERT(block[1] == 0x01);
	for (i = 2; i < ARRAY_SIZE(block); i++)
		ASSERT(block[i] == 0);

	ASSERT(!hctr2_format_partial_block(block, data, 16, true));
	checks++;
}

/* ---- frozen vectors: encrypt, decrypt, exact in-place ---- */
static void frozen_chctr2_one(const struct conf_vec *v, bool simd)
{
	const char *profile = "chctr2-aes256-polyval-v1";
	const char *impl = simd ? "accelerated" : "generic";
	struct chctr2_ctx *ctx =
		aligned_alloc(__alignof__(*ctx), sizeof(*ctx));
	u8 *out = malloc(v->len);
	u8 *buf = malloc(v->len);

	ASSERT(ctx && out && buf);
	ASSERT(v->key_len == 64);
	chctr2_setkey(ctx, v->key, simd);

	chctr2_crypt(ctx, out, v->plaintext, v->len, v->tweak, v->tweak_len,
		     true, simd);
	check_bytes(profile, v->id, impl, "encrypt", v->ciphertext, out,
		    v->len);
	chctr2_crypt(ctx, out, v->ciphertext, v->len, v->tweak, v->tweak_len,
		     false, simd);
	check_bytes(profile, v->id, impl, "decrypt", v->plaintext, out,
		    v->len);

	memcpy(buf, v->plaintext, v->len);
	chctr2_crypt(ctx, buf, buf, v->len, v->tweak, v->tweak_len, true,
		     simd);
	check_bytes(profile, v->id, impl, "encrypt-inplace", v->ciphertext,
		    buf, v->len);
	memcpy(buf, v->ciphertext, v->len);
	chctr2_crypt(ctx, buf, buf, v->len, v->tweak, v->tweak_len, false,
		     simd);
	check_bytes(profile, v->id, impl, "decrypt-inplace", v->plaintext,
		    buf, v->len);

	free(ctx);
	free(out);
	free(buf);
}

static void frozen_twkd_one(const struct conf_vec *v, bool simd)
{
	const char *profile = "hctr2-twkd-cenc126-aes256-polyval-v1";
	const char *impl = simd ? "accelerated" : "generic";
	struct hctr2_twkd_ctx *ctx =
		aligned_alloc(__alignof__(*ctx), sizeof(*ctx));
	u8 *out = malloc(v->len);
	u8 *buf = malloc(v->len);

	ASSERT(ctx && out && buf);
	ASSERT(v->key_len == 32 && v->tweak_len == TWKD_TWEAK_LEN);
	ASSERT((v->tweak[0] & 0xc0) == 0);
	twkd_setkey(ctx, v->key);

	twkd_crypt(ctx, out, v->plaintext, v->len, v->tweak, true, simd);
	check_bytes(profile, v->id, impl, "encrypt", v->ciphertext, out,
		    v->len);
	twkd_crypt(ctx, out, v->ciphertext, v->len, v->tweak, false, simd);
	check_bytes(profile, v->id, impl, "decrypt", v->plaintext, out,
		    v->len);

	memcpy(buf, v->plaintext, v->len);
	twkd_crypt(ctx, buf, buf, v->len, v->tweak, true, simd);
	check_bytes(profile, v->id, impl, "encrypt-inplace", v->ciphertext,
		    buf, v->len);
	memcpy(buf, v->ciphertext, v->len);
	twkd_crypt(ctx, buf, buf, v->len, v->tweak, false, simd);
	check_bytes(profile, v->id, impl, "decrypt-inplace", v->plaintext,
		    buf, v->len);

	free(ctx);
	free(out);
	free(buf);
}

static void test_frozen_vectors(bool simd_ok)
{
	size_t i;

	for (i = 0; i < chctr2_conf_tv_count; i++) {
		frozen_chctr2_one(&chctr2_conf_tv[i], false);
		if (simd_ok)
			frozen_chctr2_one(&chctr2_conf_tv[i], true);
	}
	for (i = 0; i < twkd_conf_tv_count; i++) {
		frozen_twkd_one(&twkd_conf_tv[i], false);
		if (simd_ok)
			frozen_twkd_one(&twkd_conf_tv[i], true);
	}
	if (!simd_ok)
		skips++;
}

/* ---- official HCTR2 vectors (ported from test_hctr2_testvecs) ---- */
static void official_one(const char *id, const struct hctr2_testvec *v,
			 size_t key_len, bool simd)
{
	const char *impl = simd ? "accelerated" : "generic";
	size_t len = v->plaintext.len;
	u8 *ctext = malloc(len);
	u8 *ptext = malloc(len);
	struct hctr2_ctx ctx;

	ASSERT(ctext && ptext);
	ASSERT(v->key.len == key_len);
	ASSERT(len >= BLOCKCIPHER_BLOCK_SIZE);
	ASSERT(v->ciphertext.len == len);

	hctr2_setkey(&ctx, v->key.data, key_len, simd);
	hctr2_crypt(&ctx, ctext, v->plaintext.data, len, v->tweak.data,
		    v->tweak.len, true, simd);
	check_bytes("hctr2-official", id, impl, "encrypt", v->ciphertext.data,
		    ctext, len);
	hctr2_crypt(&ctx, ptext, v->ciphertext.data, len, v->tweak.data,
		    v->tweak.len, false, simd);
	check_bytes("hctr2-official", id, impl, "decrypt", v->plaintext.data,
		    ptext, len);
	free(ctext);
	free(ptext);
}

static void test_official_hctr2(bool simd_ok)
{
	char id[32];
	size_t i;

	for (i = 0; i < hctr2_aes128_tv_count; i++) {
		snprintf(id, sizeof(id), "aes128[%zu]", i);
		official_one(id, &hctr2_aes128_tv[i], AES_KEYSIZE_128, false);
		if (simd_ok)
			official_one(id, &hctr2_aes128_tv[i], AES_KEYSIZE_128,
				     true);
	}
	for (i = 0; i < hctr2_aes192_tv_count; i++) {
		snprintf(id, sizeof(id), "aes192[%zu]", i);
		official_one(id, &hctr2_aes192_tv[i], AES_KEYSIZE_192, false);
		if (simd_ok)
			official_one(id, &hctr2_aes192_tv[i], AES_KEYSIZE_192,
				     true);
	}
	for (i = 0; i < hctr2_aes256_tv_count; i++) {
		snprintf(id, sizeof(id), "aes256[%zu]", i);
		official_one(id, &hctr2_aes256_tv[i], AES_KEYSIZE_256, false);
		if (simd_ok)
			official_one(id, &hctr2_aes256_tv[i], AES_KEYSIZE_256,
				     true);
	}
	if (!simd_ok)
		skips++;
}

/* ---- CHCTR2 optimized == black-box composition, deterministic ---- */
static void chctr2_composition_one(size_t len, size_t tweak_len, bool simd)
{
	const char *impl = simd ? "accelerated" : "generic";
	char id[48];
	u8 key[64], tweak[32];
	u8 *pt = malloc(len);
	u8 *ct = malloc(len);
	u8 *ref = malloc(len);
	u8 *tmp = malloc(len);
	struct chctr2_ctx *cctx =
		aligned_alloc(__alignof__(*cctx), sizeof(*cctx));
	struct hctr2_ctx hctx1, hctx2;

	ASSERT(pt && ct && ref && tmp && cctx);
	snprintf(id, sizeof(id), "composition-m%zu-t%zu", len, tweak_len);
	det_seed(0x43484354ULL ^ ((u64)len << 8) ^ tweak_len);
	det_fill(key, sizeof(key));
	det_fill(tweak, sizeof(tweak));
	det_fill(pt, len);

	chctr2_setkey(cctx, key, simd);
	hctr2_setkey(&hctx1, key, 32, simd);
	hctr2_setkey(&hctx2, key + 32, 32, simd);

	chctr2_crypt(cctx, ct, pt, len, tweak, tweak_len, true, simd);
	hctr2_crypt(&hctx1, tmp, pt, len, tweak, tweak_len, true, simd);
	hctr2_crypt(&hctx2, ref, tmp, len, tweak, tweak_len, true, simd);
	check_bytes("chctr2-internal", id, impl, "encrypt-vs-composition",
		    ref, ct, len);

	chctr2_crypt(cctx, tmp, ct, len, tweak, tweak_len, false, simd);
	check_bytes("chctr2-internal", id, impl, "decrypt-roundtrip", pt, tmp,
		    len);

	free(pt);
	free(ct);
	free(ref);
	free(tmp);
	free(cctx);
}

static void test_chctr2_composition(bool simd_ok)
{
	/* 65647..65664 straddle the middle hash's table boundary; the
	 * asserts keep the coverage honest if the constant ever changes. */
	static const size_t lens[] = { 16,    17,    31,    48,	   64,
				       128,   255,   512,   4096,  65536,
				       65647, 65648, 65649, 65664, 131072 };
	static const size_t tweak_lens[] = { 0, 16, 32 };
	size_t i, j;

	ASSERT(polyval_xor_nblocks(16, 65648 - 16) == POLYVAL_XOR_MAX_POWERS);
	ASSERT(polyval_xor_nblocks(16, 65649 - 16) > POLYVAL_XOR_MAX_POWERS);

	for (i = 0; i < ARRAY_SIZE(lens); i++) {
		for (j = 0; j < ARRAY_SIZE(tweak_lens); j++) {
			chctr2_composition_one(lens[i], tweak_lens[j], false);
			if (simd_ok)
				chctr2_composition_one(lens[i], tweak_lens[j],
						       true);
		}
	}
	if (!simd_ok)
		skips++;
}

/* ---- TwKD KDF known-answer test (constants from hctr2_twkd.c's KAT,
 * originally generated with an independent AES-256 implementation) ---- */
static void test_twkd_kdf_kat(bool simd_ok)
{
	static const u8 L[32] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
	};
	static const u8 T[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
				  0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
				  0xcc, 0xdd, 0xee, 0xff };
	static const u8 in0[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
				    0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
				    0xcc, 0xdd, 0xee, 0xff };
	static const u8 in1[16] = { 0x40, 0x11, 0x22, 0x33, 0x44, 0x55,
				    0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
				    0xcc, 0xdd, 0xee, 0xff };
	static const u8 in2[16] = { 0x80, 0x11, 0x22, 0x33, 0x44, 0x55,
				    0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
				    0xcc, 0xdd, 0xee, 0xff };
	static const u8 expected[32] = {
		0xb7, 0x55, 0xbd, 0x67, 0xc0, 0xcd, 0x84, 0xc0,
		0xa6, 0xaf, 0x30, 0xdd, 0xbd, 0x16, 0x2f, 0x6e,
		0x9b, 0xe3, 0x71, 0x6e, 0x2c, 0x48, 0xbb, 0xc7,
		0xf0, 0xb6, 0x30, 0xb4, 0x56, 0xea, 0xf9, 0x67
	};
	struct hctr2_twkd_ctx ctx;
	u8 e0[16], e1[16], e2[16], ref[32], subkey[32];
	int s;

	twkd_setkey(&ctx, L);
	for (s = 0; s < 2; s++) {
		bool simd = s == 1;

		if (simd && !simd_ok) {
			skips++;
			continue;
		}
		aes_encrypt(&ctx.kdf_aes, e0, in0, simd);
		aes_encrypt(&ctx.kdf_aes, e1, in1, simd);
		aes_encrypt(&ctx.kdf_aes, e2, in2, simd);
		xor(ref, e0, e1, 16);
		xor(ref + 16, e0, e2, 16);
		check_bytes("twkd-internal", "kdf-kat", simd ? "accelerated" :
			    "generic", "raw-aes", expected, ref, 32);

		twkd_derive(&ctx, T, subkey, simd);
		check_bytes("twkd-internal", "kdf-kat", simd ? "accelerated" :
			    "generic", "derive", expected, subkey, 32);
	}
}

/* ---- TwKD == HCTR2 with independently derived subkey, deterministic ---- */
static void twkd_equivalence_one(size_t len, bool simd)
{
	const char *impl = simd ? "accelerated" : "generic";
	char id[48];
	u8 L[32], tweak[16], in[16], e0[16], e1[16], e2[16], subkey[32];
	u8 *pt = malloc(len);
	u8 *ct = malloc(len);
	u8 *ref = malloc(len);
	u8 *rt = malloc(len);
	struct hctr2_twkd_ctx tctx;
	struct hctr2_ctx href;

	ASSERT(pt && ct && ref && rt);
	snprintf(id, sizeof(id), "equivalence-m%zu", len);
	det_seed(0x54774b44ULL ^ len);
	det_fill(L, sizeof(L));
	det_fill(tweak, sizeof(tweak));
	tweak[0] &= 0x3f; /* canonical T0 */
	det_fill(pt, len);

	twkd_setkey(&tctx, L);
	twkd_crypt(&tctx, ct, pt, len, tweak, true, simd);

	/* straight-line derivation, independent of twkd_derive */
	memcpy(in, tweak, 16);
	in[0] &= 0x3f;
	aes_encrypt(&tctx.kdf_aes, e0, in, simd);
	in[0] |= 0x40;
	aes_encrypt(&tctx.kdf_aes, e1, in, simd);
	in[0] ^= 0xc0; /* 0x40 -> 0x80 */
	aes_encrypt(&tctx.kdf_aes, e2, in, simd);
	xor(subkey, e0, e1, 16);
	xor(subkey + 16, e0, e2, 16);
	hctr2_setkey(&href, subkey, 32, simd);
	hctr2_crypt(&href, ref, pt, len, tweak, 0, true, simd);
	check_bytes("twkd-internal", id, impl, "encrypt-vs-derived", ref, ct,
		    len);

	twkd_crypt(&tctx, rt, ct, len, tweak, false, simd);
	check_bytes("twkd-internal", id, impl, "decrypt-roundtrip", pt, rt,
		    len);

	free(pt);
	free(ct);
	free(ref);
	free(rt);
}

static void test_twkd_equivalence(bool simd_ok)
{
	static const size_t lens[] = { 16,  17,	 31,   48,   64,    128,
				       255, 512, 4096, 65536, 131072 };
	size_t i;

	for (i = 0; i < ARRAY_SIZE(lens); i++) {
		twkd_equivalence_one(lens[i], false);
		if (simd_ok)
			twkd_equivalence_one(lens[i], true);
	}
	if (!simd_ok)
		skips++;
}

/* ---- merged-hash generic vs accelerated differential, deterministic
 * (ported from test_polyval_xor; includes table-boundary sizes) ---- */
static void polyval_xor_one(const struct polyval_xor_key *gk,
			    const struct polyval_xor_key *sk, size_t tweak_len,
			    size_t msg_len, const u8 *tweak, const u8 *msg)
{
	char id[48];
	u8 dg[16], ds[16];

	snprintf(id, sizeof(id), "pvx-m%zu-t%zu", msg_len, tweak_len);
	polyval_xor_hash(gk, tweak, tweak_len, msg, msg_len, dg, false);
	polyval_xor_hash(sk, tweak, tweak_len, msg, msg_len, ds, true);
	check_bytes("polyval-xor-internal", id, "generic-vs-accelerated",
		    "hash", dg, ds, 16);
}

static void test_polyval_xor_diff(bool simd_ok)
{
	/* 65632: with a 16-byte tweak, exactly POLYVAL_XOR_MAX_POWERS blocks
	 * (largest in-table).  65633/65648: just past it.  131056: well past. */
	static const size_t msg_lens[] = { 0,	1,     15,    16,    17,
					   127, 128,   129,   4096,  65632,
					   65633, 65648, 131056 };
	static const size_t tweak_lens[] = { 0, 16, 32 };
	struct polyval_xor_key *gk = malloc(sizeof(*gk));
	struct polyval_xor_key *sk = malloc(sizeof(*sk));
	u8 *msg = malloc(131056);
	u8 h1_raw[16], h2_raw[16], tweak[32];
	size_t i, j;

	ASSERT(gk && sk && msg);
	if (!simd_ok) {
		skips++;
		free(gk);
		free(sk);
		free(msg);
		return;
	}
	ASSERT(polyval_xor_nblocks(16, 65632) == POLYVAL_XOR_MAX_POWERS);
	ASSERT(polyval_xor_nblocks(16, 65633) > POLYVAL_XOR_MAX_POWERS);

	det_seed(0x50565853ULL);
	det_fill(h1_raw, 16);
	det_fill(h2_raw, 16);
	det_fill(tweak, sizeof(tweak));
	det_fill(msg, 131056);
	polyval_xor_setkey(gk, h1_raw, h2_raw, false);
	polyval_xor_setkey(sk, h1_raw, h2_raw, true);

	for (i = 0; i < ARRAY_SIZE(tweak_lens); i++)
		for (j = 0; j < ARRAY_SIZE(msg_lens); j++)
			polyval_xor_one(gk, sk, tweak_lens[i], msg_lens[j],
					tweak, msg);
	free(gk);
	free(sk);
	free(msg);
}

/* ---- XCTR in-place == out-of-place, deterministic ---- */
static void test_xctr_inplace(bool simd_ok)
{
	static const size_t lens[] = { 15, 16, 17, 64, 255, 256 };
	char id[32];
	u8 key[32], iv[16], src[256], out[256], tmp[256];
	struct aes_ctx ctx;
	size_t i;
	int s;

	det_seed(0x58435452ULL);
	det_fill(key, sizeof(key));
	det_fill(iv, sizeof(iv));
	det_fill(src, sizeof(src));
	aes_setkey(&ctx, key, AES_KEYSIZE_256);
	for (s = 0; s < 2; s++) {
		bool simd = s == 1;

		if (simd && !simd_ok) {
			skips++;
			continue;
		}
		for (i = 0; i < ARRAY_SIZE(lens); i++) {
			snprintf(id, sizeof(id), "inplace-m%zu", lens[i]);
			xctr_crypt(&ctx, out, src, lens[i], iv, simd);
			memcpy(tmp, src, lens[i]);
			xctr_crypt(&ctx, tmp, tmp, lens[i], iv, simd);
			check_bytes("xctr-internal", id, simd ? "accelerated" :
				    "generic", "in-place", out, tmp, lens[i]);
		}
	}
}

/* ---- manifest mode: externally supplied cases, one process ---- */
static int read_exact(FILE *f, u8 *buf, size_t n)
{
	return fread(buf, 1, n, f) == n;
}

static void manifest_case(u32 profile, u32 op, u32 impl, const u8 *key,
			  const u8 *tweak, u32 tweak_len, const u8 *in,
			  const u8 *expected, u64 len, const char *id)
{
	bool simd = impl == 1;
	bool encrypt = op == 0;
	const char *impl_name = simd ? "accelerated" : "generic";
	const char *op_name = encrypt ? "encrypt" : "decrypt";
	u8 *out = malloc(len);

	ASSERT(out);
	if (profile == 0) {
		struct chctr2_ctx *ctx =
			aligned_alloc(__alignof__(*ctx), sizeof(*ctx));

		ASSERT(ctx);
		chctr2_setkey(ctx, key, simd);
		chctr2_crypt(ctx, out, in, len, tweak, tweak_len, encrypt,
			     simd);
		check_bytes("chctr2-aes256-polyval-v1", id, impl_name,
			    op_name, expected, out, len);
		free(ctx);
	} else {
		struct hctr2_twkd_ctx *ctx =
			aligned_alloc(__alignof__(*ctx), sizeof(*ctx));

		ASSERT(ctx);
		twkd_setkey(ctx, key);
		twkd_crypt(ctx, out, in, len, tweak, encrypt, simd);
		check_bytes("hctr2-twkd-cenc126-aes256-polyval-v1", id,
			    impl_name, op_name, expected, out, len);
		free(ctx);
	}
	free(out);
}

static int run_manifest(const char *path, bool simd_ok)
{
	FILE *f = fopen(path, "rb");
	u8 hdr[28];
	long n = 0;

	if (!f) {
		fprintf(stderr, "cannot open manifest '%s'\n", path);
		return 2;
	}
	while (read_exact(f, hdr, sizeof(hdr))) {
		u32 profile = get_unaligned_le32(hdr);
		u32 op = get_unaligned_le32(hdr + 4);
		u32 impl = get_unaligned_le32(hdr + 8);
		u32 key_len = get_unaligned_le32(hdr + 12);
		u32 tweak_len = get_unaligned_le32(hdr + 16);
		u64 msg_len = get_unaligned_le64(hdr + 20);
		char id[32];
		u8 *key, *tweak, *in, *expected;
		bool valid;

		n++;
		snprintf(id, sizeof(id), "manifest#%ld", n);
		/* full profile validation before the core is touched */
		valid = profile <= 1 && op <= 1 && impl <= 1 &&
			key_len <= 64 && tweak_len <= 64 && msg_len >= 16 &&
			msg_len <= ((u64)1 << 28);
		if (valid && profile == 0)
			valid = key_len == 64;
		if (valid && profile == 1)
			valid = key_len == 32 && tweak_len == TWKD_TWEAK_LEN;
		if (!valid) {
			fprintf(stderr,
				"%s: profile-invalid record header\n", id);
			failures++;
			break; /* framing unknown -- cannot resync */
		}
		key = malloc(key_len);
		tweak = malloc(tweak_len ? tweak_len : 1);
		in = malloc(msg_len);
		expected = malloc(msg_len);
		ASSERT(key && tweak && in && expected);
		if (!read_exact(f, key, key_len) ||
		    !read_exact(f, tweak, tweak_len) ||
		    !read_exact(f, in, msg_len) ||
		    !read_exact(f, expected, msg_len)) {
			fprintf(stderr, "%s: truncated manifest\n", id);
			failures++;
			free(key);
			free(tweak);
			free(in);
			free(expected);
			break;
		}
		if (profile == 1 && (tweak[0] & 0xc0) != 0) {
			fprintf(stderr, "%s: noncanonical T0\n", id);
			failures++;
		} else if (impl == 1 && !simd_ok) {
			skips++;
		} else {
			manifest_case(profile, op, impl, key, tweak,
				      tweak_len, in, expected, msg_len, id);
		}
		free(key);
		free(tweak);
		free(in);
		free(expected);
	}
	fclose(f);
	return 0;
}

int main(int argc, char *argv[])
{
	bool simd_ok = simd_supported();

	if (!simd_ok)
		printf("conformance: accelerated implementation unsupported on this CPU; reporting skips\n");

	if (argc == 3 && !strcmp(argv[1], "--manifest")) {
		int err = run_manifest(argv[2], simd_ok);

		if (err)
			return err;
		printf("conformance(manifest): %d checks, %d failures, %d skipped\n",
		       checks, failures, skips);
		return failures ? 1 : 0;
	}
	if (argc != 1) {
		fprintf(stderr, "usage: conformance_tests [--manifest FILE]\n");
		return 2;
	}

	test_format();
	test_frozen_vectors(simd_ok);
	test_official_hctr2(simd_ok);
	test_chctr2_composition(simd_ok);
	test_twkd_kdf_kat(simd_ok);
	test_twkd_equivalence(simd_ok);
	test_polyval_xor_diff(simd_ok);
	test_xctr_inplace(simd_ok);

	printf("conformance: %d checks, %d failures, %d skipped\n", checks,
	       failures, skips);
	return failures ? 1 : 0;
}
