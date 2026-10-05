/*
 * Copyright 2026 CHCTR-HCTR2TwKD authors
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

#include "polyval_xor.h"
#include "hctr2_format.h"
#include "util.h"

#ifdef __x86_64__
asmlinkage void clmul_polyval_mul(u8 *op1, const u8 *op2);
#endif

size_t polyval_xor_nblocks(size_t tweak_len, size_t msg_len)
{
	return 1 + (tweak_len + 15) / 16 + (msg_len + 15) / 16;
}

void polyval_xor_setkey(struct polyval_xor_key *key, const u8 *h1_raw,
			const u8 *h2_raw, bool simd)
{
	polyval_setkey(&key->h1, h1_raw, simd);
	polyval_setkey(&key->h2, h2_raw, simd);
#ifdef __x86_64__
	if (simd) {
		u8 p1[16], p2[16];
		size_t j;

		/* g[j-1] = H1^j ^ H2^j; powers chained with the same
		 * Montgomery multiplication polyval_setkey_simd uses. */
		memcpy(p1, h1_raw, 16);
		memcpy(p2, h2_raw, 16);
		xor(key->g[0], p1, p2, 16);
		for (j = 1; j < POLYVAL_XOR_MAX_POWERS; j++) {
			clmul_polyval_mul(p1, h1_raw);
			clmul_polyval_mul(p2, h2_raw);
			xor(key->g[j], p1, p2, 16);
		}
	}
#endif
}

/*
 * Reference path: hash pad(T,M) twice with the ordinary polyval (keys H1 and
 * H2) and XOR the digests.  Padding matches hctr2.c: little-endian length
 * block (tweak_len*8*2 + 2, +1 if the message is not block-aligned), then
 * zero-padded tweak, then message with a 0x01 marker byte if not aligned.
 */
static void polyval_xor_two_pass(const struct polyval_xor_key *key,
				 const u8 *tweak, size_t tweak_len,
				 const u8 *msg, size_t msg_len, u8 digest[16],
				 bool simd)
{
	const struct polyval_key *pk[2] = { &key->h1, &key->h2 };
	u8 dig2[16];
	u8 block[16];
	le128 lenblock;
	int i;

	for (i = 0; i < 2; i++) {
		u8 *out = i ? dig2 : digest;
		struct polyval_state st;

		polyval_init(&st);
		hctr2_format_length_block(&lenblock, tweak_len,
					  msg_len % 16 == 0);
		polyval_update(&st, pk[i], (u8 *)&lenblock, 1, simd);

		polyval_update(&st, pk[i], tweak, tweak_len / 16, simd);
		if (hctr2_format_partial_block(block, tweak, tweak_len, false))
			polyval_update(&st, pk[i], block, 1, simd);

		polyval_update(&st, pk[i], msg, msg_len / 16, simd);
		if (hctr2_format_partial_block(block, msg, msg_len, true))
			polyval_update(&st, pk[i], block, 1, simd);
		polyval_emit(&st, out, simd);
	}
	xor(digest, digest, dig2, 16);
}

void polyval_xor_hash(const struct polyval_xor_key *key, const u8 *tweak,
		      size_t tweak_len, const u8 *msg, size_t msg_len,
		      u8 digest[16], bool simd)
{
#ifdef __x86_64__
	if (simd && polyval_xor_nblocks(tweak_len, msg_len) <=
				    POLYVAL_XOR_MAX_POWERS) {
		polyval_xor_hash_clmul(key, tweak, tweak_len, msg, msg_len,
				       digest);
		return;
	}
#endif
	polyval_xor_two_pass(key, tweak, tweak_len, msg, msg_len, digest, simd);
}
