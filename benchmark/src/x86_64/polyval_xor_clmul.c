/*
 * Copyright 2026 CHCTR-HCTR2TwKD authors
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 *
 * One-pass merged POLYVAL over pad(T,M): inner product of the padded input
 * blocks with the precomputed table G_j = H1^j ^ H2^j.  Because there is no
 * Horner chaining, the schoolbook partial products (LO/MI/HI) accumulate by
 * XOR across the whole input and a single Montgomery reduction finishes.
 */

#include <immintrin.h>

#include "hctr2_format.h"
#include "polyval_xor.h"
#include "util.h"

struct pxacc {
	__m128i lo, mi, hi;
};

static inline void acc_block(struct pxacc *a, __m128i x, __m128i y)
{
	a->lo = _mm_xor_si128(a->lo, _mm_clmulepi64_si128(x, y, 0x00));
	a->mi = _mm_xor_si128(a->mi, _mm_clmulepi64_si128(x, y, 0x01));
	a->mi = _mm_xor_si128(a->mi, _mm_clmulepi64_si128(x, y, 0x10));
	a->hi = _mm_xor_si128(a->hi, _mm_clmulepi64_si128(x, y, 0x11));
}

static inline void acc_mem(struct pxacc *a, const u8 *block,
			   const u8 (*g)[16])
{
	acc_block(a, _mm_loadu_si128((const __m128i *)block),
		  _mm_load_si128((const __m128i *)*g));
}

/* Step g down by `step` table entries. g always walks from &base[m-1] down
 * to &base[0], one entry per input block; the last block processed lands
 * exactly on &base[0]. A trailing "prepare for the next block" decrement
 * after that last block would form &base[-1] -- never dereferenced, but
 * still UB per C11 6.5.6p8. Clamp at base instead. */
static inline const u8 (*g_dec(const u8 (*g)[16], const u8 (*base)[16],
			       size_t step))[16]
{
	return (g == base + (step - 1)) ? base : g - step;
}

/* Translation of montgomery_reduction in polyval-clmulni_asm.S. */
static inline __m128i pxacc_reduce(const struct pxacc *a)
{
	const __m128i gstar =
		_mm_set1_epi64x((long long)0xc200000000000000ULL);
	__m128i pl = _mm_xor_si128(a->lo, _mm_slli_si128(a->mi, 8));
	__m128i ph = _mm_xor_si128(a->hi, _mm_srli_si128(a->mi, 8));
	__m128i t;

	t = _mm_clmulepi64_si128(pl, gstar, 0x00); /* T = P_0 * g* */
	t = _mm_shuffle_epi32(t, 0x4e);		   /* swap 64-bit halves */
	t = _mm_xor_si128(t, pl);		   /* P_1+T_0 : P_0+T_1 */
	ph = _mm_xor_si128(ph, t);
	t = _mm_clmulepi64_si128(t, gstar, 0x11);  /* V = (P_1+T_0) * g* */
	return _mm_xor_si128(ph, t);
}

void polyval_xor_hash_clmul(const struct polyval_xor_key *key, const u8 *tweak,
			    size_t tweak_len, const u8 *msg, size_t msg_len,
			    u8 digest[16])
{
	size_t m = polyval_xor_nblocks(tweak_len, msg_len);
	/* g walks DOWN from the entry for power m as the input walks up */
	const u8 (*g)[16] = &key->g[m - 1];
	struct pxacc a = { _mm_setzero_si128(), _mm_setzero_si128(),
			   _mm_setzero_si128() };
	le128 lenblock;
	u8 block[16];
	size_t n, rem;

	ASSERT(m <= POLYVAL_XOR_MAX_POWERS);

	hctr2_format_length_block(&lenblock, tweak_len, msg_len % 16 == 0);
	acc_mem(&a, (const u8 *)&lenblock, g);
	g = g_dec(g, key->g, 1);

	for (n = tweak_len / 16; n; n--, tweak += 16, g = g_dec(g, key->g, 1))
		acc_mem(&a, tweak, g);
	rem = tweak_len % 16;
	if (rem) {
		ASSERT(hctr2_format_partial_block(block, tweak, rem, false));
		acc_mem(&a, block, g);
		g = g_dec(g, key->g, 1);
	}

	n = msg_len / 16;
	while (n >= 8) {
		acc_mem(&a, msg + 0 * 16, g - 0);
		acc_mem(&a, msg + 1 * 16, g - 1);
		acc_mem(&a, msg + 2 * 16, g - 2);
		acc_mem(&a, msg + 3 * 16, g - 3);
		acc_mem(&a, msg + 4 * 16, g - 4);
		acc_mem(&a, msg + 5 * 16, g - 5);
		acc_mem(&a, msg + 6 * 16, g - 6);
		acc_mem(&a, msg + 7 * 16, g - 7);
		msg += 8 * 16;
		g = g_dec(g, key->g, 8);
		n -= 8;
	}
	for (; n; n--, msg += 16, g = g_dec(g, key->g, 1))
		acc_mem(&a, msg, g);
	rem = msg_len % 16;
	if (rem) {
		ASSERT(hctr2_format_partial_block(block, msg, rem, true));
		acc_mem(&a, block, g);
	}

	_mm_storeu_si128((__m128i *)digest, pxacc_reduce(&a));
}
