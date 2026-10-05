/*
 * Copyright 2026 CHCTR-HCTR2TwKD authors
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */
#pragma once

#include "polyval.h"

/*
 * Merged POLYVAL: computes H_H1(T,M) ^ H_H2(T,M) (the CHCTR2 middle hash
 * layer, ePrint 2026/085 Fig. 2) in one pass.  POLYVAL is linear in the
 * vector of key powers, so the merged hash is the inner product of the padded
 * input blocks with G_j = H1^j ^ H2^j (Montgomery dot-powers).  G_j is not a
 * geometric sequence, so this is strictly one-shot: every block's power index
 * depends on the total block count, known up front.  No streaming API.
 */

/* 4096 message blocks (64 KiB) + 1 length block + 2 tweak blocks + margin.
 * Note: table sized for the paper's 64 KiB benchmark; longer inputs fall
 * back to two passes -- enlarge if bigger messages must stay fast. */
#define POLYVAL_XOR_MAX_POWERS 4104

struct polyval_xor_key {
	struct polyval_key h1;
	struct polyval_key h2;
#ifdef __x86_64__
	/* g[j-1] = H1^j ^ H2^j in Montgomery form, ascending j */
	u8 g[POLYVAL_XOR_MAX_POWERS][16] __attribute__((aligned(16)));
#endif
};

/* Total block count of pad(T,M): length block + padded tweak + padded msg.
 * Exposed so tests assert boundary sizes with the same formula. */
size_t polyval_xor_nblocks(size_t tweak_len, size_t msg_len);

void polyval_xor_setkey(struct polyval_xor_key *key, const u8 *h1_raw,
			const u8 *h2_raw, bool simd);
void polyval_xor_hash(const struct polyval_xor_key *key, const u8 *tweak,
		      size_t tweak_len, const u8 *msg, size_t msg_len,
		      u8 digest[16], bool simd);

#ifdef __x86_64__
/* One-pass CLMUL fast path; requires
 * polyval_xor_nblocks(...) <= POLYVAL_XOR_MAX_POWERS and simd setkey. */
void polyval_xor_hash_clmul(const struct polyval_xor_key *key, const u8 *tweak,
			    size_t tweak_len, const u8 *msg, size_t msg_len,
			    u8 digest[16]);
#endif
