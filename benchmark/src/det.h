/*
 * Copyright 2026 CHCTR-HCTR2TwKD authors
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 *
 * Deterministic test bytes (splitmix64).  Repeatability only -- not crypto.
 */
#pragma once

#include "util.h"

static u64 det_state;

static inline void det_seed(u64 seed)
{
	det_state = seed;
}

static inline u8 det_u8(void)
{
	u64 z = (det_state += 0x9e3779b97f4a7c15ULL);

	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
	z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
	return (u8)((z ^ (z >> 31)) >> 56);
}

static inline void det_fill(u8 *p, size_t n)
{
	while (n--)
		*p++ = det_u8();
}
