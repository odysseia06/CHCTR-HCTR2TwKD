/*
 * Copyright 2026 CHCTR-HCTR2TwKD authors
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */
#pragma once

#include "polyval.h"

static inline void
hctr2_format_length_block(le128 *block, size_t tweak_len,
			  bool message_is_block_aligned)
{
	block->b = cpu_to_le64((u64)tweak_len * 8 * 2 +
			       (message_is_block_aligned ? 2 : 3));
	block->a = cpu_to_le64(0);
}

/*
 * Format the final partial block of a tweak or message.  Tweaks are padded
 * with zeroes; messages additionally append the HCTR2 0x01 marker.
 */
static inline bool
hctr2_format_partial_block(u8 block[POLYVAL_BLOCK_SIZE], const u8 *data,
			   size_t nbytes, bool message_padding)
{
	size_t remainder = nbytes % POLYVAL_BLOCK_SIZE;

	if (!remainder)
		return false;
	memset(block, 0, POLYVAL_BLOCK_SIZE);
	memcpy(block, data + nbytes - remainder, remainder);
	if (message_padding)
		block[remainder] = 0x01;
	return true;
}
