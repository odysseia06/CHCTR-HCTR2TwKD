/*
 * Copyright 2026 CHCTR-HCTR2TwKD authors
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 *
 * Declarations for the build-time generated frozen-vector fixtures
 * (tools/vectors_to_c.py).
 */
#pragma once

#include "util.h"

struct conf_vec {
	const char *id;
	const u8 *key;
	size_t key_len;
	const u8 *tweak;
	size_t tweak_len;
	const u8 *plaintext;
	const u8 *ciphertext;
	size_t len;
};

extern const struct conf_vec chctr2_conf_tv[];
extern const size_t chctr2_conf_tv_count;
extern const struct conf_vec twkd_conf_tv[];
extern const size_t twkd_conf_tv_count;
