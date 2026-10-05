/*
 * Copyright 2026 CHCTR-HCTR2TwKD authors
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */
#pragma once

#include <stdbool.h>

#ifdef __aarch64__
#include <sys/auxv.h>
#ifndef HWCAP_AES
#define HWCAP_AES (1 << 3)
#endif
#ifndef HWCAP_PMULL
#define HWCAP_PMULL (1 << 4)
#endif
#endif

/* Can the accelerated (simd=true) code paths execute on this CPU?
 * Test-executable-side detection only; the mode APIs do not dispatch. */
static inline bool simd_supported(void)
{
#ifdef _WIN32
	/* Windows MINGW: SIMD assembly not compiled, use generic implementations */
	return false;
#elif defined(__x86_64__)
	return __builtin_cpu_supports("aes") &&
	       __builtin_cpu_supports("pclmul") &&
	       __builtin_cpu_supports("avx");
#elif defined(__aarch64__)
	unsigned long hwcap = getauxval(AT_HWCAP);

	return (hwcap & HWCAP_AES) && (hwcap & HWCAP_PMULL);
#else
	return false;
#endif
}
