# CHCTR2 and HCTR2-TwKD

C implementation and benchmark of the two wide-block encryption modes from
Chen et al., [*Beyond-Birthday-Bound Security with HCTR2: Cascaded Construction
and Tweak-based Key Derivation*](https://eprint.iacr.org/2026/085), IACR ePrint
2026/085. Built on Google's [HCTR2 benchmark](https://github.com/google/hctr2).

## The modes

**CHCTR2** runs HCTR2 twice, with independent AES-256 keys K1 and K2:

    CHCTR2(T, M) = HCTR2[K2](T, HCTR2[K1](T, M))

The two hashes in the middle are merged into one pass that computes
`H1(T,R) ^ H2(T,R)` (paper Fig. 4). The cost per block is 2 AES calls and 3
GF(2^128) multiplications. It gives 2n/3-bit multi-user security with no limit
on tweak reuse.

**HCTR2-TwKD** runs HCTR2 under a per-tweak key derived with CENC (paper Sec. 8):

    K = (E_L(00||T) ^ E_L(01||T)) || (E_L(00||T) ^ E_L(10||T))
    HCTR2-TwKD(T, M) = HCTR2[K](empty tweak, M)

L is an AES-256 key and T is a 126-bit tweak. The cost per block is the same as
HCTR2. Each message adds 3 AES calls and one key schedule. Security is
2n/3-bit as long as a single tweak processes no more than about 2^(n/3)
blocks.

## Encoding choices

The paper leaves these details open. This code and its test vectors fix them as
follows:

- The CHCTR2 key is 64 bytes, `K1 || K2`. Each layer uses `H = E_K(0)` and
  `L = E_K(1)`, as in HCTR2.
- The hash padding and length block are exactly HCTR2's, so each layer is plain
  HCTR2.
- The TwKD tweak is 16 bytes. The 2-bit KDF prefix goes in the top two bits of
  byte 0, so those bits must be zero. A tweak with them set is rejected, by
  `ASSERT` in C and `AssertionError` in Python.
- TwKD's inner HCTR2 tweak is empty, matching the paper's benchmark setup.

## Build and test

Requires Linux x86-64 (WSL2 works) with AES-NI and PCLMUL, plus meson, ninja,
and python3.

```sh
cd benchmark
meson setup build
ninja -C build
meson test -C build                     # conformance suite
./build/cipherbench --bufsize=65536 --ntries=25 HCTR2 CHCTR2 HCTR2-TwKD
```

The conformance suite checks the following:

- the official HCTR2 vectors
- the frozen CHCTR2 and TwKD vectors
- that optimized CHCTR2 matches two black-box HCTR2 calls
- that TwKD matches HCTR2 under the derived key
- a KDF known-answer test
- that the generic and SIMD paths agree
- in-place operation

The Python reference model needs `pip install pycryptodome`:

```sh
cd reference
python3 -m unittest test_reference      # model tests + 700 official HCTR2 vectors
python3 generate_vectors.py             # verify frozen vectors in test_vectors/reference/v1
python3 differential.py ../benchmark/build/conformance_tests   # live Python-vs-C cases
```

## Results

These runs used 64 KiB messages and `--ntries=25` on an AMD Ryzen 7 9800X3D
(Zen 5), under WSL2:

| Mode               | Enc (cpb) | Dec (cpb) | Throughput |
|--------------------|-----------|-----------|------------|
| AES-256-HCTR2      | 1.37      | 1.37      | 3.44 GB/s  |
| AES-256-CHCTR2     | 2.23      | 2.23      | 2.10 GB/s  |
| AES-256-HCTR2-TwKD | 1.39      | 1.39      | 3.39 GB/s  |

CHCTR2 is 1.61x slower than HCTR2-TwKD here. The paper reports 1.67x on Zen 5
(Ryzen 5 9600X) and 1.71x on Arrow Lake.

The cpb figures are wall-clock time multiplied by the nominal 4.7 GHz clock,
because WSL2 exposes no cpufreq. The paper used hardware counters instead, so
compare ratios rather than absolute values.

## Limitations

- This is benchmark code, not a hardened library. There is no key erasure and
  no constant-time audit beyond what the imported primitives provide.
- The single-pass merged hash is x86-64 only and covers up to 4104 blocks
  (about 64 KiB). Longer inputs, and aarch64, fall back to two POLYVAL passes,
  which is correct but costs 4 multiplications per block.
- The aarch64 build is inherited from upstream and is untested here. On Windows
  (MinGW), only the generic conformance tests build.

## Layout

    benchmark/src/     chctr2.c, hctr2_twkd.c, polyval_xor*.c (merged hash), HCTR2 core
    benchmark/tests/   conformance runner
    reference/         Python model, vector generator, differential driver
    test_vectors/      official HCTR2 vectors and frozen CHCTR2/TwKD vectors
    third_party/       Linux kernel AES and GF(2^128) code
    2026-085.pdf       the paper

## Credits and license

The paper is by Yu Long Chen, Yukihito Hiraga, Nicky Mouha, Yusuke Naito, Yu
Sasaki, and Takeshi Sugawara, and is licensed CC BY 4.0. The benchmark
framework, HCTR2 core, and official vectors come from `google/hctr2` at commit
`0b0b537`.

Local changes to that code are small:

- a `--cpufreq` option
- in-place-safe generic XCTR
- the HCTR2 core exposed through `hctr2.h`
- XTS removed
- non-executable-stack notes in the assembly

Code outside `third_party/` is MIT (see `LICENSE`). `third_party/linux-kernel/`
is GPLv2, and one file is dual GPLv2/BSD-3. The x86-64 binaries link that code,
so redistributing binaries must follow GPLv2.
