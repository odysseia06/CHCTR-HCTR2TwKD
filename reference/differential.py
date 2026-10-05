"""Live differential corpus (spec section 7): the Python model computes
expected outputs for every case, writes one binary manifest, and runs
`conformance_tests --manifest` once.  Whole outputs are compared.

Usage: python3 differential.py [path/to/conformance_tests]
Takes ~1-2 minutes (pure-Python POLYVAL on multi-KiB messages).
"""

import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from chctr2 import CHCTR2
from generate_vectors import det_bytes, twkd_t0
from twkd import HCTR2TwKD

# must match benchmark/src/polyval_xor.h
POLYVAL_XOR_MAX_POWERS = 4104

PROFILE_CHCTR2, PROFILE_TWKD = 0, 1
OP_ENC, OP_DEC = 0, 1
IMPLS = (0, 1)  # generic, accelerated

CHCTR2_SMALL_MSG = [16, 17, 31, 32, 47, 48, 63, 64, 255, 512]
CHCTR2_SMALL_TWEAK = [0, 1, 15, 16, 17, 31, 32]
CHCTR2_LARGE_MSG = [4096, 65536, 65647, 65648, 65649, 65664, 131072]
CHCTR2_LARGE_TWEAK = [0, 16, 32]
TWKD_MSG = [16, 17, 31, 32, 47, 48, 63, 64, 255, 512, 4096, 65536, 131072]


def middle_hash_nblocks(tweak_len, msg_len):
    """polyval_xor_nblocks() for the CHCTR2 middle hash (input = nbytes-16)."""
    return 1 + (tweak_len + 15) // 16 + (msg_len + 15) // 16


def assert_boundary_honest():
    """The table-boundary sizes must sit on the intended side of the table,
    independently of the optimized implementation."""
    assert middle_hash_nblocks(16, 65648 - 16) == POLYVAL_XOR_MAX_POWERS
    assert middle_hash_nblocks(16, 65649 - 16) == POLYVAL_XOR_MAX_POWERS + 1


def records(profile, key, tweak, pt, ct):
    for impl in IMPLS:
        for op, inp, exp in ((OP_ENC, pt, ct), (OP_DEC, ct, pt)):
            hdr = struct.pack("<IIIIIQ", profile, op, impl, len(key),
                              len(tweak), len(inp))
            yield hdr + key + tweak + inp + exp


def chctr2_cases():
    cases = [(m, t) for m in CHCTR2_SMALL_MSG for t in CHCTR2_SMALL_TWEAK]
    cases += [(m, t) for m in CHCTR2_LARGE_MSG for t in CHCTR2_LARGE_TWEAK]
    for k in range(64):
        seed = f"chctr2-diff-{k:02d}"
        m = 16 + int.from_bytes(det_bytes(seed + "-mlen", 4), "big") % 8177
        t = int.from_bytes(det_bytes(seed + "-tlen", 4), "big") % 65
        cases.append((m, t))
    return cases


def twkd_cases():
    cases = [(m, ("pattern", p)) for p in ("zero", "inc", "alt", "highbit")
             for m in TWKD_MSG]
    for k in range(32):
        cases.append((16 + int.from_bytes(
            det_bytes(f"twkd-diff-{k:02d}-mlen", 4), "big") % 8177,
            ("sha", f"twkd-diff-{k:02d}")))
    return cases


def write_manifest(f):
    total = 0
    for m, t in chctr2_cases():
        cid = f"chctr2-live-m{m}-t{t}"
        key = det_bytes(cid + "-key", 64)
        tweak = det_bytes(cid + "-tweak", t)
        pt = det_bytes(cid + "-msg", m)
        ct = CHCTR2(key).encrypt(pt, tweak)
        for rec in records(PROFILE_CHCTR2, key, tweak, pt, ct):
            f.write(rec)
            total += 1
    for m, (kind, val) in twkd_cases():
        cid = f"twkd-live-m{m}-{val}"
        L = det_bytes(cid + "-L", 32)
        if kind == "pattern":
            t0 = twkd_t0(val, cid)
        else:
            t0 = bytearray(det_bytes(cid + "-t0", 16))
            t0[0] &= 0x3F
            t0 = bytes(t0)
        pt = det_bytes(cid + "-msg", m)
        ct = HCTR2TwKD(L).encrypt(pt, t0)
        for rec in records(PROFILE_TWKD, L, t0, pt, ct):
            f.write(rec)
            total += 1
    return total


def main():
    binary = Path(sys.argv[1] if len(sys.argv) > 1 else
                  "../benchmark/build/conformance_tests")
    if not binary.exists():
        sys.exit(f"conformance binary not found: {binary}")
    assert_boundary_honest()
    with tempfile.NamedTemporaryFile(suffix=".manifest") as tmp:
        total = write_manifest(tmp)
        tmp.flush()
        print(f"differential: wrote {total} cases, running {binary}")
        result = subprocess.run([str(binary), "--manifest", tmp.name])
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
