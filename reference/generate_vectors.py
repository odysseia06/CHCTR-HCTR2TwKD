"""Frozen vector corpus for schema chctr-hctr2twkd-v1.

Default run verifies the committed files against in-memory regeneration
(exit 1 on drift); --write rewrites them.  Deterministic: test bytes come
from counter-mode SHA-256 expansion, never a language RNG.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

from chctr2 import CHCTR2
from twkd import HCTR2TwKD

V1DIR = Path(__file__).resolve().parent.parent / "test_vectors" / \
    "reference" / "v1"

MSG_LENS = [16, 17, 31, 32, 47, 48, 63, 64, 255]
CHCTR2_TWEAK_LENS = [0, 1, 15, 16, 17, 31, 32]
CHCTR2_PATTERNS = ["zero", "inc", "alt", "sha"]
TWKD_PATTERNS = ["zero", "inc", "alt", "highbit"]


def det_bytes(case_id, n):
    """block_i = SHA256("CHCTR-HCTR2TwKD-v1" || case_id || uint64_be(i))"""
    out = b""
    i = 0
    while len(out) < n:
        out += hashlib.sha256(b"CHCTR-HCTR2TwKD-v1" + case_id.encode() +
                              i.to_bytes(8, "big")).digest()
        i += 1
    return out[:n]


def pattern_bytes(pattern, case_id, n):
    if pattern == "zero":
        return bytes(n)
    if pattern == "inc":
        return bytes(i % 256 for i in range(n))
    if pattern == "alt":
        return bytes(0x55 if i % 2 == 0 else 0xAA for i in range(n))
    assert pattern == "sha", pattern
    return det_bytes(case_id, n)


def twkd_t0(pattern, vid):
    if pattern == "zero":
        return bytes(16)
    if pattern == "inc":
        return bytes(range(16))
    if pattern == "alt":
        t = bytearray(0x55 if i % 2 == 0 else 0xAA for i in range(16))
        t[0] &= 0x3F  # canonical: two MSBs of byte 0 zero
        return bytes(t)
    assert pattern == "highbit", pattern
    return bytes([0x20]) + bytes(15)  # highest canonical data bit set


def _vec(vid, key, tweak, pt, ct, trace):
    return {"id": vid, "key": key.hex(), "tweak": tweak.hex(),
            "plaintext": pt.hex(), "ciphertext": ct.hex(),
            "trace": {k: v.hex() for k, v in trace.items()}}


def chctr2_vectors():
    vecs = []
    for pattern in CHCTR2_PATTERNS:
        for i, mlen in enumerate(MSG_LENS):
            tlen = CHCTR2_TWEAK_LENS[i % len(CHCTR2_TWEAK_LENS)]
            vid = f"chctr2-{pattern}-m{mlen:03d}-t{tlen:02d}"
            key = pattern_bytes(pattern, vid + "-key", 64)
            tweak = pattern_bytes(pattern, vid + "-tweak", tlen)
            pt = pattern_bytes(pattern, vid + "-msg", mlen)
            ct, trace = CHCTR2(key).trace(pt, tweak)
            vecs.append(_vec(vid, key, tweak, pt, ct, trace))
    return sorted(vecs, key=lambda v: v["id"])


def twkd_vectors():
    vecs = []
    for pattern in TWKD_PATTERNS:
        data_pattern = "sha" if pattern == "highbit" else pattern
        for mlen in MSG_LENS:
            vid = f"twkd-{pattern}-m{mlen:03d}"
            L = pattern_bytes(data_pattern, vid + "-L", 32)
            t0 = twkd_t0(pattern, vid)
            pt = pattern_bytes(data_pattern, vid + "-msg", mlen)
            ct, trace = HCTR2TwKD(L).trace(pt, t0)
            vecs.append(_vec(vid, L, t0, pt, ct, trace))
    return sorted(vecs, key=lambda v: v["id"])


def corpus():
    def doc(profile, vectors):
        return {
            "schema": "chctr-hctr2twkd-v1",
            "profile": profile,
            "provenance": {
                "paper": "IACR ePrint 2026/085",
                "generator": "reference/generate_vectors.py",
                "generator_version": 1,
            },
            "vectors": vectors,
        }

    return {
        "chctr2-aes256-polyval-v1.json":
            doc("chctr2-aes256-polyval-v1", chctr2_vectors()),
        "hctr2-twkd-cenc126-aes256-polyval-v1.json":
            doc("hctr2-twkd-cenc126-aes256-polyval-v1", twkd_vectors()),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--write", action="store_true",
                    help="rewrite the frozen files (reviewable change)")
    args = ap.parse_args()

    V1DIR.mkdir(parents=True, exist_ok=True)
    drift = 0
    for fname, obj in corpus().items():
        path = V1DIR / fname
        text = json.dumps(obj, indent=2) + "\n"
        if args.write:
            path.write_text(text)
            print(f"wrote {path} ({len(obj['vectors'])} vectors)")
        elif path.exists() and path.read_text() == text:
            print(f"ok {fname} ({len(obj['vectors'])} vectors)")
        else:
            print(f"DRIFT: {fname} does not match regeneration",
                  file=sys.stderr)
            drift = 1
    sys.exit(drift)


if __name__ == "__main__":
    main()
