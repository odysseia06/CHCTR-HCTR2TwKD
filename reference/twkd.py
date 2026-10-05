"""HCTR2-TwKD (ePrint 2026/085 Sec. 3.4 / Sec. 8): HCTR2 keyed per tweak by
the CENC-126 KDF.  T0 is a canonical 16-byte value (two MSBs of byte 0
zero); the inner HCTR2 tweak is empty."""

from Crypto.Cipher import AES

from hctr2 import HCTR2, xor


def kdf_inputs(t0):
    assert len(t0) == 16
    assert t0[0] >> 6 == 0, "noncanonical T0"
    return tuple(bytes([(t0[0] & 0x3F) | prefix]) + t0[1:]
                 for prefix in (0x00, 0x40, 0x80))


class HCTR2TwKD:
    def __init__(self, L):
        assert len(L) == 32
        self.kdf_aes = AES.new(L, AES.MODE_ECB)

    def derive(self, t0):
        i0, i1, i2 = kdf_inputs(t0)
        e0 = self.kdf_aes.encrypt(i0)
        e1 = self.kdf_aes.encrypt(i1)
        e2 = self.kdf_aes.encrypt(i2)
        return xor(e0, e1) + xor(e0, e2)

    def encrypt(self, pt, t0):
        return HCTR2(self.derive(t0)).encrypt(pt, b"")

    def decrypt(self, ct, t0):
        return HCTR2(self.derive(t0)).decrypt(ct, b"")

    def trace(self, pt, t0):
        """Encrypt and return (ct, spec-level intermediates)."""
        i0, i1, i2 = kdf_inputs(t0)
        e0 = self.kdf_aes.encrypt(i0)
        e1 = self.kdf_aes.encrypt(i1)
        e2 = self.kdf_aes.encrypt(i2)
        dk = xor(e0, e1) + xor(e0, e2)
        inner = HCTR2(dk)
        ct = inner.encrypt(pt, b"")
        return ct, {
            "kdf_input_00": i0, "kdf_input_01": i1, "kdf_input_10": i2,
            "e0": e0, "e1": e1, "e2": e2, "derived_key": dk,
            "h": inner.h, "l": inner.L,
        }
