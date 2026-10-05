"""CHCTR2 (ePrint 2026/085 Sec. 3.3): HCTR2 cascaded under two independent
keys.  Implemented as the explicit black-box composition -- deliberately NOT
the C implementation's merged-hash optimization."""

from hctr2 import HCTR2, hctr2_hash, xor


class CHCTR2:
    def __init__(self, key):
        assert len(key) == 64
        self.layer1 = HCTR2(key[:32])
        self.layer2 = HCTR2(key[32:])

    def encrypt(self, pt, tweak):
        return self.layer2.encrypt(self.layer1.encrypt(pt, tweak), tweak)

    def decrypt(self, ct, tweak):
        return self.layer1.decrypt(self.layer2.decrypt(ct, tweak), tweak)

    def trace(self, pt, tweak):
        """Encrypt and return (ct, intermediates named as in Fig. 4).

        r is the paper's R: the right part of the layer-1 output only.
        """
        l1, l2 = self.layer1, self.layer2
        r = l1.encrypt(pt, tweak)
        ct = l2.encrypt(r, tweak)
        z1 = hctr2_hash(l1.h, tweak, pt[16:])
        x10 = xor(pt[:16], z1)
        y10 = l1.aes.encrypt(x10)
        x20 = xor(r[:16], hctr2_hash(l2.h, tweak, r[16:]))
        y20 = l2.aes.encrypt(x20)
        z2 = hctr2_hash(l2.h, tweak, ct[16:])
        assert xor(y20, z2) == ct[:16]  # wiring self-check
        return ct, {
            "h1": l1.h, "h2": l2.h, "l1": l1.L, "l2": l2.L,
            "z1": z1, "x10": x10, "y10": y10, "r": r[16:],
            "x20": x20, "y20": y20, "z2": z2,
        }
