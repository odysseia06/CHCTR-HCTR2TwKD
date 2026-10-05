"""Tests for the pure-Python reference model.  Run from reference/:
    python3 -m unittest -v test_reference
"""
import unittest
from pathlib import Path

from Crypto.Cipher import AES

from polyval import gf_dot, polyval
from hctr2 import HCTR2, hctr2_hash, length_block, pad_blocks, xctr, xor
from cvec import parse_hctr2_testvecs
from chctr2 import CHCTR2
from twkd import HCTR2TwKD, kdf_inputs


class TestAes(unittest.TestCase):
    def test_fips197_aes256(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f"
                            "101112131415161718191a1b1c1d1e1f")
        pt = bytes.fromhex("00112233445566778899aabbccddeeff")
        ct = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
        aes = AES.new(key, AES.MODE_ECB)
        self.assertEqual(aes.encrypt(pt), ct)
        self.assertEqual(aes.decrypt(ct), pt)


class TestPolyval(unittest.TestCase):
    def test_rfc8452_example(self):
        h = bytes.fromhex("25629347589242761d31f826ba4b757b")
        x1 = bytes.fromhex("4f4f95668c83dfb6401762bb2d01a262")
        x2 = bytes.fromhex("d1a24ddd2721d006bbe45f20d3c9f362")
        self.assertEqual(
            polyval(h, [x1, x2]),
            bytes.fromhex("f7a3b47b846119fae5b7866cf5e5b77e"))

    def test_linearity(self):
        h = bytes.fromhex("25629347589242761d31f826ba4b757b")
        a = bytes(range(16))
        b = bytes(range(16, 32))
        ab = bytes(x ^ y for x, y in zip(a, b))
        pa = int.from_bytes(polyval(h, [a]), "little")
        pb = int.from_bytes(polyval(h, [b]), "little")
        self.assertEqual(polyval(h, [ab]), (pa ^ pb).to_bytes(16, "little"))

    def test_dot_stays_in_field(self):
        self.assertLess(gf_dot((1 << 128) - 1, (1 << 128) - 1), 1 << 128)


class TestHctr2Format(unittest.TestCase):
    def test_length_block(self):
        self.assertEqual(length_block(16, False),
                         (16 * 8 * 2 + 3).to_bytes(16, "little"))
        self.assertEqual(length_block(16, True),
                         (16 * 8 * 2 + 2).to_bytes(16, "little"))

    def test_padding(self):
        data = bytes(range(17))
        self.assertEqual(pad_blocks(data, False)[1], bytes([16]) + bytes(15))
        self.assertEqual(pad_blocks(data, True)[1],
                         bytes([16, 0x01]) + bytes(14))
        self.assertEqual(pad_blocks(data[:16], True), [data[:16]])
        self.assertEqual(pad_blocks(b"", True), [])


class TestXctr(unittest.TestCase):
    def test_counter_construction(self):
        aes = AES.new(bytes(range(32)), AES.MODE_ECB)
        iv = bytes.fromhex("00112233445566778899aabbccddeeff")
        blocks = [aes.encrypt(xor(iv, i.to_bytes(16, "little")))
                  for i in (1, 2, 3)]
        self.assertEqual(xctr(aes, iv, 33), b"".join(blocks)[:33])


class TestOfficialVectors(unittest.TestCase):
    def test_all(self):
        path = (Path(__file__).resolve().parent.parent / "test_vectors" /
                "converted" / "cstruct" / "hctr2_testvecs.c")
        arrays = parse_hctr2_testvecs(path)
        self.assertEqual(
            sorted(arrays),
            ["hctr2_aes128_tv", "hctr2_aes192_tv", "hctr2_aes256_tv"])
        total = 0
        for name, entries in arrays.items():
            self.assertTrue(entries, name)
            for v in entries:
                mode = HCTR2(v["key"])
                self.assertEqual(mode.encrypt(v["plaintext"], v["tweak"]),
                                 v["ciphertext"], name)
                self.assertEqual(mode.decrypt(v["ciphertext"], v["tweak"]),
                                 v["plaintext"], name)
                total += 1
        print(f"\nofficial HCTR2 vectors passed: {total}")


class TestKdfKat(unittest.TestCase):
    def test_kat(self):
        # Same constants as the C KAT (hctr2_twkd.c), originally generated
        # with an independent AES-256 implementation.
        L = bytes(range(32))
        t = bytes.fromhex("00112233445566778899aabbccddeeff")
        i0, i1, i2 = kdf_inputs(t)
        self.assertEqual(i0.hex(), "00112233445566778899aabbccddeeff")
        self.assertEqual(i1.hex(), "40112233445566778899aabbccddeeff")
        self.assertEqual(i2.hex(), "80112233445566778899aabbccddeeff")
        self.assertEqual(HCTR2TwKD(L).derive(t).hex(),
                         "b755bd67c0cd84c0a6af30ddbd162f6e"
                         "9be3716e2c48bbc7f0b630b456eaf967")

    def test_noncanonical_rejected(self):
        self.assertRaises(AssertionError, kdf_inputs,
                          bytes([0x40]) + bytes(15))
        self.assertRaises(AssertionError, kdf_inputs,
                          bytes([0x80]) + bytes(15))


class TestChctr2(unittest.TestCase):
    def test_roundtrip_and_trace(self):
        mode = CHCTR2(bytes(range(64)))
        tweak = bytes(range(17))
        pt = bytes(range(47))
        ct, trace = mode.trace(pt, tweak)
        self.assertEqual(mode.encrypt(pt, tweak), ct)
        self.assertEqual(mode.decrypt(ct, tweak), pt)
        self.assertEqual(list(trace), ["h1", "h2", "l1", "l2", "z1", "x10",
                                       "y10", "r", "x20", "y20", "z2"])
        self.assertEqual(len(trace["r"]), len(pt) - 16)
        for name, val in trace.items():
            if name != "r":
                self.assertEqual(len(val), 16, name)


class TestTwkd(unittest.TestCase):
    def test_roundtrip_and_trace(self):
        mode = HCTR2TwKD(bytes(range(32)))
        t0 = bytes([0x20]) + bytes(15)
        pt = bytes(range(63))
        ct, trace = mode.trace(pt, t0)
        self.assertEqual(mode.encrypt(pt, t0), ct)
        self.assertEqual(mode.decrypt(ct, t0), pt)
        self.assertEqual(list(trace), ["kdf_input_00", "kdf_input_01",
                                       "kdf_input_10", "e0", "e1", "e2",
                                       "derived_key", "h", "l"])
        self.assertEqual(trace["derived_key"], mode.derive(t0))


if __name__ == "__main__":
    unittest.main()
