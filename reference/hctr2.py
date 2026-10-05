"""HCTR2 (Crowley-Huckleberry-Biggers), pure Python; AES via PyCryptodome.

Conventions match the HCTR2 paper: h = E_K(bin(0)), L = E_K(bin(1)) with
bin() little-endian; the hash's first block encodes tweak_len*8*2 + 2,
plus 1 if the message is not block-aligned; tweaks zero-pad, messages
zero-pad with a 0x01 marker; XCTR keystream block i is E(S xor bin(i)).
"""

from Crypto.Cipher import AES

from polyval import polyval

BLOCK = 16


def xor(a, b):
    assert len(a) == len(b)
    return (int.from_bytes(a, "little") ^
            int.from_bytes(b, "little")).to_bytes(len(a), "little")


def length_block(tweak_len, msg_aligned):
    return (tweak_len * 8 * 2 + (2 if msg_aligned else 3)).to_bytes(
        16, "little")


def pad_blocks(data, message_padding):
    blocks = [data[i:i + 16]
              for i in range(0, len(data) - len(data) % 16, 16)]
    rem = len(data) % 16
    if rem:
        last = bytearray(16)
        last[:rem] = data[-rem:]
        if message_padding:
            last[rem] = 0x01
        blocks.append(bytes(last))
    return blocks


def hctr2_hash(h, tweak, msg):
    blocks = [length_block(len(tweak), len(msg) % 16 == 0)]
    blocks += pad_blocks(tweak, False)
    blocks += pad_blocks(msg, True)
    return polyval(h, blocks)


def xctr(aes, iv, n):
    nblocks = (n + 15) // 16
    ctr = b"".join(xor(iv, (i + 1).to_bytes(16, "little"))
                   for i in range(nblocks))
    return aes.encrypt(ctr)[:n]


class HCTR2:
    def __init__(self, key):
        self.aes = AES.new(key, AES.MODE_ECB)
        self.h = self.aes.encrypt(bytes(16))
        self.L = self.aes.encrypt((1).to_bytes(16, "little"))

    def _crypt(self, data, tweak, encrypt):
        assert len(data) >= BLOCK
        M, N = data[:16], data[16:]
        MM = xor(M, hctr2_hash(self.h, tweak, N))
        UU = self.aes.encrypt(MM) if encrypt else self.aes.decrypt(MM)
        S = xor(xor(MM, UU), self.L)
        V = xor(N, xctr(self.aes, S, len(N))) if N else b""
        U = xor(UU, hctr2_hash(self.h, tweak, V))
        return U + V

    def encrypt(self, pt, tweak):
        return self._crypt(pt, tweak, True)

    def decrypt(self, ct, tweak):
        return self._crypt(ct, tweak, False)
