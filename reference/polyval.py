"""POLYVAL (RFC 8452) over GF(2^128), pure Python.

Field elements are 16-byte strings read little-endian: bit i of the
integer is the coefficient of x^i.  The field product includes POLYVAL's
x^-128 factor: gf_dot(a, b) = a*b*x^-128 mod x^128+x^127+x^126+x^121+1.
"""

_P = (1 << 128) | (1 << 127) | (1 << 126) | (1 << 121) | 1


def gf_dot(a, b):
    z = 0
    for i in range(128):
        if (b >> i) & 1:
            z ^= a << i
    # multiply by x^-128: 128 divisions by x (P has constant term 1)
    for _ in range(128):
        if z & 1:
            z ^= _P
        z >>= 1
    return z


def polyval(h, blocks):
    """POLYVAL(H, X_1..X_n): S = 0; S = (S xor X_i) * H per block."""
    hi = int.from_bytes(h, "little")
    s = 0
    for blk in blocks:
        s = gf_dot(s ^ int.from_bytes(blk, "little"), hi)
    return s.to_bytes(16, "little")
