"""Parser for the frozen official HCTR2 vectors in their C-struct form
(test_vectors/converted/cstruct/hctr2_testvecs.c)."""

import re
from pathlib import Path

_ARRAY = re.compile(
    r"const struct hctr2_testvec (hctr2_aes\d+_tv)\[\] = \{(.*?)\n\};", re.S)
_FIELD = re.compile(
    r"\.(key|tweak|plaintext|ciphertext)\s*=\s*\{\.len\s*=\s*(\d+),"
    r"\s*\.data\s*=\s*((?:\"[^\"]*\"\s*)+)\}")
_ORDER = ("key", "tweak", "plaintext", "ciphertext")


def parse_hctr2_testvecs(path):
    text = Path(path).read_text()
    arrays = {}
    for m in _ARRAY.finditer(text):
        name, body = m.group(1), m.group(2)
        fields = _FIELD.findall(body)
        assert fields and len(fields) % 4 == 0, name
        entries = []
        for i in range(0, len(fields), 4):
            rec = {}
            for (fname, flen, fdata), expect in zip(fields[i:i + 4], _ORDER):
                assert fname == expect, (name, i, fname)
                data = bytes(int(h, 16)
                             for h in re.findall(r"\\x([0-9a-fA-F]{2})",
                                                 fdata))
                assert len(data) == int(flen), (name, i, fname)
                rec[fname] = data
            entries.append(rec)
        arrays[name] = entries
    return arrays
