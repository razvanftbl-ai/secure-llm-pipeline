import json
import os

import seclib

PATH = "vault.bin"
MAGIC = b"veil-vault-v1"


def _aad(i):
    return MAGIC + b"|" + str(i).encode()


def _lines(path):
    with open(path) as f:
        return [l.strip() for l in f if l.strip()]


class Vault:
    def __init__(self, key, path, count):
        self.key = key          # bytearray, zeroized on close()
        self.path = path
        self.count = count      # number of entries (not counting the check line)

    @classmethod
    def create(cls, path=PATH):
        """New vault. Returns (vault, 5 share hex strings). Shown ONCE, never stored."""
        key = bytearray(seclib.generate_key())
        shares = [s.hex() for s in seclib.split_secret(bytes(key), 3, 5)]
        with open(path, "w") as f:
            f.write(seclib.encrypt(bytes(key), b"ok", _aad(0)).hex() + "\n")
        return cls(key, path, 0), shares

    @classmethod
    def unlock(cls, share_hexes, path=PATH):
        """Rebuild the key from >=3 shares. Raises ValueError if wrong."""
        shares = [bytes.fromhex(h.strip()) for h in share_hexes]
        key = bytearray(seclib.combine_shares(shares))
        lines = _lines(path)
        try:
            seclib.decrypt(bytes(key), bytes.fromhex(lines[0]), _aad(0))
        except ValueError:
            for i in range(len(key)):
                key[i] = 0
            raise ValueError("wrong shares: vault stays locked")
        return cls(key, path, len(lines) - 1)

    def append(self, entry):
        self.count += 1
        blob = seclib.encrypt(bytes(self.key), json.dumps(entry).encode(), _aad(self.count))
        with open(self.path, "a") as f:
            f.write(blob.hex() + "\n")

    def close(self):
        for i in range(len(self.key)):
            self.key[i] = 0


def read_all(key, path=PATH):
    """Decrypt every entry. Raises ValueError if anything was tampered with or reordered."""
    out = []
    for i, line in enumerate(_lines(path)[1:], start=1):
        data = seclib.decrypt(bytes(key), bytes.fromhex(line), _aad(i))
        out.append(json.loads(data))
    return out
