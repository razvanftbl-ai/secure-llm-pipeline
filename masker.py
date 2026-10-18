import re
import json
import seclib

PATTERNS = [
    ("EMAIL", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("IBAN", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")),
    ("CNP", re.compile(r"\b[1-8]\d{12}\b")),
    ("PHONE", re.compile(r"(?:\+40|0040|0)7\d{8}\b")),
    ("CARD", re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b")),
    ("PERSON", re.compile(r"\b[A-Z][a-zăâîșț]+ [A-Z][a-zăâîșț]+\b")),
]


class Masker:
    def __init__(self):
        self.mapping = {}   # token -> valoare reala
        self.reverse = {}   # valoare reala -> token
        self.counters = {}

    def _token(self, kind, value):
        if value in self.reverse:
            return self.reverse[value]
        self.counters[kind] = self.counters.get(kind, 0) + 1
        tok = f"[{kind}_{self.counters[kind]}]"
        self.mapping[tok] = value
        self.reverse[value] = tok
        return tok

    def mask(self, text):
        for kind, pat in PATTERNS:
            text = pat.sub(lambda m, k=kind: self._token(k, m.group(0)), text)
        return text

    def unmask(self, text):
        for tok, val in self.mapping.items():
            text = text.replace(tok, val)
        return text

    def export_encrypted(self, key):
        data = json.dumps(self.mapping).encode()
        return seclib.encrypt(key, data, b"mapping-v1")

    def import_encrypted(self, key, blob):
        data = seclib.decrypt(key, blob, b"mapping-v1")
        self.mapping = json.loads(data)
        self.reverse = {v: k for k, v in self.mapping.items()}
