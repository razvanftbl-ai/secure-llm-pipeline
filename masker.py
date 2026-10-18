import json
import re

import seclib

# (kind, compiled regex, capture group to mask; 0 = whole match, category)
# Order matters: secrets first, then personal data.
PATTERNS = [
    ("PRIVATE_KEY", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), 0, "secret"),
    ("ANTHROPIC_KEY", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"), 0, "secret"),
    ("OPENAI_KEY", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}"), 0, "secret"),
    ("AWS_KEY", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 0, "secret"),
    ("GITHUB_TOKEN", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), 0, "secret"),
    ("GOOGLE_KEY", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), 0, "secret"),
    ("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"), 0, "secret"),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), 0, "secret"),
    ("PASSWORD", re.compile(r"(?i)(?:password|passwd|pwd|secret|api[_-]?key|token)\s*[=:]\s*['\"]?(?!\[)([^\s'\",;]{5,}[^\s'\",;.])"), 1, "secret"),
    ("EMAIL", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), 0, "personal"),
    ("IBAN", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"), 0, "personal"),
    ("CARD", re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b"), 0, "personal"),
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), 0, "personal"),
    ("CNP", re.compile(r"\b[1-8]\d{12}\b"), 0, "personal"),
    ("PHONE", re.compile(r"(?<![\w\[])\+?\d[\d\s().-]{7,}\d(?!\w)"), 0, "personal"),
    ("PERSON", re.compile(r"(?i:\b(?:my name is|i am|i'm|this is|name:))\s+([A-Z][a-z]+(?: [A-Z][a-z]+)+)"), 1, "personal"),
]


class Masker:
    def __init__(self):
        self.mapping = {}    # token -> real value
        self.reverse = {}    # real value -> token
        self.counters = {}
        self.kinds = {}      # token -> (kind, category)

    def _token(self, kind, category, value):
        if value in self.reverse:
            return self.reverse[value]
        self.counters[kind] = self.counters.get(kind, 0) + 1
        tok = f"[{kind}_{self.counters[kind]}]"
        self.mapping[tok] = value
        self.reverse[value] = tok
        self.kinds[tok] = (kind, category)
        return tok

    def mask(self, text):
        for kind, pat, grp, category in PATTERNS:
            def repl(m, kind=kind, grp=grp, category=category):
                if grp == 0:
                    return self._token(kind, category, m.group(0))
                s, e, o = m.start(grp), m.end(grp), m.start(0)
                full = m.group(0)
                return full[: s - o] + self._token(kind, category, m.group(grp)) + full[e - o :]
            text = pat.sub(repl, text)
        return text

    def unmask(self, text):
        for tok, val in self.mapping.items():
            text = text.replace(tok, val)
        return text

    def report(self):
        """Counts of what was blocked in this session."""
        out = {"secret": 0, "personal": 0, "by_kind": {}}
        for tok, (kind, category) in self.kinds.items():
            out[category] += 1
            out["by_kind"][kind] = out["by_kind"].get(kind, 0) + 1
        out["total"] = out["secret"] + out["personal"]
        return out

    def export_encrypted(self, key):
        data = json.dumps(self.mapping).encode()
        return seclib.encrypt(key, data, b"mapping-v1")

    def import_encrypted(self, key, blob):
        data = seclib.decrypt(key, blob, b"mapping-v1")
        self.mapping = json.loads(data)
        self.reverse = {v: k for k, v in self.mapping.items()}
