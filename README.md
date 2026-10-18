# Veil

**A local privacy firewall between you and any LLM.**

Veil runs on your machine as an OpenAI-compatible proxy. Before a prompt leaves your device, secrets (API keys, passwords, tokens) and personal data (names, emails, phones, IBANs, SSNs) are replaced with placeholder tokens. The provider only ever sees `[EMAIL_1]`, `[OPENAI_KEY_1]`, and so on. The answer is restored locally. The master key never reaches the provider.

Track: AI pipeline secret sharing. Made by **Major Matt Razvan**.

## Why it matters

People paste source code with API keys, customer data and patient records into AI tools every day. Veil makes that safe by default, and works with any app by changing one line (`base_url`).

## How it works

1. **Mask**: a scanner detects secrets and personal data and swaps them for tokens.
2. **Send**: only the masked text goes to the provider (`store: false` for zero retention).
3. **Restore**: tokens in the answer are replaced with the real values, locally.
4. **Encrypt**: the token-to-value mapping is encrypted with AES-256-GCM (random 96-bit nonce, AAD).
5. **Vault**: conversation history is stored encrypted on disk. The vault key is split with **Shamir 3-of-5**; any 3 key holders can open it, fewer than 3 learn nothing.
6. **Fail closed**: if masking fails, the request is blocked, never forwarded in clear.

## Core (Rust)

`seclib` (Rust + PyO3) implements AES-256-GCM and Shamir Secret Sharing over GF(256) with branch-free field arithmetic, Lagrange interpolation at x = 0, and `zeroize` for key material.

## Features

- OpenAI-compatible endpoint: `POST /v1/chat/completions`
- Secret scanner: OpenAI, Anthropic, AWS, GitHub, Google, Slack, JWT, private keys, `password=` pairs
- Personal data: email, phone, IBAN, card, SSN, CNP, names
- Web UI (localhost only): playground, leak report, audit log, vault reader
- Prompt injection demo: the provider has no key to reveal

## Threat model

Adversary: the LLM provider (curious or compromised) and a network observer. The local device is assumed uncompromised while running.

## Mitigated risks

| Risk | Mitigation |
|---|---|
| Sensitive data reaches the provider | Local masking before sending |
| Master key in prompts or logs | Key never leaves the device |
| Single point of compromise for history | Shamir 3-of-5 vault |
| AES-GCM nonce reuse | Fresh random nonce per encryption |
| Data tampering or reordering | GCM tag + entry index in AAD |
| Key left in memory | `zeroize` in Rust, wiped after use |
| Provider keeps history | `store: false` |
| Remote access to the UI | Host check (localhost only), attempt limit on vault |

## Limitations

- Detection is heuristic (regex). Unusual formats, lowercase names or letter-only passwords can be missed. Production use would add entropy checks and a local NER model.
- Context stays visible to the provider ("my 7-year-old daughter in Iasi").
- Message length is not hidden.
- While running, the vault key is in process memory; the 3-of-5 threshold protects history at rest, not against an attacker controlling the live process.
- Python `bytes` objects are immutable and cannot be fully zeroized.
- Truncating the end of `vault.bin` is not detected (reordering and edits are).
- Losing 3 shares makes the history unrecoverable.

## Run

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install maturin requests fastapi uvicorn
maturin develop --release
python test_security.py && python test_vault.py
python proxy.py        # open http://127.0.0.1:8000
```

Optional: `export OPENAI_API_KEY=...` for a real LLM. Without it, a mock is used.

Use from any app:

```python
from openai import OpenAI
client = OpenAI(base_url="http://127.0.0.1:8000/v1", api_key="unused")
```

## Video

(add YouTube link here)
