import getpass
import os
import sys
import threading
import time

import requests
import seclib
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse

import vault
from masker import Masker

app = FastAPI(title="Veil")

# Key used to encrypt the per-request mapping: split 3-of-5, full key never kept.
_master = seclib.generate_key()
SHARES = seclib.split_secret(_master, 3, 5)
del _master

VAULT = None
VAULT_LOCK = threading.Lock()
STATS = {"requests": 0, "secret": 0, "personal": 0, "by_kind": {}}
LOG = []  # masked-only audit log (never real values)


def upstream(messages, model):
    """Send already-masked messages to the provider. Mock if no key."""
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        last = messages[-1]["content"] if messages else ""
        return f'[MOCK LLM] I received: "{last}"'
    r = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"model": model, "store": False, "messages": messages},
        timeout=60,
    )
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]


@app.get("/")
def index():
    return FileResponse("web/index.html")


@app.get("/logo.svg")
def logo():
    return FileResponse("web/logo.svg", media_type="image/svg+xml")


@app.get("/api/stats")
def stats():
    return STATS


@app.get("/api/log")
def log():
    return LOG[-50:]


@app.post("/v1/chat/completions")
def chat_completions(body: dict):
    messages = body.get("messages")
    if not isinstance(messages, list) or not messages:
        raise HTTPException(400, "messages is required")
    model = body.get("model", "gpt-4o-mini")

    key = bytearray(seclib.combine_shares(SHARES[:3]))
    try:
        m = Masker()
        try:
            masked_msgs = []
            for msg in messages:
                content = msg.get("content", "")
                if not isinstance(content, str):
                    raise ValueError("only text content is supported")
                masked_msgs.append({"role": msg.get("role", "user"), "content": m.mask(content)})
        except Exception as e:
            # fail closed: never forward unmasked data
            raise HTTPException(400, f"Veil blocked the request: {e}")

        answer = upstream(masked_msgs, model)
        final = m.unmask(answer)

        rep = m.report()
        STATS["requests"] += 1
        STATS["secret"] += rep["secret"]
        STATS["personal"] += rep["personal"]
        for k, v in rep["by_kind"].items():
            STATS["by_kind"][k] = STATS["by_kind"].get(k, 0) + v
        blob = m.export_encrypted(bytes(key))
        now = time.strftime("%H:%M:%S")
        LOG.append({
            "time": now,
            "sent_to_provider": masked_msgs[-1]["content"],
            "blocked": rep["total"],
            "mapping_bytes": len(blob),
        })

        # Encrypted history: real text is stored ONLY inside the vault.
        if VAULT is not None:
            with VAULT_LOCK:
                VAULT.append({
                    "time": now,
                    "real": messages[-1].get("content", ""),
                    "provider_saw": masked_msgs[-1]["content"],
                    "answer": final,
                })

        return {
            "id": "veil-" + str(int(time.time() * 1000)),
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": final}, "finish_reason": "stop"}],
            "veil": {
                "sent_to_provider": masked_msgs[-1]["content"],
                "blocked": rep,
                "mapping_bytes": len(blob),
                "mapping_hex": blob.hex()[:48],
                "vault_entries": VAULT.count if VAULT else 0,
            },
        }
    finally:
        for i in range(len(key)):
            key[i] = 0


def open_vault():
    if not os.path.exists(vault.PATH):
        v, shares = vault.Vault.create()
        print("\n=== NEW VAULT CREATED ===")
        print("Write these 5 shares down NOW. They are shown only once.")
        print("Any 3 of them unlock the history; fewer than 3 reveal nothing.\n")
        for i, s in enumerate(shares, 1):
            print(f"Share {i}: {s}")
        print()
        return v
    print("Vault found. Enter 3 of the 5 shares to unlock (input hidden).")
    hexes = [getpass.getpass(f"Share {i + 1}: ") for i in range(3)]
    try:
        return vault.Vault.unlock(hexes)
    except (ValueError, IndexError) as e:
        print("Could not unlock:", e)
        sys.exit(1)


if __name__ == "__main__":
    VAULT = open_vault()
    try:
        uvicorn.run(app, host="127.0.0.1", port=8000)
    finally:
        VAULT.close()
        print("Vault key wiped from memory.")
