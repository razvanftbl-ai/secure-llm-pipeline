import os

import requests


def call_llm(masked_prompt):
    """Send ONLY the masked text. Uses OpenAI if a key is set, otherwise a local mock."""
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        return _mock(masked_prompt)

    r = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={"Authorization": f"Bearer {api_key}"},
        json={
            "model": "gpt-4o-mini",
            "store": False,
            "messages": [
                {
                    "role": "system",
                    "content": "Tokens shaped like [TYPE_N] are placeholders for private data. "
                               "Keep them exactly as written in your answer.",
                },
                {"role": "user", "content": masked_prompt},
            ],
        },
        timeout=60,
    )
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]


def _mock(masked_prompt):
    return f"[MOCK LLM] I received: \"{masked_prompt}\""
