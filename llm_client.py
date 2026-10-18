import os
import requests


def call_llm(masked_prompt):
    """Trimite DOAR textul mascat. Foloseste OpenAI daca exista cheie, altfel mock."""
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
                    "content": "Tokenurile de forma [TIP_N] sunt placeholdere. "
                               "Pastreaza-le exact asa cum sunt in raspuns.",
                },
                {"role": "user", "content": masked_prompt},
            ],
        },
        timeout=60,
    )
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]


def _mock(masked_prompt):
    return f"[MOCK LLM] Am primit: «{masked_prompt}». Salut [PERSON_1], iti raspund pe [EMAIL_1]."
