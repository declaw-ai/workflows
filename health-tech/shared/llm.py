"""Real LLM client shared by all baseline (non-sandboxed) workflows.

Uses OpenAI gpt-4.1 by default. Reads OPENAI_API_KEY from the environment.
"""
from __future__ import annotations

import os
from typing import Any

DEFAULT_MODEL = "gpt-4.1"


def _client():
    from openai import OpenAI  # type: ignore
    if not os.getenv("OPENAI_API_KEY"):
        raise RuntimeError("OPENAI_API_KEY not set")
    return OpenAI()


def chat(system: str, user: str, *, model: str = DEFAULT_MODEL,
         max_tokens: int = 800) -> str:
    resp = _client().chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        max_completion_tokens=max_tokens,
    )
    return resp.choices[0].message.content or ""


def chat_json(system: str, user: str, *, model: str = DEFAULT_MODEL,
              max_tokens: int = 800) -> dict[str, Any]:
    """Same as chat() but asks for a JSON object response and parses it."""
    import json
    resp = _client().chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system + "\nRespond with a single JSON object."},
            {"role": "user", "content": user},
        ],
        response_format={"type": "json_object"},
        max_completion_tokens=max_tokens,
    )
    return json.loads(resp.choices[0].message.content or "{}")
