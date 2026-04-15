"""Real LLM clients shared by all baseline (non-sandboxed) workflows.

Covers both providers + both streaming modes:
  * OpenAI non-stream:   chat()          via gpt-4.1
  * OpenAI streaming:    chat_stream()   yields string deltas
  * Anthropic non-stream: chat_anthropic()       via claude-sonnet-4-6
  * Anthropic streaming:  chat_anthropic_stream() yields string deltas
  * JSON mode:            chat_json()    (OpenAI only — JSON-structured output)

Reads OPENAI_API_KEY / ANTHROPIC_API_KEY from the environment.
"""
from __future__ import annotations

import os
from typing import Any, Iterator

DEFAULT_MODEL = "gpt-4.1"
DEFAULT_CLAUDE_MODEL = "claude-haiku-4-5-20251001"


def _openai_client():
    from openai import OpenAI  # type: ignore
    if not os.getenv("OPENAI_API_KEY"):
        raise RuntimeError("OPENAI_API_KEY not set")
    return OpenAI()


def _anthropic_client():
    from anthropic import Anthropic  # type: ignore
    if not os.getenv("ANTHROPIC_API_KEY"):
        raise RuntimeError("ANTHROPIC_API_KEY not set")
    return Anthropic()


# ---------- OpenAI ----------

def chat(system: str, user: str, *, model: str = DEFAULT_MODEL,
         max_tokens: int = 800) -> str:
    """OpenAI, non-streaming. Returns the full response string."""
    resp = _openai_client().chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        max_completion_tokens=max_tokens,
    )
    return resp.choices[0].message.content or ""


def chat_stream(system: str, user: str, *, model: str = DEFAULT_MODEL,
                max_tokens: int = 800) -> Iterator[str]:
    """OpenAI, streaming. Yields string deltas as they arrive.

    Server-Sent Events under the hood; each chunk is a content delta. SSE
    bodies are uncompressed by OpenAI, so Declaw's MITM proxy can scan /
    rehydrate them via chunk-boundary buffering — same mechanism the
    health-tech demos rely on.
    """
    stream = _openai_client().chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        max_completion_tokens=max_tokens,
        stream=True,
    )
    for chunk in stream:
        delta = chunk.choices[0].delta.content if chunk.choices else None
        if delta:
            yield delta


def chat_json(system: str, user: str, *, model: str = DEFAULT_MODEL,
              max_tokens: int = 800) -> dict[str, Any]:
    """OpenAI chat() constrained to a JSON object response."""
    import json
    resp = _openai_client().chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system + "\nRespond with a single JSON object."},
            {"role": "user", "content": user},
        ],
        response_format={"type": "json_object"},
        max_completion_tokens=max_tokens,
    )
    return json.loads(resp.choices[0].message.content or "{}")


# ---------- Anthropic ----------

def chat_anthropic(system: str, user: str, *, model: str = DEFAULT_CLAUDE_MODEL,
                   max_tokens: int = 800) -> str:
    """Anthropic Claude, non-streaming. Returns full response text."""
    resp = _anthropic_client().messages.create(
        model=model,
        system=system,
        messages=[{"role": "user", "content": user}],
        max_tokens=max_tokens,
    )
    # Response content is a list of blocks; concatenate the text blocks.
    parts = [b.text for b in resp.content if getattr(b, "type", "") == "text"]
    return "".join(parts)


def chat_anthropic_stream(system: str, user: str, *,
                          model: str = DEFAULT_CLAUDE_MODEL,
                          max_tokens: int = 800) -> Iterator[str]:
    """Anthropic Claude, streaming. Yields string deltas as they arrive.

    Uses the messages.stream() context manager which re-assembles
    ContentBlockDelta events into a text iterator.
    """
    client = _anthropic_client()
    with client.messages.stream(
        model=model,
        system=system,
        messages=[{"role": "user", "content": user}],
        max_tokens=max_tokens,
    ) as stream:
        for delta in stream.text_stream:
            if delta:
                yield delta
