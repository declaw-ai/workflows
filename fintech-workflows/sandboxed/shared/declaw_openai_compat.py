"""Import-side-effect shim: make the OpenAI Python SDK's default call path
compatible with declaw PII rehydration.

Problem: the OpenAI SDK uses httpx, which adds `Accept-Encoding: gzip, deflate`
by default. OpenAI honors it and returns gzipped bodies. The declaw security
proxy can't currently scan compressed response bodies for redaction tokens,
so `rehydrate_response=True` is effectively a no-op on the default call path.

Fix: monkey-patch `httpx.Client` (and `AsyncClient`) so that any client
created without an explicit `Accept-Encoding` header receives `identity`,
which keeps responses plaintext and lets the proxy rehydrate tokens.

Usage — at the very top of any file that imports openai:

    import declaw_openai_compat  # noqa: F401 -- import for side effect
    from openai import OpenAI
    client = OpenAI()  # now rehydration-safe by default
"""
from __future__ import annotations

import httpx

_HEADER = "Accept-Encoding"
_VALUE = "identity"


def _inject_default(headers_arg):
    existing = httpx.Headers(headers_arg) if headers_arg is not None else httpx.Headers()
    has = any(k.lower() == _HEADER.lower() for k in existing.keys())
    if not has:
        existing[_HEADER] = _VALUE
    return existing


_orig_sync_init = httpx.Client.__init__
_orig_async_init = httpx.AsyncClient.__init__


def _patched_sync_init(self, *args, **kwargs):
    kwargs["headers"] = _inject_default(kwargs.get("headers"))
    return _orig_sync_init(self, *args, **kwargs)


def _patched_async_init(self, *args, **kwargs):
    kwargs["headers"] = _inject_default(kwargs.get("headers"))
    return _orig_async_init(self, *args, **kwargs)


def _already_patched(fn) -> bool:
    return getattr(fn, "_declaw_patched", False)


if not _already_patched(httpx.Client.__init__):
    _patched_sync_init._declaw_patched = True  # type: ignore[attr-defined]
    httpx.Client.__init__ = _patched_sync_init  # type: ignore[assignment]

if not _already_patched(httpx.AsyncClient.__init__):
    _patched_async_init._declaw_patched = True  # type: ignore[attr-defined]
    httpx.AsyncClient.__init__ = _patched_async_init  # type: ignore[assignment]


def is_patched() -> bool:
    return _already_patched(httpx.Client.__init__) and _already_patched(
        httpx.AsyncClient.__init__
    )
