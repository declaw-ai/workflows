"""Replay event stream for the landing-page visual (replayable) demos.

When `DECLAW_EMIT_EVENTS=<path>` is set, a workflow records a timeline of the
"declaw moments" — rule decision, PII redaction/rehydration, injection scan,
governance pack, human gate, adverse-action, audit — and flushes a JSON file a
front-end can scrub through. The events come from a REAL sandboxed run, so the
landing-page replay is authentic, not a mockup. No-op unless the env var is set,
so it never affects normal runs.

Event vocabulary (keep stable — the front-end keys off it):
  rule_decision · pii_redact · pii_rehydrate · injection_scan · governance_pack
  · human_gate · adverse_action · egress · audit
"""
from __future__ import annotations

import json
import os
import time

_ENABLED = bool(os.getenv("DECLAW_EMIT_EVENTS"))
_events: list[dict] = []
_t0: float | None = None
_meta: dict = {}


def start(workflow: str, **meta) -> None:
    """Begin a capture (call once at the top of main)."""
    global _t0, _events, _meta
    _t0 = time.time()
    _events = []
    _meta = {"workflow": workflow, **meta}


def record(event: str, actor: str, detail: dict | None = None) -> None:
    """Record one timeline event. No-op unless DECLAW_EMIT_EVENTS is set."""
    if not _ENABLED:
        return
    global _t0
    if _t0 is None:
        _t0 = time.time()
    _events.append({
        "seq": len(_events) + 1,
        "t_ms": int((time.time() - _t0) * 1000),
        "event": event,
        "actor": actor,
        "detail": detail or {},
    })


def flush() -> dict | None:
    """Write the captured timeline to DECLAW_EMIT_EVENTS (call once at the end)."""
    if not _ENABLED:
        return None
    path = os.environ["DECLAW_EMIT_EVENTS"]
    out = {**_meta, "event_count": len(_events), "events": _events}
    with open(path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"  [replay] {len(_events)} events -> {path}")
    return out
