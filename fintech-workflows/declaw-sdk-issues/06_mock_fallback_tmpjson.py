"""Declaw SDK issue #06 — reference MockSandbox doesn't write /tmp/in.json
to the host disk, so scripts using the real-sandbox I/O convention crash
in mock (no-DECLAW_API_KEY) mode.

Scope: this is a bug in OUR helpers, not strictly the SDK; it's included
for completeness because it affects anyone who copies the health-tech /
data-intelligence declaw_helpers.py pattern and tries to run without a
live Declaw key. The fix we shipped to fintech-workflows can be merged
upstream into health-tech if desired.

EXPECTED: When DECLAW_API_KEY is unset, calling
          `run_python_in_sandbox(name, code, policy, payload=...)`
          with a `code` that does
              with open("/tmp/in.json") as f:
                  inp = json.load(f)
          should Just Work — the payload should be readable from
          `/tmp/in.json` inside the fallback.

OBSERVED: Original helper stores the payload in
          `MockSandbox.files_storage` (an in-memory dict) and then
          immediately `exec()`s the code locally. `open("/tmp/in.json")`
          hits FileNotFoundError.

WORKAROUND: Fallback now writes `/tmp/in.json` to real disk, runs the
            script, then reads `/tmp/out.json` back. Implemented in
            `fintech-workflows/sandboxed/shared/declaw_helpers.py`.

FIX (if upstreamed): Either (a) ship the same `/tmp`-on-disk shim in the
                     health-tech/data-intelligence helpers, or (b)
                     rewrite the fallback to pre-process the `code`
                     string and redirect any `open("/tmp/in.json")`
                     literals to the in-memory dict (more surgical but
                     fragile).

Env: none required — this demonstrates a local-only bug.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import textwrap
from dataclasses import dataclass
from typing import Any


# Minimal reproduction of the ORIGINAL (buggy) helper from health-tech.
@dataclass
class _BuggyMockSandbox:
    sandbox_id: str
    files_storage: dict

    def files_write(self, path: str, content: str) -> None:
        self.files_storage[path] = content


def _buggy_run_python_in_sandbox(name: str, code: str,
                                  payload: dict | None = None) -> dict:
    sbx = _BuggyMockSandbox(sandbox_id=f"mock-{name}", files_storage={})
    sbx.files_write("/tmp/in.json", json.dumps(payload or {}))
    local_ns: dict[str, Any] = {}
    exec(code, {"__INPUT__": payload or {}}, local_ns)
    return local_ns.get("__OUTPUT__", {})


# Patched helper (what the fintech-workflows shim does).
def _fixed_run_python_in_sandbox(name: str, code: str,
                                  payload: dict | None = None) -> dict:
    # Write payload to real disk so scripts that open("/tmp/in.json") work.
    with open("/tmp/in.json", "w") as f:
        json.dump(payload or {}, f)
    try:
        os.remove("/tmp/out.json")
    except FileNotFoundError:
        pass
    local_ns: dict[str, Any] = {}
    exec(code, {"__INPUT__": payload or {}, "__name__": "__sandboxed__"}, local_ns)
    try:
        with open("/tmp/out.json") as f:
            return json.load(f)
    except FileNotFoundError:
        return local_ns.get("__OUTPUT__", {})


SAMPLE_SCRIPT = textwrap.dedent("""
    import json
    with open("/tmp/in.json") as f:
        inp = json.load(f)
    out = {"echo": inp.get("greeting", "?"),
           "len": len(inp.get("greeting", ""))}
    with open("/tmp/out.json", "w") as f:
        json.dump(out, f)
""")


def main() -> None:
    print("=" * 72)
    print("Declaw SDK issue #06 — reference MockSandbox missing /tmp/in.json")
    print("=" * 72)

    payload = {"greeting": "hello declaw"}

    # Make sure no stale /tmp/in.json from a previous run masks the bug.
    for p in ("/tmp/in.json", "/tmp/out.json"):
        try:
            os.remove(p)
        except FileNotFoundError:
            pass

    print("\n[A] Original buggy helper (fresh /tmp, no prior in.json):")
    try:
        res = _buggy_run_python_in_sandbox("test", SAMPLE_SCRIPT, payload=payload)
        print(f"    returned: {res}")
        a_ok = bool(res)
    except FileNotFoundError as e:
        print(f"    FileNotFoundError: {e}")
        a_ok = False

    print("\n[B] Fixed helper (writes /tmp/in.json to real disk):")
    try:
        res = _fixed_run_python_in_sandbox("test", SAMPLE_SCRIPT, payload=payload)
        print(f"    returned: {res}")
        b_ok = bool(res) and res.get("echo") == "hello declaw"
    except Exception as e:
        print(f"    error: {type(e).__name__}: {e}")
        b_ok = False

    print("\nEXPECTED : [A] FAILS, [B] PASSES (demonstrates the fix)")
    print(f"OBSERVED : A={'PASS' if a_ok else 'FAIL'}, "
          f"B={'PASS' if b_ok else 'FAIL'}")
    if not a_ok and b_ok:
        print("VERDICT  : PASS — bug reproduced in original, fixed in patched helper")
    else:
        print("VERDICT  : UNEXPECTED — inspect above")


if __name__ == "__main__":
    main()
