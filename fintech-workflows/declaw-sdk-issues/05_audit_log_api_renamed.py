"""Declaw SDK issue #05 — no public client method to retrieve audit log.

EXPECTED: `Sandbox` created with `AuditConfig(enabled=True)` exposes a
          documented method — e.g. `sandbox.get_audit_log()` returning
          a list of structured event dicts — so the orchestrator can
          persist the trail for regulator replay.

OBSERVED: Three plausible attribute names all return `callable is None`
          on the returned Sandbox object:
            * get_audit_log
            * audit_log
            * get_audit_logs
          Events are presumably stored server-side (control plane /
          gateway logs) but the client cannot fetch them.

WORKAROUND: Skip the in-workflow audit-retrieval step and tell operators
            to pull the trail from the Declaw dashboard / export API.

FIX (server-side): Pick one canonical method name on `Sandbox` — I'd
                   suggest `sandbox.audit_events()` returning typed
                   structs — and keep old names as deprecated aliases.
                   Add to the public SDK reference docs.

Env: DECLAW_API_KEY, DECLAW_DOMAIN
"""
from __future__ import annotations

import os
import sys
import textwrap

from declaw import (
    ALL_TRAFFIC, AuditConfig, NetworkPolicy, Sandbox, SecurityPolicy,
)


CANDIDATE_NAMES = [
    "get_audit_log",
    "audit_log",
    "get_audit_logs",
    "audit_events",
    "get_events",
    "events",
    "logs",
]


def policy() -> SecurityPolicy:
    return SecurityPolicy(
        network=NetworkPolicy(allow_out=["httpbin.org"], deny_out=[ALL_TRAFFIC]),
        audit=AuditConfig(enabled=True),
    )


def main() -> None:
    print("=" * 72)
    print("Declaw SDK issue #05 — audit-log retrieval API missing on client")
    print("=" * 72)

    if not os.getenv("DECLAW_API_KEY"):
        print("need DECLAW_API_KEY")
        sys.exit(0)

    sbx = Sandbox.create(template="ai-agent", timeout=60, security=policy())
    try:
        # Generate one outbound call so there is something to audit.
        sbx.files.write("/tmp/script.py", textwrap.dedent("""
            import json, ssl, urllib.request
            ctx = ssl._create_unverified_context()
            urllib.request.urlopen(urllib.request.Request(
                "https://httpbin.org/post", data=b'{"x":1}',
                headers={"Content-Type":"application/json"}),
                timeout=15, context=ctx).read()
            print("DONE")
        """))
        sbx.commands.run("python3 /tmp/script.py", timeout=60)

        print("\nProbing candidate attribute names on the Sandbox object:\n")
        found_any = False
        for name in CANDIDATE_NAMES:
            attr = getattr(sbx, name, None)
            present = attr is not None
            callable_ = callable(attr)
            print(f"  {name:20s}  present={present!s:5}  callable={callable_!s:5}")
            if callable_:
                try:
                    events = attr()
                    found_any = True
                    print(f"    -> returned {len(events)} event(s): "
                          f"{type(events).__name__}")
                    if events:
                        sample = events[0]
                        keys = list(sample.keys()) if isinstance(sample, dict) else "(not a dict)"
                        print(f"    -> first event keys: {keys}")
                except Exception as e:
                    print(f"    -> call raised: {type(e).__name__}: {e}")

        print("\nEXPECTED : at least one name above returns a non-empty list")
        print(f"OBSERVED : found_any_callable = {found_any}")
        print(f"VERDICT  : {'PASS' if found_any else 'FAIL — client cannot retrieve audit log'}")
    finally:
        sbx.kill()


if __name__ == "__main__":
    main()
