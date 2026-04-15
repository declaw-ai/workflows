"""Declaw SDK issue #05 — audit events not retrievable from Sandbox object.

CONFIRMED BY DECLAW TEAM (2026-04-16): This is BY DESIGN — audit events
are not exposed through any method on the `Sandbox` object. They are
recorded server-side and surfaced via the Declaw dashboard / a separate
control-plane API.

So the "issue" is partly documentation — the `AuditConfig(enabled=True)`
flag signals to the user that audits are on, but there is currently no
client-facing mechanism to pull them back into an orchestrator for local
replay / SIEM forwarding / regulator evidence packaging.

REQUEST: either
  (a) add a `Sandbox.audit_events()` method that proxies to the control
      plane, returning a list of typed event structs for the sandbox's
      lifetime, OR
  (b) publish a `declaw.audit.export(sandbox_id=..., since=..., until=...)`
      client helper and document it prominently. Either way, link from
      `AuditConfig` docstring so integrators know where to look.

This script probes for the commonly-guessed names and confirms none exist,
so the reproducer output matches the expectation.

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

        print("\nEXPECTED : by design, no Sandbox-level audit retrieval "
              "method (events flow to the dashboard / control plane)")
        print(f"OBSERVED : found_any_callable = {found_any}")
        if not found_any:
            print("VERDICT  : BY-DESIGN — confirmed with Declaw team. "
                  "Retrieve audits via the Declaw dashboard / control-plane "
                  "API, not through the Sandbox object. Consider this script "
                  "a reminder to not try.")
        else:
            print("VERDICT  : UNEXPECTED — a retrieval method now exists! "
                  "Please update the helper in "
                  "sandboxed/shared/declaw_helpers.py to use it.")
    finally:
        sbx.kill()


if __name__ == "__main__":
    main()
