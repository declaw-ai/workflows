"""Declaw SDK issue #04 — NetworkPolicy allows L4 handshake to
non-allowlisted hosts.

EXPECTED: With `NetworkPolicy(allow_out=["api.openai.com"],
          deny_out=[ALL_TRAFFIC])`, a raw
          `socket.create_connection(("evil.com", 443), timeout=3)`
          should fail (OSError / timeout). Rationale: a primitive
          "can this sandbox reach an arbitrary host" check is expected
          to hold at L4; otherwise it reads like the policy is
          misconfigured or bypassed.

OBSERVED: The connection succeeds (TCP handshake completes). No bytes
          actually flow past the TLS ClientHello because the SNI is
          matched at L7 and traffic is dropped there — but the
          `socket.create_connection` call returns a usable socket.

WORKAROUND: Probe using an HTTPS call instead of a raw socket; that one
            correctly fails. For our primitive-suite readability we just
            report the observation.

FIX (server-side): Either (a) resolve allow-listed domains at
                   sandbox-create time and install a per-sandbox iptables
                   `ACCEPT <ips> / DROP default` rule so L4 is enforced
                   alongside SNI; or (b) document the current L7-only
                   semantics prominently and update the primitive-check
                   narrative.

Env: DECLAW_API_KEY, DECLAW_DOMAIN
"""
from __future__ import annotations

import os
import sys
import textwrap

from declaw import (
    ALL_TRAFFIC, AuditConfig, NetworkPolicy, Sandbox, SecurityPolicy,
)


def policy() -> SecurityPolicy:
    return SecurityPolicy(
        network=NetworkPolicy(
            allow_out=["api.openai.com"],
            deny_out=[ALL_TRAFFIC],
        ),
        audit=AuditConfig(enabled=True),
    )


PROBE = textwrap.dedent("""
    import socket
    # (a) L4 probe: raw TCP connect to a non-allowlisted host.
    try:
        s = socket.create_connection(("evil.com", 443), timeout=3)
        s.close()
        print("L4_EVIL_COM: REACH")
    except OSError as e:
        print(f"L4_EVIL_COM: BLOCK ({type(e).__name__})")

    # (b) L7 probe: actually try to send bytes; this SHOULD fail.
    import ssl, http.client
    try:
        ctx = ssl._create_unverified_context()
        conn = http.client.HTTPSConnection("evil.com", 443, timeout=5, context=ctx)
        conn.request("GET", "/")
        conn.getresponse()
        print("L7_EVIL_COM: REACH")
    except Exception as e:
        print(f"L7_EVIL_COM: BLOCK ({type(e).__name__})")

    # (c) Positive control: allowlisted host should reach at both layers.
    try:
        s = socket.create_connection(("api.openai.com", 443), timeout=5)
        s.close()
        print("L4_OPENAI:   REACH")
    except OSError as e:
        print(f"L4_OPENAI:   BLOCK ({type(e).__name__})")
""")


def run() -> tuple[str, str]:
    if not os.getenv("DECLAW_API_KEY"):
        print("need DECLAW_API_KEY")
        sys.exit(0)
    sbx = Sandbox.create(template="ai-agent", timeout=60, security=policy())
    try:
        sbx.files.write("/tmp/script.py", PROBE)
        r = sbx.commands.run("python3 /tmp/script.py", timeout=45)
        return r.stdout or "", r.stderr or ""
    finally:
        sbx.kill()


def main() -> None:
    print("=" * 72)
    print("Declaw SDK issue #04 — L4 TCP connect reaches non-allowlisted host")
    print("=" * 72)
    out, err = run()
    print(out)
    if err:
        print("[stderr]", err[:400])

    l4_evil_reach = "L4_EVIL_COM: REACH" in out
    l7_evil_block = "L7_EVIL_COM: BLOCK" in out
    l4_openai_reach = "L4_OPENAI:   REACH" in out

    print("\nEXPECTED : L4_EVIL_COM BLOCK, L7_EVIL_COM BLOCK, L4_OPENAI REACH")
    print(f"OBSERVED : L4 evil.com reach = {l4_evil_reach}, "
          f"L7 evil.com blocked = {l7_evil_block}, "
          f"L4 openai reach = {l4_openai_reach}")
    if l4_evil_reach and l7_evil_block and l4_openai_reach:
        print("VERDICT  : DEGRADED — L4 permissive, L7 enforcement works as "
              "designed. Document or tighten.")
    elif not l4_evil_reach:
        print("VERDICT  : PASS (L4 now enforced — was this fixed?)")
    else:
        print("VERDICT  : UNKNOWN — inspect raw output above.")


if __name__ == "__main__":
    main()
