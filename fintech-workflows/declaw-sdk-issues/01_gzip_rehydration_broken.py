"""Declaw SDK issue #01 — gzip response body breaks PII rehydration.

EXPECTED: With `PIIConfig(rehydrate_response=True)`, an OpenAI response that
          contains a PII token (emitted because the same PII was in the
          request) must come back to the agent with the ORIGINAL PII
          (rehydrated). Example: request contains email
          `alice@example.com`; response echoes it; agent should read
          `alice@example.com`, not `[REDACTED_EMAIL_ADDRESS_3]`.

OBSERVED: The model response still contains the redaction token. Root
          cause: OpenAI returns `Content-Encoding: gzip` by default
          (because httpx's default `Accept-Encoding` is `gzip, deflate`),
          and the Declaw proxy does not decode the gzipped body before
          running the rehydration substitution.

WORKAROUND: Ship a per-sandbox monkey-patch that forces
            `Accept-Encoding: identity` on all httpx clients created
            inside the sandbox, so OpenAI returns plaintext.

FIX (server-side): Make the proxy decode `Content-Encoding: gzip|br|deflate`
                   on responses before scanning, rehydrate tokens, then
                   either re-encode or strip the header.

Env: DECLAW_API_KEY, DECLAW_DOMAIN, OPENAI_API_KEY
"""
from __future__ import annotations

import os
import sys
import textwrap

from declaw import (
    ALL_TRAFFIC, AuditConfig, NetworkPolicy, PIIConfig, Sandbox, SecurityPolicy,
)


def policy() -> SecurityPolicy:
    return SecurityPolicy(
        pii=PIIConfig(
            enabled=True,
            types=["email", "person_name", "phone", "ssn", "credit_card"],
            action="redact",
            rehydrate_response=True,        # this is the thing under test
        ),
        network=NetworkPolicy(
            allow_out=["api.openai.com", "pypi.org", "*.pythonhosted.org"],
            deny_out=[ALL_TRAFFIC],
        ),
        audit=AuditConfig(enabled=True),
    )


PROBE_WITHOUT_SHIM = textwrap.dedent("""
    from openai import OpenAI
    r = OpenAI().chat.completions.create(
        model="gpt-4.1",
        messages=[{"role":"user","content":
                   "Echo bot. Repeat verbatim between markers. "
                   "<<<email=alice@example.com name=Alice Smith>>>"}],
        max_completion_tokens=80,
    )
    print("AGENT_READ_BACK:", r.choices[0].message.content)
""")


def run() -> tuple[str, str]:
    if not (os.getenv("DECLAW_API_KEY") and os.getenv("OPENAI_API_KEY")):
        print("need DECLAW_API_KEY + OPENAI_API_KEY")
        sys.exit(0)
    sbx = Sandbox.create(
        template="ai-agent", timeout=120, security=policy(),
        envs={"OPENAI_API_KEY": os.environ["OPENAI_API_KEY"]},
    )
    try:
        sbx.files.write("/tmp/script.py", PROBE_WITHOUT_SHIM)
        r = sbx.commands.run("python3 /tmp/script.py", timeout=90)
        return r.stdout or "", r.stderr or ""
    finally:
        sbx.kill()


def main() -> None:
    print("=" * 72)
    print("Declaw SDK issue #01 — gzip response body breaks rehydration")
    print("=" * 72)
    out, err = run()
    print(out)
    if err:
        print("[stderr]", err[:400])

    read_back = ""
    for line in out.splitlines():
        if line.startswith("AGENT_READ_BACK:"):
            read_back = line.split(":", 1)[1].strip()
            break

    email_ok = "alice@example.com" in read_back
    name_ok = "Alice Smith" in read_back
    print("\nEXPECTED : agent reads original email + name after rehydration")
    print(f"OBSERVED : agent read back: {read_back!r}")
    print(f"VERDICT  : {'PASS' if (email_ok and name_ok) else 'FAIL'}  "
          f"(email rehydrated={email_ok}, name rehydrated={name_ok})")
    print("\nNote: if this reads FAIL, apply the declaw_openai_compat.py shim")
    print("      (ships Accept-Encoding: identity) and rerun — it should PASS.")


if __name__ == "__main__":
    main()
