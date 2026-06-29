"""Verify declaw PII dehydration + rehydration against two destinations.

Two probes:
  1. httpbin.org/post — controlled echo. Whatever httpbin receives in the
     request body is mirrored back in the response. This lets us compare
     what the destination got vs. what the agent reads.
  2. api.openai.com    — real LLM (gpt-4.1) asked to repeat the input
     verbatim between markers. Tests whether the proxy can rehydrate
     tokens inside an OpenAI response body (chunked / gzip-encoded).

Run:
    DECLAW_API_KEY=...  DECLAW_DOMAIN=api.declaw.ai \\
    OPENAI_API_KEY=sk-...  python sandboxed/verify_pii_handling.py

What we expect to see (declaw >= 1.3.0):
                          rehydrate=False         rehydrate=True
    httpbin destination   tokens                  originals
    OpenAI  destination   tokens                  originals

Conclusion: outbound redaction is reliable on both destinations, and inbound
rehydration now fires on BOTH plain HTTP/JSON destinations AND OpenAI's
chunked/gzip response stream — the earlier gap (rehydration was a no-op on the
OpenAI path) is fixed proxy-side. So `rehydrate_response=True` lets the agent
read back original PHI transparently regardless of destination, while the LLM
only ever sees opaque tokens.
"""
from __future__ import annotations

import os
import sys
import textwrap

from declaw import (
    ALL_TRAFFIC,
    AuditConfig,
    NetworkPolicy,
    PIIConfig,
    Sandbox,
    SecurityPolicy,
)


HTTPBIN_PROBE = textwrap.dedent("""
    import json, ssl, urllib.request
    # Sandbox clock can lag → TLS verify fails. PII is the thing under test
    # here, not chain trust (the proxy MITMs anyway). Skip verify.
    ctx = ssl._create_unverified_context()
    body = json.dumps({
        "patient_email": "alice.smith@example.com",
        "patient_phone": "555-867-5309",
        "ssn": "123-45-6789",
    }).encode()
    req = urllib.request.Request(
        "https://httpbin.org/post",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    resp_text = urllib.request.urlopen(req, timeout=20, context=ctx).read().decode()
    echoed = json.loads(resp_text)["json"]
    print("AGENT_READ_BACK:", json.dumps(echoed))
""")


OPENAI_PROBE = textwrap.dedent("""
    from openai import OpenAI
    PHI = "Patient email is jordan@example.com and SSN is 123-45-6789."
    client = OpenAI()
    r = client.chat.completions.create(
        model="gpt-4.1",
        messages=[{"role": "user", "content":
                   f"Echo bot. Repeat verbatim between markers. <<<{PHI}>>>"}],
        max_completion_tokens=120,
    )
    print("AGENT_READ_BACK:", r.choices[0].message.content)
""")


def policy(allow_domains: list[str], rehydrate: bool) -> SecurityPolicy:
    return SecurityPolicy(
        pii=PIIConfig(
            enabled=True,
            types=["email", "phone", "ssn"],
            action="redact",
            rehydrate_response=rehydrate,
        ),
        network=NetworkPolicy(
            allow_out=allow_domains,
            deny_out=[ALL_TRAFFIC],
        ),
        audit=AuditConfig(enabled=True),
    )


def run_probe(name: str, probe: str, allow_domains: list[str],
              rehydrate: bool, pip_packages: list[str] | None = None,
              envs: dict[str, str] | None = None) -> str:
    sbx = Sandbox.create(
        template="python", timeout=180,
        security=policy(allow_domains, rehydrate),
        envs=envs or {},
    )
    try:
        if pip_packages:
            ri = sbx.commands.run(
                "pip install --quiet "
                "--trusted-host pypi.org "
                "--trusted-host files.pythonhosted.org "
                f"{' '.join(pip_packages)}",
                timeout=180,
            )
            if ri.exit_code != 0:
                return f"[pip exit={ri.exit_code}] {ri.stderr.strip()[:400]}"
        sbx.files.write("/tmp/p.py", probe)
        out = sbx.commands.run("python3 /tmp/p.py", timeout=90)
        if out.exit_code != 0:
            return f"[exit={out.exit_code}] STDERR: {out.stderr.strip()[:400]}"
        return out.stdout.strip()
    finally:
        sbx.kill()


GREEN = "\033[32m"; RED = "\033[31m"; END = "\033[0m"

# Originals the probes embed; rehydrate=True must restore these, rehydrate=False
# must NOT (the agent reads tokens instead).
HTTPBIN_ORIGINALS = ["alice.smith@example.com", "555-867-5309", "123-45-6789"]
OPENAI_ORIGINALS = ["jordan@example.com", "123-45-6789"]

passes = 0
fails = 0


def check(restored: bool, originals: list[str], out: str, label: str) -> None:
    """When restored=True we expect the originals back; when False we expect
    none of them (tokens stand in)."""
    global passes, fails
    present = [o for o in originals if o in out]
    good = (len(present) == len(originals)) if restored else (len(present) == 0)
    if good:
        passes += 1
        print(f"  {GREEN}PASS{END} {label}")
    else:
        fails += 1
        print(f"  {RED}FAIL{END} {label} (originals present: {present})")


def main() -> None:
    if not os.getenv("DECLAW_API_KEY"):
        print("DECLAW_API_KEY not set"); sys.exit(1)

    print("=" * 64)
    print("Probe 1: httpbin echo  (controlled destination)")
    print("=" * 64)
    for rehydrate in (False, True):
        out = run_probe("httpbin", HTTPBIN_PROBE,
                        allow_domains=["httpbin.org", "*.httpbin.org"],
                        rehydrate=rehydrate)
        print(f"\nrehydrate_response={rehydrate}:")
        for line in out.splitlines():
            print(f"  {line}")
        check(rehydrate, HTTPBIN_ORIGINALS, out,
              f"httpbin rehydrate={rehydrate}: "
              + ("originals restored" if rehydrate else "tokens only (no originals)"))

    if not os.getenv("OPENAI_API_KEY"):
        print("\n(skip OpenAI probe — OPENAI_API_KEY not set)")
    else:
        print()
        print("=" * 64)
        print("Probe 2: OpenAI gpt-4.1 echo  (real LLM destination)")
        print("=" * 64)
        for rehydrate in (False, True):
            out = run_probe("openai", OPENAI_PROBE,
                            allow_domains=["api.openai.com", "pypi.org",
                                           "*.pythonhosted.org",
                                           "files.pythonhosted.org"],
                            rehydrate=rehydrate,
                            pip_packages=["openai"],
                            envs={"OPENAI_API_KEY": os.environ["OPENAI_API_KEY"]})
            print(f"\nrehydrate_response={rehydrate}:")
            for line in out.splitlines():
                print(f"  {line}")
            # declaw >= 1.3.0: rehydration now fires on the OpenAI response too.
            check(rehydrate, OPENAI_ORIGINALS, out,
                  f"OpenAI rehydrate={rehydrate}: "
                  + ("originals restored" if rehydrate else "tokens only (no originals)"))

    print(f"\n{GREEN}{passes} pass{END}   {RED}{fails} fail{END}")
    sys.exit(0 if fails == 0 else 1)


if __name__ == "__main__":
    main()
