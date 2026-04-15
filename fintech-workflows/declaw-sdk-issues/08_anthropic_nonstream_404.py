"""Declaw SDK issue #08 — PII-heavy Anthropic request bodies get mangled
by the proxy and come back as 404 "model not found".

DISCOVERED: 2026-04-16 while getting workflow 16 + 17 to run end-to-end.

This looks like the Anthropic-side counterpart of the already-fixed
OpenAI issue #02 (outbound JSON body mangled by PII redaction).

EXPECTED: `client.messages.create(model="claude-sonnet-4-5", ...)` and
          `client.messages.stream(...)` from inside a Declaw sandbox
          should succeed regardless of whether the request content
          contains PII identifiers (PANs, SSNs, customer names).

OBSERVED: The call succeeds when the request content is PII-free
          ("Say hi in 3 words."). The call fails with
          `anthropic.NotFoundError: 404 — model: <name>` when the
          request content contains structured JSON with PAN/SSN/
          customer records — i.e., anything Declaw's PII scanner
          would try to redact. Error reproduces on both
          `messages.create` (non-streaming) and `messages.stream`.

So the failing combination is
            (Anthropic)  ×  (PII-heavy JSON body)  ×  (via Declaw proxy)

Why 404 instead of 400: the proxy's PII redaction probably mutates the
JSON body in a way that breaks the framing of the `model` field. When
Anthropic parses the malformed body, the `model` field is missing or
corrupted, so the server returns "model: <garbage> not found" — a 404.

The original OpenAI version of this bug (SDK issue #02) returned
"could not parse JSON body" instead — slightly different error from
Anthropic, same root cause.

WORKAROUND: Pre-redact PII on the host before sending into the sandbox
            (so the proxy's scanner has nothing to match on). Alternatively
            use `log_only` PII action + accept the content flows
            unredacted. Workflow 16 currently uses the streaming path
            as a partial workaround, which also fails the same way when
            the payload is PII-heavy — so the real fix is proxy-side.

FIX (proxy-side): Make the Anthropic-path outbound-body redaction
                  JSON-aware the same way the OpenAI-path was fixed —
                  parse as JSON, walk string values, redact in-place,
                  update Content-Length. Pure byte-level regex over a
                  JSON body will keep mangling `model` when a match
                  sits adjacent to the `"model":` field.

Env: DECLAW_API_KEY, DECLAW_DOMAIN, ANTHROPIC_API_KEY
"""
from __future__ import annotations

import os
import sys
import textwrap

from declaw import (
    ALL_TRAFFIC, AuditConfig, NetworkPolicy, PIIConfig, Sandbox, SecurityPolicy,
)


# Match the real workflow conditions: PIIConfig enabled, action=redact,
# rehydrate_response=True — same as compliance_rag_policy / broker_trade_policy
# that workflows 16 + 17 use.
def policy(pii_enabled: bool) -> SecurityPolicy:
    kwargs = dict(
        network=NetworkPolicy(
            allow_out=["api.anthropic.com", "pypi.org", "*.pythonhosted.org"],
            deny_out=[ALL_TRAFFIC],
        ),
        audit=AuditConfig(enabled=True),
    )
    if pii_enabled:
        kwargs["pii"] = PIIConfig(
            enabled=True,
            types=["ssn", "credit_card", "email", "phone", "person_name"],
            action="redact",
            rehydrate_response=True,
        )
    return SecurityPolicy(**kwargs)


# 4 probes: {non-stream, stream} x {no-PII, heavy-PII}. If (no-PII) works
# but (heavy-PII) 404s, the bug is PII-body-mangling — the Anthropic-path
# counterpart of the already-fixed OpenAI issue #02.
NO_PII = "Say hi in 3 words."
HEAVY_PII = (
    "Draft a 2-sentence decline notice for customer Aarav Sharma "
    "(PAN ABCDE1234F, Aadhaar 2345 6789 0123, SSN 123-45-6789, "
    "phone +91 98210 34567, email aarav.sharma@example.com) — "
    "transaction 410599998877 flagged as high-risk."
)


def probe(call_shape: str, content: str) -> str:
    # call_shape is "nonstream" or "stream"
    if call_shape == "nonstream":
        body = textwrap.dedent(f"""
            import sys, anthropic
            print(f"anthropic SDK: {{anthropic.__version__}}", file=sys.stderr, flush=True)
            c = anthropic.Anthropic()
            try:
                r = c.messages.create(
                    model="claude-sonnet-4-5",
                    max_tokens=60,
                    messages=[{{"role":"user","content":{content!r}}}],
                )
                print("STATUS:200")
                print("REPLY:", "".join(
                    b.text for b in r.content if getattr(b, "type", "") == "text")[:180])
            except Exception as e:
                print("STATUS:ERROR")
                print("ERR:", type(e).__name__, str(e)[:220])
        """)
    else:  # stream
        body = textwrap.dedent(f"""
            import sys, anthropic
            c = anthropic.Anthropic()
            try:
                out = []
                with c.messages.stream(
                    model="claude-sonnet-4-5",
                    max_tokens=60,
                    messages=[{{"role":"user","content":{content!r}}}],
                ) as s:
                    for delta in s.text_stream:
                        out.append(delta)
                print("STATUS:200")
                print("REPLY:", "".join(out)[:180])
            except Exception as e:
                print("STATUS:ERROR")
                print("ERR:", type(e).__name__, str(e)[:220])
        """)
    return body


def run(probe_code: str, pii_enabled: bool) -> tuple[str, str]:
    sbx = Sandbox.create(
        template="ai-agent", timeout=90, security=policy(pii_enabled),
        envs={"ANTHROPIC_API_KEY": os.environ["ANTHROPIC_API_KEY"]},
    )
    try:
        # Keep anthropic pinned recent so symptoms are reproducible regardless
        # of the ai-agent template's baked-in SDK version.
        sbx.commands.run(
            "pip install --quiet --upgrade --no-cache-dir "
            "--trusted-host pypi.org --trusted-host files.pythonhosted.org "
            "anthropic>=0.68.0", timeout=240,
        )
        sbx.files.write("/tmp/probe.py", probe_code)
        r = sbx.commands.run("python3 /tmp/probe.py", timeout=60)
        return r.stdout or "", r.stderr or ""
    finally:
        sbx.kill()


def parse_status(out: str) -> tuple[str, str]:
    status, reply = "UNKNOWN", ""
    for line in out.splitlines():
        if line.startswith("STATUS:"):
            status = line.split(":", 1)[1].strip()
        if line.startswith("REPLY:") or line.startswith("ERR:"):
            reply = line.split(":", 1)[1].strip()
    return status, reply


def main() -> None:
    print("=" * 72)
    print("Declaw SDK issue #08 — PII-heavy Anthropic body mangled by proxy")
    print("=" * 72)
    if not (os.getenv("DECLAW_API_KEY") and os.getenv("ANTHROPIC_API_KEY")):
        print("need DECLAW_API_KEY + ANTHROPIC_API_KEY")
        sys.exit(0)

    # 4-cell matrix: call shape × PII policy on. Content is heavy-PII for
    # every cell so any redaction path gets exercised.
    results = {}
    for shape in ("nonstream", "stream"):
        for pii_policy in (False, True):
            tag = f"{shape} × pii-policy={pii_policy}"
            print(f"\n[{tag}]")
            out, err = run(probe(shape, HEAVY_PII), pii_enabled=pii_policy)
            print(out.strip())
            if err.strip():
                print("[stderr]", err.strip()[:200])
            status, snippet = parse_status(out)
            results[tag] = (status, snippet)

    print("\n=== Matrix ===")
    for tag, (status, snippet) in results.items():
        print(f"  {tag:40s}  status={status:6s}  reply/err={snippet[:50]!r}")

    no_policy_ok = all(results[f"{s} × pii-policy=False"][0] == "200"
                       for s in ("nonstream", "stream"))
    pii_policy_fails = all(results[f"{s} × pii-policy=True"][0] == "ERROR"
                           for s in ("nonstream", "stream"))

    print("\nEXPECTED : all 4 cells STATUS=200")
    print(f"OBSERVED : no-policy cells ok={no_policy_ok}, "
          f"pii-policy cells fail={pii_policy_fails}")
    if no_policy_ok and pii_policy_fails:
        print("VERDICT  : FAIL — bug reproduced. Anthropic requests with "
              "PII-heavy content 404 through the proxy when PIIConfig is "
              "enabled on the policy. Without PIIConfig the same content "
              "succeeds. Cause: outbound PII redaction on Anthropic JSON "
              "bodies mangles the request framing (`model` field). Same "
              "shape as SDK issue #02 (fixed for OpenAI), needs same "
              "JSON-aware redaction path for api.anthropic.com.")
    elif no_policy_ok and not pii_policy_fails:
        print("VERDICT  : PASS — all paths work. Bug appears fixed.")
    else:
        print("VERDICT  : UNKNOWN — inspect above.")


if __name__ == "__main__":
    main()
