"""Declaw SDK issue #03 — built-in `ssn` type does not fire.

EXPECTED: With `PIIConfig(types=[..., "ssn", "email", "person_name"],
          action="redact")`, a request body containing `123-45-6789`
          must have the SSN redacted before the body reaches OpenAI
          (observable via `rehydrate_response=False` — the model
          echoes the token, not the original).

OBSERVED: `email` and `person_name` get redacted correctly, but `ssn`
          passes through untouched. The model sees the raw
          `123-45-6789` in the request.

WORKAROUND: Add a `TransformationRule(direction="outbound",
            match=r"\\b\\d{3}-\\d{2}-\\d{4}\\b", replace="[REDACTED_SSN]")`
            explicitly. Works, but `ssn` as a built-in type is advertised
            to work without a rule.

FIX (server-side): The built-in SSN detector's regex is either absent or
                   tagged under a different name (`social_security`,
                   `us_ssn`, etc.) in this build. Align with Presidio /
                   advertised type list, add a unit test.

Env: DECLAW_API_KEY, DECLAW_DOMAIN, OPENAI_API_KEY
"""
from __future__ import annotations

import os
import sys
import textwrap

from declaw import (
    ALL_TRAFFIC, AuditConfig, NetworkPolicy, PIIConfig, Sandbox, SecurityPolicy,
)


def policy_no_rehydrate(allow_domains) -> SecurityPolicy:
    # rehydrate=False so we see exactly what the destination received.
    return SecurityPolicy(
        pii=PIIConfig(
            enabled=True,
            types=["ssn", "email", "person_name", "credit_card", "phone"],
            action="redact",
            rehydrate_response=False,
        ),
        network=NetworkPolicy(allow_out=allow_domains,
                              deny_out=[ALL_TRAFFIC]),
        audit=AuditConfig(enabled=True),
    )


HTTPBIN_PROBE = textwrap.dedent("""
    # Isolated from issue #02 — httpbin echoes the JSON body back without
    # re-parsing, so we can see exactly what the redactor left intact.
    import json, ssl, urllib.request
    ctx = ssl._create_unverified_context()
    body = json.dumps({
        "ssn": "123-45-6789",
        "email": "alice@example.com",
        "name": "Alice Smith",
    }).encode()
    r = urllib.request.urlopen(urllib.request.Request(
        "https://httpbin.org/post", data=body,
        headers={"Content-Type":"application/json"}), timeout=15, context=ctx)
    echoed = json.loads(r.read().decode())["json"]
    print("DEST_SAW:", json.dumps(echoed))
""")


# Ship the Accept-Encoding shim inline so we see the MODEL-visible string.
PROBE = textwrap.dedent("""
    import sys
    sys.path.insert(0, "/tmp")
    try:
        import declaw_openai_compat  # noqa
    except Exception:
        pass
    from openai import OpenAI
    msg = ("Echo bot. Repeat verbatim between markers. "
           "<<<ssn=123-45-6789 email=alice@example.com name=Alice Smith>>>")
    r = OpenAI().chat.completions.create(
        model="gpt-4.1",
        messages=[{"role": "user", "content": msg}],
        max_completion_tokens=120,
    )
    print("MODEL_SAW:", r.choices[0].message.content)
""")


SHIM = textwrap.dedent("""
    import httpx
    _s = httpx.Client.__init__; _a = httpx.AsyncClient.__init__
    def _inj(h):
        hd = httpx.Headers(h) if h is not None else httpx.Headers()
        if not any(k.lower()=="accept-encoding" for k in hd.keys()):
            hd["Accept-Encoding"] = "identity"
        return hd
    httpx.Client.__init__ = lambda self,*a,**kw: _s(self,*a,**{**kw,"headers":_inj(kw.get("headers"))})
    httpx.AsyncClient.__init__ = lambda self,*a,**kw: _a(self,*a,**{**kw,"headers":_inj(kw.get("headers"))})
""")


def run_openai() -> tuple[str, str]:
    sbx = Sandbox.create(
        template="ai-agent", timeout=120,
        security=policy_no_rehydrate(["api.openai.com", "pypi.org",
                                      "*.pythonhosted.org"]),
        envs={"OPENAI_API_KEY": os.environ["OPENAI_API_KEY"]},
    )
    try:
        sbx.files.write("/tmp/declaw_openai_compat.py", SHIM)
        sbx.files.write("/tmp/script.py", PROBE)
        r = sbx.commands.run("python3 /tmp/script.py", timeout=90)
        return r.stdout or "", r.stderr or ""
    finally:
        sbx.kill()


def run_httpbin() -> tuple[str, str]:
    sbx = Sandbox.create(
        template="ai-agent", timeout=120,
        security=policy_no_rehydrate(["httpbin.org"]),
    )
    try:
        sbx.files.write("/tmp/script.py", HTTPBIN_PROBE)
        r = sbx.commands.run("python3 /tmp/script.py", timeout=60)
        return r.stdout or "", r.stderr or ""
    finally:
        sbx.kill()


def main() -> None:
    print("=" * 72)
    print("Declaw SDK issue #03 — built-in `ssn` type does not redact")
    print("=" * 72)

    if not (os.getenv("DECLAW_API_KEY") and os.getenv("OPENAI_API_KEY")):
        print("need DECLAW_API_KEY + OPENAI_API_KEY")
        sys.exit(0)

    # (A) Isolated httpbin probe — independent of issue #02.
    print("\n[A] httpbin.org/post probe (isolates #03 from #02):")
    out_b, err_b = run_httpbin()
    print(out_b)
    if err_b:
        print("[stderr]", err_b[:300])

    dest_saw = ""
    for line in out_b.splitlines():
        if line.startswith("DEST_SAW:"):
            dest_saw = line.split(":", 1)[1].strip()
            break

    if dest_saw:
        ssn_redacted_b = "123-45-6789" not in dest_saw
        email_redacted_b = "alice@example.com" not in dest_saw
        name_redacted_b = "Alice Smith" not in dest_saw
        print(f"[A] ssn_redacted={ssn_redacted_b}, "
              f"email_redacted={email_redacted_b}, name_redacted={name_redacted_b}")
    else:
        ssn_redacted_b = email_redacted_b = name_redacted_b = None
        print("[A] httpbin probe did not produce DEST_SAW — check stderr above")

    # (B) OpenAI probe — may be masked by #02. Informational only.
    print("\n[B] OpenAI echo probe (may hit issue #02 first):")
    out_a, err_a = run_openai()
    print(out_a)
    upstream_blocked = (
        "could not parse the JSON body" in (err_a + out_a)
        or "BadRequestError" in (err_a + out_a)
    )
    model_saw = ""
    for line in out_a.splitlines():
        if line.startswith("MODEL_SAW:"):
            model_saw = line.split(":", 1)[1].strip()
            break

    if upstream_blocked and not model_saw:
        print("[B] BLOCKED-BY-#02 (as expected when SSN redaction in a "
              "JSON body hits the proxy's outbound mangling path)")
    elif model_saw:
        print(f"[B] MODEL_SAW: {model_saw!r}")

    # Final verdict is driven by the httpbin probe (which is independent
    # of #02). If httpbin couldn't run at all, fall back to UNKNOWN.
    print("\nEXPECTED : all three identifiers replaced with [REDACTED_*] "
          "on both paths")
    if dest_saw is None or ssn_redacted_b is None:
        print("VERDICT  : UNKNOWN (httpbin probe did not return DEST_SAW)")
    elif email_redacted_b and name_redacted_b and not ssn_redacted_b:
        print("VERDICT  : FAIL — `ssn` type present in config but not enforced "
              "(email + name redacted correctly; SSN passes through)")
    elif all([ssn_redacted_b, email_redacted_b, name_redacted_b]):
        print("VERDICT  : PASS (all three types enforced on the httpbin path)")
    else:
        print("VERDICT  : DEGRADED — multiple types not firing, check PIIConfig")


if __name__ == "__main__":
    main()
