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


def policy_no_rehydrate() -> SecurityPolicy:
    # rehydrate=False so we see exactly what the model received.
    return SecurityPolicy(
        pii=PIIConfig(
            enabled=True,
            types=["ssn", "email", "person_name", "credit_card", "phone"],
            action="redact",
            rehydrate_response=False,
        ),
        network=NetworkPolicy(
            allow_out=["api.openai.com", "pypi.org", "*.pythonhosted.org"],
            deny_out=[ALL_TRAFFIC],
        ),
        audit=AuditConfig(enabled=True),
    )


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


def run() -> tuple[str, str]:
    if not (os.getenv("DECLAW_API_KEY") and os.getenv("OPENAI_API_KEY")):
        print("need DECLAW_API_KEY + OPENAI_API_KEY")
        sys.exit(0)
    sbx = Sandbox.create(
        template="ai-agent", timeout=120, security=policy_no_rehydrate(),
        envs={"OPENAI_API_KEY": os.environ["OPENAI_API_KEY"]},
    )
    try:
        sbx.files.write("/tmp/declaw_openai_compat.py", SHIM)
        sbx.files.write("/tmp/script.py", PROBE)
        r = sbx.commands.run("python3 /tmp/script.py", timeout=90)
        return r.stdout or "", r.stderr or ""
    finally:
        sbx.kill()


def main() -> None:
    print("=" * 72)
    print("Declaw SDK issue #03 — built-in `ssn` type does not redact")
    print("=" * 72)
    out, err = run()
    print(out)
    if err:
        print("[stderr]", err[:400])

    model_saw = ""
    for line in out.splitlines():
        if line.startswith("MODEL_SAW:"):
            model_saw = line.split(":", 1)[1].strip()
            break

    ssn_redacted = "123-45-6789" not in model_saw
    email_redacted = "alice@example.com" not in model_saw
    name_redacted = "Alice Smith" not in model_saw

    print("\nEXPECTED : all three identifiers replaced with [REDACTED_*]")
    print(f"OBSERVED : ssn_redacted={ssn_redacted}, "
          f"email_redacted={email_redacted}, name_redacted={name_redacted}")
    if email_redacted and name_redacted and not ssn_redacted:
        print("VERDICT  : FAIL — `ssn` type present in config but not enforced")
    elif all([ssn_redacted, email_redacted, name_redacted]):
        print("VERDICT  : PASS")
    else:
        print("VERDICT  : DEGRADED — multiple types not firing, check PIIConfig")


if __name__ == "__main__":
    main()
