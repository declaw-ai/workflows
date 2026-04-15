"""Declaw SDK issue #02 — outbound PII redaction mangles JSON request body.

EXPECTED: When the proxy redacts a PII match inside a
          `Content-Type: application/json` request body, the resulting
          body must still be valid JSON (match replaced within the
          string value, quotes + escaping preserved, Content-Length
          updated).

OBSERVED: OpenAI returns `400 Bad Request` — "We could not parse the
          JSON body of your request. (HINT: This likely means you
          aren't using your HTTP library correctly...)".

TRIGGER: Person_name redaction, specifically. Diagnosed 2026-04-16:

   Probe                                       Person_name triggered?  Status
   --------------------------------------------------------------------
   A. "Patient email is jordan@example.com
       and SSN is 123-45-6789."                 no                     200
   B. "ssn=123-45-6789 name=Aarav Sharma"       yes  (Aarav Sharma)    400
   C. "name=Aarav Sharma"                       yes                    400
   D. "email=alice@example.com"                 no                     200

   So the body mangle is caused by the `person_name` substitution
   (`Aarav Sharma` → `[REDACTED_PERSON_N]`), not email or SSN redaction.

WHY HEALTH-TECH WORKFLOWS DIDN'T HIT THIS: Their payloads carry names
   inside JSON keys (e.g. {"patient_name": "..."} inside a state dict)
   more than as free-text values in chat content, and ambiguous names
   ("jordan", "Patient") don't score as person_name in the ML
   classifier. The fintech workflows trip it because clean first+last
   names like "Aarav Sharma" / "Priya Iyer" in user-visible message
   strings score cleanly.

LIKELY MECHANISM: `[REDACTED_PERSON_N]` (≈20 chars) is longer than
                  `Aarav Sharma` (12 chars). If the proxy redacts bytes
                  in place without updating Content-Length, the server
                  reads past end-of-body → JSON parse fails.

WORKAROUND: None reliable. Avoid placing raw person names in user
            message strings (keep them in structured keys), or pre-redact
            names in the agent before the sandbox boundary.

FIX (server-side): Parse the request body as JSON when Content-Type
                   permits, walk string values, run the PII regex
                   against each value in isolation, re-serialise, and
                   update Content-Length. Or, if raw-bytes is intentional,
                   at minimum (a) only redact inside matched JSON string
                   tokens, (b) re-escape the replacement token for JSON,
                   and (c) rewrite Content-Length.

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
            types=["ssn", "credit_card", "email", "phone", "person_name"],
            action="redact",
            rehydrate_response=True,
        ),
        network=NetworkPolicy(
            allow_out=["api.openai.com", "pypi.org", "*.pythonhosted.org"],
            deny_out=[ALL_TRAFFIC],
        ),
        audit=AuditConfig(enabled=True),
    )


PROBE = textwrap.dedent("""
    # Ship the Accept-Encoding shim first so issue #01 is not confounding
    # with issue #02 — we want to isolate the OUTBOUND JSON mangling.
    import sys
    sys.path.insert(0, "/tmp")
    try:
        import declaw_openai_compat  # noqa: F401
    except Exception:
        pass

    from openai import OpenAI
    # Raw SSN in the request content — this triggers outbound redaction.
    msg = ("Echo bot. Repeat verbatim between markers. "
           "<<<ssn=123-45-6789 name=Aarav Sharma>>>")
    try:
        r = OpenAI().chat.completions.create(
            model="gpt-4.1",
            messages=[{"role": "user", "content": msg}],
            max_completion_tokens=80,
        )
        print("STATUS: 200")
        print("AGENT_READ_BACK:", r.choices[0].message.content)
    except Exception as e:
        print("STATUS: ERROR")
        print("ERROR_TYPE:", type(e).__name__)
        print("ERROR_MSG:", str(e)[:500])
""")


# Minimal Accept-Encoding shim shipped inline to rule out issue #01.
COMPAT_SHIM = textwrap.dedent("""
    import httpx
    _orig_s = httpx.Client.__init__
    _orig_a = httpx.AsyncClient.__init__
    def _inject(h):
        hd = httpx.Headers(h) if h is not None else httpx.Headers()
        if not any(k.lower() == "accept-encoding" for k in hd.keys()):
            hd["Accept-Encoding"] = "identity"
        return hd
    def _ps(self, *a, **kw):
        kw["headers"] = _inject(kw.get("headers")); return _orig_s(self, *a, **kw)
    def _pa(self, *a, **kw):
        kw["headers"] = _inject(kw.get("headers")); return _orig_a(self, *a, **kw)
    httpx.Client.__init__ = _ps
    httpx.AsyncClient.__init__ = _pa
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
        sbx.files.write("/tmp/declaw_openai_compat.py", COMPAT_SHIM)
        sbx.files.write("/tmp/script.py", PROBE)
        r = sbx.commands.run("python3 /tmp/script.py", timeout=90)
        return r.stdout or "", r.stderr or ""
    finally:
        sbx.kill()


def main() -> None:
    print("=" * 72)
    print("Declaw SDK issue #02 — outbound JSON body mangled by PII redaction")
    print("=" * 72)
    out, err = run()
    print(out)
    if err:
        print("[stderr]", err[:400])

    got_400 = (
        "could not parse the JSON body" in out
        or "400" in out and "ERROR_TYPE: BadRequestError" in out
    )
    got_200 = "STATUS: 200" in out
    verdict = "FAIL (proxy mangled JSON)" if got_400 else \
              "PASS" if got_200 else "UNKNOWN"
    print("\nEXPECTED : STATUS: 200 (redaction applied to JSON value only)")
    print(f"OBSERVED : 400 JSON-parse error from OpenAI = {got_400}")
    print(f"VERDICT  : {verdict}")


if __name__ == "__main__":
    main()
