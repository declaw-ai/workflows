"""Root-cause diagnosis for SDK issue #02 — which kind of PII in a JSON
body actually triggers the outbound mangling?

Three probes against OpenAI, same policy, only the content differs:
  A. email + ssn in a natural sentence (health-tech's pattern — works)
  B. ssn + person_name in key=value form (fintech's #02 pattern — fails)
  C. person_name only (isolates person_name as the trigger)
  D. email only (isolates email redaction)

Each variant is sent in its own sandbox so effects don't bleed.
"""
from __future__ import annotations
import os, sys, textwrap
from declaw import (
    ALL_TRAFFIC, AuditConfig, NetworkPolicy, PIIConfig, Sandbox, SecurityPolicy,
)

def policy():
    return SecurityPolicy(
        pii=PIIConfig(enabled=True,
                      types=["ssn","credit_card","email","phone","person_name"],
                      action="redact", rehydrate_response=True),
        network=NetworkPolicy(allow_out=["api.openai.com","pypi.org",
                                         "*.pythonhosted.org"],
                              deny_out=[ALL_TRAFFIC]),
        audit=AuditConfig(enabled=True),
    )

SHIM = textwrap.dedent("""
    import httpx
    _s=httpx.Client.__init__;_a=httpx.AsyncClient.__init__
    def _inj(h):
        hd=httpx.Headers(h) if h is not None else httpx.Headers()
        if not any(k.lower()=="accept-encoding" for k in hd.keys()):
            hd["Accept-Encoding"]="identity"
        return hd
    httpx.Client.__init__=lambda s,*a,**kw:_s(s,*a,**{**kw,"headers":_inj(kw.get("headers"))})
    httpx.AsyncClient.__init__=lambda s,*a,**kw:_a(s,*a,**{**kw,"headers":_inj(kw.get("headers"))})
""")

def probe(content: str) -> str:
    return textwrap.dedent(f"""
        import sys
        sys.path.insert(0,"/tmp")
        try: import declaw_openai_compat
        except Exception: pass
        from openai import OpenAI
        try:
            r = OpenAI().chat.completions.create(
                model="gpt-4.1",
                messages=[{{"role":"user","content":{content!r}}}],
                max_completion_tokens=80,
            )
            print("STATUS:200")
            print("REPLY:", r.choices[0].message.content)
        except Exception as e:
            print("STATUS:ERROR")
            print("ERR:", type(e).__name__, str(e)[:160])
    """)

def run(label, content):
    sbx = Sandbox.create(template="ai-agent", timeout=90, security=policy(),
                         envs={"OPENAI_API_KEY":os.environ["OPENAI_API_KEY"]})
    try:
        sbx.files.write("/tmp/declaw_openai_compat.py", SHIM)
        sbx.files.write("/tmp/script.py", probe(content))
        r = sbx.commands.run("python3 /tmp/script.py", timeout=60)
        out = r.stdout or ""
        print(f"\n=== {label} ===\ncontent: {content!r}")
        print(out.strip())
    finally:
        sbx.kill()

if not (os.getenv("DECLAW_API_KEY") and os.getenv("OPENAI_API_KEY")):
    sys.exit("need DECLAW_API_KEY + OPENAI_API_KEY")

run("A. natural sentence (health-tech style)",
    "Echo bot. Repeat verbatim between markers. <<<Patient email is jordan@example.com and SSN is 123-45-6789.>>>")
run("B. key=value (fintech #02 style)",
    "Echo bot. Repeat verbatim between markers. <<<ssn=123-45-6789 name=Aarav Sharma>>>")
run("C. person_name only",
    "Echo bot. Repeat verbatim between markers. <<<name=Aarav Sharma>>>")
run("D. email only",
    "Echo bot. Repeat verbatim between markers. <<<email=alice@example.com>>>")
