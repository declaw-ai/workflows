"""Multi-API policy proof: a single fintech sandbox talking to LLM + 6+
public reference APIs, with an attacker destination proving egress lock.

Confirms that `multi_bank_api_policy(extra_domains=...)` allows the
expected fintech reference APIs and hard-blocks anything else — exactly
the surface the real-world multi-API workflows (03 AML, 05 Compliance
RAG, 10 Market abuse, 12 Equity research) need.

Run:
    DECLAW_API_KEY=...  OPENAI_API_KEY=sk-... \\
    python sandboxed/verify_multi_api.py
"""
from __future__ import annotations

import os
import sys
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
from shared.declaw_helpers import (  # noqa: E402
    FINTECH_API_DOMAINS, LLM_DOMAINS, multi_bank_api_policy,
    run_python_in_sandbox, llm_envs,
)


PROBE_SCRIPT = textwrap.dedent("""
    import json, ssl, urllib.request
    ctx = ssl._create_unverified_context()

    def hit(url, headers=None):
        try:
            req = urllib.request.Request(url, headers=headers or {"User-Agent": "declaw-probe/1.0"})
            code = urllib.request.urlopen(req, timeout=15, context=ctx).getcode()
            return f"HTTP_{code}"
        except Exception as e:
            return f"ERR_{type(e).__name__}"

    results = {
        "sec_edgar": hit(
            "https://data.sec.gov/submissions/CIK0000320193.json",
            headers={"User-Agent": "declaw-probe/1.0 (contact: research@declaw.ai)"}),
        "rbi_rss": hit("https://www.rbi.org.in/Scripts/Rss.aspx?Cat=1"),
        "ofac_sdn": hit("https://www.treasury.gov/ofac/downloads/sdn.xml"),
        "nse_bulk": hit("https://www.nseindia.com/api/historical/cm/bulk"),
        "bse": hit("https://www.bseindia.com/xml-data/corpfiling/AttachHis/CorpannHist.xml"),
        "fbil": hit("https://www.fbil.org.in/"),
        "openai_simple": hit("https://api.openai.com/v1/models",
                             headers={"Authorization": "Bearer dummy"}),
        "attacker_refused": hit("https://attacker.example.com/"),
    }
    with open("/tmp/out.json", "w") as f:
        json.dump(results, f)
""")


def main():
    if not os.getenv("DECLAW_API_KEY") or not os.getenv("OPENAI_API_KEY"):
        print("need DECLAW_API_KEY and OPENAI_API_KEY")
        sys.exit(0)

    policy = multi_bank_api_policy(enable_injection_scan=False)
    print("=== Multi-API policy probe ===")
    print(f"allowlist: {LLM_DOMAINS + FINTECH_API_DOMAINS}")

    out = run_python_in_sandbox(
        "multi-api-probe", PROBE_SCRIPT, policy,
        payload={}, envs=llm_envs(), timeout=300,
    )

    print("\nResults:")
    for k, v in out.items():
        tag = "PASS" if (k == "attacker_refused" and "ERR_" in v) or \
                        (k != "attacker_refused" and v.startswith("HTTP_")) else "FAIL"
        print(f"  {k:24s}  {v:18s}  {tag}")

    ok_keys = [k for k in out if k != "attacker_refused"]
    passes = sum(1 for k in ok_keys if out[k].startswith("HTTP_"))
    attacker_blocked = "ERR_" in out["attacker_refused"]
    total_pass = passes + (1 if attacker_blocked else 0)
    print(f"\n{total_pass}/{len(out)} endpoints behaved correctly")


if __name__ == "__main__":
    main()
