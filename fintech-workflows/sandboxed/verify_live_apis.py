"""Smoke-test every live public API used by the fintech workflows, from
inside a sandbox with `multi_bank_api_policy` so we also exercise the
Declaw network allowlist end-to-end.

If any endpoint is flaky (SEC rate-limit, NSE captcha, etc), CI can read
the output and skip the workflows that depend on it rather than failing.

Run:
    DECLAW_API_KEY=...  python sandboxed/verify_live_apis.py
"""
from __future__ import annotations

import os
import sys
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
from shared.declaw_helpers import (  # noqa: E402
    multi_bank_api_policy, run_python_in_sandbox, llm_envs,
)


LIVE_PROBE = textwrap.dedent("""
    import json, ssl, urllib.request
    ctx = ssl._create_unverified_context()

    def hit(url, headers=None):
        try:
            req = urllib.request.Request(url, headers=headers or {
                "User-Agent": "declaw-ai-workflows/1.0 (contact: research@declaw.ai)"})
            code = urllib.request.urlopen(req, timeout=20, context=ctx).getcode()
            return f"HTTP_{code}"
        except Exception as e:
            return f"ERR_{type(e).__name__}"

    out = {
        "SEC EDGAR companyfacts": hit(
            "https://data.sec.gov/api/xbrl/companyfacts/CIK0000320193.json"),
        "SEC EDGAR submissions":  hit(
            "https://data.sec.gov/submissions/CIK0000320193.json"),
        "RBI circular RSS":       hit("https://www.rbi.org.in/Scripts/Rss.aspx?Cat=1"),
        "OFAC SDN XML":           hit("https://www.treasury.gov/ofac/downloads/sdn.xml"),
        "NSE bulk deals":         hit("https://www.nseindia.com/api/historical/cm/bulk"),
        "BSE announcements":      hit("https://www.bseindia.com/xml-data/corpfiling/AttachHis/CorpannHist.xml"),
        "FBIL home":              hit("https://www.fbil.org.in/"),
        "openFIGI":               hit("https://api.openfigi.com/v3/mapping"),
        "Alpha Vantage stub":     hit("https://www.alphavantage.co/query?function=STATUS"),
        "GSTN public":            hit("https://services.gst.gov.in/"),
    }
    with open("/tmp/out.json", "w") as f:
        json.dump(out, f)
""")


def main():
    if not os.getenv("DECLAW_API_KEY"):
        print("need DECLAW_API_KEY; skipping live probe in local mode")
        sys.exit(0)

    pol = multi_bank_api_policy()
    out = run_python_in_sandbox(
        "live-api-smoke", LIVE_PROBE, pol,
        payload={}, envs=(llm_envs() if os.getenv("OPENAI_API_KEY") else {}),
        timeout=420,
    )
    print("\n=== Live public API smoke test ===\n")
    good = 0
    for name, code in out.items():
        tag = "OK   " if code.startswith("HTTP_") else "DEGR "
        print(f"  {tag} {name:30s}  {code}")
        if code.startswith("HTTP_"):
            good += 1
    print(f"\n{good}/{len(out)} endpoints reachable (degraded ones are "
          "non-blocking; workflows that depend on them skip gracefully).")


if __name__ == "__main__":
    main()
