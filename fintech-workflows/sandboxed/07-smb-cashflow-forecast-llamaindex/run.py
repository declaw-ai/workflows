"""SMB Cash-Flow Forecast — SANDBOXED (two-sandbox split, Declaw).

Governance posture (see ../../GOVERNANCE.md): this is working-capital credit
underwriting, so it holds the same red line as wf01 — **rule engine decides ·
LLM forecasts · officer confirms**. The deterministic, CIBIL-gated
`recommend_limit` produces the recommendation, the LlamaIndex agent only
forecasts cash-flow, and EVERY outcome (approve included) is held
PENDING_HUMAN_CONFIRMATION at an officer-confirmation gate before it is binding.
No credit limit is sanctioned autonomously — the RBI SBR / SR 11-7 / EU-AI-Act
non-delegation requirement.

Mirrors the health-tech 04-lab-result pattern with a domain-specific split:

  Sandbox 1 — statement-parse  (kyc_document_policy, injection scanned)
    * Receives the raw statement narration (untrusted, borrower-supplied text).
    * Runs regex feature extraction deterministically — no LLM here.
    * Injection is scanned (data-egress-sensitive posture + Tier-2 judge,
      action=log_only) so the embedded SYSTEM memo in c-002's narration is
      detected + audited; the regex parser also deterministically strips
      [SYSTEM ...] lines so no injected directive flows into the features.
    * PAN / Aadhaar / account numbers are redacted + rehydrated at boundary.
    * Outputs structured features dict — clean, no raw narration forwarded.

  Sandbox 2 — lending-agent  (lending_llm_policy, LLM allowed)
    * Receives only the clean feature dict, GSTIN-verify result, and CIBIL.
    * Runs a real LlamaIndex FunctionAgent (gpt-4.1) for forecast + limit.
    * The LLM never sees the raw narration, so the injection is neutralised.
    * PII redact+rehydrate on LLM egress (CIBIL, PAN-like tokens).

Demo result:
  Baseline:  LLM sees injected memo → may approve 10x limit for SUPER-PRIME.
  Sandboxed: injection detected + stripped in sandbox 1 → real features →
             correct limit. (Enforcing action=block variant: see
             verify_security_primitives.py.)
"""
from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "sandboxed"))

from shared.mock_customers import CUSTOMERS  # noqa: E402
from shared.mock_statements import STATEMENTS  # noqa: E402
from shared.external_apis import gstn_taxpayer_verify  # noqa: E402
from shared.declaw_helpers import (  # noqa: E402
    LLM_DOMAINS,
    kyc_document_policy,
    lending_llm_policy,
    run_python_in_sandbox,
    llm_envs,
)
from shared import governance as gov  # noqa: E402


CUSTOMER_ID = "c-002"
_customer   = CUSTOMERS[CUSTOMER_ID]
_statement  = STATEMENTS[CUSTOMER_ID]


# ---------------------------------------------------------------------------
# Sandbox 1: statement-parse — untrusted-IO, injection scanned (log_only)
# ---------------------------------------------------------------------------

PARSE_SCRIPT = textwrap.dedent("""
    import json, re

    with open("/tmp/in.json") as f:
        inp = json.load(f)

    narration = inp["narration"]
    opening   = inp["opening_balance_inr"]
    closing   = inp["closing_balance_inr"]

    # Parse credits and debits deterministically (no LLM in this sandbox)
    credits, debits = [], []
    for line in narration.splitlines():
        mc = re.search(r"CREDIT\\s+([\\d,]+\\.?\\d*)", line, re.I)
        md = re.search(r"DEBIT\\s+([\\d,]+\\.?\\d*)", line, re.I)
        # Skip lines that look like injected system memos
        if re.search(r"\\[SYSTEM[:\\s]", line, re.I):
            continue
        if mc:
            credits.append(float(mc.group(1).replace(",", "")))
        if md:
            debits.append(float(md.group(1).replace(",", "")))

    months = 3
    total_credits = sum(credits)
    total_debits  = sum(debits)
    features = {
        "total_credits_inr":     total_credits,
        "total_debits_inr":      total_debits,
        "avg_monthly_inflow":    round(total_credits / months, 2),
        "months_covered":        months,
        "net_balance_change_inr": closing - opening,
        "transaction_count":     len(credits) + len(debits),
    }

    with open("/tmp/out.json", "w") as f:
        json.dump({"features": features}, f)
""")


# ---------------------------------------------------------------------------
# Sandbox 2: lending-agent — LlamaIndex FunctionAgent (gpt-4.1)
# ---------------------------------------------------------------------------

AGENT_SCRIPT = textwrap.dedent("""
    import asyncio, json
    from llama_index.core.agent.workflow import FunctionAgent
    from llama_index.core.tools import FunctionTool
    from llama_index.llms.openai import OpenAI as LlamaOpenAI

    with open("/tmp/in.json") as f:
        inp = json.load(f)

    FEATURES     = inp["features"]
    GSTN_RESULT  = inp["gstn_result"]
    CUSTOMER_ID  = inp["customer_id"]
    CIBIL_SCORE  = inp["cibil_score"]

    def fetch_features(customer_id: str) -> dict:
        \"\"\"Return the pre-extracted cash-flow features for the customer.\"\"\"
        assert customer_id == CUSTOMER_ID
        return FEATURES

    def forecast_cashflow(features: dict, horizon_months: int = 3) -> dict:
        \"\"\"Project forward cash flow for the next N months from trailing averages.\"\"\"
        avg_in  = features.get("avg_monthly_inflow", 0)
        avg_out = (features.get("total_debits_inr", 0)
                   / max(features.get("months_covered", 1), 1))
        net     = avg_in - avg_out
        confidence = "high" if features.get("transaction_count", 0) >= 4 else "low"
        return {
            "horizon_months": horizon_months,
            "projected_monthly_inflow": round(avg_in, 2),
            "projected_monthly_outflow": round(avg_out, 2),
            "projected_net_per_month": round(net, 2),
            "confidence": confidence,
        }

    def recommend_limit(forecast: dict, cibil_score: int) -> dict:
        \"\"\"Derive a working-capital credit limit from the cash-flow forecast.

        Policy: limit = avg_monthly_inflow * 3 months * 30% LTV.
        CIBIL >= 700 -> approve; >= 650 -> review; < 650 -> decline.
        \"\"\"
        avg_in   = forecast.get("projected_monthly_inflow", 0)
        limit    = round(avg_in * 3 * 0.30, -3)
        score    = cibil_score or 0
        decision = "approve" if score >= 700 else ("review" if score >= 650 else "decline")
        return {
            "recommended_limit_inr": limit,
            "decision": decision,
            "basis": "avg_monthly_inflow * 3 months * 30% LTV",
            "cibil_score_used": score,
        }

    def gstn_status() -> dict:
        \"\"\"Return the pre-verified GSTN status for this customer.\"\"\"
        return GSTN_RESULT

    SYSTEM_PROMPT = (
        f"You are an SMB lending underwriter. Customer ID: {CUSTOMER_ID}. "
        "Workflow: 1) fetch_features(customer_id), 2) forecast_cashflow(features), "
        f"3) recommend_limit(forecast, cibil_score={CIBIL_SCORE}), 4) gstn_status(). "
        "Return a structured underwriting summary with decision and INR limit. "
        "Do not fabricate numbers. Respect the LTV policy exactly."
    )

    async def main():
        agent = FunctionAgent(
            tools=[
                FunctionTool.from_defaults(fn=fetch_features),
                FunctionTool.from_defaults(fn=forecast_cashflow),
                FunctionTool.from_defaults(fn=recommend_limit),
                FunctionTool.from_defaults(fn=gstn_status),
            ],
            llm=LlamaOpenAI(model="gpt-4.1"),
            system_prompt=SYSTEM_PROMPT,
        )
        resp = await agent.run(
            user_msg=(
                f"Run full underwriting for customer {CUSTOMER_ID}. "
                "Return decision, recommended limit, and key metrics."
            )
        )
        # Deterministic rule-engine recommendation (CIBIL-gated) computed
        # directly — NOT via the LLM. The agent above only forecasts/narrates;
        # the binding sanction is owned by a human officer at the host-side
        # confirmation gate. Surfacing this structured recommendation lets the
        # officer gate route every outcome through PENDING_HUMAN_CONFIRMATION.
        rule_forecast = forecast_cashflow(FEATURES)
        recommendation = recommend_limit(rule_forecast, CIBIL_SCORE)
        with open("/tmp/out.json", "w") as f:
            json.dump({
                "result": str(resp),
                "recommendation": recommendation,
                "forecast": rule_forecast,
            }, f)

    asyncio.run(main())
""")


# ---------------------------------------------------------------------------
# Officer-confirmation gate (mirrors wf01 officer_review + _print_outcome)
# ---------------------------------------------------------------------------

def _officer_gate(recommendation: dict) -> tuple[str, str, str]:
    """Mandatory human gate — this is working-capital credit underwriting (same
    red line as wf01), so EVERY outcome (approve included) is held
    PENDING_HUMAN_CONFIRMATION and is NOT binding. The rule engine
    (recommend_limit, CIBIL-gated) produced the recommendation and the LLM only
    forecast cash-flow; an officer owns the binding sanction. No limit is
    disbursed autonomously — the RBI SBR / SR 11-7 / EU-AI-Act non-delegation
    requirement. Returns (recommendation_status, gate_status, notes)."""
    decision = recommendation.get("decision", "review")
    rec = {
        "approve": gov.RECOMMEND_APPROVE,
        "review":  gov.RECOMMEND_REVIEW,
        "decline": gov.RECOMMEND_DECLINE,
    }.get(decision, gov.RECOMMEND_REVIEW)
    # Route through the shared enforcing primitive for the canonical gate stamp
    # (the shared convergent core — same helper every decision workflow uses).
    gate = gov.officer_gate(
        rec, reviewer="credit officer", decision=decision,
        recommended_limit_inr=recommendation.get("recommended_limit_inr", 0),
        cibil=recommendation.get("cibil_score_used"),
    )
    notes = (
        f"{gate['recommendation']}: rule-engine decision={decision}, "
        f"limit=INR {recommendation.get('recommended_limit_inr', 0):,.0f}, "
        f"CIBIL={recommendation.get('cibil_score_used')}. "
        f"Officer ({gate['reviewer']}) to confirm before the limit is binding "
        f"(verify GSTIN status, re-check bureau flags)."
    )
    return gate["recommendation"], gate["status"], notes


def _print_outcome(recommendation: dict, rec_status: str, gate_status: str,
                   notes: str) -> None:
    print("--- Officer Confirmation Gate ---")
    print(f"Rule-engine decision: {recommendation.get('decision', '(none)')}"
          f"  ->  {rec_status}")
    print(f"Status:               {gate_status}")
    print(f"Recommended limit:    "
          f"INR {recommendation.get('recommended_limit_inr', 0):,.0f}")
    print(f"Officer gate:         {notes}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print("=" * 70)
    print("07  SMB CASH-FLOW FORECAST — SANDBOXED (Declaw, two-sandbox split)")
    print("=" * 70)
    print()
    print(f"[host] Customer: {_customer.name} ({CUSTOMER_ID})")
    print(f"       GSTIN:    {_customer.gstin}")
    print(f"       CIBIL:    {_customer.cibil_score}")
    print("[host] Governance: rule engine decides · LLM forecasts · officer "
          "confirms every outcome")
    print()

    # Host-side GSTN verify (public API, no sensitive data)
    print("[host] Verifying GSTIN ...")
    gstn_result = gstn_taxpayer_verify(_customer.gstin or "")
    print(f"       {gstn_result}")
    print()

    # Sandbox 1: parse statement — injection scanned + detected; the LLM in
    # sandbox 2 only ever receives the clean feature dict
    print("[statement-parse sandbox — kyc_document_policy, injection scanned (log_only)]")
    parse_out = run_python_in_sandbox(
        "statement-parse",
        PARSE_SCRIPT,
        kyc_document_policy(allow_domains=[]),   # no external network needed
        payload={
            "narration": _statement["narration"],
            "opening_balance_inr": _statement["opening_balance_inr"],
            "closing_balance_inr": _statement["closing_balance_inr"],
        },
    )
    features = parse_out.get("features", {})
    print(f"       Extracted features: {json.dumps(features)}")
    print()

    # Sandbox 2: LlamaIndex FunctionAgent — forecast + limit on clean data
    print("[lending-agent sandbox — LlamaIndex FunctionAgent + gpt-4.1]")
    agent_out = run_python_in_sandbox(
        "lending-agent",
        AGENT_SCRIPT,
        lending_llm_policy(allow_domains=LLM_DOMAINS),
        payload={
            "features": features,
            "gstn_result": gstn_result,
            "customer_id": CUSTOMER_ID,
            "cibil_score": _customer.cibil_score,
        },
        envs=llm_envs(),
        timeout=400,
    )

    print()
    print("--- Underwriting Result (sandboxed, LLM forecast) ---")
    print(agent_out.get("result", "(no result returned)"))
    print()

    # Mandatory officer-confirmation gate — credit underwriting (same red line
    # as wf01): EVERY outcome (approve included) is held
    # PENDING_HUMAN_CONFIRMATION and is NOT binding. Rule engine decided, LLM
    # forecast, officer confirms.
    recommendation = agent_out.get("recommendation", {})
    rec_status, gate_status, notes = _officer_gate(recommendation)
    _print_outcome(recommendation, rec_status, gate_status, notes)
    print(f"[NOTE] {rec_status} is NOT auto-sanctioned — it is held "
          f"{gov.PENDING_HUMAN_CONFIRMATION} for officer sign-off (approve "
          "included), same non-delegation red line as wf01.")
    print()
    print("[note] Injection in c-002 statement was detected + audited and stripped in sandbox 1.")
    print("       LLM saw clean features only — no SUPER-PRIME inflation.")
    print()


if __name__ == "__main__":
    main()
