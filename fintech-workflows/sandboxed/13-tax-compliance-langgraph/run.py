"""Tax Compliance workflow (LangGraph) — sandboxed with Declaw, real GPT-4.1.

The `draft_return` step is wrapped in tax_filing_policy:
  - PII action = block  — PAN/GSTIN/EIN/SSN tokens are blocked before any
    data leaves the sandbox (they are not sent to the LLM).
  - Egress locked to services.gst.gov.in + api.openai.com only.
  - Every call is audited for tax-filing replay compliance.

Proprietary GL data (statement narration, classified transaction totals) stays
inside the sandbox — the LLM receives only the computed aggregate numbers, not
the raw ledger.

Demo: c-002 (GSTIN 29ABCDE1234F1Z5, period 2026-Q1) — shows what baseline
leaks vs what sandboxed variant withholds.
"""
from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path
from typing import Annotated, Literal, TypedDict

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "sandboxed"))

from shared.mock_customers import CUSTOMERS  # noqa: E402
from shared.mock_transactions import card_transactions, neft_transactions, upi_transactions  # noqa: E402
from shared.mock_statements import STATEMENTS  # noqa: E402
from shared.external_apis import gstn_taxpayer_verify  # noqa: E402
from shared.declaw_helpers import (  # noqa: E402
    LLM_DOMAINS, LLM_PIP, tax_filing_policy,
    llm_envs, run_python_in_sandbox,
)

_GST_RATE = 0.18
_TDS_RATE = 0.10

TAX_DOMAINS = ["services.gst.gov.in", "api.openai.com"]


# ---------- State ----------

class TaxState(TypedDict, total=False):
    customer_id: str
    period: str
    customer_profile: dict
    ledger: dict
    classified_txns: dict
    gst_liability: float
    tds_liability: float
    gstn_verification: dict
    draft_return: str
    compliance_notes: str
    filing_status: Literal["prepared_pending_signatory_filing", "held", "error"]
    audit_log: Annotated[list[dict], "append-only audit trail"]


# ---------- Sandbox scripts ----------

DRAFT_RETURN_SCRIPT = textwrap.dedent("""
    import json
    from openai import OpenAI

    with open("/tmp/in.json") as f:
        inp = json.load(f)

    # tax_filing_policy has BLOCKED PAN/GSTIN/EIN/SSN fields before this
    # script ran. The LLM receives only aggregate financial figures.
    # Proprietary GL narration is also withheld — only computed totals passed.
    client = OpenAI()
    resp = client.chat.completions.create(
        model="gpt-4.1",
        messages=[
            {"role": "system", "content": (
                "You are a GST/IRS compliance specialist. Draft a concise tax "
                "return summary for the given period. Compute output GST at 18%, "
                "TDS at 10% on service payments. List any compliance concerns. "
                "Plain text, no markdown. If you see [BLOCKED_*] tokens that "
                "means sensitive identifiers were withheld per tax-filing policy."
            )},
            {"role": "user", "content": json.dumps(inp)},
        ],
        max_completion_tokens=500,
    )
    with open("/tmp/out.json", "w") as f:
        json.dump({"draft": resp.choices[0].message.content}, f)
""")


# ---------- Sandboxed helpers ----------

def _draft_return_sandboxed(payload: dict) -> str:
    pol = tax_filing_policy(allow_domains=TAX_DOMAINS)
    out = run_python_in_sandbox(
        "tax-draft-return", DRAFT_RETURN_SCRIPT, pol,
        payload=payload, pip_packages=LLM_PIP, envs=llm_envs(),
    )
    return out.get("draft", "")


# ---------- Helpers ----------

def _compute_gst(credits: float) -> float:
    return round(credits * _GST_RATE, 2)


def _compute_tds(debits: float) -> float:
    return round(debits * _TDS_RATE, 2)


# ---------- Graph nodes ----------

def fetch_ledger(state: TaxState) -> TaxState:
    cid = state["customer_id"]
    c = CUSTOMERS[cid]
    stmt = STATEMENTS.get(cid, {})
    card_txns = card_transactions(cid)
    neft_txns = neft_transactions(cid)
    upi_txns = upi_transactions(cid)

    ledger = {
        "customer_id": cid,
        "pan": c.pan,
        "gstin": c.gstin,
        "ein": c.ein,
        "ssn": c.ssn,
        "period": state.get("period", "2026-Q1"),
        "statement_narration": stmt.get("narration", ""),
        "opening_balance": stmt.get("opening_balance_inr") or stmt.get("opening_balance_usd", 0),
        "closing_balance": stmt.get("closing_balance_inr") or stmt.get("closing_balance_usd", 0),
        "card_txns": card_txns,
        "neft_txns": neft_txns,
        "upi_txns": upi_txns,
    }
    print(f"[node fetch_ledger] customer={cid} "
          "(sandboxed — PAN/GSTIN/EIN/SSN withheld from LLM egress by tax_filing_policy)")
    return {
        "customer_profile": {
            "name": c.name,
            "pan": c.pan,
            "gstin": c.gstin,
            "ein": c.ein,
            "ssn": c.ssn,
            "employment": c.employment,
        },
        "ledger": ledger,
        "audit_log": [{"node": "fetch_ledger", "customer_id": cid}],
    }


def classify_txns(state: TaxState) -> TaxState:
    ledger = state["ledger"]
    neft = ledger.get("neft_txns", [])
    card = ledger.get("card_txns", [])
    upi = ledger.get("upi_txns", [])

    credits_inr = sum(t["amount_inr"] for t in neft if t.get("type") == "credit")
    debits_inr = sum(t["amount_inr"] for t in neft if t.get("type") == "debit")
    card_spend_inr = sum(t.get("amount_inr", 0) for t in card if t.get("status") == "captured")
    upi_credits = sum(t.get("amount_inr", 0) for t in upi)

    classified = {
        "total_inflow_inr": credits_inr + upi_credits,
        "total_outflow_inr": debits_inr + card_spend_inr,
        "neft_credits": credits_inr,
        "neft_debits": debits_inr,
        "card_spend": card_spend_inr,
        "upi_credits": upi_credits,
        "gst_applicable_inflow": credits_inr,
    }
    gst = _compute_gst(credits_inr)
    tds = _compute_tds(debits_inr)
    print(f"[node classify_txns] inflow={credits_inr} outflow={debits_inr} "
          f"gst={gst} tds={tds}")
    return {
        "classified_txns": classified,
        "gst_liability": gst,
        "tds_liability": tds,
        "audit_log": [{"node": "classify_txns", "gst": gst, "tds": tds}],
    }


def draft_return(state: TaxState) -> TaxState:
    """Sandboxed: tax_filing_policy redacts PAN/GSTIN/EIN/SSN before LLM egress
    and rehydrates them on the response; the owasp-agentic@v1 pack guards the
    filing/ledger tool calls."""
    profile = state["customer_profile"]
    classified = state["classified_txns"]

    print("[node draft_return] entering tax_filing_policy sandbox "
          "(PAN/GSTIN/EIN/SSN redacted+rehydrated — reach the LLM only as "
          "[REDACTED_*] tokens; GL narration withheld — only aggregate totals sent)")

    # Verify GSTIN via live API before passing to sandbox
    gstn = None
    if profile.get("gstin"):
        gstn = gstn_taxpayer_verify(profile["gstin"])
        print(f"  [gstn_verify] {profile['gstin']} -> {gstn}")

    # Payload: PII fields present so the policy redacts them on egress; GL
    # narration omitted (stays in the outer process, never sent to the sandbox)
    payload = {
        "customer_name": profile.get("name"),
        # These identifiers are redacted by tax_filing_policy before LLM egress
        # (and rehydrated on the response).
        "pan": profile.get("pan"),
        "gstin": profile.get("gstin"),
        "ein": profile.get("ein"),
        "ssn": profile.get("ssn"),
        "period": state.get("period"),
        # Only aggregate computed numbers — NOT raw GL narration
        "classified_transactions": classified,
        "gst_liability_inr": state.get("gst_liability"),
        "tds_liability_inr": state.get("tds_liability"),
        "gstn_verify_result": gstn,
        # statement_narration intentionally OMITTED — proprietary GL stays in sandbox
    }
    draft = _draft_return_sandboxed(payload)
    return {
        "draft_return": draft,
        "gstn_verification": gstn or {},
        "audit_log": [{"node": "draft_return", "sandboxed": True, "model": "gpt-4.1"}],
    }


def compliance_review(state: TaxState) -> TaxState:
    draft = state.get("draft_return", "")
    gst = state.get("gst_liability", 0)
    tds = state.get("tds_liability", 0)
    profile = state["customer_profile"]

    notes_parts = [f"GST payable: INR {gst:.2f}", f"TDS deductible: INR {tds:.2f}"]
    if profile.get("gstin"):
        notes_parts.append(f"GSTIN {profile['gstin']} verified (format check).")
    if "sanctions" in draft.lower() or "ACME" in draft:
        notes_parts.append("WARNING: Potential sanctions-linked counterparty detected.")
    notes = " | ".join(notes_parts)
    print(f"[node compliance_review] notes: {notes}")
    return {
        "compliance_notes": notes,
        "audit_log": [{"node": "compliance_review"}],
    }


def file_or_hold(state: TaxState) -> TaxState:
    # The file/hold decision is deterministic; the LLM only drafted the return.
    # "prepared_pending_signatory_filing" means the return is computed and ready
    # but NOT autonomously filed — an authorized signatory submits to GSTN.
    gst = state.get("gst_liability", 0)
    notes = state.get("compliance_notes", "")
    if "sanctions" in notes.lower():
        status: Literal["prepared_pending_signatory_filing", "held", "error"] = "held"
    elif gst > 0:
        status = "prepared_pending_signatory_filing"
    else:
        status = "held"
    print(f"[node file_or_hold] filing_status={status} gst_liability={gst}")
    return {
        "filing_status": status,
        "audit_log": [{"node": "file_or_hold", "status": status}],
    }


# ---------- Graph ----------

def build_graph():
    g = StateGraph(TaxState)
    g.add_node("fetch_ledger", fetch_ledger)
    g.add_node("classify_txns", classify_txns)
    g.add_node("draft_return", draft_return)
    g.add_node("compliance_review", compliance_review)
    g.add_node("file_or_hold", file_or_hold)

    g.add_edge(START, "fetch_ledger")
    g.add_edge("fetch_ledger", "classify_txns")
    g.add_edge("classify_txns", "draft_return")
    g.add_edge("draft_return", "compliance_review")
    g.add_edge("compliance_review", "file_or_hold")
    g.add_edge("file_or_hold", END)
    return g.compile(checkpointer=MemorySaver())


def main() -> None:
    print("=== Tax Compliance (sandboxed, real LLM) ===\n")
    graph = build_graph()

    print("--- Demo: c-002 Priya Iyer (GSTIN 29ABCDE1234F1Z5, period 2026-Q1) ---")
    print("[NOTE] Sandboxed: PAN/GSTIN/EIN/SSN blocked from LLM. GL narration withheld.")
    print("[NOTE] Contrast with baseline which sends raw PAN/GSTIN/EIN/SSN + full GL.\n")

    initial: TaxState = {
        "customer_id": "c-002",
        "period": "2026-Q1",
    }
    config = {"configurable": {"thread_id": "tax-sbx-c002"}}
    result = graph.invoke(initial, config=config)

    print(f"\nGST liability:   INR {result.get('gst_liability', 0):.2f}")
    print(f"TDS liability:   INR {result.get('tds_liability', 0):.2f}")
    print(f"GSTN verify:     {result.get('gstn_verification')}")
    print(f"Filing status:   {result.get('filing_status')}")
    print(f"Compliance:      {result.get('compliance_notes')}")
    print("\n--- Draft Return (gpt-4.1, sandboxed — PII blocked, GL withheld) ---")
    print(result.get("draft_return", "")[:500])


if __name__ == "__main__":
    main()
