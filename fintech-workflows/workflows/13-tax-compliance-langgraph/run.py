"""Tax Compliance workflow built with LangGraph (real GPT-4.1) — BASELINE.

Flow: fetch_ledger -> classify_txns -> draft_return -> compliance_review
      -> file_or_hold

The `draft_return` LLM step INTENTIONALLY sends proprietary GL data plus
customer PAN/GSTIN/EIN to the LLM (IP leak + PII leak). Compare against
sandboxed/13 which wraps this step in tax_filing_policy (PII action=block —
PAN/EIN tokens only on LLM egress; GL data stays in sandbox).

Demo: c-002 has a GSTIN — compute GST liability from mock_transactions +
mock_statements; show what leaks baseline vs sandboxed.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated, Literal, TypedDict

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from shared.llm import chat, chat_json  # noqa: E402
from shared.mock_customers import CUSTOMERS  # noqa: E402
from shared.mock_transactions import card_transactions, neft_transactions, upi_transactions  # noqa: E402
from shared.mock_statements import STATEMENTS  # noqa: E402
from shared.external_apis import gstn_taxpayer_verify  # noqa: E402

# GST rates for demo (simplified)
_GST_RATE = 0.18   # 18% default
_TDS_RATE = 0.10   # 10% TDS on services


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
    filing_status: Literal["filed", "held", "error"]
    audit_log: Annotated[list[dict], "append-only audit trail"]


# ---------- Helpers ----------

def _compute_gst(credits: float, debits: float) -> float:
    """Simplified output GST on inflows at 18%."""
    return round(credits * _GST_RATE, 2)


def _compute_tds(debits: float) -> float:
    """Simplified TDS on service outflows at 10%."""
    return round(debits * _TDS_RATE, 2)


# ---------- Graph nodes ----------

def fetch_ledger(state: TaxState) -> TaxState:
    cid = state["customer_id"]
    c = CUSTOMERS[cid]
    stmt = STATEMENTS.get(cid, {})
    card_txns = card_transactions(cid)
    neft_txns = neft_transactions(cid)
    upi_txns = upi_transactions(cid)

    # Assemble raw GL from all transaction sources
    ledger = {
        "customer_id": cid,
        "pan": c.pan,           # RAW PAN in ledger — intentional for demo
        "gstin": c.gstin,       # RAW GSTIN in ledger
        "ein": c.ein,           # RAW EIN in ledger
        "ssn": c.ssn,           # RAW SSN in ledger
        "period": state.get("period", "2026-Q1"),
        "statement_narration": stmt.get("narration", ""),
        "opening_balance": stmt.get("opening_balance_inr") or stmt.get("opening_balance_usd", 0),
        "closing_balance": stmt.get("closing_balance_inr") or stmt.get("closing_balance_usd", 0),
        "card_txns": card_txns,
        "neft_txns": neft_txns,
        "upi_txns": upi_txns,
    }
    print(f"[node fetch_ledger] customer={cid} PAN={c.pan} GSTIN={c.gstin} "
          f"EIN={c.ein} SSN={c.ssn}")  # UNSANDBOXED — raw PII in log
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
        "gst_applicable_inflow": credits_inr,  # B2B NEFT inflows are GST-taxable
    }
    gst = _compute_gst(credits_inr, debits_inr)
    tds = _compute_tds(debits_inr)
    print(f"[node classify_txns] inflow_inr={credits_inr} outflow_inr={debits_inr} "
          f"gst_liability={gst} tds={tds}")
    return {
        "classified_txns": classified,
        "gst_liability": gst,
        "tds_liability": tds,
        "audit_log": [{"node": "classify_txns", "gst": gst, "tds": tds}],
    }


def draft_return(state: TaxState) -> TaxState:
    """LLM call — INTENTIONALLY sends proprietary GL + PAN/GSTIN/EIN/SSN to LLM."""
    profile = state["customer_profile"]
    ledger = state["ledger"]
    classified = state["classified_txns"]

    print("[node draft_return] calling gpt-4.1 "
          "(UNSANDBOXED — proprietary GL + PAN/GSTIN/EIN/SSN sent to LLM)")
    print(f"  [WARN] Leaking to LLM: PAN={profile['pan']} GSTIN={profile['gstin']} "
          f"EIN={profile['ein']} SSN={profile['ssn']} "
          "(UNSANDBOXED — IP leak + PII leak)")

    gstn = None
    if profile.get("gstin"):
        gstn = gstn_taxpayer_verify(profile["gstin"])

    system = (
        "You are a GST/IRS compliance specialist. Draft a concise tax return "
        "summary for the given period. Compute output GST at 18%, TDS at 10% on "
        "service payments. List any compliance concerns. Plain text, no markdown."
    )
    user_payload = {
        # PII + proprietary data leak:
        "customer_name": profile.get("name"),
        "pan": profile.get("pan"),          # RAW PAN — DPDP violation
        "gstin": profile.get("gstin"),      # RAW GSTIN — sensitive
        "ein": profile.get("ein"),          # RAW EIN — GLBA violation
        "ssn": profile.get("ssn"),          # RAW SSN — GLBA violation
        "period": ledger.get("period"),
        "statement_narration": ledger.get("statement_narration"),  # proprietary GL
        "classified_transactions": classified,                      # proprietary GL
        "gst_liability_inr": state.get("gst_liability"),
        "tds_liability_inr": state.get("tds_liability"),
        "gstn_verify_result": gstn,
    }
    draft = chat(system, json.dumps(user_payload), max_tokens=500)
    return {
        "draft_return": draft,
        "gstn_verification": gstn or {},
        "audit_log": [{"node": "draft_return", "model": "gpt-4.1", "sandboxed": False}],
    }


def compliance_review(state: TaxState) -> TaxState:
    draft = state.get("draft_return", "")
    gst = state.get("gst_liability", 0)
    tds = state.get("tds_liability", 0)
    profile = state["customer_profile"]

    notes_parts = [f"GST payable: INR {gst:.2f}", f"TDS deductible: INR {tds:.2f}"]
    if profile.get("gstin"):
        notes_parts.append(f"GSTIN {profile['gstin']} verified (format check).")
    # Check for high-risk signals in draft
    if "sanctions" in draft.lower() or "ACME" in draft:
        notes_parts.append("WARNING: Potential sanctions-linked counterparty detected in GL.")
    notes = " | ".join(notes_parts)
    print(f"[node compliance_review] notes: {notes}")
    return {
        "compliance_notes": notes,
        "audit_log": [{"node": "compliance_review"}],
    }


def file_or_hold(state: TaxState) -> TaxState:
    gst = state.get("gst_liability", 0)
    notes = state.get("compliance_notes", "")
    # Hold if compliance noted a sanctions concern
    if "sanctions" in notes.lower():
        status: Literal["filed", "held", "error"] = "held"
    elif gst > 0:
        status = "filed"
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
    print("=== Tax Compliance (baseline, real LLM) ===\n")
    graph = build_graph()

    # Primary demo: c-002 has a GSTIN (SMB, GST-registered)
    print("--- Demo: c-002 Priya Iyer (GSTIN 29ABCDE1234F1Z5, period 2026-Q1) ---")
    print("[NOTE] Baseline sends PAN/GSTIN/EIN/SSN + full GL narration to LLM.")

    initial: TaxState = {
        "customer_id": "c-002",
        "period": "2026-Q1",
    }
    config = {"configurable": {"thread_id": "tax-demo-c002"}}
    result = graph.invoke(initial, config=config)

    print(f"\nGST liability:   INR {result.get('gst_liability', 0):.2f}")
    print(f"TDS liability:   INR {result.get('tds_liability', 0):.2f}")
    print(f"GSTN verify:     {result.get('gstn_verification')}")
    print(f"Filing status:   {result.get('filing_status')}")
    print(f"Compliance:      {result.get('compliance_notes')}")
    print("\n--- Draft Return (gpt-4.1, UNSANDBOXED — PII+GL leaked to LLM) ---")
    print(result.get("draft_return", "")[:500])


if __name__ == "__main__":
    main()
