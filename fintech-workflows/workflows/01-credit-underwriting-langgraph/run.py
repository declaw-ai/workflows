"""Credit Underwriting workflow built with LangGraph (real GPT-4.1) — BASELINE.

Flow: gather -> bureau_pull -> statement_parse -> alt_data -> risk_score
      -> explain -> human_review (conditional: route to human_review only if
      declined or borderline, else END).

The `explain` LLM step INTENTIONALLY sends raw PAN, Aadhaar, CIBIL score, and
SSN in the prompt — this is the unsandboxed baseline. Compare against
sandboxed/01 which wraps `explain` in lending_llm_policy and `statement_parse`
in kyc_document_policy.

Demo recipe:
  c-003 (Rohan Desai, CIBIL 541) -> DECLINE with fair-lending-safe reason
  c-001 (Aarav Sharma,  CIBIL 762) -> APPROVE
  c-002 (Priya Iyer,   CIBIL 688) -> shows statement injection in baseline
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
from shared.mock_customers import CUSTOMERS, LENDING_POLICIES  # noqa: E402
from shared.mock_bureau import cibil_report, fico_report  # noqa: E402
from shared.mock_statements import STATEMENTS  # noqa: E402


# ---------- State ----------

class UnderwritingState(TypedDict, total=False):
    customer_id: str
    loan_amount: int
    policy_key: str
    customer_profile: dict
    bureau_report: dict
    statement: dict
    alt_data: dict
    risk_score: dict
    decision: Literal["approve", "decline", "borderline"]
    explanation: str
    human_review_notes: str
    audit_log: Annotated[list[dict], "append-only audit trail"]


# ---------- Helpers ----------

def _score_to_decision(cibil: int, income: int, policy: dict) -> tuple[str, float]:
    criteria = policy.get("criteria", [])
    # Simple rule engine: CIBIL >= 700 AND income >= 25000 INR/mo = approve
    if cibil >= 700 and income >= 25000:
        return "approve", 0.85
    if cibil >= 620 and income >= 25000:
        return "borderline", 0.52
    return "decline", 0.18


# ---------- Graph nodes ----------

def gather(state: UnderwritingState) -> UnderwritingState:
    c = CUSTOMERS[state["customer_id"]]
    profile = {
        "id": c.id,
        "name": c.name,
        "pan": c.pan,               # raw PAN in state (intentional for demo)
        "aadhaar": c.aadhaar,       # raw Aadhaar in state
        "ssn": c.ssn,
        "email": c.email,
        "phone": c.phone,
        "address": c.address,
        "monthly_income": c.monthly_income,
        "employment": c.employment,
        "gstin": c.gstin,
        "ein": c.ein,
    }
    print(f"[node gather] customer={c.id} name={c.name} "
          f"PAN={c.pan} Aadhaar={c.aadhaar}")  # UNSANDBOXED — raw PII in log
    return {
        "customer_profile": profile,
        "audit_log": [{"node": "gather", "customer_id": state["customer_id"]}],
    }


def bureau_pull(state: UnderwritingState) -> UnderwritingState:
    cid = state["customer_id"]
    cibil = cibil_report(cid)
    fico = fico_report(cid)
    print(f"[node bureau_pull] CIBIL={cibil['score']} band={cibil['score_band']} "
          f"PAN={cibil['pan']} flags={cibil['flags']}")  # UNSANDBOXED — raw PAN in log
    return {
        "bureau_report": {"cibil": cibil, "fico": fico},
        "audit_log": [{"node": "bureau_pull", "cibil_score": cibil["score"]}],
    }


def statement_parse(state: UnderwritingState) -> UnderwritingState:
    cid = state["customer_id"]
    stmt = STATEMENTS.get(cid, {})
    narration = stmt.get("narration", "")
    # NOTE (UNSANDBOXED): raw narration (which may contain injection) fed
    # directly to downstream nodes without scanning.
    print(f"[node statement_parse] bank={stmt.get('bank')} "
          f"narration_chars={len(narration)} (UNSANDBOXED — untrusted IO, no injection scan)")
    parsed = {
        "bank": stmt.get("bank"),
        "period": stmt.get("period"),
        "opening_balance": stmt.get("opening_balance_inr") or stmt.get("opening_balance_usd"),
        "closing_balance": stmt.get("closing_balance_inr") or stmt.get("closing_balance_usd"),
        "narration": narration,
    }
    return {
        "statement": parsed,
        "audit_log": [{"node": "statement_parse", "bank": stmt.get("bank")}],
    }


def alt_data(state: UnderwritingState) -> UnderwritingState:
    cid = state["customer_id"]
    c = CUSTOMERS[cid]
    # Derive signals from bureau flags and statement cash flow
    bureau = state.get("bureau_report", {})
    cibil_data = bureau.get("cibil", {})
    flags = cibil_data.get("flags", [])
    stmt = state.get("statement", {})
    opening = stmt.get("opening_balance") or 0
    closing = stmt.get("closing_balance") or 0
    alt = {
        "cash_flow_positive": closing > opening,
        "bureau_flags": flags,
        "thin_file": "no_bureau_history" in flags,
        "sub_prime_signals": "sub_prime" in flags or "written_off_last_36mo" in flags,
        "sanctions_check": "upi_sanctions" if cid == "c-003" else "clean",
        "income_inr": c.monthly_income,
    }
    return {
        "alt_data": alt,
        "audit_log": [{"node": "alt_data"}],
    }


def risk_score(state: UnderwritingState) -> UnderwritingState:
    policy = LENDING_POLICIES[state["policy_key"]]
    bureau = state["bureau_report"]
    cibil_score_val = bureau["cibil"]["score"]
    income = CUSTOMERS[state["customer_id"]].monthly_income
    decision, score = _score_to_decision(cibil_score_val, income, policy)
    risk = {
        "score": score,
        "decision": decision,
        "cibil": cibil_score_val,
        "income_monthly": income,
        "loan_amount": state.get("loan_amount", 0),
    }
    print(f"[node risk_score] score={score:.2f} decision={decision}")
    return {
        "risk_score": risk,
        "decision": decision,  # type: ignore[typeddict-item]
        "audit_log": [{"node": "risk_score", "decision": decision, "score": score}],
    }


def explain(state: UnderwritingState) -> UnderwritingState:
    """LLM call — INTENTIONALLY sends raw PAN/Aadhaar/CIBIL/SSN in the prompt."""
    profile = state["customer_profile"]
    bureau = state["bureau_report"]
    risk = state["risk_score"]
    policy = LENDING_POLICIES[state["policy_key"]]

    print("[node explain] calling gpt-4.1 "
          "(UNSANDBOXED — raw PAN/Aadhaar/SSN/CIBIL in prompt)")

    system = (
        "You are a fair-lending credit analyst. Produce a concise, plain-text "
        "explanation of the lending decision. Do NOT reference caste, religion, "
        "gender, or any protected characteristic. Cite only financial criteria. "
        "If declined, provide at least one actionable improvement suggestion."
    )
    user_payload = {
        "customer_name": profile["name"],
        "pan": profile["pan"],           # RAW PII — PCI/DPDP violation in baseline
        "aadhaar": profile["aadhaar"],   # RAW PII — DPDP violation in baseline
        "ssn": profile["ssn"],           # RAW PII — GLBA violation in baseline
        "cibil_score": risk["cibil"],
        "cibil_flags": bureau["cibil"]["flags"],
        "fico_score": bureau["fico"].get("score"),
        "decision": risk["decision"],
        "score": risk["score"],
        "loan_amount_inr": risk["loan_amount"],
        "policy_criteria": policy["criteria"],
        "statement_narration": state.get("statement", {}).get("narration", ""),
    }
    print(f"  [WARN] Sending PAN={profile['pan']} Aadhaar={profile['aadhaar']} "
          f"SSN={profile['ssn']} to OpenAI (UNSANDBOXED — raw PII in prompt)")

    explanation = chat(system, json.dumps(user_payload), max_tokens=400)
    return {
        "explanation": explanation,
        "audit_log": [{"node": "explain", "model": "gpt-4.1", "sandboxed": False}],
    }


def human_review(state: UnderwritingState) -> UnderwritingState:
    decision = state.get("decision")
    risk = state.get("risk_score", {})
    print(f"[node human_review] flagged for review — decision={decision} "
          f"score={risk.get('score', '?'):.2f}")
    notes = (
        f"Auto-routed for human review: decision={decision}, "
        f"CIBIL={risk.get('cibil')}, score={risk.get('score', 0):.2f}. "
        f"Reviewer should verify income docs and re-check bureau flags."
    )
    return {
        "human_review_notes": notes,
        "audit_log": [{"node": "human_review", "triggered": True}],
    }


# ---------- Routing ----------

def route_after_risk(state: UnderwritingState) -> str:
    return "explain"


def route_after_explain(state: UnderwritingState) -> str:
    decision = state.get("decision", "decline")
    if decision in ("decline", "borderline"):
        return "human_review"
    return END


# ---------- Graph ----------

def build_graph():
    g = StateGraph(UnderwritingState)
    g.add_node("gather", gather)
    g.add_node("bureau_pull", bureau_pull)
    g.add_node("statement_parse", statement_parse)
    g.add_node("alt_data", alt_data)
    g.add_node("risk_score", risk_score)
    g.add_node("explain", explain)
    g.add_node("human_review", human_review)

    g.add_edge(START, "gather")
    g.add_edge("gather", "bureau_pull")
    g.add_edge("bureau_pull", "statement_parse")
    g.add_edge("statement_parse", "alt_data")
    g.add_edge("alt_data", "risk_score")
    g.add_edge("risk_score", "explain")
    g.add_conditional_edges(
        "explain", route_after_explain,
        {"human_review": "human_review", END: END},
    )
    g.add_edge("human_review", END)
    return g.compile(checkpointer=MemorySaver())


def _run_demo(graph, customer_id: str, loan_amount: int, policy_key: str, thread_id: str):
    initial: UnderwritingState = {
        "customer_id": customer_id,
        "loan_amount": loan_amount,
        "policy_key": policy_key,
    }
    config = {"configurable": {"thread_id": thread_id}}
    return graph.invoke(initial, config=config)


def main() -> None:
    print("=== Credit Underwriting (baseline, real LLM) ===\n")
    graph = build_graph()

    # Demo 1: c-003 should DECLINE (CIBIL 541, DPD flags)
    print("--- Demo 1: c-003 Rohan Desai (expected: DECLINE) ---")
    r1 = _run_demo(graph, "c-003", 200000, "personal_loan_india", "uw-demo-c003")
    print(f"Decision:    {r1.get('decision')}")
    print(f"Explanation: {r1.get('explanation', '')[:300]}")
    if r1.get("human_review_notes"):
        print(f"Review:      {r1['human_review_notes']}")

    print("\n--- Demo 2: c-001 Aarav Sharma (expected: APPROVE) ---")
    r2 = _run_demo(graph, "c-001", 500000, "personal_loan_india", "uw-demo-c001")
    print(f"Decision:    {r2.get('decision')}")
    print(f"Explanation: {r2.get('explanation', '')[:300]}")

    print("\n--- Demo 3: c-002 Priya Iyer (shows adversarial memo in statement) ---")
    r3 = _run_demo(graph, "c-002", 1000000, "smb_working_capital_global", "uw-demo-c002")
    print(f"Decision:    {r3.get('decision')}")
    print(f"Explanation: {r3.get('explanation', '')[:300]}")
    print("[NOTE] c-002 statement contains prompt injection memo — baseline does NOT block it.")


if __name__ == "__main__":
    main()
