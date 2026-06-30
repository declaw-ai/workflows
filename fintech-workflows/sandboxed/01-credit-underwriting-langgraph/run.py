"""Credit Underwriting workflow (LangGraph) — sandboxed with Declaw, real GPT-4.1.

Governance posture (see ../../GOVERNANCE.md): the binding credit decision is made
by a **deterministic rule engine** (`_score_to_decision`), the **LLM only writes
the explanation**, and **every outcome — approve included — routes through an
officer-confirmation gate** before it is binding. That is the RBI/SR-11-7/EU-AI-Act
"don't delegate a material decision to an opaque model" shape, and it holds in
every target jurisdiction. The jurisdiction itself is a thin overlay
(DECLAW_JURISDICTION): it sets the adverse-action format (US ECOA reason codes vs
reasoned explanation), the GDPR Art. 22 human-review affordance, and the declaw
OPA governance pack attached to the LLM sandbox (one `policy_ref` swap).

Two sandboxed steps:
  1. statement_parse  — wrapped in kyc_document_policy (PII redact+rehydrate,
     injection scanned with the data-egress-sensitive posture + Tier-2 Gemma
     judge at threshold 0.5) so an injected memo in the bank statement is
     detected and recorded in the audit trail (action=log_only here; the
     enforcing action=block variant is proven in verify_security_primitives.py).
  2. explain          — wrapped in lending_llm_policy (PII redact+rehydrate +
     the jurisdiction's governance pack) so raw PAN/Aadhaar/SSN/CIBIL never reach
     OpenAI; the proxy replaces them with [REDACTED_*] tokens, then rehydrates
     them in the response.

Demo recipe:
  c-003 -> rule engine DECLINEs; LLM writes a jurisdiction-formatted adverse-
           action notice; pending officer confirmation
  c-001 -> rule engine APPROVEs; pending officer confirmation (not auto-sanctioned)
  c-002 -> adversarial memo in statement is DETECTED + audited by kyc_document_policy
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

from shared.mock_customers import CUSTOMERS, LENDING_POLICIES  # noqa: E402
from shared.mock_bureau import cibil_report, fico_report  # noqa: E402
from shared.mock_statements import STATEMENTS  # noqa: E402
from shared.declaw_helpers import (  # noqa: E402
    LLM_DOMAINS, LLM_PIP, lending_llm_policy, kyc_document_policy,
    llm_envs, run_python_in_sandbox,
)
from shared import governance as gov  # noqa: E402
from shared import replay  # noqa: E402


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
    adverse_action: dict          # jurisdiction-formatted reason(s) for the customer
    status: str                   # gate state: PENDING_HUMAN_CONFIRMATION until an officer signs off
    human_review_notes: str
    audit_log: Annotated[list[dict], "append-only audit trail"]


# ---------- Sandbox scripts ----------

STATEMENT_PARSE_SCRIPT = textwrap.dedent("""
    import json, re

    with open("/tmp/in.json") as f:
        inp = json.load(f)

    narration = inp.get("narration", "")
    bank = inp.get("bank", "")
    period = inp.get("period", "")
    opening = inp.get("opening_balance", 0)
    closing = inp.get("closing_balance", 0)

    # Extract credit/debit lines by simple pattern
    credits = sum(float(m) for m in re.findall(r"CREDIT\\s+([\\d,.]+)", narration))
    debits  = sum(float(m) for m in re.findall(r"DEBIT\\s+([\\d,.]+)",  narration))

    out = {
        "bank": bank,
        "period": period,
        "opening_balance": opening,
        "closing_balance": closing,
        "total_credits": credits,
        "total_debits": debits,
        "cash_flow_delta": closing - opening,
        # Narration passed through; injection defense has already scanned it
        # (data-egress-sensitive + Tier-2 judge, log_only) and any injected
        # directives are detected and recorded in the audit trail.
        "narration": narration,
    }
    with open("/tmp/out.json", "w") as f:
        json.dump(out, f)
""")


EXPLAIN_SCRIPT = textwrap.dedent("""
    import json
    from openai import OpenAI

    with open("/tmp/in.json") as f:
        inp = json.load(f)

    client = OpenAI()
    resp = client.chat.completions.create(
        model="gpt-4.1",
        messages=[
            {"role": "system", "content": (
                "You are a fair-lending credit analyst. Produce a concise, "
                "plain-text explanation of the lending decision. Do NOT reference "
                "caste, religion, gender, or any protected characteristic. Cite "
                "only financial criteria. If declined, provide at least one "
                "actionable improvement suggestion. If you see REDACTED_* tokens "
                "treat them as opaque identifiers for the applicant."
            )},
            {"role": "user", "content": json.dumps(inp)},
        ],
        max_completion_tokens=400,
    )
    with open("/tmp/out.json", "w") as f:
        json.dump({"explanation": resp.choices[0].message.content}, f)
""")


# ---------- Sandboxed helpers ----------

def _parse_statement_sandboxed(stmt: dict) -> dict:
    pol = kyc_document_policy(allow_domains=["fs.internal.example"])
    payload = {
        "bank": stmt.get("bank"),
        "period": stmt.get("period"),
        "opening_balance": stmt.get("opening_balance_inr") or stmt.get("opening_balance_usd", 0),
        "closing_balance": stmt.get("closing_balance_inr") or stmt.get("closing_balance_usd", 0),
        "narration": stmt.get("narration", ""),
    }
    return run_python_in_sandbox("kyc-statement-parse", STATEMENT_PARSE_SCRIPT, pol, payload=payload)


def _explain_sandboxed(payload: dict) -> str:
    # Jurisdiction overlay: attach the region's OPA governance pack to the LLM
    # sandbox — the same agent, made region-appropriate by one policy_ref swap.
    pol = lending_llm_policy(
        allow_domains=LLM_DOMAINS,
        governance_pack=gov.governance_pack(),
    )
    out = run_python_in_sandbox(
        "lending-explain-llm", EXPLAIN_SCRIPT, pol,
        payload=payload, pip_packages=LLM_PIP, envs=llm_envs(),
    )
    return out.get("explanation", "")


# ---------- Helpers ----------

def _score_to_decision(cibil: int, income: int, policy: dict) -> tuple[str, float]:
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
        "pan": c.pan,
        "aadhaar": c.aadhaar,
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
          "(sandboxed, PII redacted+rehydrated at proxy in downstream LLM steps)")
    return {
        "customer_profile": profile,
        "audit_log": [{"node": "gather", "customer_id": state["customer_id"]}],
    }


def bureau_pull(state: UnderwritingState) -> UnderwritingState:
    cid = state["customer_id"]
    cibil = cibil_report(cid)
    fico = fico_report(cid)
    print(f"[node bureau_pull] CIBIL={cibil['score']} band={cibil['score_band']} "
          "(sandboxed, PAN/score redacted before LLM egress)")
    return {
        "bureau_report": {"cibil": cibil, "fico": fico},
        "audit_log": [{"node": "bureau_pull", "cibil_score": cibil["score"]}],
    }


def statement_parse(state: UnderwritingState) -> UnderwritingState:
    """Sandboxed: kyc_document_policy scans injection + redacts PII in untrusted IO."""
    cid = state["customer_id"]
    stmt = STATEMENTS.get(cid, {})
    print(f"[node statement_parse] entering kyc_document_policy sandbox "
          "(injection scanned: data-egress-sensitive + Tier-2 judge, log_only, "
          "threshold=0.5 — adversarial memo is detected + audited)")
    parsed = _parse_statement_sandboxed(stmt)
    return {
        "statement": parsed,
        "audit_log": [{"node": "statement_parse", "sandboxed": True,
                       "bank": parsed.get("bank")}],
    }


def alt_data(state: UnderwritingState) -> UnderwritingState:
    cid = state["customer_id"]
    c = CUSTOMERS[cid]
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
    replay.record("rule_decision", "rule-engine",
                  {"customer": state["customer_id"], "decision": decision,
                   "cibil": cibil_score_val, "note": "deterministic — not the LLM"})
    return {
        "risk_score": risk,
        "decision": decision,  # type: ignore[typeddict-item]
        "audit_log": [{"node": "risk_score", "decision": decision, "score": score}],
    }


def explain(state: UnderwritingState) -> UnderwritingState:
    """Sandboxed: lending_llm_policy redacts PII before LLM, rehydrates after."""
    profile = state["customer_profile"]
    bureau = state["bureau_report"]
    risk = state["risk_score"]
    policy = LENDING_POLICIES[state["policy_key"]]

    juris = gov.active_jurisdiction()
    print(f"[node explain] {gov.governance_banner(juris)}")
    print("[node explain] entering lending_llm_policy sandbox "
          "(PII redacted+rehydrated at proxy — PAN/Aadhaar/SSN/CIBIL never reach "
          f"OpenAI; governance pack {juris.governance_pack} attached)")

    payload = {
        "customer_name": profile["name"],
        "pan": profile["pan"],
        "aadhaar": profile["aadhaar"],
        "ssn": profile["ssn"],
        "cibil_score": risk["cibil"],
        "cibil_flags": bureau["cibil"]["flags"],
        "fico_score": bureau["fico"].get("score"),
        "decision": risk["decision"],
        "score": risk["score"],
        "loan_amount_inr": risk["loan_amount"],
        "policy_criteria": policy["criteria"],
    }
    replay.record("pii_redact", "declaw-proxy",
                  {"customer": state["customer_id"], "to": "api.openai.com",
                   "fields": ["PAN", "Aadhaar", "SSN", "CIBIL"],
                   "as": "[REDACTED_*] tokens"})
    replay.record("governance_pack", "declaw",
                  {"jurisdiction": juris.code, "policy_ref": juris.governance_pack})
    explanation = _explain_sandboxed(payload)
    replay.record("pii_rehydrate", "declaw-proxy",
                  {"customer": state["customer_id"],
                   "note": "originals restored to the agent on the response"})

    # The LLM only writes prose; the customer-facing adverse-action notice is
    # shaped deterministically per jurisdiction (US -> ECOA reason codes).
    out: UnderwritingState = {
        "explanation": explanation,
        "audit_log": [{"node": "explain", "sandboxed": True, "model": "gpt-4.1",
                       "jurisdiction": juris.code,
                       "governance_pack": juris.governance_pack}],
    }
    if risk["decision"] in ("decline", "borderline"):
        reasons = list(bureau["cibil"]["flags"]) or [
            f"CIBIL {risk['cibil']} below approval threshold"]
        out["adverse_action"] = gov.format_adverse_action(reasons, juris)
        replay.record("adverse_action", "workflow",
                      {"customer": state["customer_id"],
                       "format": juris.adverse_action_format})
    return out


def officer_review(state: UnderwritingState) -> UnderwritingState:
    """Mandatory human gate — EVERY credit outcome (approve included) is held
    PENDING_HUMAN_CONFIRMATION here. The rule engine produced the recommendation
    and the LLM wrote the explanation; an officer owns the binding sanction. No
    funds are disbursed autonomously — that is the non-delegation requirement
    common to RBI SBR, US SR 11-7/ECOA, and the EU AI Act."""
    decision = state.get("decision")
    risk = state.get("risk_score", {})
    recommendation = {
        "approve": gov.RECOMMEND_APPROVE,
        "decline": gov.RECOMMEND_DECLINE,
        "borderline": gov.RECOMMEND_REVIEW,
    }.get(decision or "decline", gov.RECOMMEND_REVIEW)
    print(f"[node officer_review] {recommendation} — {gov.PENDING_HUMAN_CONFIRMATION} "
          f"(no autonomous sanction; officer signs off)")
    replay.record("human_gate", "officer",
                  {"customer": state.get("customer_id"), "recommendation": recommendation,
                   "status": gov.PENDING_HUMAN_CONFIRMATION,
                   "note": "binding sanction owned by a human, not the model"})
    notes = (
        f"{recommendation}: rule-engine decision={decision}, "
        f"CIBIL={risk.get('cibil')}, score={risk.get('score', 0):.2f}. "
        f"Officer to confirm before the decision is binding "
        f"(verify income docs, re-check bureau flags)."
    )
    return {
        "status": gov.PENDING_HUMAN_CONFIRMATION,
        "human_review_notes": notes,
        "audit_log": [{"node": "officer_review", "recommendation": recommendation,
                       "status": gov.PENDING_HUMAN_CONFIRMATION}],
    }


# ---------- Graph ----------

def build_graph():
    g = StateGraph(UnderwritingState)
    g.add_node("gather", gather)
    g.add_node("bureau_pull", bureau_pull)
    g.add_node("statement_parse", statement_parse)
    g.add_node("alt_data", alt_data)
    g.add_node("risk_score", risk_score)
    g.add_node("explain", explain)
    g.add_node("officer_review", officer_review)

    g.add_edge(START, "gather")
    g.add_edge("gather", "bureau_pull")
    g.add_edge("bureau_pull", "statement_parse")
    g.add_edge("statement_parse", "alt_data")
    g.add_edge("alt_data", "risk_score")
    g.add_edge("risk_score", "explain")
    # Every outcome — approve included — passes through the officer gate.
    g.add_edge("explain", "officer_review")
    g.add_edge("officer_review", END)
    return g.compile(checkpointer=MemorySaver())


def _run_demo(graph, customer_id: str, loan_amount: int, policy_key: str, thread_id: str):
    initial: UnderwritingState = {
        "customer_id": customer_id,
        "loan_amount": loan_amount,
        "policy_key": policy_key,
    }
    config = {"configurable": {"thread_id": thread_id}}
    return graph.invoke(initial, config=config)


def _print_outcome(r: UnderwritingState) -> None:
    print(f"Rule-engine decision: {r.get('decision')}  ->  {r.get('status', '(no gate)')}")
    if r.get("human_review_notes"):
        print(f"Officer gate:         {r['human_review_notes']}")
    if r.get("adverse_action"):
        print(f"Adverse-action:       {json.dumps(r['adverse_action'])}")
    print(f"LLM explanation:      {r.get('explanation', '')[:280]}")


def main() -> None:
    print("=== Credit Underwriting (sandboxed, real LLM) ===")
    print(f"Governance: rule engine decides · LLM explains · officer confirms "
          f"every outcome · {gov.governance_banner()}\n")
    replay.start("01-credit-underwriting", vertical="fintech",
                 jurisdiction=gov.active_jurisdiction().code)
    graph = build_graph()

    print("--- Demo 1: c-003 Rohan Desai (rule engine: DECLINE) ---")
    r1 = _run_demo(graph, "c-003", 200000, "personal_loan_india", "uw-sbx-c003")
    _print_outcome(r1)

    print("\n--- Demo 2: c-001 Aarav Sharma (rule engine: APPROVE — still officer-gated) ---")
    r2 = _run_demo(graph, "c-001", 500000, "personal_loan_india", "uw-sbx-c001")
    _print_outcome(r2)
    print("[NOTE] approve is NOT auto-sanctioned — it is held "
          f"{gov.PENDING_HUMAN_CONFIRMATION} for officer sign-off, same as a decline.")

    print("\n--- Demo 3: c-002 Priya Iyer (adversarial memo DETECTED by kyc_document_policy) ---")
    r3 = _run_demo(graph, "c-002", 1000000, "smb_working_capital_global", "uw-sbx-c002")
    _print_outcome(r3)
    print("[NOTE] Injection memo in c-002 statement was detected by kyc_document_policy "
          "(data-egress-sensitive + Tier-2 judge, log_only) and recorded in the audit "
          "trail; the decision is based on real financial signals only. The enforcing "
          "action=block variant is proven in verify_security_primitives.py (check 7).")

    # Emit the replay timeline for the landing-page demo (no-op unless
    # DECLAW_EMIT_EVENTS is set). Captured from this real sandboxed run.
    replay.flush()


if __name__ == "__main__":
    main()
