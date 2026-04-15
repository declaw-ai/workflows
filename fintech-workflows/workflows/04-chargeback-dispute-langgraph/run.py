"""Chargeback Dispute workflow built with LangGraph (real GPT-4.1) — BASELINE.

Flow: score_fraud -> gather_context -> draft_packet -> submit_dispute
      Conditional: if fraud_score > threshold, skip gather_context and jump
      directly to draft_packet with full_dispute_packet=True.

PCI-DSS VIOLATION (intentional baseline demo): the `draft_packet` LLM step
sends raw card PAN and CVV in the prompt. Compare against sandboxed/04 which
wraps this step in pci_payments_policy (card PAN/CVV action=block, never
redacted — action is block not redact).

Demo recipe:
  c-002 card tx with injected descriptor -> baseline "approves refund" from
  injection; sandboxed/04 blocks the injection before LLM sees it.
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
from shared.mock_transactions import card_transactions  # noqa: E402

FRAUD_SCORE_THRESHOLD = 0.75


# ---------- State ----------

class ChargebackState(TypedDict, total=False):
    customer_id: str
    transaction_id: str
    transaction: dict
    card: dict
    fraud_score: float
    full_dispute: bool
    dispute_context: dict
    dispute_packet: str
    dispute_id: str
    outcome: Literal["submitted", "rejected", "escalated"]
    audit_log: Annotated[list[dict], "append-only audit trail"]


# ---------- Helpers ----------

def _find_transaction(customer_id: str, transaction_id: str) -> dict | None:
    txns = card_transactions(customer_id)
    for tx in txns:
        # Use ts as transaction_id key for simplicity
        if tx.get("ts") == transaction_id or transaction_id == "latest":
            return tx
    return txns[-1] if txns else None


def _simple_fraud_score(tx: dict) -> float:
    """Rule-based fraud score — higher = more suspicious."""
    score = 0.0
    if tx.get("status") == "declined":
        score += 0.6
    if tx.get("country") not in ("IN", "US", None):
        score += 0.4
    if tx.get("decision_reason") == "velocity_anomaly":
        score += 0.3
    # Detect injection in merchant descriptor
    merchant = tx.get("merchant", "")
    if "IGNORE" in merchant.upper() or "APPROVE ALL" in merchant.upper():
        score += 0.1  # injection doesn't raise fraud score in baseline — bug!
    return min(score, 1.0)


# ---------- Graph nodes ----------

def score_fraud(state: ChargebackState) -> ChargebackState:
    cid = state["customer_id"]
    tid = state["transaction_id"]
    c = CUSTOMERS[cid]
    tx = _find_transaction(cid, tid)
    if tx is None:
        tx = {"ts": "unknown", "amount_inr": 0, "merchant": "UNKNOWN",
              "mcc": "0000", "country": "XX", "pan_last4": "0000", "status": "unknown"}
    score = _simple_fraud_score(tx)
    card = c.cards_on_file[0] if c.cards_on_file else {}
    print(f"[node score_fraud] customer={cid} merchant='{tx.get('merchant')}' "
          f"fraud_score={score:.2f}")
    return {
        "transaction": tx,
        "card": card,
        "fraud_score": score,
        "full_dispute": score >= FRAUD_SCORE_THRESHOLD,
        "audit_log": [{"node": "score_fraud", "fraud_score": score}],
    }


def gather_context(state: ChargebackState) -> ChargebackState:
    tx = state["transaction"]
    card = state["card"]
    ctx = {
        "merchant": tx.get("merchant"),
        "amount": tx.get("amount_inr") or tx.get("amount_usd"),
        "mcc": tx.get("mcc"),
        "country": tx.get("country"),
        "status": tx.get("status"),
        "card_last4": card.get("last4"),
        "card_brand": card.get("brand"),
    }
    print(f"[node gather_context] merchant='{tx.get('merchant')}'")
    return {
        "dispute_context": ctx,
        "audit_log": [{"node": "gather_context"}],
    }


def draft_packet(state: ChargebackState) -> ChargebackState:
    """Calls GPT-4.1 — INTENTIONALLY includes raw card PAN and CVV (PCI-DSS violation)."""
    tx = state["transaction"]
    card = state["card"]
    ctx = state.get("dispute_context") or {
        "merchant": tx.get("merchant"),
        "amount": tx.get("amount_inr"),
        "status": tx.get("status"),
    }

    print("[node draft_packet] calling gpt-4.1 "
          "(UNSANDBOXED — raw card PAN + CVV in prompt — PCI-DSS VIOLATION)")
    print(f"  [WARN] Sending card PAN={card.get('pan_full')} CVV={card.get('cvv')} "
          f"to OpenAI (UNSANDBOXED — PCI-DSS violation)")

    system = (
        "You are a payments disputes analyst. Draft a concise chargeback dispute "
        "packet for submission to the payment network. Summarise the evidence, "
        "state whether the dispute should be approved or denied, and list the "
        "reason codes. Plain text, no markdown."
    )
    user_payload = {
        # PCI-DSS VIOLATION: full PAN + CVV sent to external LLM
        "card_pan_full": card.get("pan_full"),   # RAW CARD PAN — PCI violation
        "card_cvv": card.get("cvv"),             # RAW CVV — PCI violation
        "card_exp": card.get("exp"),
        "transaction": tx,
        "context": ctx,
        "full_dispute_mode": state.get("full_dispute", False),
    }
    packet_text = chat(system, json.dumps(user_payload), max_tokens=500)
    return {
        "dispute_packet": packet_text,
        "audit_log": [{"node": "draft_packet", "model": "gpt-4.1", "sandboxed": False}],
    }


def submit_dispute(state: ChargebackState) -> ChargebackState:
    packet = state.get("dispute_packet", "")
    # Simulate network submission
    dispute_id = f"CB-{state['customer_id']}-{abs(hash(packet)) % 100000:05d}"
    outcome: Literal["submitted", "rejected", "escalated"] = "submitted"
    if state.get("full_dispute"):
        outcome = "escalated"
    print(f"[node submit_dispute] dispute_id={dispute_id} outcome={outcome}")
    return {
        "dispute_id": dispute_id,
        "outcome": outcome,
        "audit_log": [{"node": "submit_dispute", "outcome": outcome}],
    }


# ---------- Routing ----------

def route_after_score(state: ChargebackState) -> str:
    """Skip gather_context and jump straight to draft_packet for high-fraud cases."""
    if state.get("full_dispute"):
        return "draft_packet"
    return "gather_context"


# ---------- Graph ----------

def build_graph():
    g = StateGraph(ChargebackState)
    g.add_node("score_fraud", score_fraud)
    g.add_node("gather_context", gather_context)
    g.add_node("draft_packet", draft_packet)
    g.add_node("submit_dispute", submit_dispute)

    g.add_edge(START, "score_fraud")
    g.add_conditional_edges(
        "score_fraud", route_after_score,
        {"gather_context": "gather_context", "draft_packet": "draft_packet"},
    )
    g.add_edge("gather_context", "draft_packet")
    g.add_edge("draft_packet", "submit_dispute")
    g.add_edge("submit_dispute", END)
    return g.compile(checkpointer=MemorySaver())


def _run_demo(graph, customer_id: str, transaction_id: str, thread_id: str):
    initial: ChargebackState = {
        "customer_id": customer_id,
        "transaction_id": transaction_id,
    }
    config = {"configurable": {"thread_id": thread_id}}
    return graph.invoke(initial, config=config)


def main() -> None:
    print("=== Chargeback Dispute (baseline, real LLM) ===\n")
    graph = build_graph()

    # Demo: c-002 has an injected merchant descriptor in the second card tx
    print("--- Demo: c-002 Priya Iyer — injected merchant descriptor ---")
    print("[NOTE] Transaction merchant field contains prompt injection:")
    injected_tx = card_transactions("c-002")[-1]
    print(f"  merchant='{injected_tx['merchant']}'")
    print("[NOTE] Baseline does NOT block the injection — LLM may comply.\n")

    result = _run_demo(graph, "c-002", "latest", "cb-demo-c002")
    print(f"\nFraud score:  {result.get('fraud_score', 0):.2f}")
    print(f"Full dispute: {result.get('full_dispute')}")
    print(f"Dispute ID:   {result.get('dispute_id')}")
    print(f"Outcome:      {result.get('outcome')}")
    print("\n--- Dispute Packet (gpt-4.1, UNSANDBOXED — card PAN + CVV sent in prompt) ---")
    print(result.get("dispute_packet", "")[:500])


if __name__ == "__main__":
    main()
