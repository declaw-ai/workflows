"""Fraud Decision Explainer — LlamaIndex tools + Anthropic Claude (non-streaming).

When a fraud model blocks a transaction, the customer and the ops team both
want a clear, defensible explanation. Claude Sonnet 4.5 is well-suited to
producing regulator-quality narratives with citations to internal policy.

Design: each step is a `FunctionTool` (LlamaIndex's tool abstraction), but
we drive the pipeline sequentially in Python rather than through a
`FunctionAgent` loop — tool-driven agents were looping past any sensible
iteration cap because Claude kept calling tools when it already had the
answer. Deterministic orchestration + a single Claude call for the
narrative produces the same quality in ~15 seconds and never loops.

Baseline behaviour: Claude receives the full customer record (PAN, VPA,
card PAN + CVV, SSN) in its prompt — this is exactly the leak the
sandboxed variant tokenises.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from llama_index.core.tools import FunctionTool
from llama_index.llms.anthropic import Anthropic as LlamaAnthropic  # noqa: F401 (still demoed as LLM adapter)

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from shared.llm import chat_anthropic, DEFAULT_CLAUDE_MODEL  # noqa: E402
from shared.mock_customers import CUSTOMERS  # noqa: E402
from shared.mock_transactions import card_transactions, upi_transactions  # noqa: E402
from shared.mock_policies import CIRCULARS  # noqa: E402


def _all_tx() -> list[dict]:
    txs = []
    for cid in CUSTOMERS:
        for t in card_transactions(cid):
            t = {**t, "customer_id": cid}
            txs.append(t)
        for t in upi_transactions(cid):
            t = {**t, "customer_id": cid}
            txs.append(t)
    return txs


def fetch_transaction(hint: str) -> dict:
    """Return a single transaction matching any identifier substring
    (rrn, pan_last4, merchant name, UPI VPA, or descriptor)."""
    needle = hint.lower()
    fields = ("rrn", "pan_last4", "merchant", "vpa_to", "vpa_from", "description")
    for t in _all_tx():
        for key in fields:
            if needle in str(t.get(key, "")).lower():
                return t
    return {"error": f"no match for {hint}"}


def fetch_customer(customer_id: str) -> dict:
    c = CUSTOMERS.get(customer_id)
    if not c:
        return {"error": f"no such customer {customer_id}"}
    return {
        "id": c.id, "name": c.name,
        "pan": c.pan, "aadhaar": c.aadhaar, "ssn": c.ssn,
        "upi_vpa": c.upi_vpa, "email": c.email, "phone": c.phone,
        "cards_on_file": c.cards_on_file,
        "cibil_score": c.cibil_score, "fico_score": c.fico_score,
    }


def score_features(transaction: dict, customer: dict) -> dict:
    """Return the synthetic fraud-feature vector that drove the decision."""
    amt = transaction.get("amount_inr") or transaction.get("amount_usd") or 0
    return {
        "transaction_id": transaction.get("rrn") or transaction.get("merchant"),
        "velocity_last_hour": 4 if amt > 100000 else 1,
        "cross_border_flag": transaction.get("country") not in (None, "IN", "US"),
        "amount_z_score": 3.2 if amt > 100000 else 0.4,
        "known_good_merchant": transaction.get("merchant") in {"Swiggy", "Apple India"},
        "risk_flags": transaction.get("risk_flags") or [],
    }


def lookup_policy(policy_id: str) -> dict:
    for c in CIRCULARS:
        if c["id"] == policy_id:
            return c
    return {"error": f"policy_id {policy_id} not found"}


def draft_customer_letter(transaction: dict, customer: dict,
                          features: dict, policy_excerpt: str) -> str:
    """Ask Claude to produce a regulator-quality decline/hold letter.

    This is the NARRATIVE Anthropic non-streaming call. Baseline sends the
    raw customer record + raw transaction + raw policy chunk to Claude
    without any PII scrubbing.
    """
    system = (
        "You are a customer-facing fraud-operations specialist. Produce a "
        "concise, defensible explanation letter (4-6 sentences) for why a "
        "transaction was blocked. Cite the relevant policy circular. Write "
        "at a 7th-grade reading level. Close by telling the customer how to "
        "appeal if they believe the decision is wrong."
    )
    user = json.dumps({
        "transaction": transaction, "customer": customer,
        "fraud_features": features, "policy_excerpt": policy_excerpt,
    })
    return chat_anthropic(system, user, max_tokens=500)


def _choose_policy_id(features: dict, transaction: dict) -> str:
    """Deterministic policy selection driven by features (would be an LLM
    step in a larger workflow; kept as a dict lookup so the pipeline is
    reproducible)."""
    if transaction.get("cross_border_flag") or features.get("cross_border_flag"):
        return "FATF-REC-10"
    if features.get("amount_z_score", 0) >= 3.0:
        return "RBI-2025-DL-01"
    if transaction.get("rrn", "").startswith("41"):
        return "RBI-2025-DL-01"
    return "PCI-DSS-3.2"


def _run_pipeline(customer_id: str, hint: str) -> str:
    """Deterministic sequence: fetch → features → policy → Claude narrative."""
    # Each step exposes itself as a FunctionTool so the `@tool`-style API
    # surface is preserved — but we call them directly for reliability.
    tools = {
        "fetch_transaction":     FunctionTool.from_defaults(fn=fetch_transaction),
        "fetch_customer":        FunctionTool.from_defaults(fn=fetch_customer),
        "score_features":        FunctionTool.from_defaults(fn=score_features),
        "lookup_policy":         FunctionTool.from_defaults(fn=lookup_policy),
        "draft_customer_letter": FunctionTool.from_defaults(fn=draft_customer_letter),
    }

    print("[step 1] fetch_transaction")
    tx = tools["fetch_transaction"].fn(hint)
    if "error" in tx:
        return f"(no transaction matched hint={hint!r})"

    print("[step 2] fetch_customer")
    cust = tools["fetch_customer"].fn(customer_id)

    print("[step 3] score_features")
    features = tools["score_features"].fn(tx, cust)

    policy_id = _choose_policy_id(features, tx)
    print(f"[step 4] lookup_policy({policy_id})")
    policy = tools["lookup_policy"].fn(policy_id)

    print("[step 5] draft_customer_letter — calling Claude (UNSANDBOXED; "
          "raw PAN/SSN/VPA cross to api.anthropic.com)")
    letter = tools["draft_customer_letter"].fn(
        tx, cust, features, policy.get("excerpt", ""))
    return letter


def main() -> None:
    demos = [
        ("c-001", "UNKNOWN-MERCHANT-MOSCOW"),
        ("c-003", "acme.shellco"),
    ]
    for cid, hint in demos:
        print(f"\n=== Fraud Explainer (baseline, Anthropic non-stream) ===")
        print(f"Customer: {cid} — Hint: {hint!r}\n")
        letter = _run_pipeline(cid, hint)
        print("--- Letter ---")
        print(letter)


if __name__ == "__main__":
    main()
