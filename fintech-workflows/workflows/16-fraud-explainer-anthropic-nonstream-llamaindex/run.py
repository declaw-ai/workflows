"""Fraud Decision Explainer — LlamaIndex + Anthropic Claude (non-streaming).

When a fraud model blocks a transaction, the customer and the ops team both
want a clear, defensible explanation. Claude Sonnet 4.5 is well-suited to
producing regulator-quality narratives with citations to internal policy.

Tools the FunctionAgent carries:
  * fetch_transaction     — pulls a tx by id from mock_transactions
  * fetch_customer        — returns customer profile (includes raw PAN/SSN/VPA)
  * score_features        — returns the feature vector that tripped the model
  * lookup_policy         — returns a policy excerpt (which criterion was hit)
  * draft_customer_letter — Claude-powered narrative generator

Baseline behaviour: agent passes the full customer record (PAN, VPA, card
PAN + CVV, SSN) as tool payload to Claude. Any of those identifiers can
end up in the returned narrative.
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from llama_index.core.agent.workflow import FunctionAgent
from llama_index.core.tools import FunctionTool
from llama_index.llms.anthropic import Anthropic as LlamaAnthropic

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


def fetch_transaction(rrn_or_pan_last4: str) -> dict:
    """Return a single transaction matching the rrn or pan_last4 substring."""
    for t in _all_tx():
        if rrn_or_pan_last4 in str(t.get("rrn", "")) or \
           rrn_or_pan_last4 in str(t.get("pan_last4", "")):
            return t
    return {"error": f"no match for {rrn_or_pan_last4}"}


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


async def _run_agent(customer_id: str, hint: str) -> str:
    agent = FunctionAgent(
        tools=[
            FunctionTool.from_defaults(fn=fetch_transaction),
            FunctionTool.from_defaults(fn=fetch_customer),
            FunctionTool.from_defaults(fn=score_features),
            FunctionTool.from_defaults(fn=lookup_policy),
            FunctionTool.from_defaults(fn=draft_customer_letter),
        ],
        llm=LlamaAnthropic(model=DEFAULT_CLAUDE_MODEL, max_tokens=800),
        system_prompt=(
            "You are a fraud-ops explainer. Workflow:\n"
            "1. fetch_transaction(rrn_or_pan_last4) with the hint provided.\n"
            "2. fetch_customer(customer_id) using the returned transaction.\n"
            "3. score_features(transaction, customer).\n"
            "4. lookup_policy with the most relevant policy_id from {RBI-2025-DL-01, "
            "FATF-REC-10, FATF-REC-20, PCI-DSS-3.2}.\n"
            "5. draft_customer_letter(transaction, customer, features, policy_excerpt).\n"
            "Return the final letter verbatim as your answer."
        ),
    )
    print("[agent.run] calling Claude (UNSANDBOXED — raw PAN/SSN/VPA pass "
          "through tool payloads to the Claude API)")
    resp = await agent.run(
        user_msg=f"A customer transaction was blocked. "
                 f"Hint: customer_id='{customer_id}', descriptor='{hint}'. "
                 f"Produce an explanation letter."
    )
    return str(resp)


def main() -> None:
    demos = [
        ("c-001", "UNKNOWN-MERCHANT-MOSCOW"),
        ("c-003", "acme.shellco"),
    ]
    for cid, hint in demos:
        print(f"\n=== Fraud Explainer (baseline, Anthropic non-stream) ===")
        print(f"Customer: {cid} — Hint: {hint!r}\n")
        letter = asyncio.run(_run_agent(cid, hint))
        print("--- Letter ---")
        print(letter)


if __name__ == "__main__":
    main()
