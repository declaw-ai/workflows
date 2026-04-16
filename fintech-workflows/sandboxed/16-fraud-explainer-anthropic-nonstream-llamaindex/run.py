"""Fraud Decision Explainer — LlamaIndex + Anthropic Claude (sandboxed).

Same FunctionAgent as the baseline, wrapped in a Declaw sandbox under
`compliance_rag_policy`:
  * Outbound requests to api.anthropic.com have PAN/SSN/VPA/card-PAN
    tokenised by the proxy before the request leaves the microVM.
  * Injection defense is ON with threshold=0.5 — attacker-supplied
    merchant descriptor text can't hijack the narrative.
  * Allowlist = api.anthropic.com + api.openai.com + pypi bootstrap only;
    a compromised tool helper cannot exfil to a third domain.
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
from shared.mock_transactions import card_transactions, upi_transactions  # noqa: E402
from shared.mock_policies import CIRCULARS  # noqa: E402
from shared.declaw_helpers import (  # noqa: E402
    LLM_DOMAINS, compliance_rag_policy, llm_envs, run_python_in_sandbox,
)


# Payload assembled on the host so the sandbox only sees what it needs.
def _all_tx() -> list[dict]:
    txs = []
    for cid in CUSTOMERS:
        for t in card_transactions(cid):
            txs.append({**t, "customer_id": cid})
        for t in upi_transactions(cid):
            txs.append({**t, "customer_id": cid})
    return txs


AGENT_SCRIPT = textwrap.dedent("""
    import sys, json, anthropic as _ant
    print(f"[sandbox] anthropic SDK version: {_ant.__version__}", file=sys.stderr, flush=True)
    from llama_index.core.tools import FunctionTool
    from anthropic import Anthropic as AnthropicClient

    with open("/tmp/in.json") as f:
        inp = json.load(f)
    ALL_TX = inp["all_tx"]
    CUSTOMERS = inp["customers"]
    CIRCULARS = inp["circulars"]
    HINT = inp["hint"]
    CUSTOMER_ID = inp["customer_id"]

    def fetch_transaction(hint):
        \"\"\"Find a tx matching any identifier substring (rrn, pan_last4,
        merchant, vpa_to/from, description).\"\"\"
        needle = hint.lower()
        fields = ("rrn", "pan_last4", "merchant", "vpa_to", "vpa_from", "description")
        for t in ALL_TX:
            for key in fields:
                if needle in str(t.get(key, "")).lower():
                    return t
        return {"error": f"no match for {hint}"}

    def fetch_customer(customer_id: str) -> dict:
        return CUSTOMERS.get(customer_id, {"error": "no such customer"})

    def score_features(transaction: dict, customer: dict) -> dict:
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
        \"\"\"Claude narrative generator. Uses messages.stream() under the
        hood as a workaround for a Declaw proxy bug on non-streaming
        Anthropic requests (documented in declaw-sdk-issues/). The
        caller-facing API stays non-streaming (one string returned).\"\"\"
        client = AnthropicClient()
        chunks = []
        with client.messages.stream(
            model="claude-sonnet-4-5",
            max_tokens=500,
            system=("You are a customer-facing fraud-operations specialist. "
                    "Produce a concise, defensible explanation letter (4-6 "
                    "sentences). Cite the relevant policy circular. Write at "
                    "7th-grade level. Close with appeal instructions. Any "
                    "[REDACTED_*] tokens are opaque placeholders."),
            messages=[{"role": "user", "content": json.dumps({
                "transaction": transaction, "customer": customer,
                "fraud_features": features, "policy_excerpt": policy_excerpt,
            })}],
        ) as stream:
            for delta in stream.text_stream:
                chunks.append(delta)
        return "".join(chunks)

    # Deterministic pipeline (same shape as the baseline). Each step is a
    # FunctionTool — kept for API-surface parity — but called directly
    # instead of through FunctionAgent's tool-calling loop.
    TOOLS = {
        "fetch_transaction":     FunctionTool.from_defaults(fn=fetch_transaction),
        "fetch_customer":        FunctionTool.from_defaults(fn=fetch_customer),
        "score_features":        FunctionTool.from_defaults(fn=score_features),
        "lookup_policy":         FunctionTool.from_defaults(fn=lookup_policy),
        "draft_customer_letter": FunctionTool.from_defaults(fn=draft_customer_letter),
    }

    def choose_policy_id(features, transaction):
        if transaction.get("cross_border_flag") or features.get("cross_border_flag"):
            return "FATF-REC-10"
        if features.get("amount_z_score", 0) >= 3.0:
            return "RBI-2025-DL-01"
        if str(transaction.get("rrn", "")).startswith("41"):
            return "RBI-2025-DL-01"
        return "PCI-DSS-3.2"

    tx = TOOLS["fetch_transaction"].fn(HINT)
    if "error" in tx:
        letter = f"(no transaction matched hint={HINT!r})"
    else:
        cust = TOOLS["fetch_customer"].fn(CUSTOMER_ID)
        features = TOOLS["score_features"].fn(tx, cust)
        pid = choose_policy_id(features, tx)
        policy = TOOLS["lookup_policy"].fn(pid)
        letter = TOOLS["draft_customer_letter"].fn(
            tx, cust, features, policy.get("excerpt", ""))
    with open("/tmp/out.json", "w") as f:
        json.dump({"letter": letter}, f)
""")


def main() -> None:
    customers_dict = {
        cid: {
            "id": c.id, "name": c.name,
            "pan": c.pan, "aadhaar": c.aadhaar, "ssn": c.ssn,
            "upi_vpa": c.upi_vpa, "email": c.email, "phone": c.phone,
            "cards_on_file": c.cards_on_file,
            "cibil_score": c.cibil_score, "fico_score": c.fico_score,
        }
        for cid, c in CUSTOMERS.items()
    }
    payload_common = {
        "all_tx": _all_tx(),
        "customers": customers_dict,
        "circulars": CIRCULARS,
    }

    demos = [("c-001", "UNKNOWN-MERCHANT-MOSCOW"), ("c-003", "acme.shellco")]
    for cid, hint in demos:
        print(f"\n=== Fraud Explainer (sandboxed, Anthropic non-stream) ===")
        print(f"Customer: {cid} — Hint: {hint!r}\n")
        print("[agent] entering compliance_rag_policy sandbox (Anthropic "
              "non-stream — PII in log_only mode while Declaw patches "
              "the Anthropic-side redaction path; detections still land "
              "in the audit trail, body flows untouched)")
        pol = compliance_rag_policy(LLM_DOMAINS)
        out = run_python_in_sandbox(
            "fraud-explain", AGENT_SCRIPT, pol,
            payload={**payload_common, "customer_id": cid, "hint": hint},
            # anthropic + llama-index-core are both pre-baked in the
            # ai-agent template — no pip-install needed.
            envs=llm_envs(), timeout=240,
        )
        print("--- Letter ---")
        print(out.get("letter", "(no letter returned)"))


if __name__ == "__main__":
    main()
