"""Customer-support chatbot — LangGraph + OpenAI STREAMING (baseline).

A refund / statement-Q&A agent that streams its reply to the user in
real time (SSE). Node sequence:
  classify_intent -> fetch_context -> stream_reply -> log_interaction

Baseline behaviour: the customer's transaction history and their PAN /
UPI VPA / card-PAN-last-4 end up directly in the streaming prompt. Each
token chunk streams over the wire with those identifiers in it (the
stream is HTTP chunked, not batched). That's the surface a Declaw
proxy+rehydration would protect; the sandboxed sibling demonstrates it.
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

from shared.llm import chat_stream  # noqa: E402  (OpenAI streaming)
from shared.mock_customers import CUSTOMERS  # noqa: E402
from shared.mock_transactions import card_transactions, upi_transactions  # noqa: E402


# ---------- State ----------

class SupportState(TypedDict, total=False):
    customer_id: str
    user_message: str
    intent: Literal["refund", "statement_qa", "dispute", "general"]
    context: dict
    reply_chunks: list[str]
    reply_full: str
    audit_log: Annotated[list[dict], "append-only audit trail"]


# ---------- Nodes ----------

def classify_intent(state: SupportState) -> SupportState:
    msg = state["user_message"].lower()
    if "refund" in msg or "return" in msg:
        intent = "refund"
    elif "statement" in msg or "balance" in msg:
        intent = "statement_qa"
    elif "dispute" in msg or "fraud" in msg or "chargeback" in msg:
        intent = "dispute"
    else:
        intent = "general"
    return {"intent": intent, "audit_log": [{"node": "classify_intent", "intent": intent}]}


def fetch_context(state: SupportState) -> SupportState:
    cid = state["customer_id"]
    c = CUSTOMERS[cid]
    context = {
        "customer_name": c.name,
        "pan": c.pan,                                # raw PAN — baseline leaks it
        "upi_vpa": c.upi_vpa,                        # raw VPA
        "cards_last4": [card["last4"] for card in c.cards_on_file],
        "recent_card_tx": card_transactions(cid)[:3],
        "recent_upi_tx": upi_transactions(cid)[:3],
    }
    return {"context": context,
            "audit_log": [{"node": "fetch_context", "cid": cid,
                           "card_count": len(context["cards_last4"])}]}


def stream_reply(state: SupportState) -> SupportState:
    print("[node stream_reply] calling gpt-4.1 with stream=True "
          "(UNSANDBOXED — raw PAN/UPI/tx history in each SSE chunk)")
    system = (
        "You are a helpful customer-support agent for a fintech company. "
        "Answer the customer's question concisely (3-5 sentences) using the "
        "context provided. If the intent is 'refund' or 'dispute', reference "
        "the correct transaction and walk through next steps."
    )
    user = json.dumps({
        "customer_message": state["user_message"],
        "intent": state["intent"],
        "context": state["context"],
    })

    print("  [streaming] ", end="", flush=True)
    chunks: list[str] = []
    for delta in chat_stream(system, user, max_tokens=400):
        print(delta, end="", flush=True)
        chunks.append(delta)
    print()

    return {"reply_chunks": chunks, "reply_full": "".join(chunks),
            "audit_log": [{"node": "stream_reply", "chunk_count": len(chunks),
                           "model": "gpt-4.1", "stream": True}]}


def log_interaction(state: SupportState) -> SupportState:
    # In production: write to CRM / ticketing (Zendesk, Freshdesk).
    # Baseline logs the full reply + context inline — PII in log file.
    print(f"[node log_interaction] persisting interaction — "
          f"intent={state['intent']} reply_len={len(state['reply_full'])}")
    return {"audit_log": [{"node": "log_interaction", "persisted": True}]}


# ---------- Graph ----------

def build_graph():
    g = StateGraph(SupportState)
    g.add_node("classify_intent", classify_intent)
    g.add_node("fetch_context", fetch_context)
    g.add_node("stream_reply", stream_reply)
    g.add_node("log_interaction", log_interaction)
    g.add_edge(START, "classify_intent")
    g.add_edge("classify_intent", "fetch_context")
    g.add_edge("fetch_context", "stream_reply")
    g.add_edge("stream_reply", "log_interaction")
    g.add_edge("log_interaction", END)
    return g.compile(checkpointer=MemorySaver())


def main() -> None:
    graph = build_graph()
    demos = [
        ("c-001", "I bought an iPad for 89999 on 2026-04-02, it arrived damaged. "
                  "Can you process a refund?"),
        ("c-005", "Why were two $9990 wires flagged on my account? "
                  "I need an explanation for my CFO."),
    ]
    for cid, msg in demos:
        print(f"\n=== Customer Support Chatbot (baseline, OpenAI streaming) ===")
        print(f"Customer: {cid} — Message: {msg!r}\n")
        config = {"configurable": {"thread_id": f"support-{cid}"}}
        graph.invoke({"customer_id": cid, "user_message": msg}, config=config)


if __name__ == "__main__":
    main()
