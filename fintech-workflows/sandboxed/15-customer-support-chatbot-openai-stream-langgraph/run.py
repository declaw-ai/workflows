"""Customer-support chatbot — LangGraph + OpenAI STREAMING (sandboxed).

Same flow as the baseline but the streaming LLM call happens inside a
Declaw microVM under `lending_llm_policy`:
  * Each outbound chunk is PII-redacted (PAN, UPI VPA, SSN, card-PAN
    tokenized) BEFORE the Chat Completions request leaves the sandbox.
  * The SSE response stream is chunk-boundary-buffered by the proxy so
    rehydration tokens that span two delta boundaries are still
    recognised — the agent code sees original identifiers in the final
    assembled text, end users of a streamed UX never see raw PII.

The known OpenAI chunked/compressed rehydration caveat documented in
health-tech applies: inbound rehydration is best-effort on streaming
responses; outbound redaction is rock solid.
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
from shared.mock_transactions import card_transactions, upi_transactions  # noqa: E402
from shared.declaw_helpers import (  # noqa: E402
    LLM_DOMAINS, lending_llm_policy, llm_envs, run_python_in_sandbox,
)


class SupportState(TypedDict, total=False):
    customer_id: str
    user_message: str
    intent: Literal["refund", "statement_qa", "dispute", "general"]
    context: dict
    reply_chunks: list[str]
    reply_full: str
    audit_log: Annotated[list[dict], "append-only audit trail"]


# ---------- In-sandbox streaming script ----------

STREAM_REPLY_SCRIPT = textwrap.dedent("""
    import json, sys
    # The Accept-Encoding shim was written into /tmp by declaw_helpers
    sys.path.insert(0, "/tmp")
    try:
        import declaw_openai_compat  # noqa: F401
    except Exception:
        pass
    from openai import OpenAI

    with open("/tmp/in.json") as f:
        inp = json.load(f)

    system = (
        "You are a helpful customer-support agent for a fintech company. "
        "Answer the customer's question concisely (3-5 sentences) using the "
        "context provided. If the intent is 'refund' or 'dispute', reference "
        "the correct transaction and walk through next steps. Any "
        "[REDACTED_*] tokens you see are opaque placeholders for customer "
        "identifiers — treat them as such."
    )
    user = json.dumps({
        "customer_message": inp["user_message"],
        "intent": inp["intent"],
        "context": inp["context"],
    })

    client = OpenAI()
    stream = client.chat.completions.create(
        model="gpt-4.1",
        messages=[{"role":"system","content":system},
                  {"role":"user","content":user}],
        max_completion_tokens=400,
        stream=True,
    )

    chunks = []
    for chunk in stream:
        delta = chunk.choices[0].delta.content if chunk.choices else None
        if delta:
            chunks.append(delta)
    with open("/tmp/out.json", "w") as f:
        json.dump({"chunks": chunks, "full": "".join(chunks)}, f)
""")


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
        "pan": c.pan,
        "upi_vpa": c.upi_vpa,
        "cards_last4": [card["last4"] for card in c.cards_on_file],
        "recent_card_tx": card_transactions(cid)[:3],
        "recent_upi_tx": upi_transactions(cid)[:3],
    }
    return {"context": context,
            "audit_log": [{"node": "fetch_context", "cid": cid}]}


def stream_reply(state: SupportState) -> SupportState:
    print("[node stream_reply] entering lending_llm_policy sandbox "
          "(OpenAI streaming — each SSE chunk tokenised on egress, "
          "rehydrated inbound where the proxy supports it)")
    pol = lending_llm_policy(LLM_DOMAINS)
    out = run_python_in_sandbox(
        "support-stream", STREAM_REPLY_SCRIPT, pol,
        payload={
            "user_message": state["user_message"],
            "intent": state["intent"],
            "context": state["context"],
        },
        envs=llm_envs(), timeout=120,
    )
    # For parity with baseline, reprint the full reply on one line (sandboxed
    # returns the assembled result rather than each chunk printed live).
    print("  [sandboxed reply]", out["full"])
    return {"reply_chunks": out["chunks"], "reply_full": out["full"],
            "audit_log": [{"node": "stream_reply", "sandboxed": True,
                           "chunk_count": len(out["chunks"]),
                           "model": "gpt-4.1", "stream": True}]}


def log_interaction(state: SupportState) -> SupportState:
    print(f"[node log_interaction] persisting — intent={state['intent']} "
          f"reply_len={len(state['reply_full'])}")
    return {"audit_log": [{"node": "log_interaction", "persisted": True}]}


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
        print(f"\n=== Customer Support Chatbot (sandboxed, OpenAI streaming) ===")
        print(f"Customer: {cid} — Message: {msg!r}\n")
        config = {"configurable": {"thread_id": f"support-{cid}"}}
        graph.invoke({"customer_id": cid, "user_message": msg}, config=config)


if __name__ == "__main__":
    main()
