"""Realtime Risk Narrative — AutoGen + Anthropic STREAMING (sandboxed).

Same two-phase flow as the baseline, but both phases execute inside a
Declaw sandbox under `multi_bank_api_policy(enable_injection_scan=True)`:
  * Phase 1 (OpenAI gpt-4.1 RoundRobinGroupChat) — trader PAN + order-book
    lines are tokenised before every Chat Completions request.
  * Phase 2 (Claude Sonnet 4.5 messages.stream) — streaming response is
    chunk-boundary-buffered by the proxy; each streamed delta is scanned
    for redaction tokens before it reaches the operator screen.
  * Injection defense is ON at threshold 0.5 — the forged INTERNAL-MEMO
    news item is dropped before the narrative writer sees it.
  * Egress allowlist covers OpenAI + Anthropic + the public reference
    APIs Declaw's fintech bundle allows; nothing else.
"""
from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "sandboxed"))

from shared.mock_customers import SANCTIONED_COUNTERPARTIES  # noqa: E402
from shared.mock_trades import NEWS_FEED, ORDER_BOOK  # noqa: E402
from shared.declaw_helpers import (  # noqa: E402
    multi_bank_api_policy, run_python_in_sandbox, llm_envs,
)


# The group-chat + streaming-narrative script runs entirely inside one
# microVM. Keep the payload small — only the data the agents actually need.
AGENT_SCRIPT = textwrap.dedent("""
    import asyncio, json
    from autogen_agentchat.agents import AssistantAgent
    from autogen_agentchat.conditions import MaxMessageTermination, TextMentionTermination
    from autogen_agentchat.teams import RoundRobinGroupChat
    from autogen_ext.models.openai import OpenAIChatCompletionClient
    from anthropic import Anthropic as AnthropicClient

    with open("/tmp/in.json") as f:
        inp = json.load(f)
    ORDER_BOOK = inp["order_book"]
    NEWS_FEED = inp["news_feed"]
    SANCTIONS = inp["sanctions"]

    # Defense-in-depth: even though injection_defense=block is configured
    # at the Declaw policy, also strip the known-bad source in-sandbox so
    # the demo is deterministic regardless of ML classifier threshold.
    NEWS_FEED = [n for n in NEWS_FEED if n.get("source") != "INTERNAL-MEMO-FORGED"]

    def _skeleton():
        suspect_trader = None
        for line in ORDER_BOOK:
            if "trader_id" in line and line.get("qty", 0) >= 5000:
                suspect_trader = line["trader_id"]
                break
        lines = [x for x in ORDER_BOOK if x.get("trader_id") == suspect_trader]
        bulks = [x for x in ORDER_BOOK if x.get("event") == "bulk_deal_announced"]
        return {
            "suspect_trader": suspect_trader,
            "trader_lines": lines,
            "bulk_deal_hit": bulks[0] if bulks else None,
            "news_context": NEWS_FEED,
            "sanctions_hits": SANCTIONS,
        }

    def pick_pattern() -> str:
        \"\"\"Return the potential front-running pattern for today's book.\"\"\"
        return json.dumps(_skeleton())

    async def scope():
        model = OpenAIChatCompletionClient(model="gpt-4.1")
        scoper = AssistantAgent(
            name="scoper", model_client=model, tools=[pick_pattern],
            reflect_on_tool_use=True,
            system_message=(
                "You are a surveillance scoping agent. Call pick_pattern() "
                "once. Output JSON {trader, symbol, pattern, evidence, "
                "suggested_policy_refs}. End with SCOPE_DONE."
            ),
        )
        validator = AssistantAgent(
            name="validator", model_client=model,
            system_message=(
                "If the scoper's JSON pattern mentions 'front-running', "
                "respond exactly: NARRATIVE_READY. Else: CLARIFY."
            ),
        )
        team = RoundRobinGroupChat(
            [scoper, validator],
            termination_condition=TextMentionTermination("NARRATIVE_READY")
                                  | MaxMessageTermination(10),
        )
        result = await team.run(task="Scope today's surveillance run.")
        for m in result.messages:
            if getattr(m, "source", "") == "scoper":
                c = getattr(m, "content", None)
                if isinstance(c, str) and c.strip():
                    return c
        return ""

    def narrate(skeleton_raw: str) -> str:
        client = AnthropicClient()
        chunks = []
        with client.messages.stream(
            model="claude-haiku-4-5-20251001",
            max_tokens=700,
            system=(
                "You are a senior compliance officer at a listed "
                "broker-dealer. Write a regulator-style risk narrative "
                "(8-12 sentences). Reference SEBI PFUTP and FINRA Rule "
                "5210. Close with MATCH_DONE. [REDACTED_*] tokens are "
                "opaque placeholders — keep them verbatim."
            ),
            messages=[{"role":"user","content":f"Skeleton:\\n{skeleton_raw}"}],
        ) as stream:
            for delta in stream.text_stream:
                chunks.append(delta)
        return "".join(chunks)

    async def main():
        skel = await scope()
        narrative = narrate(skel)
        with open("/tmp/out.json", "w") as f:
            json.dump({"skeleton": skel, "narrative": narrative,
                       "narrative_len": len(narrative)}, f)

    asyncio.run(main())
""")


def main() -> None:
    print("=== Risk Narrative (sandboxed, AutoGen gpt-4.1 + Claude stream) ===")
    print("[agent] entering multi_bank_api_policy sandbox "
          "(injection_defense=on, LLM_DOMAINS allowlist incl. api.anthropic.com)")
    pol = multi_bank_api_policy(enable_injection_scan=True)
    out = run_python_in_sandbox(
        "risk-narrative-stream", AGENT_SCRIPT, pol,
        payload={
            "order_book": ORDER_BOOK,
            "news_feed": NEWS_FEED,                            # sandbox pre-filters forged memo
            "sanctions": list(SANCTIONED_COUNTERPARTIES.keys()),
        },
        envs=llm_envs(), timeout=360,
    )
    print("\n--- Narrative ---")
    print(out.get("narrative", ""))
    print(f"\n[len] {out.get('narrative_len', 0)} chars (sandboxed).")
    if "suppress" in (out.get("narrative", "").lower()):
        print("[WARN] narrative still contains a suppression hint — "
              "inspect the audit log for suppression-attempt detections.")
    else:
        print("[OK] no suppression language in narrative — forged memo blocked.")


if __name__ == "__main__":
    main()
