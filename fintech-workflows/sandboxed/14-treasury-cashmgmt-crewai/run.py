"""Treasury Cash Management — sandboxed, real CrewAI inside microVM.

Four-agent CrewAI sequential pipeline runs inside a single Firecracker sandbox:
  Cash-Position-Analyzer -> FX-Strategist -> Sweep-Planner -> Human-Review

Policy: treasury_ops_policy([LLM_DOMAINS, fbil, federalreserve])
  * PII redacted (PAN, account numbers, GSTIN, EIN) before reaching OpenAI
  * Tight network allowlist — only LLM + FBIL + Fed H.10 domains permitted
  * Every Sweep-Planner tool call is audited in the sandbox audit log
  * Human-Review node prints a clear "AWAITING OPERATOR SIGN-OFF" gate

Live FX: fbil_reference_rate("USDINR") fetched on the host before sandbox
so the live rate crosses the policy boundary audited (not raw from inside).

(sandboxed — Crew inside microVM)
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
from shared.mock_statements import STATEMENTS  # noqa: E402
from shared.mock_transactions import neft_transactions, ach_transactions  # noqa: E402
from shared.external_apis import fbil_reference_rate  # noqa: E402
from shared.declaw_helpers import (  # noqa: E402
    LLM_DOMAINS,
    treasury_ops_policy,
    llm_envs,
    run_python_in_sandbox,
)


CREWAI_SCRIPT = textwrap.dedent("""
    import json, os
    os.environ["CREWAI_TRACING_ENABLED"] = "false"
    os.environ["OTEL_SDK_DISABLED"] = "true"
    os.environ["OPENAI_MODEL_NAME"] = "gpt-4.1"

    import urllib.request

    from crewai import Agent, Crew, LLM, Process, Task
    from crewai.tools import tool

    llm = LLM(model="gpt-4.1")

    with open("/tmp/in.json") as f:
        inp = json.load(f)
    customer_id = inp["customer_id"]
    statement = inp["statement"]
    neft_txns = inp["neft_transactions"]
    ach_txns = inp["ach_transactions"]
    fx_rate = inp["fx_rate"]

    @tool("Get current cash positions")
    def get_cash_positions(cid: str) -> str:
        \\"\\"\\"Return JSON with current account balances (PII fields redacted by policy).\\"\\"\\"
        return json.dumps({
            "customer_id": cid,
            "bank": statement.get("bank"),
            "period": statement.get("period"),
            "opening_balance_inr": statement.get("opening_balance_inr"),
            "closing_balance_inr": statement.get("closing_balance_inr"),
            "opening_balance_usd": statement.get("opening_balance_usd"),
            "closing_balance_usd": statement.get("closing_balance_usd"),
            "neft_count": len(neft_txns),
            "ach_count": len(ach_txns),
        })

    @tool("Get FBIL reference FX rate")
    def get_fx_rate(pair: str) -> str:
        \\"\\"\\"Return the pre-fetched FBIL reference rate for the given currency pair.\\"\\"\\"
        return json.dumps(fx_rate)

    @tool("Propose a sweep transfer")
    def propose_sweep(sweep_json: str) -> str:
        \\"\\"\\"Given JSON {from_currency, to_currency, amount, rationale},
        record the proposed sweep and return a pending confirmation receipt.\\"\\"\\"
        try:
            sweep = json.loads(sweep_json)
        except Exception:
            return json.dumps({"error": "invalid sweep JSON"})
        sweep["status"] = "PENDING_HUMAN_APPROVAL"
        sweep["ref"] = (
            f"SWP-{customer_id}-{sweep.get('from_currency','?')}-"
            f"{sweep.get('to_currency','?')}"
        )
        sweep["audit_note"] = "treasury_ops_policy: sweep audited by Declaw sandbox"
        return json.dumps(sweep, indent=2)

    analyzer = Agent(
        role="Cash Position Analyzer",
        goal="Load account balances and live FX rate. Summarise INR and USD positions.",
        backstory="Treasury analyst. Use get_cash_positions and get_fx_rate. "
                  "Work with redacted position summaries — do not attempt to "
                  "reconstruct any redacted PII fields.",
        tools=[get_cash_positions, get_fx_rate],
        allow_delegation=False, llm=llm,
    )
    fx_strategist = Agent(
        role="FX Strategist",
        goal="Determine optimal INR/USD split from live FX rate and cash position. "
             "Recommend buy or sell USD direction and target amount.",
        backstory="FX trader. Use the FBIL rate and closing balances to decide "
                  "whether to move funds from INR to USD or vice versa.",
        allow_delegation=False, llm=llm,
    )
    sweep_planner = Agent(
        role="Sweep Planner",
        goal="Call propose_sweep to generate an audited INR <-> USD rebalancing plan.",
        backstory="Treasury operations. Always call propose_sweep with from_currency, "
                  "to_currency, amount, and rationale. The call is audited.",
        tools=[propose_sweep],
        allow_delegation=False, llm=llm,
    )
    human_review = Agent(
        role="Human Review Node",
        goal="Present the sweep plan for human operator sign-off. "
             "Output AWAITING_OPERATOR_SIGN_OFF prominently.",
        backstory="Treasury manager. This is a mandatory review gate. No transfer "
                  "executes without explicit operator approval beyond this node.",
        allow_delegation=False, llm=llm,
    )

    analyze_task = Task(
        description=(
            f"Load cash position for customer_id='{customer_id}'. "
            "Call get_cash_positions and get_fx_rate('USDINR'). "
            "Summarise INR and USD balances and live rate."
        ),
        expected_output="Cash position summary with INR/USD balances and live FX rate.",
        agent=analyzer,
    )
    fx_task = Task(
        description=(
            f"Based on the cash position for customer_id='{customer_id}', "
            "recommend optimal INR/USD allocation using the live FBIL rate. "
            "Specify direction and approximate rebalancing amount."
        ),
        expected_output="FX strategy: direction (buy/sell USD), target amount, rationale.",
        agent=fx_strategist,
        context=[analyze_task],
    )
    sweep_task = Task(
        description=(
            f"Create an audited sweep for customer_id='{customer_id}' by calling "
            "propose_sweep with from_currency, to_currency, amount, and rationale "
            "from the FX strategy."
        ),
        expected_output="Sweep receipt JSON from propose_sweep (status=PENDING_HUMAN_APPROVAL).",
        agent=sweep_planner,
        context=[analyze_task, fx_task],
    )
    review_task = Task(
        description=(
            f"Present the complete sweep plan for customer_id='{customer_id}' "
            "for human operator review. State AWAITING_OPERATOR_SIGN_OFF. "
            "List transfer details, FX rate, and any risk flags."
        ),
        expected_output=(
            "Human review report: sweep details, AWAITING_OPERATOR_SIGN_OFF, "
            "risk flags if any."
        ),
        agent=human_review,
        context=[analyze_task, fx_task, sweep_task],
    )

    crew = Crew(
        agents=[analyzer, fx_strategist, sweep_planner, human_review],
        tasks=[analyze_task, fx_task, sweep_task, review_task],
        process=Process.sequential, verbose=False,
    )
    result = crew.kickoff()
    with open("/tmp/out.json", "w") as f:
        json.dump({"sweep_review": str(result)}, f)
""")


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--customer", default="c-002",
                        choices=["c-002", "c-005"],
                        help="Customer ID (c-002=INR SMB, c-005=US+INR NRI)")
    args = parser.parse_args()
    customer_id = args.customer

    print("=" * 60)
    print("Treasury Cash Management Crew")
    print("(sandboxed — Crew inside microVM)")
    print("=" * 60)
    print(f"\nCustomer: {customer_id} — {CUSTOMERS[customer_id].name}")
    print("Fetching live FBIL USDINR reference rate (host-side, pre-sandbox)...")
    fx_rate = fbil_reference_rate("USDINR")
    rate_display = fx_rate.get("rate") or "unavailable (FBIL unreachable)"
    print(f"  FBIL USDINR rate: {rate_display}")
    print("treasury_ops_policy: PII redacted, sweep tool calls audited")
    print("Network allowlist: LLM + www.fbil.org.in + www.federalreserve.gov")
    print()

    statement = STATEMENTS.get(customer_id, {})
    payload = {
        "customer_id": customer_id,
        "statement": {
            k: v for k, v in statement.items() if k != "narration"
        },
        "neft_transactions": neft_transactions(customer_id),
        "ach_transactions": ach_transactions(customer_id),
        "fx_rate": fx_rate,
    }

    treasury_domains = LLM_DOMAINS + [
        "www.fbil.org.in",
        "www.federalreserve.gov",
    ]
    pol = treasury_ops_policy(allow_domains=treasury_domains)

    out = run_python_in_sandbox(
        "treasury-crew",
        CREWAI_SCRIPT,
        pol,
        payload=payload,
        pip_packages=None,
        envs=llm_envs(),
        timeout=300,
        template="ai-agent",
    )

    print("\n--- Treasury Sweep Plan (awaiting human sign-off) ---")
    print(out.get("sweep_review", out))


if __name__ == "__main__":
    main()
