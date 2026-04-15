"""Treasury Cash Management — baseline, UNSANDBOXED.

Four-agent CrewAI sequential pipeline:
  Cash-Position-Analyzer -> FX-Strategist -> Sweep-Planner -> Human-Review

Brex/Ramp-style treasury demo:
  * Cash-Position-Analyzer fetches live FBIL FX rates (fbil_reference_rate)
    then sends the full account balances + projected inflows (proprietary!)
    directly to OpenAI with no PII redaction.
  * Sweep-Planner proposes INR <-> USD rebalancing transfers based on live FX.
  * Human-Review prints the sweep plan for operator sign-off (demo node).

Input: customer c-002 (INR SMB, Leaf & Loom) or c-005 (US+INR NRI, James Whitaker)

(UNSANDBOXED — PII through Crew)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from crewai import Agent, Crew, LLM, Process, Task
from crewai.tools import tool

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
from shared.mock_customers import CUSTOMERS  # noqa: E402
from shared.mock_statements import STATEMENTS  # noqa: E402
from shared.mock_transactions import neft_transactions, ach_transactions  # noqa: E402
from shared.external_apis import fbil_reference_rate  # noqa: E402


def _build_crew(customer_id: str, fx_rate: dict) -> Crew:
    customer = CUSTOMERS[customer_id]
    statement = STATEMENTS.get(customer_id, {})
    llm = LLM(model="gpt-4.1")

    @tool("Get current cash positions")
    def get_cash_positions(cid: str) -> str:
        """Return JSON with current account balances and recent transactions."""
        stmt = STATEMENTS.get(cid, {})
        neft = neft_transactions(cid)
        ach = ach_transactions(cid)
        return json.dumps({
            "customer_id": cid,
            "customer_name": customer.name,
            "pan": customer.pan,
            "account_number": customer.account_number,
            "bank": stmt.get("bank"),
            "period": stmt.get("period"),
            "opening_balance_inr": stmt.get("opening_balance_inr"),
            "closing_balance_inr": stmt.get("closing_balance_inr"),
            "opening_balance_usd": stmt.get("opening_balance_usd"),
            "closing_balance_usd": stmt.get("closing_balance_usd"),
            "neft_transactions": neft,
            "ach_transactions": ach,
        })

    @tool("Get FBIL reference FX rate")
    def get_fx_rate(pair: str) -> str:
        """Return the FBIL reference rate for the given pair (e.g. USDINR)."""
        return json.dumps(fx_rate)

    @tool("Propose a sweep transfer")
    def propose_sweep(sweep_json: str) -> str:
        """Given JSON {from_currency, to_currency, amount, rationale},
        record the proposed sweep and return a confirmation receipt."""
        try:
            sweep = json.loads(sweep_json)
        except Exception:
            return json.dumps({"error": "invalid sweep JSON"})
        sweep["status"] = "PENDING_HUMAN_APPROVAL"
        sweep["ref"] = f"SWP-{customer_id}-{sweep.get('from_currency','?')}-"  \
                       f"{sweep.get('to_currency','?')}"
        return json.dumps(sweep, indent=2)

    analyzer = Agent(
        role="Cash Position Analyzer",
        goal="Load full account balances, recent transactions, and live FX rate. "
             "Summarise the current INR and USD cash positions.",
        backstory="Treasury analyst. Use get_cash_positions and get_fx_rate. "
                  "Include all account details in your analysis.",
        tools=[get_cash_positions, get_fx_rate],
        allow_delegation=False,
        llm=llm,
    )
    fx_strategist = Agent(
        role="FX Strategist",
        goal="Determine the optimal INR/USD split based on the live FX rate and "
             "projected inflows. Recommend whether to buy or sell USD.",
        backstory="FX trader. Analyse the rate trend and current position. "
                  "Propose a target currency allocation.",
        allow_delegation=False,
        llm=llm,
    )
    sweep_planner = Agent(
        role="Sweep Planner",
        goal="Call propose_sweep to generate a concrete INR <-> USD rebalancing "
             "transfer plan. Include amount, direction, and rationale.",
        backstory="Treasury operations. Always call propose_sweep to create the "
                  "transfer record. Include proprietary account details in the sweep.",
        tools=[propose_sweep],
        allow_delegation=False,
        llm=llm,
    )
    human_review = Agent(
        role="Human Review Node",
        goal="Present the proposed sweep plan for human operator sign-off. "
             "List all sweep details and flag any risk concerns.",
        backstory="Treasury manager. You present the sweep plan clearly for approval. "
                  "This is a mandatory review step before any transfer executes.",
        allow_delegation=False,
        llm=llm,
    )

    analyze_task = Task(
        description=(
            f"Load cash position for customer_id='{customer_id}'. "
            f"Customer: {customer.name}  PAN: {customer.pan}  "
            f"Account: {customer.account_number}\n\n"
            "Call get_cash_positions and get_fx_rate('USDINR'). "
            "Summarise INR and USD balances and live FX rate."
        ),
        expected_output="Cash position summary with INR/USD balances and FX rate.",
        agent=analyzer,
    )
    fx_task = Task(
        description=(
            f"Based on the cash position for customer_id='{customer_id}', "
            "recommend the optimal INR/USD allocation. "
            "Consider the live FBIL rate, projected inflows, and business needs."
        ),
        expected_output="FX strategy recommendation with target allocation rationale.",
        agent=fx_strategist,
        context=[analyze_task],
    )
    sweep_task = Task(
        description=(
            f"Create a concrete sweep transfer plan for customer_id='{customer_id}' "
            "using propose_sweep. Include the from/to currency, amount (INR or USD), "
            "and the business rationale from the FX strategy."
        ),
        expected_output="Sweep transfer JSON from propose_sweep tool.",
        agent=sweep_planner,
        context=[analyze_task, fx_task],
    )
    review_task = Task(
        description=(
            f"Present the complete sweep plan for customer_id='{customer_id}' "
            "for human operator review. List all transfer details, FX rate used, "
            "account numbers, and any risk concerns."
        ),
        expected_output=(
            "Human review summary: sweep details, risk flags, "
            "APPROVED_FOR_EXECUTION or HELD_FOR_FURTHER_REVIEW."
        ),
        agent=human_review,
        context=[analyze_task, fx_task, sweep_task],
    )

    return Crew(
        agents=[analyzer, fx_strategist, sweep_planner, human_review],
        tasks=[analyze_task, fx_task, sweep_task, review_task],
        process=Process.sequential,
        verbose=False,
    )


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
    print("(UNSANDBOXED — PII through Crew)")
    print("=" * 60)
    print(f"\nCustomer: {customer_id} — {CUSTOMERS[customer_id].name}")
    print("Fetching live FBIL USDINR reference rate...")
    fx_rate = fbil_reference_rate("USDINR")
    rate_display = fx_rate.get("rate") or "unavailable (FBIL unreachable)"
    print(f"  FBIL USDINR rate: {rate_display}")
    print("[!] Full account balances + PAN + account numbers sent to OpenAI")
    print()

    crew = _build_crew(customer_id, fx_rate)
    result = crew.kickoff()

    print("\n--- Treasury Sweep Plan (awaiting human sign-off) ---")
    print(result)


if __name__ == "__main__":
    main()
