"""W1 — Cross-Source KPI Q&A (real LangGraph, mimics WisdomAI pattern A).

Scenario: ops director asks "why did clinic-north no-show rate spike in
mid-February?" A single agent reasons across three data sources:

  1. warehouse (mock DuckDB-style) — no-show rates by clinic / by day
  2. CRM (mock Salesforce) — payer contract / renegotiation context
  3. support tickets (mock Zendesk) — operational incidents that week

Output: a ranked-drivers JSON advisory + a Vega-Lite-shaped chart spec.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated, TypedDict

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
from shared.llm import chat_json  # noqa: E402
from shared.mock_crm import crm_search  # noqa: E402
from shared.mock_tickets import tickets_search  # noqa: E402
from shared.mock_warehouse import (  # noqa: E402
    sql_no_show_rate_by_clinic, sql_no_show_rate_by_day,
)


class KpiState(TypedDict, total=False):
    question: str
    start: str
    end: str
    by_day: list[dict]
    by_clinic: list[dict]
    crm: list[dict]
    tickets: list[dict]
    advisory: dict
    trace: Annotated[list[dict], "tool-call trace"]


def fetch_warehouse(state: KpiState) -> KpiState:
    by_day = sql_no_show_rate_by_day(state["start"], state["end"])
    by_clinic = sql_no_show_rate_by_clinic(state["start"], state["end"])
    return {"by_day": by_day, "by_clinic": by_clinic,
            "trace": [{"source": "warehouse.sql_no_show_rate_by_day",
                       "rows": len(by_day)},
                      {"source": "warehouse.sql_no_show_rate_by_clinic",
                       "rows": len(by_clinic)}]}


def fetch_crm(state: KpiState) -> KpiState:
    rows = crm_search()  # all payer accounts
    return {"crm": rows,
            "trace": [{"source": "crm.search", "rows": len(rows)}]}


def fetch_tickets(state: KpiState) -> KpiState:
    rows = tickets_search(start=state["start"], end=state["end"])
    return {"tickets": rows,
            "trace": [{"source": "tickets.search",
                       "rows": len(rows), "window": [state['start'], state['end']]}]}


def synthesize(state: KpiState) -> KpiState:
    system = (
        "You are an ops data analyst. Given a warehouse no-show breakdown, "
        "payer-CRM context, and support tickets from the target week, "
        "produce a single JSON object with keys: "
        '{"summary": "...", '
        '"ranked_drivers": [{"driver": "...", "evidence": "...", '
        '"weight": "high|medium|low"}, ...], '
        '"chart_spec": {...vega-lite-like bar spec for clinic no-show rates...}, '
        '"recommended_next_steps": ["..."]}'
    )
    user = json.dumps({
        "question": state["question"],
        "by_day": state["by_day"][-14:],     # last 2 weeks of the window
        "by_clinic": state["by_clinic"],
        "crm": state["crm"],
        "tickets": state["tickets"],
    })
    advisory = chat_json(system, user, max_tokens=900)
    return {"advisory": advisory,
            "trace": [{"source": "gpt-4.1.synthesize"}]}


def build_graph():
    g = StateGraph(KpiState)
    g.add_node("fetch_warehouse", fetch_warehouse)
    g.add_node("fetch_crm", fetch_crm)
    g.add_node("fetch_tickets", fetch_tickets)
    g.add_node("synthesize", synthesize)
    g.add_edge(START, "fetch_warehouse")
    g.add_edge("fetch_warehouse", "fetch_crm")
    g.add_edge("fetch_crm", "fetch_tickets")
    g.add_edge("fetch_tickets", "synthesize")
    g.add_edge("synthesize", END)
    return g.compile(checkpointer=MemorySaver())


def main() -> None:
    question = ("Why did no-show rate spike the week of 2026-02-10 to "
                "2026-02-16, and what should we do about it?")
    initial = {"question": question,
               "start": "2026-02-09", "end": "2026-02-17"}
    print("=== W1 Cross-Source KPI Q&A (baseline, multi-source) ===")
    print(f"Q: {question}\n")
    config = {"configurable": {"thread_id": "kpi-qa-1"}}
    result = build_graph().invoke(initial, config=config)
    print("--- Tool trace ---")
    for t in result.get("trace", []):
        print(" ", t)
    print("\n--- Advisory (gpt-4.1) ---")
    print(json.dumps(result.get("advisory", {}), indent=2))


if __name__ == "__main__":
    main()
