"""W3 — Proactive Metric Alerting (real AutoGen, mimics WisdomAI pattern D).

Three specialist agents collaborate to detect an anomaly, drill into
dimensions, and draft an executive brief:

  * monitor  — computes the headline metric and its baseline.
  * driller  — breaks the metric down by dimension.
  * writer   — drafts a 5-sentence exec brief ending in BRIEF_READY.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.conditions import (MaxMessageTermination,
                                          TextMentionTermination)
from autogen_agentchat.teams import RoundRobinGroupChat
from autogen_ext.models.openai import OpenAIChatCompletionClient

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
from shared.mock_warehouse import (  # noqa: E402
    sql_no_show_rate_by_clinic, sql_no_show_rate_by_day,
)


def compute_metric(name: str, start: str, end: str) -> dict[str, Any]:
    """Compute a named KPI over a date range. Supported: no_show_rate."""
    if name != "no_show_rate":
        return {"error": f"unknown metric {name!r}"}
    rows = sql_no_show_rate_by_day(start, end)
    avg = sum(r["no_show_rate"] for r in rows) / max(len(rows), 1)
    peak = max(rows, key=lambda r: r["no_show_rate"])
    return {"metric": name, "window": [start, end], "avg_rate": round(avg, 3),
            "peak_day": peak["date"], "peak_rate": peak["no_show_rate"]}


def breakdown(dim: str, start: str, end: str) -> list[dict[str, Any]]:
    """Break a no_show_rate metric down by a dimension (only `clinic_id` supported)."""
    if dim != "clinic_id":
        return [{"error": f"unknown dim {dim!r}"}]
    return sql_no_show_rate_by_clinic(start, end)


async def run_team() -> list[str]:
    model = OpenAIChatCompletionClient(model="gpt-4.1")
    monitor = AssistantAgent(
        name="monitor", model_client=model,
        tools=[compute_metric], reflect_on_tool_use=True,
        system_message=(
            "You monitor the `no_show_rate` metric. Call compute_metric("
            "'no_show_rate', start, end) for the window 2026-02-09 .. "
            "2026-02-17. Report peak_day + peak_rate in one line. Hand off "
            "to driller."
        ),
    )
    driller = AssistantAgent(
        name="driller", model_client=model,
        tools=[breakdown], reflect_on_tool_use=True,
        system_message=(
            "You break down the metric by dimension. Call breakdown('clinic_id', "
            "start, end) for the same window the monitor used. Report the "
            "worst clinic and its rate. Hand off to writer."
        ),
    )
    writer = AssistantAgent(
        name="writer", model_client=model,
        system_message=(
            "You write a 5-sentence exec brief covering: headline metric "
            "change, worst-hit segment, likely why, immediate action, who "
            "owns it. End your message with the token BRIEF_READY."
        ),
    )
    team = RoundRobinGroupChat(
        [monitor, driller, writer],
        termination_condition=TextMentionTermination("BRIEF_READY")
                              | MaxMessageTermination(12),
    )
    result = await team.run(
        task="Check the no-show-rate metric for 2026-02-09..2026-02-17 and "
             "draft an exec brief if it's worth escalating."
    )
    return [
        f"[{getattr(m, 'source', '?')}] {str(getattr(m, 'content', ''))[:500]}"
        for m in result.messages
    ]


def main() -> None:
    print("=== W3 Proactive Alerting (baseline, AutoGen 3-agent chat) ===\n")
    for line in asyncio.run(run_team()):
        print(line)


if __name__ == "__main__":
    main()
