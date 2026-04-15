"""W2 — Telemetry + Manuals Fusion (real LlamaIndex, mimics WisdomAI pattern C).

Scenario: biomed engineer asks about pump-14 — the agent fuses:
  * structured time-series telemetry (vibration, temp)
  * unstructured service-manual sections (PDF/text repo)
  * work-order history (CMMS)

and produces a diagnosis + recommended action with citations.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

from llama_index.core.agent.workflow import FunctionAgent
from llama_index.core.tools import FunctionTool
from llama_index.llms.openai import OpenAI as LlamaOpenAI

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
from shared.mock_manuals import fetch_workorder_history, search_manuals  # noqa: E402
from shared.mock_timeseries import query_timeseries, timeseries_summary  # noqa: E402


def telemetry_summary(pump_id: str) -> dict[str, Any]:
    """Vibration + temp descriptive stats for a pump, with overnight spike flag."""
    return timeseries_summary(pump_id)


def telemetry_window(pump_id: str, start_ts: str, end_ts: str) -> list[dict[str, Any]]:
    """Raw readings for a pump between ISO timestamps (first 40 returned)."""
    return query_timeseries(pump_id, start_ts, end_ts)[:40]


def manuals_search(keywords: str) -> list[dict[str, str]]:
    """Search the service-manual corpus for sections matching keywords."""
    return search_manuals(keywords)


def workorder_history(pump_id: str) -> list[dict[str, str]]:
    """CMMS work-order history for a pump."""
    return fetch_workorder_history(pump_id)


async def run_agent(pump_id: str) -> str:
    agent = FunctionAgent(
        tools=[
            FunctionTool.from_defaults(fn=telemetry_summary),
            FunctionTool.from_defaults(fn=telemetry_window),
            FunctionTool.from_defaults(fn=manuals_search),
            FunctionTool.from_defaults(fn=workorder_history),
        ],
        llm=LlamaOpenAI(model="gpt-4.1"),
        system_prompt=(
            "You are a biomed engineering analyst. Workflow:\n"
            "  1. telemetry_summary(pump_id) to see vibration/temp stats.\n"
            "  2. If overnight_spike_detected, call manuals_search with "
            "     relevant keywords (e.g. 'overnight vibration spike').\n"
            "  3. Call workorder_history(pump_id) to see prior fixes.\n"
            "  4. Emit a plain-text brief with: (a) your diagnosis in one "
            "     sentence, (b) recommended work-order code + expected "
            "     downtime, (c) manual section cited."
        ),
    )
    resp = await agent.run(
        user_msg=f"Diagnose {pump_id}. What should the biomed team do tonight?"
    )
    return str(resp)


def main() -> None:
    print("=== W2 Telemetry + Manuals Fusion (baseline, LlamaIndex) ===\n")
    out = asyncio.run(run_agent("pump-14"))
    print("\n--- Diagnosis brief ---")
    print(out)


if __name__ == "__main__":
    main()
