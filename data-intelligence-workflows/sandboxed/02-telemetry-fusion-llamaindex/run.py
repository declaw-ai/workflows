"""W2 sandboxed — Telemetry + Manuals Fusion inside one declaw microVM.

Untrusted content (service manuals) can embed indirect prompt-injection,
so this policy turns `InjectionDefenseConfig(action='log_only')` on —
audit detections without blocking the workflow.
"""
from __future__ import annotations

import sys
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "sandboxed"))
from shared.mock_manuals import MANUALS, fetch_workorder_history  # noqa: E402
from shared.mock_timeseries import READINGS  # noqa: E402
from shared.declaw_helpers import (  # noqa: E402
    llm_envs, run_python_in_sandbox, wisdomai_analytics_policy,
)


FUSION_SCRIPT = textwrap.dedent("""
    import asyncio, json
    from llama_index.core.agent.workflow import FunctionAgent
    from llama_index.core.tools import FunctionTool
    from llama_index.llms.openai import OpenAI as LlamaOpenAI

    with open('/tmp/in.json') as f: inp = json.load(f)
    READINGS = inp['readings']
    MANUALS = inp['manuals']
    WORKORDERS = inp['workorders']
    PUMP_ID = inp['pump_id']

    def telemetry_summary(pump_id: str) -> dict:
        \"\"\"Vibration + temp stats and overnight-spike flag for a pump.\"\"\"
        rows = READINGS.get(pump_id, [])
        if not rows: return {'pump_id': pump_id, 'error': 'unknown pump'}
        vib = [r['vibration_mm_s'] for r in rows]
        temp = [r['temp_c'] for r in rows]
        overnight = [r for r in rows if r['ts'][11:13] in ('02','03','04')]
        ov = sum(r['vibration_mm_s'] for r in overnight)/len(overnight)
        day = [r for r in rows if r['ts'][11:13] not in ('02','03','04')]
        dy = sum(r['vibration_mm_s'] for r in day)/len(day)
        return {'pump_id': pump_id, 'n': len(rows),
                'vibration_avg': round(sum(vib)/len(vib),2),
                'temp_avg': round(sum(temp)/len(temp),2),
                'overnight_vibration_avg': round(ov,2),
                'daytime_vibration_avg': round(dy,2),
                'overnight_spike_detected': ov > dy*1.5}

    def manuals_search(keywords: str) -> list:
        \"\"\"Search service-manual corpus for sections matching keywords.\"\"\"
        toks = [t.lower() for t in keywords.split() if len(t)>=4]
        hits = []
        for mid, m in MANUALS.items():
            text = m['sections'].lower()
            if any(t in text for t in toks):
                hits.append({'manual_id': mid, 'title': m['title'],
                             'excerpt': m['sections'][:900]})
        return hits

    def workorder_history(pump_id: str) -> list:
        \"\"\"CMMS work-order history for a pump.\"\"\"
        return WORKORDERS.get(pump_id, [])

    async def main():
        agent = FunctionAgent(
            tools=[
                FunctionTool.from_defaults(fn=telemetry_summary),
                FunctionTool.from_defaults(fn=manuals_search),
                FunctionTool.from_defaults(fn=workorder_history),
            ],
            llm=LlamaOpenAI(model='gpt-4.1'),
            system_prompt=(
                'You are a biomed engineering analyst. Step 1: call '
                f'telemetry_summary(\"{PUMP_ID}\"). Step 2: if '
                'overnight_spike_detected, call manuals_search. Step 3: '
                f'call workorder_history(\"{PUMP_ID}\"). Step 4: emit a '
                'plain-text brief with diagnosis (one sentence), '
                'recommended work-order code, and manual section cited.'
            ),
        )
        resp = await agent.run(user_msg=f'Diagnose {PUMP_ID}.')
        with open('/tmp/out.json','w') as f: json.dump({'brief': str(resp)}, f)

    asyncio.run(main())
""")


def main() -> None:
    pump_id = "pump-14"
    print("=== W2 Telemetry Fusion (sandboxed, 1 microVM, injection scan ON) ===\n")
    out = run_python_in_sandbox(
        "telemetry-fusion", FUSION_SCRIPT,
        wisdomai_analytics_policy(enable_injection_scan=True),
        payload={
            "pump_id": pump_id,
            "readings": READINGS,
            "manuals": MANUALS,
            "workorders": {"pump-14": fetch_workorder_history("pump-14")},
        },
        envs=llm_envs(),
        timeout=300,
    )
    print("\n--- Diagnosis brief ---")
    print(out.get("brief", ""))


if __name__ == "__main__":
    main()
