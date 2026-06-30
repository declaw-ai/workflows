"""W3 sandboxed — Proactive Alerting inside one declaw microVM.

Proactive agents are a higher-risk deployment pattern (long-lived,
credential-holding); microVM isolation + audit log earn their keep here.
"""
from __future__ import annotations

import sys
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "sandboxed"))
from shared.mock_warehouse import APPOINTMENTS  # noqa: E402
from shared.declaw_helpers import (  # noqa: E402
    llm_envs, run_python_in_sandbox, wisdomai_analytics_policy,
)


ALERT_SCRIPT = textwrap.dedent("""
    import asyncio, json
    from autogen_agentchat.agents import AssistantAgent
    from autogen_agentchat.conditions import (MaxMessageTermination,
                                              TextMentionTermination)
    from autogen_agentchat.teams import RoundRobinGroupChat
    from autogen_ext.models.openai import OpenAIChatCompletionClient

    with open('/tmp/in.json') as f: inp = json.load(f)
    APPTS = inp['appointments']

    def _no_show_by_day(start, end):
        bday = {}
        for a in APPTS:
            if not (start <= a['scheduled_date'] <= end): continue
            b = bday.setdefault(a['scheduled_date'], {'scheduled':0,'no_show':0})
            b['scheduled'] += 1; b['no_show'] += int(a['no_show'])
        return [{'date':k, **v, 'no_show_rate': round(v['no_show']/max(v['scheduled'],1),3)}
                for k,v in sorted(bday.items())]

    def _no_show_by_clinic(start, end):
        bclinic = {}
        for a in APPTS:
            if not (start <= a['scheduled_date'] <= end): continue
            c = bclinic.setdefault(a['clinic_id'], {'scheduled':0,'no_show':0})
            c['scheduled'] += 1; c['no_show'] += int(a['no_show'])
        return [{'clinic_id':k, **v, 'no_show_rate': round(v['no_show']/max(v['scheduled'],1),3)}
                for k,v in sorted(bclinic.items())]

    def compute_metric(name: str, start: str, end: str) -> dict:
        \"\"\"Named KPI over a date range. Supported: no_show_rate.\"\"\"
        if name != 'no_show_rate': return {'error': f'unknown metric {name}'}
        rows = _no_show_by_day(start, end)
        avg = sum(r['no_show_rate'] for r in rows)/max(len(rows),1)
        peak = max(rows, key=lambda r: r['no_show_rate'])
        return {'metric': name, 'window': [start, end],
                'avg_rate': round(avg,3),
                'peak_day': peak['date'], 'peak_rate': peak['no_show_rate']}

    def breakdown(dim: str, start: str, end: str) -> list:
        \"\"\"Break no_show_rate by dim (only clinic_id).\"\"\"
        if dim != 'clinic_id': return [{'error': f'unknown dim {dim}'}]
        return _no_show_by_clinic(start, end)

    async def main():
        model = OpenAIChatCompletionClient(model='gpt-4.1')
        monitor = AssistantAgent(
            name='monitor', model_client=model,
            tools=[compute_metric], reflect_on_tool_use=True,
            system_message=(
                'You monitor the no_show_rate metric. Call '
                \"compute_metric('no_show_rate','2026-02-09','2026-02-17'). \"
                'Report peak_day + peak_rate in one line. Hand off to driller.'
            ),
        )
        driller = AssistantAgent(
            name='driller', model_client=model,
            tools=[breakdown], reflect_on_tool_use=True,
            system_message=(
                \"You drill the metric by dimension. Call breakdown('clinic_id','2026-02-09','2026-02-17'). \"
                'Report the worst clinic. Hand off to writer.'
            ),
        )
        writer = AssistantAgent(
            name='writer', model_client=model,
            system_message=(
                'You write a 5-sentence exec brief: headline metric change, '
                'worst-hit segment, likely why, immediate action, who owns. '
                'End with the literal token BRIEF_READY.'
            ),
        )
        team = RoundRobinGroupChat(
            [monitor, driller, writer],
            termination_condition=TextMentionTermination('BRIEF_READY')
                                  | MaxMessageTermination(12),
        )
        result = await team.run(task='Check no-show rate 2026-02-09..2026-02-17 and draft exec brief.')
        brief = ''
        for m in result.messages:
            if getattr(m, 'source', None) == 'writer':
                c = getattr(m, 'content', '')
                if isinstance(c, str) and 'BRIEF_READY' in c:
                    brief = c
        transcript = [f\"[{getattr(m,'source','?')}] {str(getattr(m,'content',''))[:500]}\" for m in result.messages]
        with open('/tmp/out.json','w') as f:
            json.dump({'brief': brief, 'transcript': transcript}, f)

    asyncio.run(main())
""")


def main() -> None:
    print("=== W3 Proactive Alerting (sandboxed, 1 microVM) ===\n")
    out = run_python_in_sandbox(
        "proactive-alert", ALERT_SCRIPT,
        wisdomai_analytics_policy(),
        payload={"appointments": APPOINTMENTS},
        envs=llm_envs(),
        timeout=360,
    )
    print("--- Transcript ---")
    for line in out.get("transcript", []):
        print(line)
    print("\n--- Exec brief ---")
    print(out.get("brief") or "(no writer message captured)")


if __name__ == "__main__":
    main()
