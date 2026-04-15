"""W1 sandboxed — same KPI Q&A graph, but the data-fetch and synthesize
nodes run inside Firecracker microVMs under WisdomAI-style allowlist.

Declaw benefits showcased:
  * Per-source audit: "which query hit CRM vs warehouse vs tickets last
    Tuesday?" is answerable because each hop is a separate sandbox.
  * Network allowlist — an agent trying to exfil to an unlisted host is
    iptables-DROPped at the proxy.
  * PII tokenization on the OpenAI synthesis call — CRM notes can contain
    account-manager names that shouldn't leak downstream.
"""
from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path
from typing import Annotated, TypedDict

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "sandboxed"))
from shared.mock_crm import ACCOUNTS  # noqa: E402
from shared.mock_tickets import TICKETS  # noqa: E402
from shared.mock_warehouse import APPOINTMENTS  # noqa: E402
from shared.declaw_helpers import (  # noqa: E402
    llm_envs, run_python_in_sandbox, wisdomai_analytics_policy,
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


# Each "data source" sandbox gets only the rows it needs (defense in
# depth — even if the in-VM code is compromised, it can't see the rest
# of the warehouse).

WAREHOUSE_SCRIPT = textwrap.dedent("""
    import json
    with open('/tmp/in.json') as f: inp = json.load(f)
    start, end = inp['start'], inp['end']
    rows = inp['rows']
    bday, bclinic = {}, {}
    for a in rows:
        if not (start <= a['scheduled_date'] <= end): continue
        d = bday.setdefault(a['scheduled_date'], {'scheduled':0,'no_show':0})
        d['scheduled'] += 1; d['no_show'] += int(a['no_show'])
        c = bclinic.setdefault(a['clinic_id'], {'scheduled':0,'no_show':0})
        c['scheduled'] += 1; c['no_show'] += int(a['no_show'])
    out = {
        'by_day': [{'date':k, **v, 'no_show_rate': round(v['no_show']/max(v['scheduled'],1),3)} for k,v in sorted(bday.items())],
        'by_clinic': [{'clinic_id':k, **v, 'no_show_rate': round(v['no_show']/max(v['scheduled'],1),3)} for k,v in sorted(bclinic.items())],
    }
    with open('/tmp/out.json','w') as f: json.dump(out, f)
""")


CRM_SCRIPT = textwrap.dedent("""
    import json
    with open('/tmp/in.json') as f: inp = json.load(f)
    with open('/tmp/out.json','w') as f: json.dump({'rows': inp['accounts']}, f)
""")


TICKETS_SCRIPT = textwrap.dedent("""
    import json
    with open('/tmp/in.json') as f: inp = json.load(f)
    rows = [t for t in inp['tickets']
            if inp['start'] <= t['date'] <= inp['end']]
    with open('/tmp/out.json','w') as f: json.dump({'rows': rows}, f)
""")


SYNTHESIZE_SCRIPT = textwrap.dedent("""
    import json
    from openai import OpenAI
    with open('/tmp/in.json') as f: inp = json.load(f)
    r = OpenAI().chat.completions.create(
        model='gpt-4.1',
        messages=[
            {'role':'system','content':
             'You are an ops data analyst. Given a warehouse no-show '
             'breakdown, payer-CRM context, and support tickets from the '
             'target week, produce a single JSON object with keys: '
             'summary, ranked_drivers (list of {driver, evidence, weight}), '
             'chart_spec (vega-lite bar spec for clinic no-show rates), '
             'recommended_next_steps (list). Respond with a single JSON object.'},
            {'role':'user','content': json.dumps(inp)},
        ],
        response_format={'type':'json_object'},
        max_completion_tokens=900,
    )
    with open('/tmp/out.json','w') as f:
        json.dump({'advisory': json.loads(r.choices[0].message.content)}, f)
""")


# ---------- Nodes ----------

def fetch_warehouse(state: KpiState) -> KpiState:
    print("[fetch_warehouse] sandbox — warehouse policy")
    out = run_python_in_sandbox(
        "warehouse", WAREHOUSE_SCRIPT,
        wisdomai_analytics_policy(),
        payload={"start": state["start"], "end": state["end"],
                 "rows": APPOINTMENTS},
    )
    return {"by_day": out["by_day"], "by_clinic": out["by_clinic"],
            "trace": [{"sandbox": "warehouse"}]}


def fetch_crm(state: KpiState) -> KpiState:
    print("[fetch_crm] sandbox — crm policy")
    out = run_python_in_sandbox(
        "crm", CRM_SCRIPT,
        wisdomai_analytics_policy(),
        payload={"accounts": list(ACCOUNTS.values())},
    )
    return {"crm": out["rows"], "trace": [{"sandbox": "crm"}]}


def fetch_tickets(state: KpiState) -> KpiState:
    print("[fetch_tickets] sandbox — tickets policy")
    out = run_python_in_sandbox(
        "tickets", TICKETS_SCRIPT,
        wisdomai_analytics_policy(),
        payload={"tickets": TICKETS,
                 "start": state["start"], "end": state["end"]},
    )
    return {"tickets": out["rows"], "trace": [{"sandbox": "tickets"}]}


def synthesize(state: KpiState) -> KpiState:
    print("[synthesize] sandbox — real gpt-4.1, PII redaction on")
    out = run_python_in_sandbox(
        "advisory-llm", SYNTHESIZE_SCRIPT,
        wisdomai_analytics_policy(),
        payload={
            "question": state["question"],
            "by_day": state["by_day"][-14:],
            "by_clinic": state["by_clinic"],
            "crm": state["crm"],
            "tickets": state["tickets"],
        },
        envs=llm_envs(),
    )
    return {"advisory": out["advisory"],
            "trace": [{"sandbox": "advisory-llm"}]}


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
    print("=== W1 KPI Q&A (sandboxed, 4 microVMs) ===")
    print(f"Q: {question}\n")
    result = build_graph().invoke(initial,
        config={"configurable": {"thread_id": "kpi-qa-sbx-1"}})
    print("\n--- Tool trace ---")
    for t in result.get("trace", []):
        print(" ", t)
    print("\n--- Advisory (gpt-4.1 via declaw proxy) ---")
    print(json.dumps(result.get("advisory", {}), indent=2))


if __name__ == "__main__":
    main()
