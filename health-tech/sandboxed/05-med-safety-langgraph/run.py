"""W5 — Medication Safety Copilot, sandboxed with declaw.

Governance posture (see shared/governance.py): this is a drug-interaction copilot
producing an ADVISORY (decision-support) only. The safety advisory is framed as a
RECOMMEND_REVIEW for a licensed clinician (REVIEWER_CLINICIAN), who owns the
prescribing decision. Advisory only — no hard gate.

Same LangGraph orchestration as the baseline, but every node that touches
the network runs inside a microVM with egress locked to the allowlist
{api.openai.com, rxnav.nlm.nih.gov, api.fda.gov}. PHI in the LLM-call step
crosses the declaw proxy → Guardrails NER + regex scanners tokenize names,
SSN, email, phone, address before the request body leaves the VM.

What declaw specifically buys on this workflow:
  * A jailbroken LLM that tries to POST the chart to a non-allowlisted
    host is iptables-DROPped (network policy).
  * The three non-LLM tool calls (RxNav, openFDA x2) only contain drug
    names — no PHI — and declaw's audit log proves it per-destination.
  * Per-step microVM isolation — if a compromised library tries to read
    the patient chart that an earlier step cached in /tmp, it gets
    FileNotFoundError (different sandbox).
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
from shared.mock_phi import PATIENTS  # noqa: E402
from shared import governance as gov  # noqa: E402
from shared.declaw_helpers import (  # noqa: E402
    HEALTHCARE_API_DOMAINS, LLM_DOMAINS, healthcare_multi_api_policy,
    llm_envs, run_python_in_sandbox,
)


class MedSafetyState(TypedDict, total=False):
    patient_id: str
    candidate_drug: str
    current_meds: list[str]
    interactions: list[dict]
    adverse_events: dict
    advisory: dict
    trace: Annotated[list[dict], "tool-call trace"]


# ---------- Sandboxed external-API calls (one sandbox per network hop) ----

RXNAV_INTERACTIONS_SCRIPT = textwrap.dedent("""
    import json, urllib.parse, urllib.request
    with open('/tmp/in.json') as f: inp = json.load(f)
    drugs = inp['drugs']
    out = []
    for name in drugs:
        results = []
        for field in ('generic_name', 'brand_name'):
            q = urllib.parse.quote(f'openfda.{field}:"{name}"')
            url = f'https://api.fda.gov/drug/label.json?search={q}&limit=1'
            try:
                req = urllib.request.Request(url, headers={'Accept':'application/json'})
                with urllib.request.urlopen(req, timeout=15) as r:
                    d = json.loads(r.read().decode())
                results = d.get('results') or []
                if results: break
            except Exception: pass
        if not results:
            out.append({'drug': name, 'interactions_text': None}); continue
        text = ' '.join(results[0].get('drug_interactions', []))[:800] or None
        out.append({'drug': name, 'interactions_text': text})
    with open('/tmp/out.json','w') as f: json.dump({'interactions': out}, f)
""")


OPENFDA_AE_SCRIPT = textwrap.dedent("""
    import json, urllib.parse, urllib.request
    with open('/tmp/in.json') as f: inp = json.load(f)
    drug = inp['drug']; limit = int(inp.get('limit', 5))
    search = urllib.parse.quote(f'patient.drug.medicinalproduct:"{drug}"')
    url = (f'https://api.fda.gov/drug/event.json?search={search}'
           f'&count=patient.reaction.reactionmeddrapt.exact&limit={limit}')
    try:
        req = urllib.request.Request(url, headers={'Accept':'application/json'})
        with urllib.request.urlopen(req, timeout=15) as r:
            d = json.loads(r.read().decode())
        ae = {'drug': drug, 'top_reactions': [
            {'reaction': x.get('term'), 'count': x.get('count')}
            for x in (d.get('results') or [])[:limit]]}
    except Exception:
        ae = {'drug': drug, 'top_reactions': []}
    with open('/tmp/out.json','w') as f: json.dump(ae, f)
""")


SYNTHESIZE_SCRIPT = textwrap.dedent("""
    import json
    from openai import OpenAI
    with open('/tmp/in.json') as f: inp = json.load(f)
    # Governance labels injected from shared.governance on the host (the sandbox
    # cannot import the shared module). The advisory is DECISION-SUPPORT only; a
    # licensed clinician owns the prescribing decision.
    GOV = inp.get('gov', {})
    c = OpenAI()
    r = c.chat.completions.create(
        model='gpt-4.1',
        messages=[
            {'role':'system','content':
             'You are a clinical pharmacist producing DECISION-SUPPORT only — '
             'NOT a prescribing decision. Given a patient record, a proposed new '
             'drug, FDA-label interaction text for each drug, and reported '
             'adverse-event counts, produce a JSON safety advisory with keys: '
             'risk_level (low|moderate|high), interaction_summary, '
             'top_adverse_events, recommendation. The recommendation is advisory '
             'for a licensed clinician who OWNS the prescribing decision. '
             'Be terse. Respond with a single JSON object.'},
            {'role':'user','content': json.dumps(inp)},
        ],
        response_format={'type': 'json_object'},
        max_completion_tokens=600,
    )
    advisory = json.loads(r.choices[0].message.content)
    # Stamp the advisory as decision-support owned by a licensed clinician.
    advisory['status'] = GOV.get('RECOMMEND_REVIEW', 'RECOMMEND_REVIEW')
    advisory['decision_owner'] = GOV.get('REVIEWER_CLINICIAN', 'licensed clinician')
    with open('/tmp/out.json','w') as f:
        json.dump({'advisory': advisory}, f)
""")


# ---------- Nodes ----------

def fetch_meds(state: MedSafetyState) -> MedSafetyState:
    p = PATIENTS[state["patient_id"]]
    meds = [m.split()[0] for m in p.medications]
    return {"current_meds": meds, "trace": [{"tool": "fetch_meds"}]}


def check_interactions(state: MedSafetyState) -> MedSafetyState:
    drugs = state["current_meds"] + [state["candidate_drug"]]
    print(f"[check_interactions] sandbox — calling api.fda.gov for {len(drugs)} drugs")
    out = run_python_in_sandbox(
        "rx-interactions", RXNAV_INTERACTIONS_SCRIPT,
        healthcare_multi_api_policy(),
        payload={"drugs": drugs},
    )
    return {"interactions": out["interactions"],
            "trace": [{"tool": "rx-interactions sandbox",
                       "drugs": drugs, "records": len(out['interactions'])}]}


def check_adverse(state: MedSafetyState) -> MedSafetyState:
    print(f"[check_adverse] sandbox — calling api.fda.gov/drug/event")
    out = run_python_in_sandbox(
        "openfda-ae", OPENFDA_AE_SCRIPT,
        healthcare_multi_api_policy(),
        payload={"drug": state["candidate_drug"], "limit": 5},
    )
    return {"adverse_events": out,
            "trace": [{"tool": "openfda-ae sandbox",
                       "drug": state["candidate_drug"]}]}


def synthesize(state: MedSafetyState) -> MedSafetyState:
    p = PATIENTS[state["patient_id"]]
    payload = {
        "patient": {
            "id": p.id, "name": p.name,
            "diagnoses": p.diagnoses,
            "current_meds": p.medications,
        },
        "proposed_drug": state["candidate_drug"],
        "fda_label_interactions": state["interactions"],
        "openfda_adverse_events": state["adverse_events"],
        # Governance labels — the advisory is decision-support; a licensed
        # clinician owns the prescribing decision (the sandbox can't import
        # shared.governance).
        "gov": {
            "RECOMMEND_REVIEW": gov.RECOMMEND_REVIEW,
            "REVIEWER_CLINICIAN": gov.REVIEWER_CLINICIAN,
        },
    }
    print("[synthesize] sandbox — gpt-4.1 with PHI redaction + rehydration")
    out = run_python_in_sandbox(
        "advisory-llm", SYNTHESIZE_SCRIPT,
        healthcare_multi_api_policy(),
        payload=payload, envs=llm_envs(),
    )
    return {"advisory": out["advisory"],
            "trace": [{"tool": "advisory-llm sandbox"}]}


def build_graph():
    g = StateGraph(MedSafetyState)
    g.add_node("fetch_meds", fetch_meds)
    g.add_node("check_interactions", check_interactions)
    g.add_node("check_adverse", check_adverse)
    g.add_node("synthesize", synthesize)
    g.add_edge(START, "fetch_meds")
    g.add_edge("fetch_meds", "check_interactions")
    g.add_edge("check_interactions", "check_adverse")
    g.add_edge("check_adverse", "synthesize")
    g.add_edge("synthesize", END)
    return g.compile(checkpointer=MemorySaver())


def main() -> None:
    initial = {"patient_id": "p-001", "candidate_drug": "semaglutide"}
    print("=== Med Safety Copilot (sandboxed, multi-API, 3 microVMs) ===")
    print(f"governance: {gov.governance_banner()}")
    print(f"Advisory is decision-support for a {gov.REVIEWER_CLINICIAN}; the "
          "clinician owns the prescribing decision (advisory, not a gate).")
    print(f"patient={initial['patient_id']}  proposed={initial['candidate_drug']}")
    print(f"allow_out={LLM_DOMAINS + HEALTHCARE_API_DOMAINS}\n")
    config = {"configurable": {"thread_id": "med-safety-sbx-1"}}
    result = build_graph().invoke(initial, config=config)
    print("\n--- Tool trace ---")
    for t in result.get("trace", []):
        print(" ", t)
    print("\n--- Safety advisory (DECISION-SUPPORT — clinician owns prescribing) ---")
    print(json.dumps(result.get("advisory", {}), indent=2))
    print(f"\n[note] This advisory is decision-support only; a {gov.REVIEWER_CLINICIAN} "
          "owns the prescribing decision. Nothing is prescribed autonomously.")


if __name__ == "__main__":
    main()
