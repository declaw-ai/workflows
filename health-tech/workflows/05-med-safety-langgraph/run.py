"""W5 — Medication Safety Copilot (real LangGraph, real external APIs).

Given a patient's current meds + a candidate new drug, produce a structured
safety advisory JSON. The agent orchestrates a 4-tool chain against real
public APIs:

  1. fetch_patient_meds           (local FHIR mock)
  2. rxnorm_normalize             → NLM RxNav (real HTTP)
  3. drug_interactions_from_fda   → openFDA label (real HTTP)
  4. openfda_adverse_events       → openFDA event counts (real HTTP)
  5. synthesize_advisory          → gpt-4.1 (real LLM)

Baseline version: every API call leaves the host in cleartext. The
patient's chart is in the synthesize step's prompt — PHI crosses
api.openai.com unredacted. See sandboxed/05-med-safety-langgraph for
the declaw-hardened variant.
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
from shared.external_apis import (  # noqa: E402
    drug_interactions_from_fda, openfda_adverse_events, rxnorm_normalize,
)
from shared.llm import chat_json  # noqa: E402
from shared.mock_phi import PATIENTS  # noqa: E402


class MedSafetyState(TypedDict, total=False):
    patient_id: str
    candidate_drug: str
    current_meds: list[str]
    rxcuis: list[str]
    interactions: list[dict]
    adverse_events: dict
    advisory: dict
    trace: Annotated[list[dict], "tool-call trace"]


def fetch_meds(state: MedSafetyState) -> MedSafetyState:
    p = PATIENTS[state["patient_id"]]
    # strip dosing; keep just the active ingredient word
    meds = [m.split()[0] for m in p.medications]
    return {"current_meds": meds, "trace": [{"tool": "fetch_meds", "result_count": len(meds)}]}


def normalize_drugs(state: MedSafetyState) -> MedSafetyState:
    rxcuis = []
    trace = []
    for d in state["current_meds"] + [state["candidate_drug"]]:
        r = rxnorm_normalize(d)
        rxcuis.append(r.get("rxcui"))
        trace.append({"tool": "rxnorm_normalize", "input": d, "rxcui": r.get("rxcui")})
    return {"rxcuis": [x for x in rxcuis if x], "trace": trace}


def check_interactions(state: MedSafetyState) -> MedSafetyState:
    drugs = state["current_meds"] + [state["candidate_drug"]]
    inter = drug_interactions_from_fda(drugs)
    return {"interactions": inter,
            "trace": [{"tool": "drug_interactions_from_fda",
                       "drugs": drugs, "records": len(inter)}]}


def check_adverse(state: MedSafetyState) -> MedSafetyState:
    ae = openfda_adverse_events(state["candidate_drug"], limit=5)
    return {"adverse_events": ae,
            "trace": [{"tool": "openfda_adverse_events",
                       "drug": state["candidate_drug"],
                       "reactions": len(ae.get("top_reactions", []))}]}


def synthesize(state: MedSafetyState) -> MedSafetyState:
    p = PATIENTS[state["patient_id"]]
    system = (
        "You are a clinical pharmacist. Given a patient record, a proposed "
        "new drug, FDA-label interaction text for each drug, and reported "
        "adverse-event counts, produce a JSON safety advisory with keys: "
        '{"risk_level": "low|moderate|high", "interaction_summary": "...", '
        '"top_adverse_events": [...], "recommendation": "..."}. Be terse.'
    )
    user = json.dumps({
        "patient": {"id": p.id, "name": p.name,
                    "diagnoses": p.diagnoses,
                    "current_meds": p.medications},
        "proposed_drug": state["candidate_drug"],
        "fda_label_interactions": state["interactions"],
        "openfda_adverse_events": state["adverse_events"],
    })
    advisory = chat_json(system, user, max_tokens=600)
    return {"advisory": advisory,
            "trace": [{"tool": "gpt-4.1.synthesize"}]}


def build_graph():
    g = StateGraph(MedSafetyState)
    g.add_node("fetch_meds", fetch_meds)
    g.add_node("normalize_drugs", normalize_drugs)
    g.add_node("check_interactions", check_interactions)
    g.add_node("check_adverse", check_adverse)
    g.add_node("synthesize", synthesize)
    g.add_edge(START, "fetch_meds")
    g.add_edge("fetch_meds", "normalize_drugs")
    g.add_edge("normalize_drugs", "check_interactions")
    g.add_edge("check_interactions", "check_adverse")
    g.add_edge("check_adverse", "synthesize")
    g.add_edge("synthesize", END)
    return g.compile(checkpointer=MemorySaver())


def main() -> None:
    initial = {"patient_id": "p-001", "candidate_drug": "semaglutide"}
    print(f"=== Med Safety Copilot (baseline, multi-API, real gpt-4.1) ===")
    print(f"patient={initial['patient_id']}  proposed={initial['candidate_drug']}\n")
    config = {"configurable": {"thread_id": "med-safety-1"}}
    result = build_graph().invoke(initial, config=config)
    print("--- Tool trace ---")
    for t in result.get("trace", []):
        print(" ", t)
    print("\n--- Safety advisory (gpt-4.1) ---")
    print(json.dumps(result.get("advisory", {}), indent=2))


if __name__ == "__main__":
    main()
