"""Prior Authorization workflow built with LangGraph (real GPT-4.1).

Flow: gather chart -> check policy -> assemble packet -> submit -> if denied,
draft an appeal letter via gpt-4.1.

The appeal letter call is the only LLM step. It receives a packet that
INTENTIONALLY contains the member_id and patient name in cleartext — this
baseline (non-sandboxed) version sends PHI directly to OpenAI. Compare
against sandboxed/01 which sends the same packet through declaw's PII
redaction proxy.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated, Literal, TypedDict

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
from shared.llm import chat  # noqa: E402
from shared.mock_phi import PATIENTS, PAYER_POLICIES  # noqa: E402


class PAState(TypedDict, total=False):
    patient_id: str
    requested_drug: str
    policy_key: str
    evidence: dict
    policy: dict
    packet: dict
    submission_id: str
    status: Literal["pending", "approved", "denied"]
    denial_reasons: list[str]
    appeal_letter: str
    audit_log: Annotated[list[dict], "append-only audit trail"]


def fetch_chart_evidence(patient_id: str) -> dict:
    p = PATIENTS[patient_id]
    a1c = next((l for l in p.labs if l["name"] == "Hemoglobin A1c"), None)
    return {
        "patient_name": p.name,
        "member_id": p.member_id,
        "diagnoses": p.diagnoses,
        "medications": p.medications,
        "a1c": a1c,
        "bmi": 34 if patient_id == "p-001" else None,
        "notes": p.notes,
    }


def submit_to_payer(packet: dict) -> dict:
    has_a1c = packet.get("evidence", {}).get("a1c") is not None
    if not has_a1c:
        return {"submission_id": "PA-9001", "status": "denied", "reasons": ["missing_a1c"]}
    return {"submission_id": "PA-9001", "status": "approved", "reasons": []}


def gather(state: PAState) -> PAState:
    return {"evidence": fetch_chart_evidence(state["patient_id"]),
            "audit_log": [{"node": "gather"}]}


def policy_check(state: PAState) -> PAState:
    p = PATIENTS[state["patient_id"]]
    pol = PAYER_POLICIES[state["policy_key"]]
    if p.payer not in pol["payers"]:
        raise ValueError(f"{p.payer} not covered by {state['policy_key']}")
    return {"policy": pol, "audit_log": [{"node": "policy_check"}]}


def assemble_packet(state: PAState) -> PAState:
    packet = {
        "patient_id": state["patient_id"],
        "drug": state["requested_drug"],
        "evidence": state["evidence"],
        "policy_criteria": state["policy"]["criteria"],
    }
    return {"packet": packet, "audit_log": [{"node": "assemble_packet"}]}


def submit(state: PAState) -> PAState:
    result = submit_to_payer(state["packet"])
    return {
        "submission_id": result["submission_id"],
        "status": result["status"],
        "denial_reasons": result["reasons"],
        "audit_log": [{"node": "submit", "result": result["status"]}],
    }


def draft_appeal(state: PAState) -> PAState:
    print("[node draft_appeal] calling gpt-4.1 (UNSANDBOXED — full PHI in prompt)")
    system = (
        "You are a clinical appeals specialist. Draft a concise, professional "
        "prior-authorization appeal letter justifying medical necessity. "
        "Cite the specific policy criteria the patient meets. Plain text, "
        "no markdown."
    )
    user = json.dumps({
        "submission_id": state["submission_id"],
        "denial_reasons": state["denial_reasons"],
        "packet": state["packet"],
    })
    letter = chat(system, user, max_tokens=600)
    return {"appeal_letter": letter, "audit_log": [{"node": "draft_appeal", "model": "gpt-4.1"}]}


def route_after_submit(state: PAState) -> str:
    return "draft_appeal" if state["status"] == "denied" else END


def build_graph():
    g = StateGraph(PAState)
    g.add_node("gather", gather)
    g.add_node("policy_check", policy_check)
    g.add_node("assemble_packet", assemble_packet)
    g.add_node("submit", submit)
    g.add_node("draft_appeal", draft_appeal)
    g.add_edge(START, "gather")
    g.add_edge("gather", "policy_check")
    g.add_edge("policy_check", "assemble_packet")
    g.add_edge("assemble_packet", "submit")
    g.add_conditional_edges("submit", route_after_submit,
                            {"draft_appeal": "draft_appeal", END: END})
    g.add_edge("draft_appeal", END)
    return g.compile(checkpointer=MemorySaver())


def main() -> None:
    graph = build_graph()
    # p-003 (Mei Tanaka) has no A1c on file -> guaranteed denial -> appeal drafted
    initial: PAState = {
        "patient_id": "p-003",
        "requested_drug": "mepolizumab",
        "policy_key": "mepolizumab_asthma",
    }
    config = {"configurable": {"thread_id": "demo-thread-baseline"}}
    result = graph.invoke(initial, config=config)

    print("\n=== Prior Auth Result (baseline, real LLM) ===")
    print(f"Patient:        {result['patient_id']}")
    print(f"Drug:           {result['requested_drug']}")
    print(f"Submission ID:  {result.get('submission_id')}")
    print(f"Status:         {result.get('status')}")
    if result.get("status") == "denied":
        print(f"Reasons:        {result['denial_reasons']}")
        print("\n--- Appeal Letter (gpt-4.1) ---")
        print(result["appeal_letter"])


if __name__ == "__main__":
    main()
