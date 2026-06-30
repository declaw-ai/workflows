"""Prior Authorization (LangGraph) — sandboxed with declaw, real GPT-4.1.

The appeal-letter step makes the SAME real gpt-4.1 call as the baseline,
but from inside a Firecracker microVM whose security proxy:
  * Redacts PHI (member_id, email, ssn, phone) before the request body
    leaves the VM. The OpenAI endpoint sees [REDACTED_*_n] tokens.
  * Rehydrates those tokens in the inbound response so the agent code
    receives the original PHI back, transparently.
  * Locks egress to api.openai.com + pypi (for openai package install).
  * Blocks the cloud metadata IP and everything else.
"""
from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path
from typing import Annotated, Literal, TypedDict

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "sandboxed"))
from shared.mock_phi import PATIENTS, PAYER_POLICIES  # noqa: E402
from shared.declaw_helpers import (  # noqa: E402
    LLM_DOMAINS, LLM_PIP, healthcare_llm_policy,
    healthcare_untrusted_io_policy, llm_envs, run_python_in_sandbox,
)
from shared import governance as gov  # noqa: E402


class PAState(TypedDict, total=False):
    patient_id: str
    requested_drug: str
    policy_key: str
    evidence: dict
    policy: dict
    packet: dict
    submission_id: str
    # A medical-necessity DENIAL is never autonomously binding — it is a
    # recommendation held for a licensed clinician (CMS 42 CFR 422.101(c);
    # CA SB 1120 / IL clinical-peer). Approval may be auto-issued.
    status: Literal["pending", "approved", "pending_clinician_review"]
    recommendation: str
    reviewer: str
    gate_status: str
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


# ---------- Sandboxed payer submission (untrusted clearinghouse) ----------

PAYER_SUBMIT_SCRIPT = textwrap.dedent("""
    import json
    with open("/tmp/in.json") as f:
        packet = json.load(f)
    has_a1c = packet.get("evidence", {}).get("a1c") is not None
    out = {
        "submission_id": "PA-9001",
        "status": "approved" if has_a1c else "denied",
        "reasons": [] if has_a1c else ["missing_a1c"],
    }
    with open("/tmp/out.json", "w") as f:
        json.dump(out, f)
""")


def submit_to_payer_sandboxed(packet: dict) -> dict:
    pol = healthcare_untrusted_io_policy(allow_domains=["*.payer-clearinghouse.com"])
    return run_python_in_sandbox("payer-submit", PAYER_SUBMIT_SCRIPT, pol, payload=packet)


# ---------- Sandboxed LLM appeal draft (real gpt-4.1, PII-redacting) ----------

APPEAL_SCRIPT = textwrap.dedent("""
    import json
    from openai import OpenAI
    with open("/tmp/in.json") as f:
        inp = json.load(f)
    client = OpenAI()
    resp = client.chat.completions.create(
        model="gpt-4.1",
        messages=[
            {"role": "system", "content": (
                "You are a clinical appeals specialist. Draft a concise, "
                "professional prior-authorization appeal letter justifying "
                "medical necessity. Cite the specific policy criteria the "
                "patient meets. Plain text, no markdown. If you see "
                "REDACTED_* tokens, treat them as opaque placeholders for "
                "patient identifiers."
            )},
            {"role": "user", "content": json.dumps(inp)},
        ],
        max_completion_tokens=600,
    )
    with open("/tmp/out.json", "w") as f:
        json.dump({"letter": resp.choices[0].message.content}, f)
""")


def draft_appeal_sandboxed(packet: dict, reasons: list[str]) -> str:
    pol = healthcare_llm_policy(allow_domains=LLM_DOMAINS)
    out = run_python_in_sandbox(
        "appeal-llm", APPEAL_SCRIPT, pol,
        payload={"submission_id": packet.get("submission_id", "?"),
                 "denial_reasons": reasons, "packet": packet},
        pip_packages=LLM_PIP, envs=llm_envs(),
    )
    return out["letter"]


# ---------- Graph ----------

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
    print("[node submit] entering sandbox (untrusted clearinghouse)")
    result = submit_to_payer_sandboxed(state["packet"])
    # `result["status"]` is the automated medical-necessity RECOMMENDATION, not a
    # binding decision — the clinician_review gate owns a denial.
    return {
        "submission_id": result["submission_id"],
        "status": "pending",
        "recommendation": gov.RECOMMEND_DENY if result["status"] == "denied"
                          else gov.RECOMMEND_APPROVE,
        "denial_reasons": result["reasons"],
        "audit_log": [{"node": "submit", "sandboxed": True,
                       "recommendation": result["status"]}],
    }


def clinician_review(state: PAState) -> PAState:
    """Mandatory human gate on a medical-necessity DENIAL. An LLM/automated rule
    may recommend, but a licensed clinician must own the denial before it is
    issued (CMS 42 CFR 422.101(c); CA SB 1120 "Physicians Make Decisions Act";
    IL clinical-peer). Approvals may be auto-issued; denials are held."""
    if state.get("recommendation") == gov.RECOMMEND_DENY:
        print(f"[node clinician_review] {gov.RECOMMEND_DENY} — "
              f"{gov.PENDING_HUMAN_CONFIRMATION} (a {gov.REVIEWER_CLINICIAN} must own "
              "this medical-necessity denial; not auto-denied)")
        return {
            "status": "pending_clinician_review",
            "gate_status": gov.PENDING_HUMAN_CONFIRMATION,
            "reviewer": gov.REVIEWER_CLINICIAN,
            "audit_log": [{"node": "clinician_review",
                           "recommendation": gov.RECOMMEND_DENY,
                           "status": gov.PENDING_HUMAN_CONFIRMATION}],
        }
    print("[node clinician_review] RECOMMEND_APPROVE — approval may be auto-issued")
    return {
        "status": "approved",
        "audit_log": [{"node": "clinician_review", "recommendation": gov.RECOMMEND_APPROVE}],
    }


def draft_appeal(state: PAState) -> PAState:
    print("[node draft_appeal] entering sandbox (real gpt-4.1, PII redacted+rehydrated at proxy)")
    letter = draft_appeal_sandboxed(state["packet"], state["denial_reasons"])
    return {"appeal_letter": letter,
            "audit_log": [{"node": "draft_appeal", "sandboxed": True, "model": "gpt-4.1"}]}


def route_after_review(state: PAState) -> str:
    # A recommended denial drafts an appeal (provider assist) while it is held
    # for the clinician; an approval ends.
    return "draft_appeal" if state.get("recommendation") == gov.RECOMMEND_DENY else END


def build_graph():
    g = StateGraph(PAState)
    g.add_node("gather", gather)
    g.add_node("policy_check", policy_check)
    g.add_node("assemble_packet", assemble_packet)
    g.add_node("submit", submit)
    g.add_node("clinician_review", clinician_review)
    g.add_node("draft_appeal", draft_appeal)
    g.add_edge(START, "gather")
    g.add_edge("gather", "policy_check")
    g.add_edge("policy_check", "assemble_packet")
    g.add_edge("assemble_packet", "submit")
    # Denial recommendation passes through the mandatory clinician gate.
    g.add_edge("submit", "clinician_review")
    g.add_conditional_edges("clinician_review", route_after_review,
                            {"draft_appeal": "draft_appeal", END: END})
    g.add_edge("draft_appeal", END)
    return g.compile(checkpointer=MemorySaver())


def main() -> None:
    graph = build_graph()
    initial: PAState = {
        "patient_id": "p-003",   # no A1c → guaranteed denial → appeal drafted
        "requested_drug": "mepolizumab",
        "policy_key": "mepolizumab_asthma",
    }
    config = {"configurable": {"thread_id": "demo-thread-sandboxed"}}
    result = graph.invoke(initial, config=config)

    print("\n=== Prior Auth Result (sandboxed, real LLM) ===")
    print(f"Governance:     {gov.governance_banner()}")
    print(f"Patient:        {result['patient_id']}")
    print(f"Drug:           {result['requested_drug']}")
    print(f"Submission ID:  {result.get('submission_id')}")
    print(f"Recommendation: {result.get('recommendation')}  ->  status={result.get('status')}")
    if result.get("recommendation") == gov.RECOMMEND_DENY:
        print(f"Clinician gate: {result.get('gate_status')} — owner: {result.get('reviewer')}")
        print(f"Reasons:        {result['denial_reasons']}")
        print("[NOTE] The denial is NOT issued autonomously — a licensed clinician "
              "must own it (CMS 42 CFR 422.101(c) / CA SB 1120). The letter below is "
              "drafted to assist, pending that review.")
        print("\n--- Appeal Letter (gpt-4.1, PHI rehydrated by declaw proxy) ---")
        print(result["appeal_letter"])


if __name__ == "__main__":
    main()
