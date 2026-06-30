"""Medical Coding + Claim Scrubbing built with **real CrewAI**.

Three-agent Crew with Process.sequential:
  * Coder      — assigns ICD-10 and CPT codes from the clinical note
  * Auditor    — runs NCCI / documentation-gap checks against the codes
  * Submitter  — emits the final 837 claim JSON

Each agent is a crewai.Agent with tools. Tasks are chained via context=.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from crewai import Agent, Crew, Process, Task
from crewai.tools import tool

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
from shared.mock_phi import PATIENTS  # noqa: E402


# ---------- CrewAI tools ----------

@tool("Run NCCI + documentation check")
def ncci_check(codes_json: str) -> str:
    """Given a JSON string like {"icd10": [...], "cpt": [...]}, run NCCI
    edit checks and return JSON {issues: [...], passed: bool}."""
    try:
        payload = json.loads(codes_json)
    except Exception:
        return json.dumps({"issues": ["Could not parse codes JSON"], "passed": False})
    icd10 = payload.get("icd10", [])
    cpt = payload.get("cpt", [])
    issues: list[str] = []
    if any(str(c).startswith("9921") for c in cpt) and not icd10:
        issues.append("Office visit CPT requires linked diagnosis")
    return json.dumps({"issues": issues, "passed": not issues})


@tool("Build 837 claim payload")
def build_837(claim_json: str) -> str:
    """Given a JSON string like {"patient_id": "...", "icd10": [...], "cpt": [...]},
    return the 837 claim JSON with subscriber info filled in."""
    payload = json.loads(claim_json)
    p = PATIENTS[payload["patient_id"]]
    return json.dumps({
        "claim_id": f"CLM-{p.id}",
        "subscriber": {
            "member_id": p.member_id,
            "payer": p.payer,
            "patient_name": p.name,
        },
        "diagnoses": payload.get("icd10", []),
        "procedures": payload.get("cpt", []),
    }, indent=2)


def main() -> None:
    patient_id = "p-001"
    p = PATIENTS[patient_id]
    note = "\n".join(p.notes)

    print("=== Medical Coding Crew (baseline, CrewAI + real gpt-4.1) ===\n")

    coder = Agent(
        role="Medical Coder",
        goal="Assign the most specific ICD-10 diagnosis and CPT procedure "
             "codes supported by the clinical note.",
        backstory="You are a CPC-certified coder with 10 years of outpatient "
                  "experience. You return codes as JSON with keys icd10 and cpt.",
        verbose=False,
        allow_delegation=False,
    )
    auditor = Agent(
        role="Coding Auditor",
        goal="Catch NCCI edits and documentation gaps before submission.",
        backstory="Former payer auditor. Always run ncci_check on the codes.",
        tools=[ncci_check],
        verbose=False,
        allow_delegation=False,
    )
    submitter = Agent(
        role="Claims Submitter",
        goal="Produce the final 837 claim payload using build_837 once "
             "the auditor has passed the codes.",
        backstory="EDI specialist. You always use the build_837 tool.",
        tools=[build_837],
        verbose=False,
        allow_delegation=False,
    )

    code_task = Task(
        description=(
            f"Read this clinical note for patient_id='{patient_id}' and return "
            f"JSON like {{\"icd10\": [\"E11.65\"], \"cpt\": [\"99214\"]}}:\n\n"
            f"{note}"
        ),
        expected_output='JSON object with "icd10" and "cpt" arrays',
        agent=coder,
    )
    audit_task = Task(
        description="Take the JSON from the coder and run ncci_check on it. "
                    "Report pass/fail and any issues.",
        expected_output="Audit report text including pass/fail status.",
        agent=auditor,
        context=[code_task],
    )
    submit_task = Task(
        description=(
            f"If the audit passed, call build_837 with a JSON containing "
            f"patient_id='{patient_id}' plus the icd10 and cpt arrays from "
            "the coder. Return the 837 JSON as your final answer."
        ),
        expected_output="The 837 claim JSON.",
        agent=submitter,
        context=[code_task, audit_task],
    )

    crew = Crew(
        agents=[coder, auditor, submitter],
        tasks=[code_task, audit_task, submit_task],
        process=Process.sequential,
        verbose=False,
    )
    result = crew.kickoff()
    print("\n--- Final 837 claim ---")
    print(result)


if __name__ == "__main__":
    main()
