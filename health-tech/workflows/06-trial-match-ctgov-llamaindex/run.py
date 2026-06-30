"""W6 — Clinical Trial Matching against the LIVE ClinicalTrials.gov v2 API.

Real LlamaIndex FunctionAgent + real registry (no mock trial list).

Tool chain the agent exercises:
  1. fetch_patient(patient_id)          — local FHIR mock
  2. ctgov_search(condition, status)    → clinicaltrials.gov/api/v2/studies
  3. ctgov_detail(nct_id)               → .../studies/{nct_id}
  4. LLM scoring (gpt-4.1)              — eligibility verdict with rationale
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from llama_index.core.agent.workflow import FunctionAgent
from llama_index.core.tools import FunctionTool
from llama_index.llms.openai import OpenAI as LlamaOpenAI

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
from shared.external_apis import ctgov_detail, ctgov_search  # noqa: E402
from shared.mock_phi import PATIENTS  # noqa: E402


def fetch_patient(patient_id: str) -> dict:
    """Pull the patient record."""
    p = PATIENTS[patient_id]
    return {"id": p.id, "name": p.name, "dob": p.dob, "sex": p.sex,
            "diagnoses": p.diagnoses, "medications": p.medications,
            "labs": p.labs, "notes": p.notes}


def search_trials_live(condition: str) -> list[dict]:
    """Search ClinicalTrials.gov v2 for recruiting trials matching a
    condition keyword. Returns up to 3 candidate trial summaries."""
    return ctgov_search(condition, status="RECRUITING", page_size=3)


def get_trial_detail(nct_id: str) -> dict:
    """Pull the full eligibility criteria block for a single NCT ID."""
    return ctgov_detail(nct_id)


async def run_agent(patient_id: str) -> str:
    agent = FunctionAgent(
        tools=[
            FunctionTool.from_defaults(fn=fetch_patient),
            FunctionTool.from_defaults(fn=search_trials_live),
            FunctionTool.from_defaults(fn=get_trial_detail),
        ],
        llm=LlamaOpenAI(model="gpt-4.1"),
        system_prompt=(
            "You are a clinical research coordinator. Workflow:\n"
            "  1. Call fetch_patient(patient_id) to see the chart.\n"
            "  2. Pick ONE lowercase condition word (e.g. 'prostate', "
            "     'diabetes', 'asthma') and call search_trials_live(condition).\n"
            "  3. For the most clinically-relevant NCT ID returned, call "
            "     get_trial_detail(nct_id) and review the eligibility criteria.\n"
            "  4. Emit a final plain-text verdict naming the trial, giving a "
            "     one-line eligibility assessment, and one data gap you'd want "
            "     confirmed before enrollment."
        ),
    )
    resp = await agent.run(user_msg=f"Find a matching clinical trial for patient_id={patient_id}.")
    return str(resp)


def main() -> None:
    print("=== Trial Match — LlamaIndex + live ClinicalTrials.gov v2 (baseline) ===\n")
    out = asyncio.run(run_agent("p-002"))  # Sam Okafor, prostate cancer
    print("\n--- Verdict ---")
    print(out)


if __name__ == "__main__":
    main()
