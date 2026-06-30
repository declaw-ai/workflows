"""Lab Result Explainer built with **real LlamaIndex**.

Uses a FunctionAgent (llama-index-core workflow) with two tools:
  * fetch_labs(patient_id)  — stand-in for FHIR Observation search
  * lookup_reference(name)  — retrieves a plain-language snippet for a lab

The agent reasons over the tools, composes a patient-friendly summary at
a 6th-grade reading level, and returns it.
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
from shared.mock_phi import PATIENTS  # noqa: E402


REFERENCE_DOCS = {
    "Hemoglobin A1c": "Hemoglobin A1c reflects average blood sugar over 2-3 months. Normal <5.7%, 5.7-6.4 prediabetes, >=7 usually means diabetes is not well controlled.",
    "Creatinine":     "Creatinine is a kidney waste product. Normal 0.6-1.2 mg/dL.",
    "PSA":            "PSA is a prostate protein. Above 4 ng/mL may need follow-up.",
    "WBC":            "White blood cell count. Normal 4.5-11 thousand/uL.",
    "Hemoglobin":     "Carries oxygen. Normal 12-16 g/dL women, 13.5-17.5 men.",
}


def fetch_labs(patient_id: str) -> list[dict[str, Any]]:
    """Fetch the patient's most recent lab results."""
    return PATIENTS[patient_id].labs


def lookup_reference(lab_name: str) -> str:
    """Look up a plain-language explanation for a lab test by name."""
    return REFERENCE_DOCS.get(lab_name, f"No patient-friendly reference for {lab_name}.")


async def run_agent(patient_id: str) -> str:
    p = PATIENTS[patient_id]
    agent = FunctionAgent(
        tools=[
            FunctionTool.from_defaults(fn=fetch_labs),
            FunctionTool.from_defaults(fn=lookup_reference),
        ],
        llm=LlamaOpenAI(model="gpt-4.1"),
        system_prompt=(
            "You write friendly, accurate, plain-language lab summaries for "
            "patients at a 6th-grade reading level. Workflow: first call "
            "fetch_labs(patient_id) to get the patient's labs; then for each "
            "lab call lookup_reference(lab_name) and use the snippet to write "
            "one sentence explaining what it means. Greet the patient by "
            "first name. End with a line directing them to message their care "
            "team if anything worries them. No medical advice."
        ),
    )
    response = await agent.run(
        user_msg=f"Explain my latest labs in plain language. My patient_id is "
                 f"{patient_id} and my first name is {p.name.split()[0]}."
    )
    return str(response)


def main() -> None:
    print("=== Lab Result Explainer (baseline, LlamaIndex + real gpt-4.1) ===\n")
    out = asyncio.run(run_agent("p-001"))
    print("\n--- Patient-facing message ---")
    print(out)


if __name__ == "__main__":
    main()
