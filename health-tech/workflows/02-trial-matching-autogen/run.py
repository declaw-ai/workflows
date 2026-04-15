"""Clinical Trial Matching workflow built with **real AutoGen v0.4**.

Uses `autogen_agentchat.AssistantAgent` + `RoundRobinGroupChat` + tools.
Three specialist agents collaborate in a group chat:
  * clinician      — pulls the patient record, identifies the trial-relevant
                     condition, calls fetch_patient()
  * coordinator    — searches the trial registry via search_trials() tool
  * eligibility_checker — runs evaluate_eligibility(patient, trial) tool on
                          each candidate and emits a final MATCHING_DONE token

Real gpt-4.1 calls. PHI is passed in the prompt directly — baseline
(un-sandboxed) version. See sandboxed/02 for the hardened variant.
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.conditions import MaxMessageTermination, TextMentionTermination
from autogen_agentchat.teams import RoundRobinGroupChat
from autogen_ext.models.openai import OpenAIChatCompletionClient

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
from shared.mock_phi import CLINICAL_TRIALS, PATIENTS  # noqa: E402


# ---------- Tools the AutoGen agents can call ----------

def fetch_patient(patient_id: str) -> dict[str, Any]:
    """Pull a patient record (stand-in for FHIR Patient + Condition + Observation)."""
    p = PATIENTS[patient_id]
    return {
        "id": p.id, "name": p.name, "dob": p.dob, "sex": p.sex,
        "diagnoses": p.diagnoses, "medications": p.medications,
        "labs": p.labs, "notes": p.notes,
    }


def search_trials(keyword: str) -> list[dict[str, Any]]:
    """Search the trial registry. `keyword` MUST be a single lowercase word
    (no spaces, no punctuation). Reject multi-word phrases so the coordinator
    is forced to hand off the exact KEYWORD: <word> the clinician emitted."""
    kw = keyword.strip().lower()
    if not kw or any(ch in kw for ch in " -/,.()"):
        raise ValueError(
            f"search_trials requires a single lowercase word, got {keyword!r}. "
            "Pass only the word after 'KEYWORD:' (e.g. 'prostate')."
        )
    return [t for t in CLINICAL_TRIALS if kw in json.dumps(t).lower()]


def evaluate_eligibility(patient: dict, trial: dict) -> dict[str, Any]:
    """Score a patient against a trial's inclusion criteria."""
    matched, missed = [], []
    blob = json.dumps(patient).lower()
    for crit in trial["inclusion"]:
        if any(tok.lower() in blob for tok in crit.split() if len(tok) > 4):
            matched.append(crit)
        else:
            missed.append(crit)
    return {
        "trial_id": trial["id"],
        "title": trial["title"],
        "matched": matched,
        "missed": missed,
        "verdict": "potential_match" if len(missed) <= 1 else "not_eligible",
    }


async def run_matching(patient_id: str) -> list[str]:
    model = OpenAIChatCompletionClient(model="gpt-4.1")

    clinician = AssistantAgent(
        name="clinician",
        model_client=model,
        tools=[fetch_patient],
        reflect_on_tool_use=True,
        system_message=(
            f"You are an oncology clinician. Call fetch_patient with "
            f"patient_id='{patient_id}' ONCE to see the record. Your ONLY "
            "text reply after the tool call must be this single line with no "
            "other content:\n"
            "    KEYWORD: <word>\n"
            "Where <word> is one lowercase disease word chosen from "
            "['prostate', 'diabetes', 'asthma']. Do NOT echo the patient "
            "record. Do NOT add commentary, rationale, greetings, or notes. "
            "Do NOT include qualifiers like 'metastatic' or 'recurrent'."
        ),
    )
    coordinator = AssistantAgent(
        name="coordinator",
        model_client=model,
        tools=[search_trials],
        system_message=(
            "You are a research coordinator. Find the line 'KEYWORD: <word>' "
            "in the clinician's message and extract <word>. Call "
            "search_trials(keyword=<word>) with exactly that single lowercase "
            "word — no phrases, no hyphens, no additional words. If the tool "
            "rejects your input, retry with just the word after 'KEYWORD:'. "
            "Then list the trial IDs you found."
        ),
    )
    checker = AssistantAgent(
        name="eligibility_checker",
        model_client=model,
        tools=[evaluate_eligibility],
        system_message=(
            f"You are an eligibility specialist. For each trial id from the "
            f"coordinator, first call fetch_patient(patient_id='{patient_id}') "
            "to get the patient dict, then call evaluate_eligibility(patient, "
            "trial_dict). Summarize each verdict in one line. End your FINAL "
            "message with the literal token MATCHING_DONE."
        ),
    )
    # Need fetch_patient available on checker too since it scores patient vs trial
    checker._tools = [evaluate_eligibility, fetch_patient]  # type: ignore[attr-defined]

    team = RoundRobinGroupChat(
        [clinician, coordinator, checker],
        termination_condition=TextMentionTermination("MATCHING_DONE")
                              | MaxMessageTermination(20),
    )

    transcript: list[str] = []
    async for msg in team.run_stream(task=f"Find clinical trials for patient_id={patient_id}."):
        if hasattr(msg, "source") and hasattr(msg, "content"):
            line = f"[{msg.source}] {msg.content}"
            print(line[:500])
            transcript.append(line)
    return transcript


def main() -> None:
    print("=== Trial Matching (baseline, AutoGen + real gpt-4.1) ===\n")
    asyncio.run(run_matching("p-002"))   # Sam Okafor — prostate cancer


if __name__ == "__main__":
    main()
