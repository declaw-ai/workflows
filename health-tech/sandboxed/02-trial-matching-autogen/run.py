"""Trial Matching — sandboxed, **real AutoGen v0.4 inside the microVM**.

Governance posture (see shared/governance.py): trial eligibility is a
RECOMMENDATION, not an enrollment decision. The deterministic
``evaluate_eligibility`` verdict (potential_match / not_eligible) is surfaced as
a RECOMMEND_REVIEW for a licensed clinician (REVIEWER_CLINICIAN), who owns the
enrollment decision. Advisory only — no hard gate.

The full AutoGen RoundRobinGroupChat runs inside a single Firecracker
sandbox. PHI (patient record + trial registry entries) crosses the declaw
security proxy on every outbound OpenAI call — redacted outbound,
rehydrated inbound.

Architectural trade-off vs the prior per-role-sandbox version: AutoGen's
group chat plumbing doesn't factor across separate microVMs without
rebuilding it on the host, so we keep the whole chat inside one sandbox
and get per-call PII protection instead of per-agent isolation.
"""
from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "sandboxed"))
from shared.mock_phi import CLINICAL_TRIALS, PATIENTS  # noqa: E402
from shared import governance as gov  # noqa: E402
from shared.declaw_helpers import (  # noqa: E402
    LLM_DOMAINS, healthcare_llm_policy, llm_envs, run_python_in_sandbox,
)


AUTOGEN_SCRIPT = textwrap.dedent("""
    import asyncio, json
    from autogen_agentchat.agents import AssistantAgent
    from autogen_agentchat.conditions import (MaxMessageTermination,
                                              TextMentionTermination)
    from autogen_agentchat.teams import RoundRobinGroupChat
    from autogen_ext.models.openai import OpenAIChatCompletionClient

    with open("/tmp/in.json") as f:
        inp = json.load(f)
    PATIENT = inp["patient"]
    REGISTRY = inp["registry"]

    # Governance labels injected from shared.governance on the host (the sandbox
    # cannot import the shared module). The eligibility verdict is a RECOMMENDATION
    # for a licensed clinician, who owns the enrollment decision — never an
    # autonomous enrollment.
    GOV = inp["gov"]
    RECOMMEND_REVIEW = GOV["RECOMMEND_REVIEW"]
    REVIEWER_CLINICIAN = GOV["REVIEWER_CLINICIAN"]

    def fetch_patient(patient_id: str) -> dict:
        \"\"\"Return the patient record for the given patient_id.\"\"\"
        assert patient_id == PATIENT["id"], f"unknown patient {patient_id}"
        return PATIENT

    def search_trials(keyword: str) -> list:
        \"\"\"Search the trial registry. keyword MUST be a single lowercase word.\"\"\"
        kw = keyword.strip().lower()
        if not kw or any(ch in kw for ch in " -/,.()"):
            raise ValueError(
                f"search_trials requires a single lowercase word, got {keyword!r}. "
                "Pass only the word after 'KEYWORD:' (e.g. 'prostate')."
            )
        return [t for t in REGISTRY if kw in json.dumps(t).lower()]

    def evaluate_eligibility(patient: dict, trial: dict) -> dict:
        \"\"\"Score a patient against a trial's inclusion criteria.\"\"\"
        matched, missed = [], []
        blob = json.dumps(patient).lower()
        for crit in trial["inclusion"]:
            if any(tok.lower() in blob for tok in crit.split() if len(tok) > 4):
                matched.append(crit)
            else:
                missed.append(crit)
        return {"trial_id": trial["id"], "title": trial["title"],
                "matched": matched, "missed": missed,
                "verdict": "potential_match" if len(missed) <= 1 else "not_eligible"}

    async def main():
        model = OpenAIChatCompletionClient(model="gpt-4.1")
        pid = PATIENT["id"]

        clinician = AssistantAgent(
            name="clinician", model_client=model, tools=[fetch_patient],
            reflect_on_tool_use=True,
            system_message=(
                f"You are an oncology clinician. Call fetch_patient with "
                f"patient_id='{pid}' once. Your ONLY text reply after that "
                "must be this single line with no other content:\\n"
                "    KEYWORD: <word>\\n"
                "Where <word> is one lowercase disease word chosen from "
                "['prostate', 'diabetes', 'asthma']. Do NOT echo the patient "
                "record, add rationale, or include qualifiers."
            ),
        )
        coordinator = AssistantAgent(
            name="coordinator", model_client=model, tools=[search_trials],
            system_message=(
                "Find 'KEYWORD: <word>' in the clinician's message and "
                "call search_trials(keyword=<word>) with that single lowercase "
                "word — no phrases, hyphens, or extra words. If the tool "
                "rejects your input, retry with just the word after 'KEYWORD:'."
            ),
        )
        checker = AssistantAgent(
            name="eligibility_checker", model_client=model,
            tools=[evaluate_eligibility, fetch_patient],
            system_message=(
                f"For each trial from the coordinator, call fetch_patient("
                f"'{pid}') then evaluate_eligibility(patient, trial). "
                f"Each verdict is a RECOMMENDATION ({RECOMMEND_REVIEW}) for a "
                f"{REVIEWER_CLINICIAN}, who OWNS the enrollment decision — it is "
                "NOT an enrollment decision. Summarize each verdict in one line, "
                "framed as a recommendation for clinician review. End FINAL message "
                "with token MATCHING_DONE."
            ),
        )

        team = RoundRobinGroupChat(
            [clinician, coordinator, checker],
            termination_condition=TextMentionTermination("MATCHING_DONE")
                                  | MaxMessageTermination(20),
        )
        result = await team.run(task=f"Find clinical trials for patient_id={pid}.")
        # Collect every checker message that has real text content.
        checker_msgs = []
        for m in result.messages:
            if getattr(m, "source", None) == "eligibility_checker":
                c = getattr(m, "content", None)
                if isinstance(c, str) and c.strip():
                    checker_msgs.append(c)
        final = checker_msgs[-1] if checker_msgs else ""
        transcript = [
            f"[{getattr(m, 'source', '?')}] {str(getattr(m, 'content', ''))[:300]}"
            for m in result.messages
        ]

        with open("/tmp/out.json", "w") as f:
            json.dump({"final": final, "transcript": transcript}, f)

    asyncio.run(main())
""")


def fetch_patient_record(patient_id: str) -> dict:
    p = PATIENTS[patient_id]
    return {"id": p.id, "name": p.name, "dob": p.dob, "sex": p.sex,
            "diagnoses": p.diagnoses, "medications": p.medications,
            "labs": p.labs, "notes": p.notes}


def main() -> None:
    patient = fetch_patient_record("p-002")
    print("=== Trial Matching (sandboxed, real AutoGen inside microVM) ===")
    print(f"governance: {gov.governance_banner()}")
    print(f"Eligibility is a {gov.RECOMMEND_REVIEW} for a {gov.REVIEWER_CLINICIAN}; "
          "the clinician owns the enrollment decision (advisory, not a gate).\n")

    pol = healthcare_llm_policy(allow_domains=LLM_DOMAINS)
    out = run_python_in_sandbox(
        "autogen-matching", AUTOGEN_SCRIPT, pol,
        payload={
            "patient": patient, "registry": CLINICAL_TRIALS,
            # Governance labels — the verdict is a recommendation; a licensed
            # clinician owns enrollment (the sandbox can't import shared.governance).
            "gov": {
                "RECOMMEND_REVIEW": gov.RECOMMEND_REVIEW,
                "REVIEWER_CLINICIAN": gov.REVIEWER_CLINICIAN,
            },
        },
        # autogen-agentchat + autogen-ext are baked into the `ai-agent` template
        envs=llm_envs(),
        timeout=400,
    )

    print("\n--- Transcript ---")
    for line in out.get("transcript", []):
        print(line)
    print("\n--- Eligibility RECOMMENDATION (clinician owns enrollment) ---")
    print(out.get("final") or "(no final checker message captured)")
    print(f"\n[note] This is a {gov.RECOMMEND_REVIEW} for a {gov.REVIEWER_CLINICIAN}; "
          "no patient is enrolled autonomously — a clinician owns the enrollment "
          "decision.")


if __name__ == "__main__":
    main()
