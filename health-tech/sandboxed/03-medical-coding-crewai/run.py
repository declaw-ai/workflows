"""Medical Coding — sandboxed, **real CrewAI inside the microVM**.

Full CrewAI sequential pipeline (Coder → Auditor → Draft-Assembler) runs inside
a single Firecracker sandbox. Every OpenAI call the Crew makes crosses
the declaw proxy with PII redaction + rehydration on.

Governance posture (see shared/governance.py): the crew DRAFTS ICD-10/CPT codes
and a DRAFT 837 only; a certified medical coder reviews and signs off. The 837 is
NEVER autonomously final (False Claims Act / upcoding liability) — it is held at a
human-coder gate (status PENDING_HUMAN_CONFIRMATION, reviewer
REVIEWER_CERTIFIED_CODER).

Templating note: crewai is pre-baked into the `ai-agent` template
(`run_python_in_sandbox` defaults to it), so this workflow does NOT run
``pip install crewai`` at runtime — `pip_packages=None`. That avoids the
~300 transitive deps (langchain, litellm, chromadb, embedchain, …) being
piped through declaw's MITM TLS proxy, which previously exceeded the API
gateway's request budget and tripped the backend circuit breaker (HTTP
503 "node circuit breaker open"). With crewai pre-baked there is no
runtime install and no circuit-breaker path; the latest live run passed
in ~29s on the `ai-agent` template.
"""
from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "sandboxed"))
from shared.mock_phi import PATIENTS  # noqa: E402
from shared import governance as gov  # noqa: E402
from shared.declaw_helpers import (  # noqa: E402
    LLM_DOMAINS, healthcare_llm_policy, llm_envs, run_python_in_sandbox,
)


CREWAI_SCRIPT = textwrap.dedent("""
    import json, os
    os.environ["CREWAI_TRACING_ENABLED"] = "false"
    os.environ["OTEL_SDK_DISABLED"] = "true"
    # This OpenAI project only has access to gpt-4.1 (not gpt-4o-mini which
    # is CrewAI's default). Pin it via env so every agent uses gpt-4.1.
    os.environ["OPENAI_MODEL_NAME"] = "gpt-4.1"

    from crewai import Agent, Crew, LLM, Process, Task
    from crewai.tools import tool

    llm = LLM(model="gpt-4.1")

    with open("/tmp/in.json") as f:
        inp = json.load(f)
    PATIENT = inp["patient"]
    NOTE = inp["note"]

    # Governance labels injected from shared.governance on the host (the sandbox
    # cannot import the shared module). The crew DRAFTS codes + a draft 837; a
    # certified medical coder reviews and signs off. The 837 is NEVER
    # autonomously final (False Claims Act / upcoding liability).
    GOV = inp["gov"]
    PENDING_HUMAN_CONFIRMATION = GOV["PENDING_HUMAN_CONFIRMATION"]
    DRAFT_PENDING_REVIEW = GOV["DRAFT_PENDING_REVIEW"]
    REVIEWER_CERTIFIED_CODER = GOV["REVIEWER_CERTIFIED_CODER"]

    @tool("Run NCCI and documentation check")
    def ncci_check(codes_json: str) -> str:
        \"\"\"Given JSON like {\\"icd10\\": [...], \\"cpt\\": [...]}, run NCCI edit
        checks and return JSON {issues: [...], passed: bool}.\"\"\"
        try:
            payload = json.loads(codes_json)
        except Exception:
            return json.dumps({"issues": ["Could not parse codes JSON"],
                               "passed": False})
        icd10 = payload.get("icd10", [])
        cpt = payload.get("cpt", [])
        issues = []
        if any(str(c).startswith("9921") for c in cpt) and not icd10:
            issues.append("Office visit CPT requires linked diagnosis")
        return json.dumps({"issues": issues, "passed": not issues})

    @tool("Build draft 837 claim payload")
    def build_837(claim_json: str) -> str:
        \"\"\"Given JSON {patient_id, icd10, cpt}, return a DRAFT 837 claim JSON
        held for certified-coder sign-off — NOT an autonomously final claim.\"\"\"
        payload = json.loads(claim_json)
        return json.dumps({
            "claim_id": f"CLM-{PATIENT['id']}",
            "status": PENDING_HUMAN_CONFIRMATION,
            "label": DRAFT_PENDING_REVIEW,
            "review_required_by": REVIEWER_CERTIFIED_CODER,
            "subscriber": {
                "member_id": PATIENT["member_id"],
                "payer": PATIENT["payer"],
                "patient_name": PATIENT["name"],
            },
            "diagnoses": payload.get("icd10", []),
            "procedures": payload.get("cpt", []),
        }, indent=2)

    coder = Agent(
        role="Medical Coder",
        goal="Assign the most specific ICD-10 and CPT codes supported by the note.",
        backstory="CPC-certified coder. Return JSON with icd10 and cpt arrays.",
        allow_delegation=False, llm=llm,
    )
    auditor = Agent(
        role="Coding Auditor",
        goal="Catch NCCI edits and documentation gaps before submission.",
        backstory="Former payer auditor. Always run ncci_check on proposed codes.",
        tools=[ncci_check], allow_delegation=False,
    )
    submitter = Agent(
        role="Draft Claim Assembler",
        goal=("Assemble a DRAFT 837 using build_837 once audit passes — for a "
              f"{REVIEWER_CERTIFIED_CODER} to review and sign off. NEVER mark a "
              "claim final or file it."),
        backstory=("EDI specialist. You always use the build_837 tool to produce "
                   "a DRAFT 837 held for certified-coder review; you do not file "
                   "claims and you do not make the claim binding."),
        tools=[build_837], allow_delegation=False,
    )

    code_task = Task(
        description=(
            f"Read this clinical note for patient_id='{PATIENT['id']}' and return "
            f"JSON like {{\\"icd10\\": [...], \\"cpt\\": [...]}}:\\n\\n{NOTE}"
        ),
        expected_output='JSON with icd10 and cpt arrays',
        agent=coder,
    )
    audit_task = Task(
        description="Run ncci_check on the coder's JSON. Report pass/fail.",
        expected_output="Audit report with pass/fail status.",
        agent=auditor, context=[code_task],
    )
    submit_task = Task(
        description=(
            f"If the audit passed, call build_837 with JSON containing "
            f"patient_id='{PATIENT['id']}' and the coder's icd10/cpt arrays. "
            "Return the DRAFT 837 JSON as your final answer. State clearly that "
            f"the draft is {PENDING_HUMAN_CONFIRMATION} and must be reviewed and "
            f"signed off by a {REVIEWER_CERTIFIED_CODER} before submission — it "
            "is NOT a final claim."
        ),
        expected_output=(
            f"The DRAFT 837 claim JSON ({DRAFT_PENDING_REVIEW}), pending "
            f"{REVIEWER_CERTIFIED_CODER} sign-off."
        ),
        agent=submitter, context=[code_task, audit_task],
    )

    crew = Crew(
        agents=[coder, auditor, submitter],
        tasks=[code_task, audit_task, submit_task],
        process=Process.sequential, verbose=False,
    )
    result = crew.kickoff()
    with open("/tmp/out.json", "w") as f:
        json.dump({"claim": str(result)}, f)
""")


def main() -> None:
    patient_id = "p-001"
    p = PATIENTS[patient_id]
    note = "\n".join(p.notes)
    patient = {"id": p.id, "name": p.name,
               "member_id": p.member_id, "payer": p.payer}

    print("=== Medical Coding Crew (sandboxed, real CrewAI inside microVM) ===")
    print(f"governance: {gov.governance_banner()}")
    print(f"The crew DRAFTS ICD-10/CPT + a draft 837; a {gov.REVIEWER_CERTIFIED_CODER} "
          f"reviews and signs off. The 837 is NOT autonomously final "
          f"({gov.PENDING_HUMAN_CONFIRMATION}).\n")
    pol = healthcare_llm_policy(allow_domains=LLM_DOMAINS)
    out = run_python_in_sandbox(
        "crewai-coding", CREWAI_SCRIPT, pol,
        payload={
            "patient": patient, "note": note,
            # Governance labels — the crew only DRAFTS; a certified medical coder
            # owns the binding sign-off (the sandbox can't import shared.governance).
            "gov": {
                "PENDING_HUMAN_CONFIRMATION": gov.PENDING_HUMAN_CONFIRMATION,
                "DRAFT_PENDING_REVIEW": gov.DRAFT_PENDING_REVIEW,
                "REVIEWER_CERTIFIED_CODER": gov.REVIEWER_CERTIFIED_CODER,
            },
        },
        # crewai is baked into the `ai-agent` template — no pip install needed
        pip_packages=None,
        envs=llm_envs(),
        timeout=500,
    )
    print("\n--- DRAFT 837 claim (pending certified-coder review) ---")
    print(out["claim"])
    print(f"\n[gate] Binding outcome is {gov.PENDING_HUMAN_CONFIRMATION}: the crew "
          f"only DRAFTS the codes + 837; a {gov.REVIEWER_CERTIFIED_CODER} must "
          "review and sign off before submission. Nothing is coded or filed "
          "autonomously.")


if __name__ == "__main__":
    main()
