"""Medical Coding — sandboxed, **real CrewAI inside the microVM**.

Full CrewAI sequential pipeline (Coder → Auditor → Submitter) runs inside
a single Firecracker sandbox. Every OpenAI call the Crew makes crosses
the declaw proxy with PII redaction + rehydration on.

Known infra limitation (2026-04): ``pip install crewai`` pulls ~300
transitive deps (langchain, litellm, chromadb, embedchain, …). Piped
through declaw's MITM TLS proxy this exceeds the API gateway's request
budget and trips the backend circuit breaker (HTTP 503 "node circuit
breaker open"). The workflow code itself is correct — run as-is once you
have a custom declaw Template with crewai pre-baked:

    Template.build(template='''
        FROM python:3.11-slim
        RUN pip install --no-cache-dir crewai
    ''', alias='crewai-ready')

Then swap `template="python"` for `template="crewai-ready"` in the
sandbox create call (inside `run_python_in_sandbox`) and drop
`pip_packages=["crewai"]`. The pipe install step becomes a no-op and
the circuit-breaker path disappears.
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

    @tool("Build 837 claim payload")
    def build_837(claim_json: str) -> str:
        \"\"\"Given JSON {patient_id, icd10, cpt}, return the 837 claim JSON.\"\"\"
        payload = json.loads(claim_json)
        return json.dumps({
            "claim_id": f"CLM-{PATIENT['id']}",
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
        role="Claims Submitter",
        goal="Produce the final 837 using build_837 once audit passes.",
        backstory="EDI specialist. You always use the build_837 tool.",
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
            "Return the 837 JSON as your final answer."
        ),
        expected_output="The 837 claim JSON.",
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

    print("=== Medical Coding Crew (sandboxed, real CrewAI inside microVM) ===\n")
    pol = healthcare_llm_policy(allow_domains=LLM_DOMAINS)
    out = run_python_in_sandbox(
        "crewai-coding", CREWAI_SCRIPT, pol,
        payload={"patient": patient, "note": note},
        # crewai is baked into the `ai-agent` template — no pip install needed
        pip_packages=None,
        envs=llm_envs(),
        timeout=500,
    )
    print("\n--- Final 837 claim ---")
    print(out["claim"])


if __name__ == "__main__":
    main()
