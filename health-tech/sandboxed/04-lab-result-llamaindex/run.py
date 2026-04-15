"""Lab Result Explainer — sandboxed, **real LlamaIndex inside the microVM**.

Two sandboxes:
  1. ref-loader (untrusted-IO policy)  — loads third-party reference docs
  2. llamaindex-rewrite (LLM policy)   — real FunctionAgent from
     llama-index-core; its gpt-4.1 calls cross the declaw proxy with PII
     redaction + rehydration.
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
    LLM_DOMAINS, healthcare_llm_policy, healthcare_untrusted_io_policy,
    llm_envs, run_python_in_sandbox,
)


REFERENCE_DOCS = {
    "Hemoglobin A1c": "Hemoglobin A1c reflects average blood sugar over 2-3 months. Normal <5.7%, 5.7-6.4 prediabetes, >=7 usually means diabetes is not well controlled.",
    "Creatinine":     "Creatinine is a kidney waste product. Normal 0.6-1.2 mg/dL.",
    "PSA":            "PSA is a prostate protein. Above 4 ng/mL may need follow-up.",
    "WBC":            "White blood cell count. Normal 4.5-11 thousand/uL.",
    "Hemoglobin":     "Carries oxygen. Normal 12-16 g/dL women, 13.5-17.5 men.",
}


REFERENCE_LOADER_SCRIPT = textwrap.dedent("""
    import json
    with open("/tmp/in.json") as f:
        inp = json.load(f)
    out = {lab["name"]: inp["docs"].get(lab["name"], "")
           for lab in inp["labs"]}
    with open("/tmp/out.json", "w") as f:
        json.dump(out, f)
""")


LLAMAINDEX_SCRIPT = textwrap.dedent("""
    import asyncio, json
    from llama_index.core.agent.workflow import FunctionAgent
    from llama_index.core.tools import FunctionTool
    from llama_index.llms.openai import OpenAI as LlamaOpenAI

    with open("/tmp/in.json") as f:
        inp = json.load(f)
    LABS = inp["labs"]
    REFS = inp["references"]
    FIRST_NAME = inp["patient_first_name"]
    PATIENT_ID = inp["patient_id"]

    def fetch_labs(patient_id: str) -> list:
        \"\"\"Fetch the patient's most recent lab results.\"\"\"
        assert patient_id == PATIENT_ID, f"unknown patient {patient_id}"
        return LABS

    def lookup_reference(lab_name: str) -> str:
        \"\"\"Plain-language explanation for a lab test by name.\"\"\"
        return REFS.get(lab_name, f"No reference for {lab_name}.")

    async def main():
        agent = FunctionAgent(
            tools=[
                FunctionTool.from_defaults(fn=fetch_labs),
                FunctionTool.from_defaults(fn=lookup_reference),
            ],
            llm=LlamaOpenAI(model="gpt-4.1"),
            system_prompt=(
                "You write friendly, accurate, plain-language lab summaries "
                "for patients at a 6th-grade reading level. Workflow: first "
                "call fetch_labs(patient_id) to get labs; then for each lab "
                "call lookup_reference(lab_name). Greet the patient by first "
                "name. End with a line directing them to message care team."
            ),
        )
        resp = await agent.run(
            user_msg=f"Explain my latest labs. patient_id={PATIENT_ID}, "
                     f"first name {FIRST_NAME}."
        )
        with open("/tmp/out.json", "w") as f:
            json.dump({"text": str(resp)}, f)

    asyncio.run(main())
""")


def main() -> None:
    patient_id = "p-001"
    p = PATIENTS[patient_id]

    print("=== Lab Result Explainer (sandboxed, real LlamaIndex inside microVM) ===\n")

    print("[ref-loader sandbox — untrusted third-party PDFs]")
    refs = run_python_in_sandbox(
        "ref-loader", REFERENCE_LOADER_SCRIPT,
        healthcare_untrusted_io_policy(allow_domains=["patient-ed.publisher.example"]),
        payload={"docs": REFERENCE_DOCS, "labs": p.labs},
    )

    print("\n[llamaindex-rewrite sandbox — real LlamaIndex FunctionAgent + gpt-4.1]")
    out = run_python_in_sandbox(
        "llamaindex-rewrite", LLAMAINDEX_SCRIPT,
        healthcare_llm_policy(allow_domains=LLM_DOMAINS),
        payload={
            "patient_id": patient_id,
            "patient_first_name": p.name.split()[0],
            "labs": p.labs,
            "references": refs,
        },
        # llama-index-core + llms-openai are baked into the `ai-agent` template
        envs=llm_envs(),
        timeout=400,
    )

    print("\n--- Patient-facing message ---")
    print(out["text"])


if __name__ == "__main__":
    main()
