"""W6 — Trial Match, sandboxed with declaw.

Runs the entire LlamaIndex FunctionAgent INSIDE one microVM with egress
restricted to `{api.openai.com, clinicaltrials.gov}`. Every tool call the
agent issues — including the live HTTP fetches against clinicaltrials.gov
— crosses declaw's proxy. PHI in the LLM prompt is redacted + rehydrated.

Declaw benefit most visible here: **per-destination network allowlist**.
If a compromised `ctgov_detail` helper tried to exfiltrate the patient
chart to `attacker-fake-ctgov.com`, the SNI filter refuses the connection.
"""
from __future__ import annotations

import sys
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "sandboxed"))
from shared.mock_phi import PATIENTS  # noqa: E402
from shared.declaw_helpers import (  # noqa: E402
    healthcare_multi_api_policy, llm_envs, run_python_in_sandbox,
)


TRIAL_AGENT_SCRIPT = textwrap.dedent("""
    import asyncio, json, urllib.parse, urllib.request
    from llama_index.core.agent.workflow import FunctionAgent
    from llama_index.core.tools import FunctionTool
    from llama_index.llms.openai import OpenAI as LlamaOpenAI

    with open('/tmp/in.json') as f: inp = json.load(f)
    PATIENT = inp['patient']; PID = PATIENT['id']

    def _get_json(url, timeout=15):
        req = urllib.request.Request(url, headers={'Accept':'application/json'})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())

    def fetch_patient(patient_id: str) -> dict:
        \"\"\"Pull the patient record.\"\"\"
        assert patient_id == PID
        return PATIENT

    def search_trials_live(condition: str) -> list:
        \"\"\"Search ClinicalTrials.gov v2 for RECRUITING trials matching a condition keyword.\"\"\"
        q = urllib.parse.urlencode({
            'query.cond': condition,
            'filter.overallStatus': 'RECRUITING',
            'pageSize': 3,
        })
        try:
            data = _get_json(f'https://clinicaltrials.gov/api/v2/studies?{q}')
        except Exception as e:
            return [{'error': f'{type(e).__name__}'}]
        out = []
        for s in (data.get('studies') or [])[:3]:
            p = s.get('protocolSection') or {}
            idm = p.get('identificationModule') or {}
            stm = p.get('statusModule') or {}
            cdm = p.get('conditionsModule') or {}
            dsm = p.get('designModule') or {}
            out.append({
                'nct_id': idm.get('nctId'),
                'title': idm.get('briefTitle'),
                'status': stm.get('overallStatus'),
                'phase': (dsm.get('phases') or [None])[0],
                'conditions': cdm.get('conditions') or [],
            })
        return out

    def get_trial_detail(nct_id: str) -> dict:
        \"\"\"Pull the full eligibility criteria for a single NCT ID.\"\"\"
        try:
            data = _get_json(f'https://clinicaltrials.gov/api/v2/studies/{nct_id}')
        except Exception as e:
            return {'nct_id': nct_id, 'error': f'{type(e).__name__}'}
        p = data.get('protocolSection') or {}
        e = p.get('eligibilityModule') or {}
        return {
            'nct_id': nct_id,
            'eligibility_criteria': (e.get('eligibilityCriteria') or '')[:2000],
            'minimum_age': e.get('minimumAge'),
            'maximum_age': e.get('maximumAge'),
            'sex': e.get('sex'),
        }

    async def main():
        agent = FunctionAgent(
            tools=[
                FunctionTool.from_defaults(fn=fetch_patient),
                FunctionTool.from_defaults(fn=search_trials_live),
                FunctionTool.from_defaults(fn=get_trial_detail),
            ],
            llm=LlamaOpenAI(model='gpt-4.1'),
            system_prompt=(
                'You are a clinical research coordinator. Step 1: call '
                f'fetch_patient("{PID}"). Step 2: pick ONE lowercase '
                'condition word and call search_trials_live. Step 3: call '
                'get_trial_detail on the most relevant NCT ID. Step 4: emit '
                'a final plain-text verdict naming the trial, giving a '
                'one-line eligibility assessment, and one data gap you would '
                'want confirmed before enrollment.'
            ),
        )
        resp = await agent.run(user_msg=f'Find a matching clinical trial for patient_id={PID}.')
        with open('/tmp/out.json','w') as f: json.dump({'verdict': str(resp)}, f)

    asyncio.run(main())
""")


def main() -> None:
    patient_id = "p-002"
    p = PATIENTS[patient_id]
    patient = {"id": p.id, "name": p.name, "dob": p.dob, "sex": p.sex,
               "diagnoses": p.diagnoses, "medications": p.medications,
               "labs": p.labs, "notes": p.notes}
    print("=== Trial Match — LlamaIndex + live ctgov (sandboxed, one microVM) ===\n")
    out = run_python_in_sandbox(
        "trial-match-ctgov", TRIAL_AGENT_SCRIPT,
        healthcare_multi_api_policy(),
        payload={"patient": patient},
        envs=llm_envs(),
        timeout=300,
    )
    print("\n--- Verdict (inside declaw microVM) ---")
    print(out["verdict"])


if __name__ == "__main__":
    main()
