"""W7 — MSL Literature Support, sandboxed with declaw.

Governance posture (see shared/governance.py): MLR (medical-legal-regulatory)
review is a mandatory human process. The AutoGen chat produces a DRAFT brief
only — it never states FDA-approved indications as a final, publishable answer.
The writer ends with DRAFT_READY_FOR_MLR_REVIEW; the brief is marked
DRAFT_PENDING_REVIEW and a human REVIEWER_MLR approves before publication.

Same AutoGen chat, but runs entirely inside one microVM whose egress
allowlist is `{api.openai.com, eutils.ncbi.nlm.nih.gov, api.fda.gov}`.
This workflow ingests untrusted external content (PubMed abstracts and
FDA label text) — prime territory for indirect prompt injection — so
the policy here ALSO turns on `InjectionDefenseConfig(action='log_only')`
to surface attempts in the audit log without blocking legit traffic.

Declaw benefits visible here:
  * Injection detector fires on poisoned PubMed abstracts (audit log).
  * Network allowlist stops tool drift — writer agent trying to exfil
    a draft to a non-allowlisted destination is refused at iptables.
  * Audit log per destination — compliance team can answer 'which FDA
    endpoints did this MSL query hit last week?' from structured events.
"""
from __future__ import annotations

import sys
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "sandboxed"))
from shared import governance as gov  # noqa: E402
from shared.declaw_helpers import (  # noqa: E402
    healthcare_multi_api_policy, llm_envs, run_python_in_sandbox,
)


MSL_SCRIPT = textwrap.dedent("""
    import asyncio, json, re, urllib.parse, urllib.request
    from autogen_agentchat.agents import AssistantAgent
    from autogen_agentchat.conditions import (MaxMessageTermination,
                                              TextMentionTermination)
    from autogen_agentchat.teams import RoundRobinGroupChat
    from autogen_ext.models.openai import OpenAIChatCompletionClient

    with open('/tmp/in.json') as f: inp = json.load(f)
    QUESTION = inp['question']

    # Governance labels injected from shared.governance on the host (the sandbox
    # cannot import the shared module). The LLM produces a DRAFT only; a human MLR
    # (medical-legal-regulatory) reviewer approves before publication.
    GOV = inp['gov']
    DRAFT_PENDING_REVIEW = GOV['DRAFT_PENDING_REVIEW']
    REVIEWER_MLR = GOV['REVIEWER_MLR']

    def _get_json(url, timeout=15):
        req = urllib.request.Request(url, headers={'Accept':'application/json'})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())

    def pubmed_search(query: str, retmax: int = 3) -> list:
        \"\"\"PMID list for a query from PubMed eutils.\"\"\"
        q = urllib.parse.urlencode({'db':'pubmed','term':query,'retmax':retmax,
                                     'retmode':'json','sort':'most+recent'})
        try:
            d = _get_json(f'https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi?{q}')
            return (d.get('esearchresult') or {}).get('idlist') or []
        except Exception: return []

    def pubmed_fetch(pmids: list) -> list:
        \"\"\"Titles + abstracts for PMIDs from PubMed eutils.\"\"\"
        if not pmids: return []
        q = urllib.parse.urlencode({'db':'pubmed','id':','.join(pmids),
                                     'rettype':'abstract','retmode':'xml'})
        try:
            req = urllib.request.Request(f'https://eutils.ncbi.nlm.nih.gov/entrez/eutils/efetch.fcgi?{q}')
            with urllib.request.urlopen(req, timeout=15) as r:
                xml = r.read().decode(errors='replace')
        except Exception: return []
        out = []
        for m in re.finditer(r'<PubmedArticle>(.*?)</PubmedArticle>', xml, re.S):
            b = m.group(1)
            pm = re.search(r'<PMID[^>]*>(\\d+)</PMID>', b)
            ti = re.search(r'<ArticleTitle>(.*?)</ArticleTitle>', b, re.S)
            ab = re.search(r'<Abstract>(.*?)</Abstract>', b, re.S)
            out.append({'pmid': pm.group(1) if pm else None,
                        'title': re.sub(r'<[^>]+>','',ti.group(1)).strip() if ti else None,
                        'abstract': re.sub(r'<[^>]+>',' ',ab.group(1)).strip()[:1200] if ab else ''})
        return out

    def openfda_label(drug_name: str) -> dict:
        \"\"\"FDA label for a drug (generic name first, brand as fallback).\"\"\"
        for field in ('generic_name','brand_name'):
            search = urllib.parse.quote(f'openfda.{field}:\"{drug_name}\"')
            url = f'https://api.fda.gov/drug/label.json?search={search}&limit=1'
            try:
                d = _get_json(url)
                results = d.get('results') or []
                if results:
                    r = results[0]
                    return {'drug': drug_name,
                            'indications': ' '.join(r.get('indications_and_usage', []))[:600],
                            'warnings': ' '.join(r.get('warnings', []) or r.get('warnings_and_cautions', []))[:600]}
            except Exception: pass
        return {'drug': drug_name, 'label': None}

    async def main():
        model = OpenAIChatCompletionClient(model='gpt-4.1')
        lit = AssistantAgent(
            name='literature_search', model_client=model,
            tools=[pubmed_search, pubmed_fetch], reflect_on_tool_use=True,
            system_message=(
                'You are an MSL literature-search specialist. Call '
                'pubmed_search(query, retmax=3) then pubmed_fetch(pmids). '
                'Summarize 3 findings with PMID citations in 4 bullets. '
                'Then hand off to label_lookup.'
            ),
        )
        label = AssistantAgent(
            name='label_lookup', model_client=model,
            tools=[openfda_label], reflect_on_tool_use=True,
            system_message=(
                'You are an FDA-label researcher. Call openfda_label(drug_name) '
                'and state the FDA-approved indication + key warnings in <=3 '
                'lines. Then hand off to writer.'
            ),
        )
        writer = AssistantAgent(
            name='writer', model_client=model,
            system_message=(
                'You are an MSL drafting a brief for MLR review — this is a DRAFT, '
                'NOT a final or publishable answer, and FDA-approved indications '
                'you state are draft claims awaiting review. Combine the literature '
                'bullets + FDA label snippet into a 6-sentence MLR-adjacent DRAFT '
                'with inline PMID citations. State that this is '
                f'{DRAFT_PENDING_REVIEW} and that a human {REVIEWER_MLR} must '
                'approve it before any external use or publication. '
                'End your message with the literal token DRAFT_READY_FOR_MLR_REVIEW.'
            ),
        )
        team = RoundRobinGroupChat(
            [lit, label, writer],
            termination_condition=TextMentionTermination('DRAFT_READY_FOR_MLR_REVIEW')
                                  | MaxMessageTermination(20),
        )
        result = await team.run(task=QUESTION)
        brief = ''
        for m in result.messages:
            if getattr(m, 'source', None) == 'writer':
                c = getattr(m, 'content', '')
                if isinstance(c, str) and 'DRAFT_READY_FOR_MLR_REVIEW' in c:
                    brief = c
        transcript = [f\"[{getattr(m,'source','?')}] {str(getattr(m,'content',''))[:500]}\" for m in result.messages]
        with open('/tmp/out.json','w') as f:
            json.dump({'brief': brief, 'transcript': transcript}, f)

    asyncio.run(main())
""")


QUESTION = (
    "Recent evidence on mepolizumab for severe eosinophilic asthma — what do "
    "the most-recent trials plus the FDA label say about exacerbation reduction?"
)


def main() -> None:
    print("=== MSL Literature Support (sandboxed, 1 microVM, injection scan ON) ===")
    print(f"governance: {gov.governance_banner()}")
    print(f"The LLM produces a DRAFT for MLR review; a human {gov.REVIEWER_MLR} "
          f"approves before publication ({gov.DRAFT_PENDING_REVIEW}).\n")
    out = run_python_in_sandbox(
        "msl-literature", MSL_SCRIPT,
        healthcare_multi_api_policy(enable_injection_scan=True),
        payload={
            "question": QUESTION,
            # Governance labels — the LLM only DRAFTS; a human MLR reviewer owns
            # publication (the sandbox can't import shared.governance).
            "gov": {
                "DRAFT_PENDING_REVIEW": gov.DRAFT_PENDING_REVIEW,
                "REVIEWER_MLR": gov.REVIEWER_MLR,
            },
        },
        envs=llm_envs(),
        timeout=420,
    )
    print("--- Transcript ---")
    for line in out.get("transcript", []):
        print(line)
    print("\n--- DRAFT MLR brief (pending MLR review) ---")
    print(out.get("brief") or "(no writer message captured)")
    print(f"\n[gate] This brief is {gov.DRAFT_PENDING_REVIEW}: a human "
          f"{gov.REVIEWER_MLR} must approve it before any external use or "
          "publication. Nothing is published autonomously.")


if __name__ == "__main__":
    main()
