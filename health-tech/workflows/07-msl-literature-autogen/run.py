"""W7 — MSL Literature Support (real AutoGen v0.4, live PubMed + openFDA).

A field-medical question on a drug is routed through a 3-agent group
chat. Each agent has its own tools hitting different public APIs:

  * literature_search — PubMed E-utilities (esearch + efetch)
  * label_lookup      — openFDA drug label
  * writer            — composes MLR-adjacent summary with citations

This is the first workflow that ingests untrusted external content
(PubMed abstracts + FDA label text) — a real injection vector for
agent systems. The sandboxed variant opts injection scanning back on.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.conditions import (MaxMessageTermination,
                                          TextMentionTermination)
from autogen_agentchat.teams import RoundRobinGroupChat
from autogen_ext.models.openai import OpenAIChatCompletionClient

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
from shared.external_apis import (  # noqa: E402
    openfda_label, pubmed_fetch, pubmed_search,
)


QUESTION = (
    "Recent evidence on mepolizumab for severe eosinophilic asthma — what do "
    "the most-recent trials plus the FDA label say about exacerbation reduction?"
)


async def run_chat(question: str) -> list[str]:
    model = OpenAIChatCompletionClient(model="gpt-4.1")

    lit = AssistantAgent(
        name="literature_search", model_client=model,
        tools=[pubmed_search, pubmed_fetch],
        reflect_on_tool_use=True,
        system_message=(
            "You are an MSL literature-search specialist. Given a question, "
            "call pubmed_search(query, retmax=3) to get PMIDs, then "
            "pubmed_fetch(pmids) to get titles + abstracts. Summarize the "
            "3 most informative findings with PMID citations in 4 bullet "
            "points maximum. Then hand off to label_lookup."
        ),
    )
    label = AssistantAgent(
        name="label_lookup", model_client=model,
        tools=[openfda_label],
        reflect_on_tool_use=True,
        system_message=(
            "You are an FDA-label researcher. Given the drug the literature "
            "specialist summarized, call openfda_label(drug_name) and state "
            "the FDA-approved indication + key warnings in at most 3 lines. "
            "Then hand off to the writer."
        ),
    )
    writer = AssistantAgent(
        name="writer", model_client=model,
        system_message=(
            "You are an MSL writing a brief for a field medical director. "
            "Combine the literature bullets + the FDA label snippet into a "
            "6-sentence MLR-adjacent brief with inline PMID citations. End "
            "your message with the literal token MLR_REVIEW_READY."
        ),
    )

    team = RoundRobinGroupChat(
        [lit, label, writer],
        termination_condition=TextMentionTermination("MLR_REVIEW_READY")
                              | MaxMessageTermination(20),
    )
    result = await team.run(task=question)
    return [
        f"[{getattr(m, 'source', '?')}] {str(getattr(m, 'content', ''))[:600]}"
        for m in result.messages
    ]


def main() -> None:
    print("=== MSL Literature Support (baseline, AutoGen + live PubMed/openFDA) ===\n")
    lines = asyncio.run(run_chat(QUESTION))
    for l in lines:
        print(l)


if __name__ == "__main__":
    main()
