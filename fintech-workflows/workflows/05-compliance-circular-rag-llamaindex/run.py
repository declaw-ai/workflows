"""Compliance Circular RAG — BASELINE (OnFinance ComplianceOS-lite style).

FunctionAgent with tools:
  - search_circulars   : retrieves matching chunks from the public corpus
  - cite_source        : formats a regulatory citation for the final answer
  - horizon_scan_new   : pulls the latest RBI RSS feed for live circulars

INTENTIONAL SECURITY FLAW (baseline demo):
  The agent's system prompt and tool payload include the full text of
  INTERNAL_POLICY_CONFIDENTIAL ("Ursa Capital Risk & Compliance Playbook v4.2").
  Every question the user asks causes this proprietary document to be transmitted
  to OpenAI in cleartext — an IP / regulatory data leak.

  In the sandboxed variant (sandboxed/05-...) this is prevented by:
    * compliance_rag_policy: injection_defense=block (catches injected PDFs)
    * PII redact+rehydrate (tokenises any customer IDs inside policy chunks)
    * The internal-policy text is chunked+tokenised before LLM egress.

Demo questions:
  "What is RBI's guidance on disbursal accounts for digital loans?"
  "Draft a gap analysis against PCI-DSS v4 requirement 3.2."
"""
from __future__ import annotations

import asyncio
import sys
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from shared.mock_policies import CIRCULARS, INTERNAL_POLICY_CONFIDENTIAL  # noqa: E402
from shared.external_apis import rbi_circulars_rss  # noqa: E402

from llama_index.core.agent.workflow import FunctionAgent
from llama_index.core.tools import FunctionTool
from llama_index.llms.openai import OpenAI as LlamaOpenAI


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def search_circulars(query: str) -> list[dict]:
    """Search the regulatory-circular corpus for chunks relevant to `query`.

    Returns a list of dicts with keys: id, issuer, title, excerpt.
    The corpus includes RBI, SEBI, FATF, PCI-DSS, DPDP, SEC, and FDCPA entries.
    Also appends INTERNAL_POLICY_CONFIDENTIAL — NOTE: this leaks proprietary
    text to the LLM in the baseline variant.
    """
    query_lower = query.lower()
    hits = [
        c for c in CIRCULARS
        if any(term in c["excerpt"].lower() or term in c["title"].lower()
               for term in query_lower.split())
    ]
    if not hits:
        hits = CIRCULARS  # fall back to full corpus for broad questions

    # INTENTIONAL LEAK: append internal policy as a pseudo-circular chunk
    hits = list(hits) + [{
        "id": "INTERNAL-CONFIDENTIAL",
        "issuer": "Ursa Capital",
        "title": "Risk & Compliance Playbook v4.2",
        "excerpt": INTERNAL_POLICY_CONFIDENTIAL,
    }]
    return hits


def cite_source(circular_id: str, issuer: str, title: str, relevant_text: str) -> str:
    """Format a regulatory citation for inclusion in the compliance answer.

    Returns a Markdown-formatted citation string.
    """
    return (
        f"**[{circular_id}]** {issuer} — *{title}*\n"
        f"> {relevant_text[:300]}{'...' if len(relevant_text) > 300 else ''}"
    )


def horizon_scan_new(limit: int = 5) -> list[dict]:
    """Fetch the latest RBI circulars from the live RSS feed for horizon scanning.

    Returns a list of dicts with keys: title, url, pub_date.
    Falls back to an empty list if the feed is unreachable.
    """
    return rbi_circulars_rss(limit=limit)


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = textwrap.dedent("""
    You are a compliance analyst assistant for a regulated Indian fintech (NBFC/PA).
    Your knowledge base covers RBI, SEBI, FATF, PCI-DSS, DPDP, SEC, and FDCPA regulations.

    Workflow for every user question:
    1. Call search_circulars(query) to retrieve relevant regulatory chunks.
    2. For each relevant chunk, call cite_source(...) to format the citation.
    3. If the user asks about new or upcoming regulations, call horizon_scan_new().
    4. Compose a concise, grounded answer with inline citations.
    5. End with a "Sources" section listing every cited circular.

    Always be precise about jurisdiction. Never fabricate regulation text.
    Flag if a question requires legal counsel rather than an automated analysis.
""").strip()


async def run_agent(question: str) -> str:
    agent = FunctionAgent(
        tools=[
            FunctionTool.from_defaults(fn=search_circulars),
            FunctionTool.from_defaults(fn=cite_source),
            FunctionTool.from_defaults(fn=horizon_scan_new),
        ],
        llm=LlamaOpenAI(model="gpt-4.1"),
        system_prompt=SYSTEM_PROMPT,
    )
    resp = await agent.run(user_msg=question)
    return str(resp)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

DEMO_QUESTIONS = [
    "What is RBI's guidance on disbursal accounts for digital loans?",
    "Draft a gap analysis against PCI-DSS v4 requirement 3.2.",
]


def main() -> None:
    print("=" * 70)
    print("05  COMPLIANCE CIRCULAR RAG — BASELINE (insecure)")
    print("=" * 70)
    print()
    print("[!] WARNING: INTERNAL_POLICY_CONFIDENTIAL is sent to OpenAI in")
    print("    every request via search_circulars(). This is the leak demo.")
    print()

    for i, question in enumerate(DEMO_QUESTIONS, 1):
        print(f"--- Question {i} ---")
        print(f"Q: {question}")
        print()
        answer = asyncio.run(run_agent(question))
        print("A:")
        print(answer)
        print()


if __name__ == "__main__":
    main()
