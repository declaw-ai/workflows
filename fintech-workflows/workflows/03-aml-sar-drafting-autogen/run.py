"""AML / SAR Drafting workflow — AutoGen RoundRobinGroupChat — UNSANDBOXED BASELINE.

FATF Recommendation 10 (customer due diligence) + Recommendation 20 (suspicious
activity reporting) + FinCEN SAR filing guidance.

Group chat: Alert-Triager -> Graph-Investigator -> Narrative-Drafter -> Compliance-Reviewer
- Alert-Triager:       classifies transaction patterns against OFAC SDN list
- Graph-Investigator:  maps counterparty graph, checks structuring signals
- Narrative-Drafter:   composes FATF Rec 20 / FinCEN SAR narrative
- Compliance-Reviewer: validates narrative, appends SAR_READY token

SECURITY NOTICE (UNSANDBOXED):
  * Counterparty names, PANs, VPAs, SSNs sent RAW to OpenAI
  * Full OFAC query results (including hit details) in the group-chat context
  * No injection-defense scan on transaction memo fields
Compare: sandboxed/03-aml-sar-drafting-autogen/run.py wraps the chat in
         multi_bank_api_policy(enable_injection_scan=True) and tokenises
         counterparty PII before every LLM egress.
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from shared.mock_customers import CUSTOMERS, SANCTIONED_COUNTERPARTIES  # noqa: E402
from shared.mock_transactions import upi_transactions, ach_transactions  # noqa: E402
from shared.external_apis import ofac_sdn_names, is_sanctioned  # noqa: E402

# AutoGen imports
from autogen_agentchat.agents import AssistantAgent  # noqa: E402
from autogen_agentchat.conditions import (  # noqa: E402
    MaxMessageTermination,
    TextMentionTermination,
)
from autogen_agentchat.teams import RoundRobinGroupChat  # noqa: E402
from autogen_ext.models.openai import OpenAIChatCompletionClient  # noqa: E402

# ---------------------------------------------------------------------------
# Tool functions — run in the host process (UNSANDBOXED)
# ---------------------------------------------------------------------------

_CUSTOMER_ID: str = ""  # set at runtime


def fetch_transactions(customer_id: str) -> dict:
    """Return all UPI and ACH transactions for the given customer."""
    print(f"  [UNSANDBOXED] fetch_transactions({customer_id}) — PII in tool results")
    return {
        "upi": upi_transactions(customer_id),
        "ach": ach_transactions(customer_id),
    }


def check_ofac(name: str) -> dict:
    """Check whether a counterparty name appears on the OFAC SDN list.
    UNSANDBOXED: raw name + hit details sent to OpenAI in follow-up context.
    """
    print(f"  [UNSANDBOXED] check_ofac({name!r}) — result will leak to LLM prompt unredacted")
    result = is_sanctioned(name)
    # Also check our local fixtures
    local_hit = SANCTIONED_COUNTERPARTIES.get(name.upper())
    if local_hit:
        result["local_fixture_hit"] = local_hit
        result["sanctioned"] = True
    return result


def structuring_check(transactions: list) -> dict:
    """Detect structuring patterns (transactions just below $10,000 BSA threshold).
    UNSANDBOXED: outputs contain customer PAN and VPA in plain text.
    """
    suspects = [
        t for t in transactions
        if (t.get("amount_usd") or 0) >= 9000 and (t.get("amount_usd") or 0) < 10000
    ]
    upi_suspects = [
        t for t in transactions
        if (t.get("amount_inr") or 0) >= 45000 and (t.get("risk_flags"))
    ]
    return {
        "structuring_suspects_ach": suspects,
        "high_risk_upi": upi_suspects,
        "structuring_flag": bool(suspects),
    }


# ---------------------------------------------------------------------------
# Main — group chat runs directly in host process
# ---------------------------------------------------------------------------

async def main() -> None:
    customer_id = "c-005"  # James Whitaker — structured $9990 wires to OFAC-listed entities
    # Alternatively: "c-003" — Rohan Desai — sanctions-linked VPAs
    c = CUSTOMERS[customer_id]

    print("=" * 70)
    print("AML / SAR Drafting — UNSANDBOXED BASELINE")
    print("=" * 70)
    print(f"Customer: {c.name}  PAN={c.pan}  SSN={c.ssn}  VPA={c.upi_vpa}")
    print("[WARN] Raw PII visible in host logs — UNSANDBOXED run\n")

    txns = fetch_transactions(customer_id)
    all_txns = txns["upi"] + txns["ach"]
    struct = structuring_check(all_txns)

    # UNSANDBOXED: full PII bundle passed as task context to the group chat
    task_context = json.dumps({
        "customer_id": customer_id,
        "customer_name": c.name,
        "pan": c.pan,           # RAW PAN — DPDP / GLBA violation
        "ssn": c.ssn,           # RAW SSN — GLBA violation
        "upi_vpa": c.upi_vpa,
        "email": c.email,
        "phone": c.phone,
        "address": c.address,
        "transactions": all_txns,
        "structuring_analysis": struct,
    }, indent=2)

    model = OpenAIChatCompletionClient(model="gpt-4.1")

    triager = AssistantAgent(
        name="Alert_Triager",
        model_client=model,
        tools=[fetch_transactions, check_ofac],
        reflect_on_tool_use=True,
        system_message=(
            "You are an AML Alert Triager following FATF Recommendation 10 (CDD). "
            "Given the transaction data, call check_ofac for each distinct counterparty "
            "name found in ACH wire descriptions (e.g. 'ACME-SHELLCO-LTD', "
            "'DELTA-FX-HOUSE-DMCC'). Summarise which transactions have counterparty "
            "hits and which show potential structuring (multiple transactions just under "
            "$10,000). Pass your findings to Graph-Investigator."
        ),
    )

    investigator = AssistantAgent(
        name="Graph_Investigator",
        model_client=model,
        tools=[check_ofac, structuring_check],
        reflect_on_tool_use=True,
        system_message=(
            "You are a Financial Intelligence Graph Investigator. "
            "Review the Alert Triager's findings. Call structuring_check on the ACH "
            "transactions list. Map the counterparty network: identify shell-company "
            "indicators (round amounts, Cyprus/UAE routing, no business rationale). "
            "Assess FATF typologies present (trade-based ML, structuring, layering). "
            "Summarise the counterparty graph and risk factors for the Narrative Drafter."
        ),
    )

    drafter = AssistantAgent(
        name="Narrative_Drafter",
        model_client=model,
        system_message=(
            "You are a FinCEN SAR Narrative Drafter. Using the graph investigator's "
            "findings, draft a complete SAR narrative per FinCEN SAR form instructions "
            "(fields: who, what, when, where, why suspicious). Reference FATF "
            "Recommendation 20 (reporting suspicious transactions). The narrative must "
            "include: (1) subject identification, (2) suspicious activity description, "
            "(3) amount and date range, (4) relevant typology codes. "
            "NOTE: in this UNSANDBOXED run, subject PII (name, SSN, PAN) appear in plain "
            "text. Pass to Compliance-Reviewer for final sign-off."
        ),
    )

    reviewer = AssistantAgent(
        name="Compliance_Reviewer",
        model_client=model,
        system_message=(
            "You are a Senior Compliance Reviewer. Review the SAR narrative for "
            "completeness against FinCEN SAR filing requirements and FATF Rec 20. "
            "Check: (1) all mandatory fields present, (2) no speculative language, "
            "(3) objective factual basis stated, (4) amount threshold met. "
            "Approve or request revisions. When the narrative is satisfactory, "
            "append the token SAR_READY on a line by itself to close the workflow."
        ),
    )

    team = RoundRobinGroupChat(
        [triager, investigator, drafter, reviewer],
        termination_condition=(
            TextMentionTermination("SAR_READY") | MaxMessageTermination(20)
        ),
    )

    task = (
        f"Conduct AML investigation and draft a SAR for the following case. "
        f"Transaction and customer data (UNSANDBOXED — contains raw PII):\n{task_context}"
    )

    print("--- Group Chat Transcript ---")
    result = await team.run(task=task)

    for msg in result.messages:
        source = getattr(msg, "source", "?")
        content = getattr(msg, "content", "")
        if isinstance(content, str) and content.strip():
            print(f"\n[{source}]\n{content[:600]}")

    # Extract final SAR narrative from Compliance_Reviewer
    sar_msgs = [
        m for m in result.messages
        if getattr(m, "source", "") == "Compliance_Reviewer"
        and isinstance(getattr(m, "content", ""), str)
        and getattr(m, "content", "").strip()
    ]
    final_sar = sar_msgs[-1].content if sar_msgs else "(no SAR narrative captured)"

    print("\n" + "=" * 70)
    print("FINAL SAR NARRATIVE (Compliance-Reviewer)")
    print("=" * 70)
    print(final_sar[:1200])
    print("\n[WARN] SAR narrative above contains raw PII — UNSANDBOXED baseline.")
    print("[WARN] Compare sandboxed/03 which tokenises subject identifiers before egress.")


if __name__ == "__main__":
    asyncio.run(main())
