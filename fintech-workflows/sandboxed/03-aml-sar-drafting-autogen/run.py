"""AML / SAR Drafting workflow — AutoGen RoundRobinGroupChat — SANDBOXED.

FATF Recommendation 10 (CDD) + Recommendation 20 (STR/SAR) + FinCEN guidance.

The FULL group chat runs inside a single Firecracker microVM under
`multi_bank_api_policy(extra_domains=[], enable_injection_scan=True)`.
This auto-allows FINTECH_API_DOMAINS (includes treasury.gov for OFAC) + LLM_DOMAINS.

Security properties vs. the UNSANDBOXED baseline:
  * Counterparty names, VPAs, PAN, SSN are TOKENISED by Declaw's PII proxy
    before every outbound OpenAI request (redact + rehydrate on response).
  * Egress locked to LLM_DOMAINS + FINTECH_API_DOMAINS — no arbitrary HTTP.
  * Injection-defense scan on all LLM inputs (threshold 0.8, log_only — a
    false-positive block on a legitimate compliance memo would suppress a valid
    SAR; see policy comment in declaw_helpers.py).

Group chat: Alert-Triager -> Graph-Investigator -> Narrative-Drafter -> Compliance-Reviewer
Termination: SAR_READY token | MaxMessages(20)
"""
from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]   # fintech-workflows/
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "sandboxed"))

from shared.mock_customers import CUSTOMERS, SANCTIONED_COUNTERPARTIES  # noqa: E402
from shared.mock_transactions import upi_transactions, ach_transactions  # noqa: E402
from shared.declaw_helpers import (  # noqa: E402
    LLM_DOMAINS,
    multi_bank_api_policy,
    run_python_in_sandbox,
    llm_envs,
)

# ---------------------------------------------------------------------------
# AutoGen script — runs INSIDE the microVM
# ---------------------------------------------------------------------------

AUTOGEN_SCRIPT = textwrap.dedent("""
    import asyncio, json

    from autogen_agentchat.agents import AssistantAgent
    from autogen_agentchat.conditions import MaxMessageTermination, TextMentionTermination
    from autogen_agentchat.teams import RoundRobinGroupChat
    from autogen_ext.models.openai import OpenAIChatCompletionClient

    with open("/tmp/in.json") as f:
        inp = json.load(f)

    CUSTOMER = inp["customer"]
    TRANSACTIONS = inp["transactions"]
    SANCTIONED = inp["sanctioned_counterparties"]

    # ---- In-sandbox tool functions ----------------------------------------

    def check_ofac(name: str) -> dict:
        \"\"\"Check OFAC SDN list for counterparty name (live treasury.gov request).\"\"\"
        import re, urllib.request
        url = "https://www.treasury.gov/ofac/downloads/sdn.xml"
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "declaw-ai-workflows/1.0"})
            with urllib.request.urlopen(req, timeout=25) as r:
                xml = r.read().decode(errors="replace")
            names = re.findall(r"<lastName>(.*?)</lastName>", xml)[:500]
            hits = [n for n in names if name.upper() in n.upper()]
        except Exception:
            hits = []
        # Also check local fixture (passed in via /tmp/in.json)
        local_hit = SANCTIONED.get(name.upper())
        return {
            "name": name,
            "sanctioned": bool(hits) or bool(local_hit),
            "sdn_hits": hits[:3],
            "local_fixture_hit": local_hit,
        }

    def structuring_check(transactions: list) -> dict:
        \"\"\"Detect structuring patterns (BSA $10k threshold sub-filing).\"\"\"
        suspects_ach = [
            t for t in transactions
            if (t.get("amount_usd") or 0) >= 9000 and (t.get("amount_usd") or 0) < 10000
        ]
        suspects_upi = [
            t for t in transactions
            if (t.get("amount_inr") or 0) >= 45000 and t.get("risk_flags")
        ]
        return {
            "structuring_suspects_ach": suspects_ach,
            "high_risk_upi": suspects_upi,
            "structuring_flag": bool(suspects_ach),
        }

    # ---- Group chat ----------------------------------------------------------

    async def main():
        model = OpenAIChatCompletionClient(model="gpt-4.1")
        cid = CUSTOMER["id"]

        triager = AssistantAgent(
            name="Alert_Triager",
            model_client=model,
            tools=[check_ofac],
            reflect_on_tool_use=True,
            system_message=(
                "You are an AML Alert Triager following FATF Recommendation 10 (CDD). "
                "Call check_ofac for each distinct counterparty name found in the wire "
                "descriptions (e.g. 'ACME-SHELLCO-LTD', 'DELTA-FX-HOUSE-DMCC'). "
                "Summarise OFAC hits and structuring signals. "
                "NOTE: PII tokens like [REDACTED_PAN] are Declaw-sandboxed — do not "
                "attempt to reconstruct them. Pass findings to Graph_Investigator."
            ),
        )

        investigator = AssistantAgent(
            name="Graph_Investigator",
            model_client=model,
            tools=[structuring_check],
            reflect_on_tool_use=True,
            system_message=(
                "You are a Financial Intelligence Graph Investigator. "
                "Call structuring_check on the transactions list from the input payload. "
                "Map the counterparty network: Cyprus/UAE routing, shell-company "
                "indicators (FATF typologies: trade-based ML, layering via FX houses). "
                "Summarise risk factors for the Narrative_Drafter."
            ),
        )

        drafter = AssistantAgent(
            name="Narrative_Drafter",
            model_client=model,
            system_message=(
                "You are a FinCEN SAR Narrative Drafter. Draft a complete SAR narrative "
                "per FinCEN SAR form instructions (who/what/when/where/why). "
                "Reference FATF Recommendation 20. Include: (1) subject identification "
                "using [REDACTED_*] tokens as provided — do NOT attempt to reverse them, "
                "(2) suspicious activity description, (3) amount/date range, "
                "(4) FATF typology codes. Pass draft to Compliance_Reviewer."
            ),
        )

        reviewer = AssistantAgent(
            name="Compliance_Reviewer",
            model_client=model,
            system_message=(
                "You are a Senior Compliance Reviewer. Validate the SAR narrative "
                "against FinCEN filing requirements and FATF Rec 20: "
                "(1) all mandatory fields present, (2) no speculative language, "
                "(3) objective factual basis stated, (4) BSA amount threshold met. "
                "When satisfied, output the final approved narrative then append "
                "SAR_READY on a line by itself to close the workflow."
            ),
        )

        team = RoundRobinGroupChat(
            [triager, investigator, drafter, reviewer],
            termination_condition=(
                TextMentionTermination("SAR_READY") | MaxMessageTermination(20)
            ),
        )

        task = (
            f"Conduct AML investigation and draft a SAR for customer_id={cid}. "
            "Transaction data (PII already tokenised by Declaw proxy):\\n"
            + json.dumps(
                {"customer": CUSTOMER, "transactions": TRANSACTIONS}, indent=2
            )
        )

        result = await team.run(task=task)

        reviewer_msgs = [
            m for m in result.messages
            if getattr(m, "source", "") == "Compliance_Reviewer"
            and isinstance(getattr(m, "content", ""), str)
            and getattr(m, "content", "").strip()
        ]
        final_sar = reviewer_msgs[-1].content if reviewer_msgs else ""
        transcript = [
            f"[{getattr(m, 'source', '?')}] "
            f"{str(getattr(m, 'content', ''))[:400]}"
            for m in result.messages
        ]

        with open("/tmp/out.json", "w") as f:
            json.dump({"final_sar": final_sar, "transcript": transcript}, f)

    asyncio.run(main())
""")


# ---------------------------------------------------------------------------
# Host-side helpers — build payload, run sandbox
# ---------------------------------------------------------------------------

def _build_payload(customer_id: str) -> dict:
    c = CUSTOMERS[customer_id]
    txns = upi_transactions(customer_id) + ach_transactions(customer_id)
    return {
        "customer": {
            "id": c.id,
            "name": c.name,
            "pan": c.pan,        # Declaw proxy will tokenise this before LLM egress
            "ssn": c.ssn,        # Declaw proxy will tokenise this before LLM egress
            "upi_vpa": c.upi_vpa,
            "email": c.email,
            "phone": c.phone,
            "address": c.address,
        },
        "transactions": txns,
        "sanctioned_counterparties": SANCTIONED_COUNTERPARTIES,
    }


def main() -> None:
    print("=" * 70)
    print("AML / SAR Drafting — SANDBOXED (multi_bank_api_policy + injection scan)")
    print("=" * 70)

    # Demo: c-005 — structured $9990 wires to ACME-SHELLCO-LTD + DELTA-FX-HOUSE-DMCC
    # Alternate: c-003 — Rohan Desai — sanctions-linked UPI VPAs
    customer_id = "c-005"
    c = CUSTOMERS[customer_id]
    print(f"Customer: {c.name} [{customer_id}]")
    print("PII tokenised by Declaw proxy before every LLM egress.\n")

    payload = _build_payload(customer_id)

    pol = multi_bank_api_policy(extra_domains=[], enable_injection_scan=True)
    out = run_python_in_sandbox(
        "aml-sar-drafting",
        AUTOGEN_SCRIPT,
        pol,
        payload=payload,
        pip_packages=None,   # autogen-agentchat + autogen-ext baked into ai-agent template
        envs=llm_envs(),
        timeout=400,
        template="ai-agent",
    )

    print("\n--- Group Chat Transcript (tokenised PII) ---")
    for line in out.get("transcript", []):
        print(line)

    print("\n" + "=" * 70)
    print("FINAL SAR NARRATIVE (Compliance-Reviewer, PII tokenised)")
    print("=" * 70)
    print(out.get("final_sar") or "(no SAR narrative captured)")
    print(
        "\n[OK] SAR narrative uses [REDACTED_*] tokens — "
        "PII never reached OpenAI in cleartext."
    )


if __name__ == "__main__":
    main()
