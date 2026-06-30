"""Internal policy chunks — proprietary regulatory Q&A corpus.

These are synthesised from actual RBI / SEBI / FATF / PCI-DSS public language
but tagged as 'INTERNAL-CONFIDENTIAL' to demonstrate what Declaw's network
allowlist + PII policy prevents from egressing. A policy snippet that reaches
a third-party LLM is an IP leak.
"""
from __future__ import annotations

CIRCULARS: list[dict[str, str]] = [
    {
        "id": "RBI-2025-DL-01",
        "issuer": "RBI",
        "title": "Guidelines on Digital Lending",
        "excerpt": (
            "All disbursals and repayments shall be executed between the bank "
            "accounts of the borrower and the Regulated Entity only. Data "
            "collection shall be minimal and purpose-specific. Loan aggregator "
            "apps shall disclose the APR in a Key Facts Statement before "
            "borrower consent. Recovery agents shall not contact borrowers "
            "before 8 AM or after 7 PM and shall not use threatening language."
        ),
    },
    {
        "id": "SEBI-IA-2013",
        "issuer": "SEBI",
        "title": "Investment Advisers Regulations, 2013",
        "excerpt": (
            "No person shall act as an investment adviser without obtaining a "
            "certificate of registration from SEBI. An investment adviser shall "
            "act in a fiduciary capacity. Personalised advice shall be offered "
            "only after risk-profiling the client and assessing suitability."
        ),
    },
    {
        "id": "FATF-REC-10",
        "issuer": "FATF",
        "title": "Customer Due Diligence",
        "excerpt": (
            "Financial institutions should undertake CDD measures when "
            "establishing business relations; carrying out occasional "
            "transactions above the applicable designated threshold (USD/EUR "
            "15,000); when there is a suspicion of ML/TF; or when the FI has "
            "doubts about the veracity of previously obtained identification."
        ),
    },
    {
        "id": "FATF-REC-20",
        "issuer": "FATF",
        "title": "Reporting of Suspicious Transactions",
        "excerpt": (
            "If a financial institution suspects or has reasonable grounds to "
            "suspect that funds are the proceeds of a criminal activity, or are "
            "related to terrorist financing, it should be required, by law, to "
            "report its suspicions promptly to the Financial Intelligence Unit."
        ),
    },
    {
        "id": "PCI-DSS-3.2",
        "issuer": "PCI SSC",
        "title": "PCI-DSS v4.0 Requirement 3.2",
        "excerpt": (
            "Storage of sensitive authentication data (full track data, CVV, "
            "PIN/PIN-block) is prohibited after authorisation, even if "
            "encrypted. PAN, when displayed, shall be masked to reveal no more "
            "than the first six and last four digits."
        ),
    },
    {
        "id": "DPDP-2023-S8",
        "issuer": "MeitY",
        "title": "DPDP Act — Obligations of Data Fiduciaries",
        "excerpt": (
            "A Data Fiduciary shall process personal data only for the lawful "
            "purpose for which consent has been given. Aadhaar, financial "
            "information, and biometric data are 'sensitive personal data' and "
            "shall not be transferred to jurisdictions notified by the Central "
            "Government without Data Fiduciary accountability."
        ),
    },
    {
        "id": "SEC-17-CFR-275",
        "issuer": "SEC",
        "title": "Investment Advisers Act — Fiduciary Duty",
        "excerpt": (
            "An investment adviser is a fiduciary and must act in the best "
            "interest of its clients, place clients' interests ahead of its "
            "own, and not engage in any fraudulent, deceptive, or manipulative "
            "act, practice, or course of business."
        ),
    },
    {
        "id": "FDCPA-1692d",
        "issuer": "US CFPB",
        "title": "Fair Debt Collection Practices Act",
        "excerpt": (
            "A debt collector may not engage in any conduct the natural "
            "consequence of which is to harass, oppress, or abuse any person. "
            "Calls between 9 PM and 8 AM are presumed inconvenient. "
            "Threatening violence, using obscene language, or advertising "
            "the debt is prohibited."
        ),
    },
]


# Internal, proprietary policy — must never egress to an external LLM
INTERNAL_POLICY_CONFIDENTIAL = (
    "[INTERNAL-CONFIDENTIAL — Ursa Capital Risk & Compliance Playbook v4.2]\n"
    "1. Declined underwriting reasons MUST be mapped to ECOA adverse-action "
    "codes (not bureau-side codes) in every notice.\n"
    "2. Any transaction above USD 9,500 where counterparty is domiciled in "
    "FATF-grey-list jurisdictions must file CTR + SAR within 15 business "
    "days, escalated to Head of Compliance Stephanie Park.\n"
    "3. Robo-advisor suitability override window is 48h; beyond that the client "
    "must re-profile.\n"
    "4. Any agent tool-call that would execute a trade above INR 10,00,000 or "
    "USD 15,000 MUST be human-reviewed by the Wealth desk (Bharat Menon)."
)
