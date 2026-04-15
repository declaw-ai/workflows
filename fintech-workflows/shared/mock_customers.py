"""Synthetic customer records for fintech workflow demos. NOT real PII.

Each Customer carries both an Indian identity set (PAN, Aadhaar, UPI VPA, IFSC,
GSTIN, CIBIL) and a US/global set (SSN, routing, FICO, EIN) so the same fixture
can drive workflows for Navi-style Indian NBFCs *and* Stripe/Brex-style US fintechs.

All values are intentionally fake but format-valid so that regex-based PII
detectors (including Declaw's) can find them — PAN 5A+4D+1A, Aadhaar 12 digits,
SSN 9 digits with dashes, card PAN Luhn-valid test numbers, etc.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Customer:
    id: str
    name: str
    dob: str
    # India identity set
    pan: str
    aadhaar: str         # 12-digit Aadhaar — treat as ultra-sensitive (DPDP)
    upi_vpa: str
    ifsc: str
    account_number: str
    gstin: str | None = None
    cibil_score: int | None = None
    # US / global identity set
    ssn: str | None = None
    routing_number: str | None = None
    fico_score: int | None = None
    ein: str | None = None
    # Contact
    email: str = ""
    phone: str = ""
    address: str = ""
    # Financial snapshot
    monthly_income: int = 0
    employment: str = ""
    cards_on_file: list[dict[str, Any]] = field(default_factory=list)


CUSTOMERS: dict[str, Customer] = {
    "c-001": Customer(
        id="c-001",
        name="Aarav Sharma",
        dob="1989-06-14",
        pan="ABCDE1234F",
        aadhaar="2345 6789 0123",
        upi_vpa="aarav@okicici",
        ifsc="HDFC0001234",
        account_number="50100234567890",
        gstin=None,
        cibil_score=762,
        ssn="123-45-6789",            # same customer has a US ITIN-style filing
        routing_number="021000021",
        fico_score=720,
        email="aarav.sharma@example.com",
        phone="+91 98210 34567",
        address="12 MG Road, Bengaluru 560001, India",
        monthly_income=185000,
        employment="Senior SDE at TechCo Pvt Ltd",
        cards_on_file=[
            {"last4": "1111", "pan_full": "4111 1111 1111 1111", "cvv": "123",
             "brand": "Visa", "exp": "12/28"},
        ],
    ),
    "c-002": Customer(
        id="c-002",
        name="Priya Iyer",
        dob="1994-02-28",
        pan="PQRSX5678G",
        aadhaar="3456 7890 1234",
        upi_vpa="priya.iyer@ybl",
        ifsc="ICIC0004567",
        account_number="628101511987",
        gstin="29ABCDE1234F1Z5",       # GSTIN tied to her SMB
        cibil_score=688,
        ssn=None,
        fico_score=None,
        ein="84-1234567",              # she owns a US LLC too
        email="priya@leafandloom.co",
        phone="+91 99002 11874",
        address="Flat 4B, Prestige Apts, Koramangala, Bengaluru 560095",
        monthly_income=340000,
        employment="Founder — Leaf & Loom Pvt Ltd (D2C textiles)",
        cards_on_file=[
            {"last4": "0004", "pan_full": "4242 4242 4242 4242", "cvv": "456",
             "brand": "Visa-test", "exp": "06/27"},
        ],
    ),
    "c-003": Customer(
        id="c-003",
        name="Rohan Desai",
        dob="1975-11-02",
        pan="LMNOP9012H",
        aadhaar="4567 8901 2345",
        upi_vpa="rohan@paytm",
        ifsc="SBIN0011234",
        account_number="30011234500",
        gstin=None,
        cibil_score=541,               # sub-prime — underwriting should decline
        ssn="987-65-4321",
        routing_number="011000015",
        fico_score=580,
        email="r.desai@gmail.com",
        phone="+91 88670 20199",
        address="Plot 22, Sector 18, Noida 201301",
        monthly_income=62000,
        employment="Self-employed — daily wage contractor",
        cards_on_file=[],
    ),
    "c-004": Customer(
        id="c-004",
        name="Maya Patel",
        dob="1996-09-17",
        pan="UVWXY3456J",
        aadhaar="5678 9012 3456",
        upi_vpa="maya@upi",
        ifsc="KKBK0000512",
        account_number="9876543210123",
        gstin=None,
        cibil_score=0,                 # thin-file — alt-data driven
        ssn=None,
        fico_score=None,
        email="maya.patel@freelance.io",
        phone="+91 70045 98122",
        address="221 Park Street, Kolkata 700017",
        monthly_income=98000,
        employment="Freelance UX designer",
        cards_on_file=[],
    ),
    "c-005": Customer(
        id="c-005",
        name="James Whitaker",
        dob="1982-03-21",
        pan="WHTJA8765K",              # NRI — has both sets
        aadhaar="6789 0123 4567",
        upi_vpa="james@icici",
        ifsc="ICIC0000456",
        account_number="000501987654",
        gstin=None,
        cibil_score=745,
        ssn="555-12-3456",
        routing_number="122000247",
        fico_score=780,
        ein="52-7654321",
        email="james@whitaker.ai",
        phone="+1 415 555 0183",
        address="1 Market St, San Francisco, CA 94103",
        monthly_income=720000,
        employment="CTO — Whitaker AI Inc (US)",
        cards_on_file=[
            {"last4": "0005", "pan_full": "5555 5555 5555 4444", "cvv": "789",
             "brand": "Mastercard-test", "exp": "09/29"},
        ],
    ),
}


# Fintech regulation fixtures — one policy-like dict per programme, following
# the same shape as health-tech's PAYER_POLICIES so workflows can look up the
# applicable rule set by key.
LENDING_POLICIES: dict[str, dict[str, Any]] = {
    "personal_loan_india": {
        "jurisdictions": ["IN"],
        "criteria": [
            "CIBIL score >= 700 OR 12 months of positive alt-data",
            "Monthly income >= INR 25,000",
            "Age 21-60",
            "No >90 DPD in last 24 months",
        ],
        "documentation_required": ["PAN", "Aadhaar (masked)", "Latest 6 months bank statements"],
        "max_ltv_ratio": None,
        "interest_cap_apr": 36.0,  # RBI digital-lending ceiling reference
    },
    "smb_working_capital_global": {
        "jurisdictions": ["IN", "US"],
        "criteria": [
            "Business vintage >= 24 months",
            "GSTIN or EIN active",
            "Avg monthly bank inflow >= INR 500,000 / USD 10,000",
            "No active sanctions hits",
        ],
        "documentation_required": ["GSTIN/EIN", "24 months statements", "ITR-3 or 1120-S"],
        "max_ltv_ratio": 0.3,
        "interest_cap_apr": 24.0,
    },
    "credit_card_secured_us": {
        "jurisdictions": ["US"],
        "criteria": [
            "FICO >= 580 OR no bureau file",
            "US address verified",
            "SSN or ITIN on file",
        ],
        "documentation_required": ["SSN/ITIN", "Proof of address", "Security deposit >= $200"],
        "interest_cap_apr": 29.99,
    },
}


# Known bad actors for sanctions/AML mocks
SANCTIONED_COUNTERPARTIES: dict[str, dict[str, Any]] = {
    "ACME-SHELLCO-LTD": {
        "source": "OFAC SDN (mocked)",
        "reason": "suspected trade-based money laundering",
        "country": "CY",
    },
    "DELTA-FX-HOUSE-DMCC": {
        "source": "UN consolidated (mocked)",
        "reason": "sanctions evasion typology",
        "country": "AE",
    },
}
