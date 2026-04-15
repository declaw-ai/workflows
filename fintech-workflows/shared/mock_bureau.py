"""Synthetic credit-bureau responses (CIBIL / Experian India / FICO-shaped US).

Returns a structured dict per customer with score + tradelines + flags, shaped
like what a production bureau integration would hand to the underwriting agent.
Data is intentionally correlated with `mock_customers.CUSTOMERS[*].cibil_score`
so downstream workflows see consistent risk signals.
"""
from __future__ import annotations

from typing import Any

from shared.mock_customers import CUSTOMERS  # resolved via sys.path.insert(REPO_ROOT) in run.py


def cibil_report(customer_id: str) -> dict[str, Any]:
    c = CUSTOMERS[customer_id]
    score = c.cibil_score or 0
    tradelines: list[dict[str, Any]] = []
    flags: list[str] = []

    if customer_id == "c-001":
        tradelines = [
            {"type": "credit_card", "lender": "HDFC Bank", "limit_inr": 500000,
             "utilisation_pct": 22, "status": "current", "dpd_12mo_max": 0},
            {"type": "auto_loan", "lender": "Tata Capital", "principal_inr": 850000,
             "outstanding_inr": 410000, "status": "current", "dpd_12mo_max": 0},
        ]
    elif customer_id == "c-002":
        tradelines = [
            {"type": "credit_card", "lender": "ICICI Bank", "limit_inr": 800000,
             "utilisation_pct": 58, "status": "current", "dpd_12mo_max": 5},
            {"type": "loan_against_property", "lender": "Bajaj Finance",
             "principal_inr": 2500000, "outstanding_inr": 2100000,
             "status": "current", "dpd_12mo_max": 0},
        ]
        flags.append("high_revolving_utilisation")
    elif customer_id == "c-003":
        tradelines = [
            {"type": "personal_loan", "lender": "NBFC-Navi", "principal_inr": 150000,
             "outstanding_inr": 112000, "status": "90+_DPD", "dpd_12mo_max": 112},
            {"type": "credit_card", "lender": "Axis Bank", "limit_inr": 60000,
             "utilisation_pct": 98, "status": "60_DPD", "dpd_12mo_max": 62},
        ]
        flags += ["written_off_last_36mo", "multiple_enquiries_90d", "sub_prime"]
    elif customer_id == "c-004":
        # thin-file
        flags.append("no_bureau_history")
    elif customer_id == "c-005":
        tradelines = [
            {"type": "home_loan", "lender": "HDFC", "principal_inr": 25000000,
             "outstanding_inr": 18000000, "status": "current", "dpd_12mo_max": 0},
        ]

    return {
        "customer_id": customer_id,
        "pan": c.pan,                 # INTENTIONAL: raw PAN in response — Declaw redacts before egress
        "aadhaar_masked": "XXXX XXXX " + c.aadhaar.split()[-1],
        "score": score,
        "score_band": (
            "thin_file" if score == 0 else
            "sub_prime" if score < 650 else
            "near_prime" if score < 720 else
            "prime" if score < 780 else "super_prime"
        ),
        "tradelines": tradelines,
        "flags": flags,
        "enquiries_last_30d": 1 if customer_id in {"c-001", "c-005"} else (
            4 if customer_id == "c-003" else 0),
    }


def fico_report(customer_id: str) -> dict[str, Any]:
    c = CUSTOMERS[customer_id]
    if not c.fico_score:
        return {"customer_id": customer_id, "bureau": "Experian US",
                "status": "no_hit", "score": None}
    return {
        "customer_id": customer_id,
        "bureau": "Experian US",
        "ssn_last_4": (c.ssn or "").split("-")[-1],  # INTENTIONAL: SSN in payload
        "score": c.fico_score,
        "band": "good" if c.fico_score >= 700 else "fair" if c.fico_score >= 640 else "poor",
        "tradelines_count": 6 if customer_id == "c-005" else 2,
        "delinquencies_24mo": 0 if customer_id != "c-003" else 3,
    }
