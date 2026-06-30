"""Salesforce-style mock CRM: payer relationship records."""
from __future__ import annotations
from typing import Any

ACCOUNTS: dict[str, dict[str, Any]] = {
    "acc-aetna":    {"name": "Aetna", "tier": "gold",   "network_effective_date": "2024-09-01", "renegotiation_flag": False, "notes": "Stable — no recent issues."},
    "acc-bcbs":     {"name": "BCBS",  "tier": "silver", "network_effective_date": "2024-06-01", "renegotiation_flag": True,  "notes": "Contract renegotiation Feb 2026 tightened prior-auth rules for clinic-north; many new denial codes."},
    "acc-uhc":      {"name": "UHC",   "tier": "gold",   "network_effective_date": "2025-01-01", "renegotiation_flag": False, "notes": "Quarterly audit, nothing notable."},
    "acc-medicare": {"name": "Medicare", "tier": "platinum", "network_effective_date": "2019-01-01", "renegotiation_flag": False, "notes": "CMS fee schedule updated Jan 2026 — small downward adjustment."},
}


def crm_search(account_filter: str | None = None) -> list[dict[str, Any]]:
    """Return CRM accounts. If account_filter set, substring-match on name."""
    rows = list(ACCOUNTS.values())
    if account_filter:
        rows = [r for r in rows if account_filter.lower() in r["name"].lower()]
    return rows


def crm_get(account_name: str) -> dict[str, Any] | None:
    for v in ACCOUNTS.values():
        if v["name"].lower() == account_name.lower():
            return v
    return None
