"""Convergent governance core + jurisdiction overlays (see ../../GOVERNANCE.md).

The workflows are globally relatable: the same agent runs everywhere, and the
*jurisdiction* is a thin, swappable overlay — not a fork. This module holds that
overlay as config plus a few helpers, so a workflow can:

  * decide the binding outcome deterministically / via a human gate (never the LLM),
  * format the customer-facing adverse-action reason the way the jurisdiction wants,
  * pick the declaw OPA governance pack (`policy_ref`) for the jurisdiction,
  * pin egress to an in-region data-residency profile.

Select the jurisdiction with the DECLAW_JURISDICTION env var (default "IN").
This module is pure config — it imports nothing from declaw, so it loads in the
local-mock path too.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


# ---------- Decision statuses (the LLM never emits a *binding* one) ----------
# Outcomes an LLM/rule step may PROPOSE; the binding action requires the gate.
RECOMMEND_APPROVE = "RECOMMEND_APPROVE"
RECOMMEND_DECLINE = "RECOMMEND_DECLINE"
RECOMMEND_REVIEW = "RECOMMEND_REVIEW"
# Gate states owned by the human node.
PENDING_HUMAN_CONFIRMATION = "PENDING_HUMAN_CONFIRMATION"
DRAFT_READY_FOR_OFFICER_REVIEW = "DRAFT_READY_FOR_OFFICER_REVIEW"


@dataclass(frozen=True)
class JurisdictionProfile:
    code: str
    name: str
    regulators: tuple[str, ...]
    # "reason_codes" (US ECOA principal reasons) vs "reasoned_explanation"
    adverse_action_format: str
    # EU/UK: expose an explicit human-review affordance (GDPR Art. 22)
    automated_decision_rights: bool
    # EU: credit scoring + insurance pricing are high-risk → extra logging/oversight
    high_risk_regime: bool
    # in-region egress requirement (RBI payments localization, GDPR transfers)
    data_residency: str | None
    # declaw OPA governance pack referenced per jurisdiction
    governance_pack: str
    notes: str = ""
    # extra in-region endpoints to keep egress inside the residency boundary
    residency_domains: tuple[str, ...] = field(default_factory=tuple)


JURISDICTION_PROFILES: dict[str, JurisdictionProfile] = {
    "IN": JurisdictionProfile(
        code="IN", name="India",
        regulators=("RBI", "SEBI", "IRDAI"),
        adverse_action_format="reasoned_explanation",
        automated_decision_rights=False,   # DPDP grants no GDPR-Art-22-style ADM right
        high_risk_regime=False,
        data_residency="in-region (RBI 2018 payments-data localization)",
        governance_pack="baseline-hardening@v1",
        notes="RBI AI guidance (FREE-AI 2025, MRM drafts) recommendatory; "
              "SBR outsourcing keeps the RE accountable.",
    ),
    "US": JurisdictionProfile(
        code="US", name="United States",
        regulators=("Fed/OCC (SR 11-7)", "CFPB/ECOA", "SEC/FINRA", "FinCEN"),
        adverse_action_format="reason_codes",   # ECOA Reg B principal reasons
        automated_decision_rights=False,
        high_risk_regime=False,
        data_residency=None,
        governance_pack="nist-ai-rmf@v1",
        notes="ECOA reason codes are the hard, in-force requirement on credit denial; "
              "CFPB: AI is not an exemption.",
    ),
    "EU": JurisdictionProfile(
        code="EU", name="European Union",
        regulators=("EU AI Act", "EBA", "EDPB/DPAs (GDPR)"),
        adverse_action_format="reasoned_explanation",
        automated_decision_rights=True,    # GDPR Art. 22 human-review right
        high_risk_regime=True,             # credit scoring + insurance pricing
        data_residency="GDPR transfer rules",
        governance_pack="eu-ai-act@v1",
        notes="Strongest overlay: AI-Act high-risk obligations + GDPR Art. 22.",
    ),
    "UK": JurisdictionProfile(
        code="UK", name="United Kingdom",
        regulators=("FCA", "PRA", "ICO"),
        adverse_action_format="reasoned_explanation",
        automated_decision_rights=True,
        high_risk_regime=False,
        data_residency="UK GDPR transfer rules",
        governance_pack="nist-ai-rmf@v1",
        notes="Principles-based; like EU minus the binding AI Act.",
    ),
    "SG": JurisdictionProfile(
        code="SG", name="Singapore",
        regulators=("MAS (FEAT/Veritas)",),
        adverse_action_format="reasoned_explanation",
        automated_decision_rights=False,
        high_risk_regime=False,
        data_residency=None,
        governance_pack="iso-42001@v1",
        notes="MAS FEAT is principles-based guidance — covered by the core; thin overlay.",
    ),
    "AE": JurisdictionProfile(
        code="AE", name="UAE / Gulf",
        regulators=("DIFC", "ADGM"),
        adverse_action_format="reasoned_explanation",
        automated_decision_rights=False,
        high_risk_regime=False,
        data_residency=None,
        governance_pack="baseline-hardening@v1",
        notes="Principles-based data + AI guidance; light overlay.",
    ),
}

DEFAULT_JURISDICTION = "IN"


def active_jurisdiction() -> JurisdictionProfile:
    """The jurisdiction profile selected by DECLAW_JURISDICTION (default IN)."""
    code = os.getenv("DECLAW_JURISDICTION", DEFAULT_JURISDICTION).upper()
    return JURISDICTION_PROFILES.get(code, JURISDICTION_PROFILES[DEFAULT_JURISDICTION])


def governance_pack(profile: JurisdictionProfile | None = None) -> str:
    """The declaw OPA governance-pack policy_ref for the jurisdiction — the
    one-line swap that makes the same agent region-appropriate."""
    return (profile or active_jurisdiction()).governance_pack


def format_adverse_action(reasons: list[str],
                          profile: JurisdictionProfile | None = None) -> dict:
    """Shape a customer-facing adverse-action notice for the jurisdiction.

    US → ECOA Reg B principal reason codes; everyone else → a reasoned
    explanation. EU/UK additionally advertise the right to human review (Art. 22).
    """
    p = profile or active_jurisdiction()
    out: dict = {"jurisdiction": p.code, "format": p.adverse_action_format}
    if p.adverse_action_format == "reason_codes":
        out["reason_codes"] = [
            {"code": f"AA{idx + 1:02d}", "principal_reason": r}
            for idx, r in enumerate(reasons)
        ]
    else:
        out["reasons"] = list(reasons)
    if p.automated_decision_rights:
        out["human_review_right"] = (
            "You may request human review of this decision and meaningful "
            "information about the logic involved (GDPR Art. 22).")
    return out


def governance_banner(profile: JurisdictionProfile | None = None) -> str:
    """One-line summary for terminal output — makes the overlay visible in demos."""
    p = profile or active_jurisdiction()
    bits = [f"jurisdiction={p.code} ({p.name})",
            f"regulators={'/'.join(p.regulators)}",
            f"governance_pack={p.governance_pack}",
            f"adverse_action={p.adverse_action_format}"]
    if p.high_risk_regime:
        bits.append("EU-AI-Act-high-risk")
    if p.automated_decision_rights:
        bits.append("Art.22-human-review")
    if p.data_residency:
        bits.append(f"data_residency={p.data_residency}")
    return " | ".join(bits)
