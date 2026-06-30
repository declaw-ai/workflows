"""Convergent governance core for health-tech — human-gate + overlays.

Same principle as the fintech vertical (see ../../GOVERNANCE.md): the workflows
are globally relatable, the LLM never owns a MATERIAL clinical / coverage / coding
decision, and the jurisdiction is a thin overlay. Grounded in health-AI research:
across US / EU-UK / India / SG / UAE a LICENSED HUMAN must own any material
clinical, coverage, or coding decision (US Medicare-Advantage 42 CFR 422.101(c) +
CMS 2024 PA rule + state physician-review laws like CA SB 1120 / IL clinical-peer;
FDA non-device CDS "independent practitioner review"; EU AI Act high-risk medical;
FCA coding liability). The overlay differs only in WHO the human is and the
PHI-residency target.

Select jurisdiction with DECLAW_JURISDICTION (default "US"). Pure config — imports
nothing from declaw, so it loads on the local-mock path too.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


# ---------- Decision statuses (the LLM never emits a *binding* one) ----------
RECOMMEND_APPROVE = "RECOMMEND_APPROVE"
RECOMMEND_DENY = "RECOMMEND_DENY"
RECOMMEND_REVIEW = "RECOMMEND_REVIEW"
PENDING_HUMAN_CONFIRMATION = "PENDING_HUMAN_CONFIRMATION"
DRAFT_PENDING_REVIEW = "DRAFT_PENDING_REVIEW"
DRAFT_READY_FOR_MLR_REVIEW = "DRAFT_READY_FOR_MLR_REVIEW"

# ---------- Who the licensed human reviewer is (the health overlay) ----------
REVIEWER_CLINICIAN = "licensed clinician"          # prior-auth / clinical decisions
REVIEWER_CERTIFIED_CODER = "certified medical coder"  # ICD-10/CPT / 837 claims
REVIEWER_MLR = "MLR (medical-legal-regulatory) reviewer"  # medical/promotional content


@dataclass(frozen=True)
class HealthJurisdiction:
    code: str
    name: str
    frameworks: tuple[str, ...]
    # in-region PHI residency requirement (egress kept in-region)
    phi_residency: str | None
    # EU AI Act high-risk medical layer → extra logging + human oversight
    high_risk_regime: bool
    governance_pack: str
    notes: str = ""


HEALTH_JURISDICTIONS: dict[str, HealthJurisdiction] = {
    "US": HealthJurisdiction(
        code="US", name="United States",
        frameworks=("HIPAA", "CMS / Medicare Advantage", "FDA CDS/SaMD",
                    "state physician-review laws (CA SB 1120, IL clinical-peer)"),
        phi_residency=None,
        high_risk_regime=False,
        governance_pack="nist-ai-rmf@v1",
        notes="Medical-necessity DENIAL must be made by a licensed clinician, not "
              "an algorithm (42 CFR 422.101(c); CMS 2024 PA rule).",
    ),
    "EU": HealthJurisdiction(
        code="EU", name="European Union",
        frameworks=("GDPR (special-category health data)", "EU MDR", "EU AI Act (high-risk medical)"),
        phi_residency="GDPR transfer rules",
        high_risk_regime=True,
        governance_pack="eu-ai-act@v1",
        notes="Medical AI is high-risk under the AI Act: human oversight + "
              "transparency + record-keeping on top of MDR.",
    ),
    "UK": HealthJurisdiction(
        code="UK", name="United Kingdom",
        frameworks=("UK GDPR", "MHRA / DTAC", "NICE ESF"),
        phi_residency="UK GDPR transfer rules",
        high_risk_regime=False,
        governance_pack="nist-ai-rmf@v1",
        notes="Principles-based; clinician owns the clinical decision.",
    ),
    "IN": HealthJurisdiction(
        code="IN", name="India",
        frameworks=("DPDP Act", "ABDM", "Telemedicine Practice Guidelines"),
        phi_residency="in-region (DPDP + ABDM health-data handling)",
        high_risk_regime=False,
        governance_pack="baseline-hardening@v1",
        notes="Registered medical practitioner owns the clinical decision.",
    ),
    "SG": HealthJurisdiction(
        code="SG", name="Singapore",
        frameworks=("PDPA", "MOH AIHGle", "HSA"),
        phi_residency=None,
        high_risk_regime=False,
        governance_pack="iso-42001@v1",
        notes="MOH AI-in-healthcare guidelines: clinician-in-the-loop.",
    ),
    "AE": HealthJurisdiction(
        code="AE", name="UAE / Gulf",
        frameworks=("DoH Abu Dhabi (Circular 147/2022)", "DHA", "PDPL"),
        phi_residency="in-region (Abu Dhabi DoH health-data localization)",
        high_risk_regime=False,
        governance_pack="baseline-hardening@v1",
        notes="Health-data localization; licensed clinician owns the decision.",
    ),
}

DEFAULT_JURISDICTION = "US"


def active_jurisdiction() -> HealthJurisdiction:
    code = os.getenv("DECLAW_JURISDICTION", DEFAULT_JURISDICTION).upper()
    return HEALTH_JURISDICTIONS.get(code, HEALTH_JURISDICTIONS[DEFAULT_JURISDICTION])


def governance_pack(j: HealthJurisdiction | None = None) -> str:
    return (j or active_jurisdiction()).governance_pack


def governance_banner(j: HealthJurisdiction | None = None) -> str:
    j = j or active_jurisdiction()
    bits = [f"jurisdiction={j.code} ({j.name})",
            f"frameworks={'/'.join(j.frameworks)}",
            f"governance_pack={j.governance_pack}"]
    if j.high_risk_regime:
        bits.append("EU-AI-Act-high-risk-medical")
    if j.phi_residency:
        bits.append(f"phi_residency={j.phi_residency}")
    return " | ".join(bits)


# ---------- Enforcing primitives (deterministic gates — the shared core) ----------
# Make the human gate non-bypassable in code, not a prompt instruction or an
# LLM-emitted token. Route every workflow that owns a material clinical/coverage/
# coding decision through one of these so enforcement quality is uniform.

def officer_gate(recommendation: str, *, reviewer: str = REVIEWER_CLINICIAN, **detail) -> dict:
    """Stamp a recommendation as held for a licensed human reviewer. The binding
    clinical/coverage/coding decision is owned by the human, never the LLM."""
    return {"status": PENDING_HUMAN_CONFIRMATION, "recommendation": recommendation,
            "reviewer": reviewer, **detail}


def require_human(content, *, reviewer: str, status: str = DRAFT_PENDING_REVIEW, **detail) -> dict:
    """Wrap an LLM-produced artifact as a DRAFT held for a named human reviewer —
    a deterministic stamp on the artifact in code, NOT an LLM-emitted token."""
    return {"status": status, "reviewer": reviewer, "content": content, **detail}
