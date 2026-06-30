# Compliance review — hand-off for counsel (read before any public use)

> ⚠️ **Not legal advice.** This repo's regulatory mapping is **engineering guidance
> informed by research**, not a compliance certification. The workflows use
> **synthetic data only**. Before any claim here is used in a landing page,
> marketing copy, sales deck, or customer commitment, it must be reviewed by
> qualified counsel for the relevant jurisdiction. This document exists to make
> that review fast and structured.

## How to use this doc
Every regulatory statement in the repo falls into one of two buckets:

- **Engineering fact** — something the code *demonstrably does*, verifiable on a
  replay / in the verify scripts. Safe to state boldly (e.g. on the landing page).
- **Legal interpretation** — a claim that the architecture *satisfies / aligns with*
  a statute. This is a legal judgment; it must be **hedged** in public copy and
  **signed off** by counsel below.

**Language policy (enforced across the repo + any public copy):**
- ✅ Engineering facts: "the LLM never issues the binding decision", "PII is redacted
  on egress", "every action is audited", "the denial is held for a human".
- ⚠️ Legal claims: use **"designed to support" / "aligns with the direction of" /
  "maps to"** — **never** "compliant with", "guarantees", "satisfies", "certified".

## Bucket 1 — Engineering facts (verifiable; safe to show)
These are proven by the verify scripts + the live runs (fintech 17/17, health 7/7)
and are replayable on screen. They carry no legal-claim risk.

| Fact | Evidence |
|------|----------|
| The LLM does not emit the binding decision — a deterministic rule or a human gate does | `GOVERNANCE.md`; every decision workflow; live `human-gate`/`recommend` markers |
| PII/PHI is redacted on egress and rehydrated on response (CVV never rehydrated) | `verify_pii_handling.py`; live runs |
| Prompt injection is detected/blocked | `verify_security_primitives.py` ck7; injection demos |
| Per-action audit record (data-left-which-sandbox-to-where) | declaw audit store; `AuditConfig` |
| Egress is allowlisted / pinned to a residency region | `verify_security_primitives.py` ck1/5/10; `NetworkPolicy` |
| Governance pack denies disallowed commands at the gate | `verify_security_primitives.py` ck12 |
| Secrets brokered via vault never enter the VM | `verify_security_primitives.py` ck11 |

## Bucket 2 — Legal interpretations (HEDGE + sign off before public use)
Each row: the claim, where it appears, the source from the research passes, and a
counsel verdict column. Citations are starting points, not authority.

### Fintech
| # | Claim (as it should appear, hedged) | Where | Source | Counsel verdict |
|---|--------------------------------------|-------|--------|-----------------|
| F1 | Material credit decisions should not be fully delegated to an opaque model; the institution stays accountable | wf01/07; GOVERNANCE | RBI SBR Annex XIII; Fed/OCC SR 11-7 | ☐ |
| F2 | US credit denials carry ECOA/Reg B adverse-action **reason codes** | wf01 (US overlay) | ECOA / Reg B; CFPB circular 2022-03 | ☐ |
| F3 | EU AI Act classifies credit scoring + insurance pricing as high-risk | GOVERNANCE; EU overlay | EU AI Act Annex III | ☐ |
| F4 | EU/UK: right to human review of solely-automated decisions | GOVERNANCE; EU/UK overlay | GDPR Art. 22 | ☐ |
| F5 | India payments-data localization (data residency) | GOVERNANCE; IN overlay | RBI 2018 storage-of-payment-system-data directive | ☐ |
| F6 | Card CVV must not be retained/returned post-auth | wf04; pci policy | PCI-DSS v4 req 3.2 | ☐ |
| F7 | India DPDP does **not** grant a GDPR-Art-22-style automated-decision right (so we don't claim it does) | GOVERNANCE | DPDP Act 2023 (research-verified, refuted the overreach) | ☐ |

### Health-tech
| # | Claim (hedged) | Where | Source | Counsel verdict |
|---|----------------|-------|--------|-----------------|
| H1 | A medical-necessity **denial** must be owned by a licensed clinician, not an algorithm | wf01; GOVERNANCE | CMS 42 CFR 422.101(c); CMS 2024 Interop/PA final rule; CA SB 1120; IL clinical-peer | ☐ |
| H2 | Algorithmic-denial litigation establishes real exposure | GOVERNANCE rationale | UnitedHealth nH Predict; Cigna PXDX suits | ☐ |
| H3 | CDS that leaves an independent practitioner review may be non-device | wf05 framing | FDA CDS guidance; 21st C. Cures non-device CDS criteria | ☐ |
| H4 | EU AI Act high-risk applies to medical AI | GOVERNANCE; EU overlay | EU AI Act + MDR | ☐ |
| H5 | Autonomous medical coding / 837 carries FCA/upcoding exposure → coder sign-off | wf03 | False Claims Act; coding-compliance practice | ☐ |
| H6 | Medical/promotional content requires MLR review before publication | wf07 | FDA OPDP; industry MLR practice | ☐ |
| H7 | PHI handling + residency (HIPAA / GDPR special-category / DPDP+ABDM) | GOVERNANCE; health overlay | HIPAA; GDPR Art. 9; DPDP+ABDM; Abu Dhabi DoH 147/2022 | ☐ |

## Landing-page / public-demo gate (because the demos are public copy)
- **Synthetic data only** — show a persistent "synthetic data · illustrative" label.
- **Disclaimer footer** on any demo that names a statute: "illustrative; not legal advice."
- **Hedge all Bucket-2 language** per the policy above; lead with Bucket-1 facts.
- **Exclude repo-only workflows** from the public rotation — currently **wf06**
  (autonomous robo-advice), per `GOVERNANCE.md §3`.
- No "compliant / certified / guarantees" anywhere in public copy.

## Sign-off
- [ ] Counsel (fintech jurisdictions) — name / date
- [ ] Counsel (health jurisdictions) — name / date
- [ ] Marketing copy reviewed against the hedged-language policy — name / date
