# Compliance review — verification of the repo's regulatory claims

> ⚠️ **Not legal advice.** This repo's regulatory mapping is **engineering
> guidance informed by primary-source research**, not a compliance
> certification, and it uses **synthetic data only**. Nothing here asserts that
> any deployment "complies" with any law — every legal statement is deliberately
> hedged (see the language policy below). Before relying on any claim for a real
> regulated workload, validate it with qualified counsel for *your* jurisdiction.
>
> This document is a **verification record**: every regulatory citation in the
> repo was checked against the primary source, and every claim was audited
> against the hedged-language policy. Verification last refreshed **2026-07-01**.

## How to use this doc
Every regulatory statement in the repo falls into one of two buckets:

- **Engineering fact** — something the code *demonstrably does*, verifiable on a
  replay / in the verify scripts. Safe to state boldly (e.g. on the landing page).
- **Legal interpretation** — a claim that the architecture *satisfies / aligns with*
  a statute. This is a legal judgment; it is **hedged** in public copy and its
  citation has been **verified** against the primary source (table in Bucket 2).

**Language policy (enforced across the repo + any public copy):**
- ✅ Engineering facts: "the LLM never issues the binding decision", "PII is redacted
  on egress", "every action is audited", "the denial is held for a human".
- ⚠️ Legal claims: use **"designed to support" / "aligns with the direction of" /
  "maps to"** — **never** "compliant with", "guarantees", "satisfies", "certified".
- 🚫 **Do not call declaw a "human-in-the-loop / HITL / human-gate" layer.** The
  human gate is a **workflow-layer control**; declaw has no approval-gate primitive
  today (its own governance packs classify HITL as *advisory*). Correct framing:
  *"declaw makes autonomous execution impossible (egress/command denial) and audits
  it; your workflow owns the human approval."* See `GOVERNANCE.md` §1a.

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

## Bucket 2 — Legal interpretations (citation-verified + hedged)
Each row: the claim as it should appear (hedged), where it appears, the primary
source, and the verification verdict. **Verdict legend:** ✅ citation verified &
accurately hedged · ⚠️ kept deliberately general (named instance is illustrative,
not exhaustive). Citations are accurate starting points, not a substitute for counsel.

### Fintech
| # | Claim (as it should appear, hedged) | Where | Primary source | Verdict |
|---|--------------------------------------|-------|----------------|---------|
| F1 | Material credit decisions should not be fully delegated to an opaque model; the institution stays accountable | wf01/07; GOVERNANCE | RBI SBR outsourcing accountability; Fed/OCC **SR 11-7** model risk mgmt | ✅ |
| F2 | US credit denials carry ECOA/Reg B adverse-action **reason codes** — and an algorithm is not an exemption | wf01 (US overlay) | ECOA / Reg B; **CFPB Circular 2022-03** | ✅ |
| F3 | EU AI Act classifies credit scoring + life/health-insurance pricing as high-risk | GOVERNANCE; EU overlay | **EU AI Act Annex III** §5(b) credit, §5(c) insurance | ✅ |
| F4 | EU/UK: right to human review of solely-automated decisions with legal/significant effect | GOVERNANCE; EU/UK overlay | **GDPR Art. 22** | ✅ |
| F5 | India payments-data localization (data residency) | GOVERNANCE; IN overlay | **RBI "Storage of Payment System Data", 6 Apr 2018** | ✅ |
| F6 | Card CVV must not be retained/returned post-auth | wf04; pci policy | **PCI-DSS v4.0 req 3.3.1** (SAD not retained after authorization) | ✅ |
| F7 | India DPDP does **not** grant a GDPR-Art-22-style automated-decision right (so we don't claim it does) | GOVERNANCE | DPDP Act 2023 — no ADM/profiling right; max penalty ₹250 cr | ✅ (refutes the overreach) |

### Health-tech
| # | Claim (hedged) | Where | Primary source | Verdict |
|---|----------------|-------|----------------|---------|
| H1 | A medical-necessity **denial** must be owned by a licensed clinician, not an algorithm | wf01; GOVERNANCE | CMS **42 CFR 422.566(d)** (physician denies for medical necessity) + **422.101(c)**; CMS-0057-F 2024 PA rule; **CA SB 1120** (eff. 1 Jan 2025) + a growing set of US state physician-review laws | ⚠️ state cite kept general — CA SB 1120 is the firm one; "growing set" is not an exhaustive list |
| H2 | Algorithmic-denial litigation establishes real exposure | GOVERNANCE rationale | UnitedHealth/NaviHealth **nH Predict** class action; **Cigna PXDX** suits | ✅ |
| H3 | CDS that leaves an independent practitioner review may be non-device | wf05 framing | FDA CDS guidance; 21st C. Cures **non-device CDS** criteria | ✅ (hedged "may be") |
| H4 | EU AI Act high-risk applies to medical AI | GOVERNANCE; EU overlay | EU AI Act Art. 6(1) + Annex I (MDR-regulated devices) | ✅ |
| H5 | Autonomous medical coding / 837 carries FCA/upcoding exposure → coder sign-off | wf03 | False Claims Act; coding-compliance practice | ✅ |
| H6 | Medical/promotional content requires MLR review before publication | wf07 | FDA OPDP; industry MLR practice | ✅ |
| H7 | PHI handling + residency (HIPAA / GDPR special-category / DPDP+ABDM / UAE health-data rules) | GOVERNANCE; health overlay | HIPAA; GDPR Art. 9; DPDP + ABDM; UAE/Abu Dhabi health-data rules | ⚠️ kept general — named UAE instrument is illustrative |

## Landing-page / public-demo gate (because the demos are public copy)
- **Synthetic data only** — show a persistent "synthetic data · illustrative" label.
- **Disclaimer footer** on any demo that names a statute: "illustrative; not legal advice."
- **Hedge all Bucket-2 language** per the policy above; lead with Bucket-1 facts.
- **Exclude repo-only workflows** from the public rotation — currently **wf06**
  (autonomous robo-advice), per `GOVERNANCE.md §3`.
- No "compliant / certified / guarantees" anywhere in public copy.

## Verification record
- **Citations** — every Bucket-2 source checked against the primary text
  (statute / regulator page / final or proposed rule), last refreshed 2026-07-01.
- **Language** — repo + this register audited against the hedged-language policy;
  no "compliant / certified / guarantees / satisfies" remains on a legal claim.
- **Residual — genuinely a legal call, by design.** Engineering can verify that a
  citation is accurate and that the wording is hedged. What it *cannot* produce is
  a jurisdiction-specific legal opinion that a given production deployment
  "complies" — which is exactly why **the repo asserts no such thing** and every
  claim is hedged. If you put these workflows in front of a regulated customer,
  route the hedged Bucket-2 claims through that customer's compliance/legal
  function for their jurisdiction; nothing in the repo's framing depends on a
  compliance opinion we don't have.
