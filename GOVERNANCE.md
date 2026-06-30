# Governance Model — convergent core + jurisdiction overlays

This repo ships **one globally-relatable set** of reference AI-agent workflows, not
a separate suite per country. The decision is grounded in how AI / automated-
decisioning regulation actually lines up across the geographies we target
(India + US + EU/UK + Singapore + UAE): the **core principles converge**, and the
genuine differences are a **small, swappable overlay** — not a different workflow.

The same convergent core maps 1:1 onto declaw primitives, so building it is also
the strongest declaw showcase: the agent stays the same, you **swap one policy
reference** and get region-appropriate governance.

---

## 1. The convergent governance core (true in every target geography)

A workflow is "safe to feature" when **the LLM is not the entity that emits the
binding, customer-impacting decision.** Two safe shapes:

1. a **deterministic rule engine decides**, the LLM only explains / classifies /
   forecasts / drafts; or
2. the LLM **proposes/drafts**, and a **human gate in code** owns the action.

Every target regulator converges on the same six requirements for AI near a
material decision. Each is a declaw primitive — so the core is non-bypassable,
not advisory:

| Convergent requirement | declaw primitive that enforces/evidences it |
|---|---|
| Institution stays accountable; no full delegation of a material decision to an opaque model | the **human gate** (`PENDING_HUMAN_APPROVAL` / officer-confirm node) |
| Human-in-the-loop / oversight on high-impact decisions | non-bypassable human node in the graph |
| Explainability + adverse-action reason for the customer | structured explanation output + **audit** record |
| Fairness / bias discipline | governance-pack attestation (`nist-ai-rmf@v1`, `eu-ai-act@v1`) |
| Auditability + record-keeping | the **audit trail** (compliance evidence) |
| Data privacy + residency | **egress allowlist** pinned in-region + **credential vault** (keys/PII never leave) |

> Evidence note: principle-level convergence is well-supported (e.g. KPMG's
> cross-jurisdiction analysis: alignment on human-centricity, transparency,
> accountability, robustness/safety). The "regulatory modes diverge by
> epistemology" counter-thesis did **not** survive adversarial review. Bind the
> design to genuine convergence — not to a "Brussels effect" assumption.

---

## 2. The jurisdiction overlay (the few things that genuinely differ)

These are the *only* places a geography needs more than the core. They are
**config**, surfaced per workflow as a `jurisdiction profile`, not forks.

| Geography | What's genuinely different (required overlay) | declaw `policy_ref` |
|---|---|---|
| **EU** | EU AI Act classifies **credit scoring + life/health-insurance pricing as high-risk** → extra logging + human-oversight + risk-mgmt. **GDPR Art. 22** → right to human review of solely-automated decisions + meaningful information. | `eu-ai-act@v1` |
| **US** | **ECOA / Reg B adverse-action reason codes** — specific principal reasons on credit denials (CFPB: AI is not an exemption). **SR 11-7** model validation discipline. | `nist-ai-rmf@v1` |
| **India** | **RBI payments-data localization (in-force, 2018)** → data residency is the hard one. SBR outsourcing accountability. AI guidance (FREE-AI Aug 2025, MRM drafts) is *recommendatory* and converges on the core. NB: **DPDP does not grant GDPR-Art-22-style automated-decision rights** — don't claim it does. | `baseline-hardening@v1` + in-region egress |
| **Singapore** | **MAS FEAT** is **principles-based guidance**, not a hard fairness-testing mandate → covered by the core; near-zero overlay. | `iso-42001@v1` |
| **UK** | FCA/PRA + ICO, principles-based; like EU minus the binding AI Act. | `nist-ai-rmf@v1` |
| **UAE/Gulf** | DIFC/ADGM data + AI guidance, principles-based; light overlay. | `baseline-hardening@v1` |

**Overlay knobs (all config):**
- `adverse_action_format`: `reason_codes` (US ECOA) vs `reasoned_explanation` (others)
- `data_residency_region`: pins the egress allowlist to in-region endpoints (India, EU)
- `automated_decision_rights`: EU/UK → expose an explicit human-review affordance (GDPR Art. 22)
- `high_risk_regime`: EU → extra logging + human-oversight attestation on credit/insurance
- `governance_pack`: the `policy_ref` swapped onto the sandbox per the table above

Switching jurisdiction = swapping the profile (and its `policy_ref`). **The
swap itself is a declaw demo.**

---

## 3. Per-workflow target posture (fintech)

Decision owner after remediation, and the human gate that must exist in code.
🟢 already a model citizen · 🟡 reframe/relabel · 🔴 behavior restructure.

| # | Workflow | Decision owner (target) | Human gate | Action |
|---|----------|-------------------------|-----------|--------|
| 01 | Credit Underwriting | rule engine; LLM explains | officer-confirm on **all** outcomes (incl. approve) | 🟡 add approve-path gate (reference impl) |
| 02 | KYC Verification | deterministic thresholds + officer | officer issues APPROVED/REJECTED | 🔴 LLM extracts/flags only |
| 03 | AML / SAR Drafting | LLM drafts; officer files | relabel `SAR_READY`→`DRAFT_READY_FOR_OFFICER_REVIEW` | 🟡 |
| 04 | Chargeback Dispute | rule (fraud score) + LLM drafts | packet is a draft; confirm before submit | 🟡 |
| 05 | Compliance RAG | assistive Q&A (no decision) | n/a | 🟢 |
| 06 | Robo-Advisor | research assist for a registered adviser | sandboxed variant: adviser issues the recommendation | 🔴 baseline = labelled threat-demo; **repo-only, not landing-page** |
| 07 | SMB Cash-Flow Underwriting | rule engine; LLM forecasts | add officer-confirm (it's credit) | 🔴→🟡 |
| 08 | Collections Outreach | LLM drafts; deterministic tone gate | queued for approval before send | 🟡 |
| 09 | Merchant Onboarding | rule engine; LLM classifies MCC | confirm on auto-approve | 🟡 |
| 10 | Market-Abuse Surveillance | LLM drafts memo; officer escalates/suppresses | sandboxed variant: remove autonomous `ALERT_SUPPRESSED` | 🔴 baseline = labelled threat-demo |
| 11 | Insurance Claim Triage | LLM recommends; human on payout/denial | `AUTO_APPROVED`→`RECOMMEND_APPROVE` | 🟡 |
| 12 | Equity Research | research **draft** for a registered analyst | implement the real `human_reviewed` gate the docs promise | 🔴 + doc/code fix |
| 13 | Tax Compliance | rule engine; LLM drafts | relabel `filed`→`prepared — pending signatory filing` | 🟡 |
| 14 | Treasury Cash Mgmt | LLM proposes; **every** sweep pends approval | already mandatory | 🟢 **reference pattern** |
| 15 | Support Chatbot | informational only | n/a | 🟢 |
| 16 | Fraud Explainer | upstream model decided; LLM explains | n/a (explain-only) | 🟢 |
| 17 | Risk Narrative | LLM drafts for analyst | implement analyst pause before audit-write (or soften doc) | 🟡 |

### 3b. Per-workflow target posture (health-tech)

Health applies the **same convergent core**, grounded in health-AI research: across
US/EU-UK/India/SG/UAE a **licensed human must own any material clinical / coverage /
coding decision** (US Medicare-Advantage 42 CFR 422.101(c) + CMS 2024 PA rule + state
physician-review laws like CA SB 1120 / IL clinical-peer; FDA non-device CDS
"independent practitioner review"; EU AI Act high-risk medical; FCA coding liability).
The overlay differs from finance only in *who the human is* (clinician / certified
coder / MLR reviewer) and the **PHI-residency** target. Config lives in
`health-tech/sandboxed/shared/governance.py`.

| # | Workflow | Decision owner (target) | Human gate | Action |
|---|----------|-------------------------|-----------|--------|
| 01 | Prior Authorization | rule recommends; **licensed clinician** owns a denial | clinician gate on `RECOMMEND_DENY` (CMS / CA SB 1120) | 🔴 done |
| 02 | Clinical Trial Matching | eligibility = recommendation; clinician owns enrollment | advisory (reframed) | 🟡 done |
| 03 | Medical Coding + 837 | LLM drafts codes; **certified coder** signs off | coder gate before 837 is final (FCA) | 🔴 done |
| 04 | Lab Result Explainer | explain-only | n/a | 🟢 |
| 05 | Medication Safety | drug-interaction copilot; clinician owns prescribing | advisory (reframed) | 🟡 done |
| 06 | Trial Match (ClinicalTrials.gov) | search/retrieval | n/a | 🟢 |
| 07 | MSL Literature | LLM drafts brief; **MLR reviewer** owns publication | MLR draft gate | 🔴 done |

Must-gate (evidence-backed): **01 coverage denial, 03 coding/837, 07 MLR**. Safely
advisory (still logged + explainable): **02, 04, 05, 06**.

**Data-intelligence** is assistive analytics/BI — no binding customer decision, so the
core applies with **no decision-flow change** (outputs are already "recommended …" /
"for analyst"). Confirmed against the research: governance packs / volumes are
deliberately not added there (would be gratuitous).

---

## 4. declaw capability-coverage map (nothing is lost; surface expands)

Guarantee that the regulatory work does not dilute the declaw showcase — every
primitive still appears, and three gain new framing:

| declaw capability | Still showcased? | Where |
|---|---|---|
| PII redact + rehydrate (OpenAI + Anthropic) | ✅ unchanged | all sandboxed LLM steps; `verify_pii_handling.py` |
| Injection-defense cascade (mode + judge + pack) | ✅ unchanged | untrusted-input workflows; `verify_security_primitives.py` ck7 |
| Network egress allowlist | ✅ unchanged + **now = data-residency** | every policy; jurisdiction overlay |
| Credential vault | ✅ unchanged | `provision_vault.py`; `verify_security_primitives.py` ck11 |
| OPA governance packs | ✅ unchanged + **now drive jurisdiction overlay** | tool-agentic policies; `verify_security_primitives.py` ck12 |
| Volumes | ✅ unchanged | wf05 |
| Audit trail | ✅ unchanged + **now = compliance evidence** | all policies; human-gate records |
| FS isolation / metadata block | ✅ unchanged | `verify_security_primitives.py` |
| **Human gate** (new emphasis) | ➕ new showcase | wf01/14 pattern across decision workflows |

Closing the loop: after the remediation, the verify suites + a representative
workflow run are re-executed live so "still showcased" is proven, not asserted.

---

## 4a. Baseline vs sandboxed (the operating principle — option C)

The repo's pedagogy is **baseline (without declaw) vs sandboxed (with declaw)**.
That settles how the threat-demo workflows are handled:

- **Baseline = the realistic, often unsafe-by-default pattern** that teams actually
  build (the LLM autonomously decides / suppresses / publishes). This is the
  *contrast*; keeping it unsafe is the point — it's what declaw fixes. Label it
  clearly as the unsafe pattern.
- **Sandboxed = always the convergent governance core** — the LLM is demoted to
  propose/draft, a human (or deterministic rule) owns the binding action, and the
  PII / injection / egress / audit controls apply. This is the differentiator:
  **declaw turns a non-compliant agent into a compliant one**, not "declaw blocks
  one attack."

So `02`/`12` get restructured decision-flow in the sandboxed variant; `06`/`10`
keep the unsafe baseline as the contrast and gain a governed (propose→human)
sandboxed variant.

**Landing-page exclusion:** `06` (autonomous robo-advice) stays **repo-only** —
do not feature it in the public landing-page "workflow theatre" even labelled.
A vendor site running autonomous investment-advice theatre is a brand/regulatory
risk. `10` is fine to feature once its sandboxed variant is governed.

## 5. Positioning

declaw is the **non-bypassable governance + human-gate + audit + data-residency
layer** that lets you put an LLM *near* a regulated decision in any jurisdiction —
egress hygiene is one pillar of that, not the whole pitch. The convergent core is
the product; the jurisdiction overlay is a one-line `policy_ref` swap.

> This is engineering/design guidance informed by regulatory research, **not legal
> advice**. The binding specifics (EU AI Act high-risk obligations + timeline,
> ECOA reason-code exactness) should get a compliance/legal pass before they become
> public landing-page copy.
