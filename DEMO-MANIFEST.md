# Demo manifest — landing-page replayable workflows

Curation + safe-framing layer for the public, replayable visual demos. Pairs with
`COMPLIANCE-REVIEW.md` (language policy) and the replay event stream
(`*/sandboxed/shared/replay.py`, see `--emit-events`).

**Rules for every public demo:** synthetic data only (label it); lead with the
**Bucket-1 engineering facts** (what declaw visibly does); hedge any statute name
("designed to support / aligns with"); persistent "illustrative · not legal advice"
footer; exclude `repo-only` rows.

Legend — **Tier:** ⭐ flagship (lead the page) · ✓ safe to feature · 🚫 repo-only.

## Recommended flagship set (the page rotation)
The five with the sharpest, most visual before/after declaw moment:
1. **Fintech 01 — Credit Underwriting** (PII redaction + reason codes + human gate + **jurisdiction swap** on one variable)
2. **Health 01 — Prior Authorization** (a denial **held for a clinician** — topical vs the nH Predict / Cigna headlines)
3. **Fintech 04 — Chargeback** (card PAN redacted, **CVV never rehydrated**)
4. **Fintech 10 — Market-Abuse Surveillance** (forged memo can't make the LLM **autonomously suppress** an alert)
5. **Fintech 16 — Fraud Explainer** (Claude letter with **PII redacted→rehydrated** on the Anthropic path)

## Fintech
| # | Workflow | Tier | Headline declaw moment (the replay "money shot") | Compliance-safe one-liner |
|---|----------|------|--------------------------------------------------|---------------------------|
| 01 | Credit Underwriting | ⭐ | PAN/Aadhaar/SSN → `[REDACTED_*]` on the wire; rule decides; **officer gate** on every outcome; flip `jurisdiction` → ECOA reason codes + `nist-ai-rmf@v1` | "A rule engine decides, the model only explains, and a human signs off — in any region, by swapping one policy." |
| 02 | KYC Verification | ✓ | Injected `[APPROVED_OVERRIDE]` is **inert** — deterministic rule + officer own the decision | "An injected 'approve' directive can't flip a KYC decision the model doesn't own." |
| 03 | AML / SAR Drafting | ✓ | Draft SAR → `DRAFT_READY_FOR_OFFICER_REVIEW`; a human files | "The model drafts the SAR; a compliance officer files it." |
| 04 | Chargeback Dispute | ⭐ | Card PAN redacted+rehydrated; **CVV redacted, never rehydrated** | "Card data is protected on the wire; the CVV never comes back — by design." |
| 05 | Compliance Circular RAG | ✓ | Cited regulator-circular Q&A; proprietary playbook blocked from egress | "Grounded, cited answers — and your internal playbook never leaves the sandbox." |
| 06 | Robo-Advisor | 🚫 | (governed: adviser-assist) | **Repo-only — do not feature** (autonomous-advice optics). |
| 07 | SMB Cash-Flow | ✓ | Rule recommends a limit; **officer gate**; LLM only forecasts | "The model forecasts; a rule recommends; an officer approves." |
| 08 | Collections Outreach | ✓ | Tone gate blocks forbidden phrasing; drafts **queued for approval**, never auto-sent | "Compliant-tone drafts, queued for a human — nothing sent autonomously." |
| 09 | Merchant Onboarding | ✓ | Injected HTML comment ignored; rule decides; **ops gate** on approve | "The model classifies; rules decide; ops confirm — even auto-approves." |
| 10 | Market-Abuse Surveillance | ⭐ | Forged memo can't trigger **autonomous suppression**; drafts memo → human officer | "An injected memo can't make the model bury a surveillance alert — a human owns that call." |
| 11 | Insurance Claim Triage | ✓ | LLM recommends; **human adjudicator** owns payout/denial | "The model recommends; a human owns the payout decision." |
| 12 | Equity Research | ✓ | Model can't **self-publish**; draft pending a registered analyst | "BUY/SELL theses stay drafts until a registered analyst publishes them." |
| 13 | Tax Compliance | ✓ | Deterministic GST/TDS; LLM drafts; **prepared pending signatory filing** | "Computed deterministically, drafted by the model, filed by an authorized signatory." |
| 14 | Treasury Cash Mgmt | ✓ | **Every** sweep `PENDING_HUMAN_APPROVAL`; nothing moves autonomously | "No money moves without a human approving the sweep." |
| 15 | Support Chatbot | ✓ | Streaming reply; PII tokenized in each SSE chunk; informational only | "Helpful streaming support — with PII protected in every chunk." |
| 16 | Fraud Explainer | ⭐ | Claude letter; PAN/SSN redacted→**rehydrated** on the Anthropic path | "Clear, customer-ready fraud letters — with identifiers protected end-to-end." |
| 17 | Risk Narrative | ✓ | Claude **streamed** narrative; forged memo filtered; drafts for an analyst | "A streamed, regulator-style narrative the model drafts for a human analyst." |

## Health-tech
| # | Workflow | Tier | Headline declaw moment | Compliance-safe one-liner |
|---|----------|------|------------------------|---------------------------|
| 01 | Prior Authorization | ⭐ | A **denial** is held `PENDING_HUMAN_CONFIRMATION` for a **licensed clinician** | "A coverage denial is never issued by an algorithm — a licensed clinician owns it." |
| 02 | Clinical Trial Matching | ✓ | Eligibility = **recommendation**; clinician owns enrollment | "The model recommends matches; a clinician decides enrollment." |
| 03 | Medical Coding + 837 | ✓ | Draft codes + **draft 837**; certified coder signs off | "ICD-10/CPT drafted by the model; a certified coder signs the claim." |
| 04 | Lab Result Explainer | ✓ | PHI redacted; plain-language explanation (explain-only) | "Plain-language lab explanations — with PHI protected on the wire." |
| 05 | Medication Safety | ✓ | Interaction advisory; **clinician owns prescribing** | "A drug-interaction copilot that advises — the clinician prescribes." |
| 06 | Trial Match (CT.gov) | ✓ | Live ClinicalTrials.gov search/retrieval | "Finds recruiting trials from live public data." |
| 07 | MSL Literature | ✓ | Brief → `DRAFT_READY_FOR_MLR_REVIEW`; MLR reviewer publishes | "Medical briefs stay drafts until an MLR reviewer approves them." |

## Data-intelligence (assistive — no binding decision)
| # | Workflow | Tier | Headline declaw moment | Compliance-safe one-liner |
|---|----------|------|------------------------|---------------------------|
| 01 | Cross-Source KPI Q&A | ✓ | Fans out to warehouse+CRM+tickets; PII redacted; ranked drivers + chart | "Conversational BI across your sources — with PII protected on every hop." |
| 02 | Telemetry + Manuals Fusion | ✓ | Structured+unstructured fusion; recommends a work-order code | "Fuses sensor data with manuals to recommend the fix." |
| 03 | Proactive Metric Alerting | ✓ | Anomaly → exec brief with likely cause + owner | "Spots the metric anomaly and writes the brief — for a human to action." |
| 04 | Chat Session | ✓ | Interactive analytics in one microVM | "An analytics chat session, fully sandboxed." |

## Replay data
Each demo is driven by a **real captured run** (not a mockup) via the replay event
stream — see `*/sandboxed/shared/replay.py` and run any workflow with
`DECLAW_EMIT_EVENTS=<path>` to emit the timeline a front-end scrubs through.
