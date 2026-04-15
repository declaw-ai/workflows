# Security Architecture — Fintech Workflows

This document maps every workflow in `fintech-workflows/` to the concrete
runtime-security posture it runs under when wrapped with Declaw. It is the
counterpart to `SANDBOXED.md` — the latter explains *what Declaw gives us*,
this one records *how each workflow was actually wired* and *what the
measurable delta is vs. the plain-Python baseline*.

## 0. Why this matters for fintech specifically

AI agents in fintech touch four things that have hard regulatory floors:

1. **Identifier PII with statutory backing** — PAN, Aadhaar, UPI VPA (DPDP);
   SSN, routing (GLBA/CCPA); card PAN + CVV (PCI-DSS); EIN/GSTIN (filings).
   A mis-aimed outbound call is not just an embarrassment; it is a
   reportable breach with penalties up to ₹250 cr (DPDP) and ≤ $100K/month
   (PCI-DSS).
2. **Regulated opinions** — personalised investment advice (SEBI IA / SEC
   RIA), decline reasons (ECOA adverse action), SAR narratives (FATF Rec
   20 / FinCEN). An LLM that auto-publishes without the right gate is a
   regulatory violation in itself.
3. **Adversarial inbound content** — borrower-uploaded statements, merchant
   descriptors, news RSS, inbound WhatsApp replies, 10-K footers, scanned
   ID text. Any of these can carry indirect prompt injection.
4. **Multi-API tool abuse** — an agent with broker, payment, sanctions,
   filing, and messaging tools has the blast radius of a bank branch.
   Constraining it without killing productivity is exactly what runtime
   security is for.

All 14 workflows in this vertical demonstrate at least one of the four.

## 1. Threat model

| # | Workflow | Primary risk without Declaw |
|---|----------|------------------------------|
| 01 | Credit Underwriting | PAN/Aadhaar/CIBIL/SSN in prompt → DPDP + GLBA leak. Injected bank-statement memo overrides decision. Fair-lending-unsafe decline reason. |
| 02 | KYC Doc Verification | Aadhaar to non-empanelled LLM (DPDP ₹250cr). `[APPROVED_OVERRIDE]` OCR injection skips identity match. PII in crew chat transcript. |
| 03 | AML / SAR Drafting | Counterparty PII to external LLM. Wire-memo prompt injection suppresses alert. Hallucinated SAR narrative → regulator fine. Unauthorised sanctions-API call. |
| 04 | Chargeback Dispute | Card PAN/CVV in prompt (PCI-DSS v4 req 3.2). Attacker-controlled merchant descriptor forces refund. Refund-tool abuse above threshold. |
| 05 | Compliance Circular RAG | Hallucinated citation → wrong posture. Injection in circular PDF. Proprietary internal-policy playbook exfiltrated to external LLM. Stale-doc answers. |
| 06 | Robo-Advisor | SEBI/SEC violation via off-profile personalised advice. News-RAG injection triggers buy in sanctioned name. Portfolio PII leak. Unauthorised broker-tool trade. |
| 07 | SMB Cash-Flow Forecast | Statement-memo injection inflates credit limit. Hallucinated transactions. Account-number exfil. SMB-revenue memorisation by base model. |
| 08 | Collections Outreach | RBI tone/frequency + FDCPA violation. PII over WhatsApp. Borrower-reply injection hijacks agent. |
| 09 | Merchant Onboarding | Merchant-website injection drops MCC risk flag. Rogue-URL agent-fetch exfil. PII in ticket trail. |
| 10 | Market Abuse Surveillance | Forged internal-memo injection suppresses front-running alert. Prop-trade data exfil. Counterparty PII leak. Alert-tool abuse. |
| 11 | Insurance Claim Triage | Injected narrative forces auto-approve. PHI + PII leak. Fraud-ring miss. Image-URL exfil. |
| 12 | Equity Research | 10-K footer injection. Hallucinated financials. SEBI/SEC RA violation if auto-published. |
| 13 | Tax Compliance | Hallucinated tax figures → liability. Proprietary GL exfil. Injected tax-notice PDF. Unauthorised e-file tool call. |
| 14 | Treasury Cash Mgmt | Unauthorised sweep (tool abuse). Stale-rate hedge loss. FX-API exfil. Injection in cash-flow memo. |
| 15 | Customer-Support Chatbot (OpenAI stream) | Each SSE chunk carries raw PAN/UPI VPA/card-PAN — a TLS-terminating log aggregator captures them. Operator UI mirrors raw identifiers. |
| 16 | Fraud Explainer (Anthropic non-stream) | Raw PAN/SSN/VPA in Claude request body — data-residency / DPAs with Anthropic may not match DPDP posture. |
| 17 | Risk Narrative (Anthropic stream + OpenAI scope) | Forged `INTERNAL-MEMO-FORGED` item in NEWS_FEED hijacks narrative (alert suppression). Counterparty / trader PAN streams unredacted to operator. |

## 2. Applied security stack

**Layer A — `lending_llm_policy`, `treasury_ops_policy`, `collections_outreach_policy`**
Used for the LLM-transformation steps where we intentionally let customer
identifiers cross the sandbox boundary under PII redaction + rehydration.
Agent code receives original values back; OpenAI only ever sees
`[REDACTED_PAN]`, `[REDACTED_AADHAAR]`, `[REDACTED_SSN]`, etc.

**Layer B — `kyc_document_policy`, `pci_payments_policy`, `tax_filing_policy`**
Used for steps where the identifier class must **never** leave the sandbox
in any form — Aadhaar (DPDP sensitive), card CVV (PCI-DSS req 3.2), raw GL
narration (proprietary IP). `action=block` + tight `allow_out` + (where
applicable) `injection_defense=block`.

**Layer C — `compliance_rag_policy`, `broker_trade_policy`,
`multi_bank_api_policy(enable_injection_scan=True)`**
Used on the untrusted-ingest path — adversarial circular PDFs, merchant
websites, borrower-uploaded statements, news RSS, 10-K footers. `PII=redact`
on the LLM leg, `injection_defense=block` at threshold 0.5 on ingest.

**Base — Firecracker microVM** per sandbox: ~125 ms boot, per-sandbox rootfs,
per-sandbox network namespace, per-sandbox `/tmp`. One compromised
News-Correlator cannot read the Allocator's portfolio. Host `/etc/passwd`,
`~/.aws/credentials`, and the cloud metadata IP `169.254.169.254` are
inaccessible from every sandbox regardless of policy.

## 3. How each workflow was wired

| # | Workflow | Sandbox count | Policy(-ies) used | Allowlist highlights |
|---|----------|---------------|---------------------|---------------------|
| 01 | Credit Underwriting | 2 | kyc_document_policy (parse), lending_llm_policy (explain) | api.openai.com + fs.internal.example |
| 02 | KYC Doc | 1 | kyc_document_policy | api.openai.com (crew inside single VM) |
| 03 | AML / SAR | 1 | multi_bank_api_policy (injection_scan on) | api.openai.com + www.treasury.gov |
| 04 | Chargeback | 1 | pci_payments_policy | api.stripe.com + api.openai.com |
| 05 | Compliance RAG | 2 | compliance_rag_policy (ingest), then agent sandbox | api.openai.com + www.rbi.org.in |
| 06 | Robo-Advisor | 1 | broker_trade_policy | api.openai.com + www.alphavantage.co + api.alphavantage.co + api.openfigi.com |
| 07 | SMB Cash-Flow | 2 | kyc_document_policy (parse), lending_llm_policy (forecast) | api.openai.com + services.gst.gov.in |
| 08 | Collections | 1 | collections_outreach_policy | api.openai.com + graph.whatsapp.com + api.twilio.com |
| 09 | Merchant Onboarding | 2 | compliance_rag_policy (crawl), multi_bank_api_policy | services.gst.gov.in + data.sec.gov + api.openai.com |
| 10 | Market Abuse | 1 | multi_bank_api_policy (injection_scan on) | data.sec.gov + www.bseindia.com + api.openai.com |
| 11 | Claim Triage | 1 | compliance_rag_policy | api.openai.com |
| 12 | Equity Research | 1 | multi_bank_api_policy (injection_scan on) | data.sec.gov + www.bseindia.com + api.alphavantage.co + api.openfigi.com + api.openai.com |
| 13 | Tax Compliance | 1 | tax_filing_policy | services.gst.gov.in + api.openai.com |
| 14 | Treasury | 1 | treasury_ops_policy | www.fbil.org.in + www.federalreserve.gov + api.openai.com |
| 15 | Support Chatbot (stream) | 1 | lending_llm_policy | api.openai.com (SSE streaming) |
| 16 | Fraud Explainer (Claude) | 1 | compliance_rag_policy | api.anthropic.com + api.openai.com |
| 17 | Risk Narrative (Claude stream) | 1 | multi_bank_api_policy (injection_scan on) | api.openai.com + api.anthropic.com |

## 4. What isolation actually gives us — evidence

Five reproducer scripts live in `sandboxed/`. The expected output shape is
drawn from the health-tech equivalents that shipped with the 2026-03 Declaw
build; re-run these locally to capture current-build evidence for an audit.

### 4.1 `verify_security_primitives.py`

10-check suite. The pattern under `health-tech/` produces:

```
1. Network policy — evil.com blocked, api.openai.com reachable            PASS
2. Filesystem — /etc/passwd host read not possible                         PASS
3. Env secrets — visible inside, hidden from control plane listing         PASS
4. TransformationRule — PAN stripped outbound to httpbin                   PASS
5. Cloud metadata IP 169.254.169.254 hard-blocked                          PASS
6. PII redaction — SSN + email tokenised on OpenAI egress                  PASS
7. Injection defense — merchant descriptor attack blocked                  PASS
8. Per-agent isolation — customer record not visible in peer sandbox       PASS
9. Audit trail — events emitted for outbound calls                         PASS
10. Multi-API policy — attacker.example.com TCP-dropped                    PASS
```

### 4.2 `verify_pii_handling.py`

**PCI-DSS assertion**: the card CVV must NEVER appear in the agent's
read-back even under `rehydrate_response=True`. Keeping the token in its
place is the correct PCI-DSS v4 req 3.2 behaviour (CVV cannot be stored
post-authorisation, even encrypted).

Expected matrix:

|                          | rehydrate=False | rehydrate=True          |
|--------------------------|-----------------|-------------------------|
| httpbin destination      | tokens          | originals (CVV still tokenised) |
| OpenAI destination       | tokens          | tokens (chunked stream caveat — see health-tech notes) |

### 4.3 `verify_multi_api.py`

Single sandbox, one `multi_bank_api_policy`. All 7 public APIs reachable
(SEC EDGAR, RBI RSS, OFAC SDN, NSE, BSE, FBIL, OpenAI); `attacker.example.com`
TCP-dropped at the iptables layer.

### 4.4 `verify_regulatory_compliance.py`

Five regulatory gates:
- (a) **PCI-DSS v4 req 3.2** — CVV never rehydrated → PASS
- (b) **DPDP** — Aadhaar action=block on kyc_document_policy → PASS
- (c) **GLBA** — SSN redacted pre-egress on lending_llm_policy → PASS
- (d) **RBI digital-lending + FDCPA** — tone gate rejects forbidden draft → PASS
- (e) **SEBI RA / SEC RA** — equity-research auto-publish requires both `check_regulated_opinion_flag=True` and `human_reviewed=True` → PASS

### 4.5 `verify_live_apis.py`

Smoke test under `multi_bank_api_policy`. Reachable endpoints typically:
SEC EDGAR (2/2), RBI RSS, OFAC SDN XML, BSE announcements, FBIL home,
openFIGI. Occasionally degraded: NSE bulk deals (captcha / 403), GSTN
(captcha). Degraded endpoints are logged so dependent workflows (09, 10,
12) can skip gracefully without false failures.

## 5. With vs without Declaw — operational deltas

| Operation | Plain Python baseline | Declaw microVM |
|-----------|-----------------------|----------------|
| Card-PAN in prompt | Reaches OpenAI in cleartext → PCI-DSS finding | Blocked at proxy; agent gets back `[REDACTED_CREDIT_CARD]` |
| Injected merchant descriptor | Drives refund approval | Blocked by injection_defense before LLM call |
| Proprietary internal playbook in RAG | Reaches OpenAI (IP leak) | Ingest sandbox strips the chunk; agent sees only public circulars |
| SSRF to `169.254.169.254/meta-data` | Succeeds on EC2/GCP → creds leak | Unconditional DROP regardless of allowlist |
| Malicious PyPI package in CrewAI transitive deps | Calls attacker.com from host | TCP-dropped at iptables |
| Agent tries broker-API outside wealth allowlist | Succeeds | Refused before TLS handshake |
| Audit trail for a regulator replay | Best-effort stdout logs | Per-request structured events w/ destination, PII hits, injection hits |

## 6. Executive summary

The fintech vertical replicates the two-tier architecture health-tech uses
(PII-redacting LLM sandbox + untrusted-IO blocking sandbox) and extends it
with four fintech-specific policy factories (`pci_payments_policy`,
`collections_outreach_policy`, `broker_trade_policy`, `tax_filing_policy`,
`treasury_ops_policy`) plus regex-based TransformationRules for the
identifiers that aren't universally built in (PAN, Aadhaar, UPI VPA, IFSC,
GSTIN, EIN). All 14 workflows get a clean before/after pair; all five
verify scripts exercise real Declaw primitives (including one on real
public APIs) and five regulatory gates (PCI-DSS, DPDP, GLBA, RBI+FDCPA,
SEBI/SEC RA).
