# Fintech AI Workflow Examples

Reference implementations of common fintech AI workflows built with four
different agent frameworks, shipped as **baseline** (plain Python process)
and **sandboxed** (declaw Firecracker microVM) pairs so you can see how the
same workflow hardens end-to-end against the failure modes fintech agents
actually hit — PAN/Aadhaar/SSN/card-PAN leakage, prompt injection from
borrower-uploaded documents and merchant descriptors, tool abuse against
core-banking APIs, and proprietary-policy exfiltration.

Every workflow makes **real** `gpt-4.1` calls. Workflows that naturally
exercise public reference APIs (05 Compliance RAG, 09 Merchant Onboarding,
10 Market Abuse Surveillance, 12 Equity Research, 14 Treasury) additionally
hit **live** public fintech endpoints — SEC EDGAR, RBI circular RSS, OFAC
SDN, NSE/BSE, FBIL, GSTN — so Declaw's per-destination network allowlist
is enforced against real domains.

These examples mirror patterns shipped by real fintech companies — OnFinance
(ComplianceOS, InvestigativeOS, NeoGPT), Navi (ML underwriting), Razorpay
(Agent Studio), Stripe (payments foundation model + EDD agent), Brex, Ramp.

## Workflows

| # | Workflow | Framework | Provider / Mode | External APIs | Tier |
|---|----------|-----------|-----------------|---------------|------|
| 01 | Credit Underwriting | **LangGraph** — state machine with HITL | OpenAI · non-stream | OpenAI | 2 |
| 02 | KYC Document Verification | **CrewAI** — role-based sequential `Process` | OpenAI · non-stream | OpenAI | 2 |
| 03 | AML / SAR Drafting | **AutoGen v0.4** — `RoundRobinGroupChat` | OpenAI · non-stream | OpenAI + OFAC SDN + UN sanctions | 3 |
| 04 | Chargeback Dispute | **LangGraph** — conditional-route state machine | OpenAI · non-stream | OpenAI + Stripe (test mode) | 2 |
| 05 | Compliance Circular RAG | **LlamaIndex** — `FunctionAgent` w/ RAG tools | OpenAI · non-stream | OpenAI + RBI circular RSS | 3 |
| 06 | Robo-Advisor | **CrewAI** — 4-role crew | OpenAI · non-stream | OpenAI + Alpha Vantage + openFIGI | 3 |
| 07 | SMB Cash-Flow Forecast | **LlamaIndex** — FunctionAgent + statement OCR | OpenAI · non-stream | OpenAI + GSTN | 2 |
| 08 | Collections Outreach | **AutoGen** — 4-agent group chat w/ tone rules | OpenAI · non-stream | OpenAI | 2 |
| 09 | Merchant Onboarding | **LangGraph** — risk-crawl + classify | OpenAI · non-stream | OpenAI + GSTN + SEC EDGAR | 3 |
| 10 | Market Abuse Surveillance | **AutoGen** — pattern detect ↔ news correlate | OpenAI · non-stream | OpenAI + SEC EDGAR Form 4 + BSE | 3 |
| 11 | Insurance Claim Triage | **CrewAI** — 5-role crew | OpenAI · non-stream | OpenAI | 2 |
| 12 | Equity Research Analyst | **LlamaIndex** — FunctionAgent w/ filings tools | OpenAI · non-stream | OpenAI + SEC EDGAR + Alpha Vantage + openFIGI + BSE | 3 |
| 13 | Tax Compliance | **LangGraph** — ledger + file/hold state machine | OpenAI · non-stream | OpenAI + GSTN | 2 |
| 14 | Treasury Cash Management | **CrewAI** — cash-position + FX + sweep | OpenAI · non-stream | OpenAI + FBIL | 2 |
| 15 | Customer-Support Chatbot | **LangGraph** — streaming SSE reply | **OpenAI · streaming** | OpenAI | 2 |
| 16 | Fraud Decision Explainer | **LlamaIndex** — FunctionAgent, regulator-grade letters | **Anthropic · non-stream** | Anthropic + OpenAI | 2 |
| 17 | Realtime Risk Narrative | **AutoGen** scope + Claude stream writer | **Anthropic · streaming** (+ OpenAI scope) | OpenAI + Anthropic | 3 |

**Framework spread:** 5× LangGraph, 4× CrewAI, 4× AutoGen, 4× LlamaIndex.
**Provider / mode spread:** 14× OpenAI non-stream, 1× OpenAI streaming,
1× Anthropic non-stream, 1× Anthropic streaming.
**Domain spread:** 2 lending, 2 payments, 3 compliance, 1 onboarding, 1 wealth,
1 collections, 1 insurance, 1 research, 1 tax, 1 treasury, 1 SMB lending,
1 support, 1 fraud-explain, 1 surveillance narrative.

**Workflows 01–04 + 06–08 + 11 + 13–14** exercise single-destination agents
(LLM + internal tools) and are the easiest to reason about for PII redaction
and microVM isolation.
**Workflows 05 + 09 + 10 + 12** exercise multi-API tool chains — the scenario
where Declaw's per-destination allowlist, per-destination audit, and egress
minimization earn their keep.

## Layout

```
fintech-workflows/
├── README.md
├── SECURITY.md                               # applied security architecture + evidence
├── SANDBOXED.md                              # threat model → declaw primitive mapping
├── shared/
│   ├── llm.py                                # OpenAI + Anthropic helpers — chat(), chat_stream(), chat_anthropic(), chat_anthropic_stream(), chat_json()
│   ├── mock_customers.py                     # Customer dataclass (India + US identity sets) + LENDING_POLICIES
│   ├── mock_bureau.py                        # CIBIL + Experian/FICO response shapes
│   ├── mock_transactions.py                  # card + UPI + ACH + NEFT histories (adversarial items flagged)
│   ├── mock_statements.py                    # bank-statement fixtures (incl. prompt-injection memos)
│   ├── mock_merchants.py                     # merchant profiles + adversarial website HTML
│   ├── mock_claims.py                        # FNOL fixtures
│   ├── mock_portfolio.py                     # robo-advisor fixtures + adversarial news item
│   ├── mock_trades.py                        # order book + forged-memo news (surveillance demo)
│   ├── mock_policies.py                      # RBI/SEBI/FATF/PCI-DSS excerpts + INTERNAL playbook
│   └── external_apis.py                      # SEC EDGAR / RBI / OFAC / NSE / BSE / FBIL / GSTN / AlphaVantage / openFIGI wrappers
├── workflows/                                # baseline, in-process
│   ├── 01-credit-underwriting-langgraph/
│   ├── 02-kyc-doc-verification-crewai/
│   ├── ...
│   ├── 14-treasury-cashmgmt-crewai/
│   ├── 15-customer-support-chatbot-openai-stream-langgraph/   # OpenAI streaming
│   ├── 16-fraud-explainer-anthropic-nonstream-llamaindex/     # Anthropic non-stream
│   └── 17-risk-narrative-anthropic-stream-autogen/            # Anthropic streaming
└── sandboxed/                                # declaw-wrapped variants
    ├── 01..17/run.py                         # one per baseline, same numbering
    ├── shared/
    │   ├── declaw_helpers.py                 # lending_llm_policy, kyc_document_policy,
    │   │                                     # pci_payments_policy, compliance_rag_policy,
    │   │                                     # multi_bank_api_policy, collections_outreach_policy,
    │   │                                     # broker_trade_policy, tax_filing_policy, treasury_ops_policy
    │   └── declaw_openai_compat.py           # Accept-Encoding shim (same as health-tech)
    ├── verify_pii_handling.py                # PAN/Aadhaar/SSN/card-PAN/CVV redaction + rehydration proof
    ├── verify_security_primitives.py         # 10 primitive checks adapted to fintech
    ├── verify_multi_api.py                   # allowlist proof across 6+ public fintech APIs
    ├── verify_regulatory_compliance.py       # PCI-DSS, DPDP, GLBA, RBI+FDCPA, SEBI/SEC RA gates
    └── verify_live_apis.py                   # live-endpoint smoke test under multi_bank_api_policy
```

## Run

Install the framework libs (all baked into declaw's `ai-agent` template,
so sandboxed runs install nothing per-run):

```bash
pip install langgraph openai anthropic "autogen-agentchat>=0.4.0" "autogen-ext[openai]>=0.4.0" \
            crewai llama-index-core llama-index-llms-openai llama-index-llms-anthropic declaw
```

Baseline:
```bash
export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-ant-...         # required for workflows 16, 17
# Optional — only workflows that use live market data need it:
export ALPHAVANTAGE_API_KEY=...
python workflows/01-credit-underwriting-langgraph/run.py
```

Sandboxed:
```bash
export OPENAI_API_KEY=sk-...  ANTHROPIC_API_KEY=sk-ant-...  \
       DECLAW_API_KEY=dcl_...  DECLAW_DOMAIN=api.declaw.ai
python sandboxed/01-credit-underwriting-langgraph/run.py
```

Without `DECLAW_API_KEY`, sandboxed scripts fall back to `local-mock` mode: they
log what *would* have been sandboxed and run the step in-process, so the
workflow still produces output.

## Verification

Five reproducer scripts under `sandboxed/`:

| Script | Checks |
|--------|--------|
| `verify_security_primitives.py` | 10 Declaw primitives — network allowlist, cross-sandbox FS isolation, metadata-IP block, env-secret hiding, TransformationRule stripping PAN outbound, injection defense on adversarial merchant descriptor, audit trail |
| `verify_pii_handling.py` | PII dehydration + rehydration for PAN, Aadhaar, UPI VPA, IFSC, GSTIN, CIBIL, SSN, routing, card PAN, card CVV, email, phone, name — against both httpbin and OpenAI endpoints. **PCI-DSS assertion**: card CVV is never rehydrated. |
| `verify_multi_api.py` | Single sandbox under `multi_bank_api_policy` — 7 legit public APIs reachable, `attacker.example.com` TCP-dropped |
| `verify_regulatory_compliance.py` | PCI-DSS (CVV never rehydrated), DPDP (Aadhaar block), GLBA (SSN redact), RBI digital-lending + FDCPA (tone gate), SEBI/SEC RA (auto-publish gate) |
| `verify_live_apis.py` | Smoke-tests every live public API (SEC EDGAR, RBI, OFAC, NSE, BSE, FBIL, openFIGI, AlphaVantage, GSTN) from inside a sandbox — degraded endpoints surface as warnings so dependent workflows can skip gracefully |

## PII handling status

See `SECURITY.md` for the applied architecture and the with-vs-without
declaw benefits table, plus live evidence quoted straight from the
verification scripts above.
