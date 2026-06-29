# Health-Tech AI Workflow Examples

Reference implementations of common health-tech AI workflows built with
four different agent frameworks, shipped as **baseline** (plain Python
process) and **sandboxed** (declaw Firecracker microVM) pairs so you can
see how the same workflow hardens end-to-end.

Every workflow makes **real** `gpt-4.1` calls. Workflows 5–7 additionally
hit live public health APIs (NLM RxNav, openFDA, ClinicalTrials.gov v2,
PubMed E-utilities) — no mocked responses.

## Workflows

| # | Workflow | Framework | External APIs | Tier |
|---|----------|-----------|---------------|------|
| 01 | Prior Authorization | **LangGraph** — state machine with HITL | OpenAI | 2 |
| 02 | Clinical Trial Matching | **AutoGen v0.4** — `RoundRobinGroupChat` of 3 specialists | OpenAI | 3 |
| 03 | Medical Coding + Claim Scrub | **CrewAI 1.14** — role-based sequential `Process` | OpenAI | 2 |
| 04 | Lab Result Explainer | **LlamaIndex** — `FunctionAgent` with FHIR tools | OpenAI | 1 |
| 05 | Medication Safety Copilot | **LangGraph** — 4-node tool chain | RxNav + openFDA label + openFDA event + OpenAI | 3 |
| 06 | Live Clinical Trial Match | **LlamaIndex** — FunctionAgent w/ live-registry tools | ClinicalTrials.gov v2 + OpenAI | 3 |
| 07 | MSL Literature Support | **AutoGen** — 3-agent literature → label → writer | PubMed esearch/efetch + openFDA label + OpenAI | 3 |

**Workflows 1–4** exercise single-destination agents (LLM only) and are
the easiest to reason about for PII redaction and microVM isolation.
**Workflows 5–7** exercise multi-API tool chains — the scenario where
declaw's per-destination allowlist, per-destination audit, and egress
minimization really earn their keep.

## Layout

```
health-tech/
├── README.md
├── SECURITY.md                               # applied security architecture + live evidence
├── SANDBOXED.md                              # threat model → declaw primitive mapping
├── shared/
│   ├── mock_phi.py                           # synthetic patients, payer policies, reference labs
│   ├── llm.py                                # OpenAI chat() / chat_json() used by baselines
│   └── external_apis.py                      # real RxNav / openFDA / ctgov / PubMed wrappers
├── workflows/                                # baseline, in-process
│   ├── 01-prior-auth-langgraph/
│   ├── 02-trial-matching-autogen/
│   ├── 03-medical-coding-crewai/
│   ├── 04-lab-result-llamaindex/
│   ├── 05-med-safety-langgraph/              # new — real RxNav + openFDA multi-API chain
│   ├── 06-trial-match-ctgov-llamaindex/      # new — live ClinicalTrials.gov v2
│   └── 07-msl-literature-autogen/            # new — live PubMed + FDA label
└── sandboxed/                                # declaw-wrapped variants
    ├── 01..07/run.py                         # one per baseline
    ├── shared/declaw_helpers.py              # healthcare_llm_policy, healthcare_untrusted_io_policy, healthcare_multi_api_policy, ...
    ├── provision_vault.py                    # opt-in: broker the OpenAI key via the credential vault
    ├── verify_security_primitives.py         # primitive checks (network, FS, metadata, env, transforms)
    ├── verify_pii_handling.py                # dehydrate + rehydrate proof (originals restored over OpenAI)
    └── verify_multi_api.py                   # multi-API: allowlist + PHI redaction on the OpenAI path
```

## Run

Install the framework libs (all baked into declaw's `ai-agent` template,
so sandboxed runs install nothing per-run):

```bash
pip install langgraph openai "autogen-agentchat>=0.4.0" "autogen-ext[openai]>=0.4.0" \
            crewai llama-index-core llama-index-llms-openai "declaw>=1.3.0"
```

Baseline:
```bash
export OPENAI_API_KEY=sk-...
python workflows/05-med-safety-langgraph/run.py
```

Sandboxed:
```bash
export OPENAI_API_KEY=sk-...  DECLAW_API_KEY=dcl_...  DECLAW_DOMAIN=api.declaw.ai
python sandboxed/05-med-safety-langgraph/run.py
```

Optionally broker the OpenAI key via the SDK 1.3.0 credential vault so it never
enters the VM (provision once, then `export DECLAW_OPENAI_VAULT_REF=...`); unset
the ref to fall back to env forwarding. See `SANDBOXED.md` for the details.

## Verification

Three reproducer scripts under `sandboxed/`:

| Script | Checks |
|--------|--------|
| `verify_security_primitives.py` | declaw primitives (network allowlist, cross-sandbox FS, metadata-IP, env secrets, transformation rules) |
| `verify_pii_handling.py` | PII dehydrate + rehydrate on httpbin + OpenAI — asserts `rehydrate=True` restores the **originals** (not tokens) over OpenAI, `rehydrate=False` yields tokens only |
| `verify_multi_api.py` | live RxNav + openFDA + ctgov reachable AND exfil to `attacker.example.com` blocked AND PHI (incl. SSN) tokenized on OpenAI path — all in one sandbox |

## PHI handling status

See `SECURITY.md` for the applied architecture and the with-vs-without
declaw benefits table, plus live evidence quoted straight from the
verification scripts above.
