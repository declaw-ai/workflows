# Data-Intelligence Workflows — WisdomAI-style Agentic Analytics

Three reference workflows mimicking the agentic-BI patterns shipping in
products like **WisdomAI**, implemented as **baseline** (in-process) and
**sandboxed** (declaw Firecracker microVM) pairs. Built against the
**declaw Python SDK 1.3.0**.

Every workflow makes real `gpt-4.1` calls. Data is deterministic synthetic
(no external APIs needed) so a clean-clone demo runs offline except for
the OpenAI call.

## Workflows

| # | Workflow | Framework | Mimics WisdomAI pattern |
|---|----------|-----------|-------------------------|
| 01 | Cross-Source KPI Q&A | **LangGraph** state machine, 4 nodes | Family A — conversational BI fanning out to warehouse + CRM + tickets, emitting ranked drivers + chart spec |
| 02 | Telemetry + Manuals Fusion | **LlamaIndex FunctionAgent** | Family C — ConocoPhillips-style structured+unstructured fusion (pump telemetry + service-manual text + CMMS history) |
| 03 | Proactive Metric Alerting | **AutoGen v0.4** `RoundRobinGroupChat` of 3 | Family D — monitor → driller → writer emits an exec brief on a metric anomaly |

## Layout

```
data-intelligence-workflows/
├── README.md
├── SECURITY.md                           # plain-English declaw benefits + per-workflow evidence
├── SANDBOXED.md                          # threat model → declaw primitive mapping
├── shared/
│   ├── llm.py                            # OpenAI chat() / chat_json()
│   ├── mock_warehouse.py                 # appointments / visits / claims — 90 days, seeded
│   ├── mock_crm.py                       # payer-account stand-in for Salesforce
│   ├── mock_tickets.py                   # Zendesk-style ticket corpus
│   ├── mock_timeseries.py                # pump vibration + temp readings
│   └── mock_manuals.py                   # service-manual + CMMS stand-in
├── workflows/                            # baseline, in-process
│   ├── 01-kpi-qa-langgraph/run.py
│   ├── 02-telemetry-fusion-llamaindex/run.py
│   └── 03-proactive-alert-autogen/run.py
└── sandboxed/                            # declaw-wrapped
    ├── 01..03/run.py                     # one per baseline
    ├── shared/declaw_helpers.py          # wisdomai_analytics_policy, run_python_in_sandbox, vault refs
    ├── provision_vault.py                # optional: broker OPENAI_API_KEY via the credential vault
    └── verify_wisdomai_pattern.py        # 5-check proof of declaw guarantees
```

## Run

```bash
pip install langgraph openai "autogen-agentchat>=0.4.0" \
            "autogen-ext[openai]>=0.4.0" llama-index-core llama-index-llms-openai "declaw>=1.3.0"

export OPENAI_API_KEY=sk-...

# Baseline
python workflows/01-kpi-qa-langgraph/run.py

# Sandboxed
export DECLAW_API_KEY=dcl-...  DECLAW_DOMAIN=api.declaw.ai
python sandboxed/01-kpi-qa-langgraph/run.py

# Proof of declaw's guarantees on a federated-analytics workload
python sandboxed/verify_wisdomai_pattern.py
```

All three sandboxed variants run on the `ai-agent` declaw template —
zero per-run pip install.

### Optional: broker the OpenAI key via the credential vault

By default the host's `OPENAI_API_KEY` is forwarded into the microVM as
an env var. To keep the real key out of the VM entirely, provision it
once into the declaw credential vault and switch the workflows onto the
vault path:

```bash
python sandboxed/provision_vault.py        # creates secret "data-intel-openai"
export DECLAW_OPENAI_VAULT_REF=data-intel-openai
```

When the ref is set, `wisdomai_analytics_policy` sandboxes pass
`vault_refs` so the egress proxy injects the key on the matching
outbound request; the in-VM env only ever holds the placeholder
`declaw:vault-managed`. Unset the ref to fall back to env forwarding.

## WisdomAI context (why these three workflows)

Based on research, WisdomAI ships a **Federated Agentic Intelligence
Platform** — a universal MCP client for analytics that connects directly
to live SaaS, warehouses, and file repos without copying data. Their
disclosed customer stories give three reference patterns:

- **Patreon / Cisco** — cross-source KPI Q&A with ranked drivers → W1
- **ConocoPhillips** — structured telemetry + unstructured manuals for
  field workers → W2
- **Proactive agents alerting on metric changes** (product marketing) → W3

## Declaw hardening

See `SECURITY.md` for the with-vs-without comparison and live evidence
from `verify_wisdomai_pattern.py`. Short version: the microVM + PII
proxy + per-destination allowlist reproduce WisdomAI's enterprise
security posture (single-tenant, RBAC, row/column security, SOC 2) at
the runtime layer for any agent code you write.
