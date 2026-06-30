# Declaw Agent Workflow Examples

Reference implementations of real-world AI-agent workflows, shipped as
**baseline** (plain Python, no Declaw) and **sandboxed** (running inside a
[Declaw](https://declaw.ai) Firecracker microVM) pairs — so you can see exactly
how the *same* agent hardens end-to-end against the failure modes agents actually
hit: PII/PHI leakage, prompt injection from untrusted documents and tool output,
tool abuse, data exfiltration, and over-reliance on a non-deterministic model for
a material decision.

Every workflow makes **real** LLM calls (and, where relevant, hits real public
APIs). All input data is **synthetic**.

## Verticals

| Directory | Domain | Workflows |
|---|---|---|
| [`fintech-workflows/`](fintech-workflows/) | Fintech | underwriting, KYC, AML/SAR drafting, chargebacks, compliance RAG, robo-advisor, collections, merchant onboarding, market-abuse surveillance, insurance triage, equity research, tax, treasury, support, fraud explainer, risk narrative |
| [`health-tech/`](health-tech/) | Health-tech | prior authorization, trial matching, medical coding, lab-result explainer, medication safety, MSL literature |
| [`data-intelligence-workflows/`](data-intelligence-workflows/) | Data intelligence | KPI Q&A, telemetry fusion, proactive alerting, chat session |

Each vertical has a `workflows/` (baseline) and `sandboxed/` (with Declaw) tree of
the same agents, plus its own `README.md` / `SANDBOXED.md` / `SECURITY.md`.

Built with four agent frameworks — **LangGraph**, **CrewAI**, **AutoGen**, and
**LlamaIndex** — to show the controls are framework-agnostic.

## Governance model

The core principle across every demo: **the LLM is never the entity that emits a
binding, customer-impacting decision** — a deterministic rule or a human gate
owns it, and Declaw makes autonomous execution impossible and audits it. See
[`GOVERNANCE.md`](GOVERNANCE.md) for the convergent core + per-jurisdiction overlays,
and [`COMPLIANCE-REVIEW.md`](COMPLIANCE-REVIEW.md) for the engineering-fact vs.
legal-claim split.

> ⚠️ These examples are engineering reference material, **not legal advice**, and
> use synthetic data only. Validate any regulatory claim with qualified counsel
> for your jurisdiction before relying on it.

## Quickstart

```bash
# 1. Install the Declaw SDK + a framework (per workflow requirements.txt)
pip install declaw langgraph openai          # example

# 2. Set your keys
export DECLAW_API_KEY=dcl_...
export OPENAI_API_KEY=sk-...   ANTHROPIC_API_KEY=sk-ant-...   # as needed

# 3. Run a baseline (no Declaw) and its sandboxed counterpart
python fintech-workflows/workflows/01-credit-underwriting-langgraph/run.py
python fintech-workflows/sandboxed/01-credit-underwriting-langgraph/run.py
```

Get a Declaw API key and read the docs at **[declaw.ai](https://declaw.ai)** ·
**[docs.declaw.ai](https://docs.declaw.ai)**.

## License

[Apache License 2.0](LICENSE). Copyright 2026 Declaw.
