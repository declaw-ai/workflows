# Sandboxed Variants — declaw integration

The `workflows/` directory has the **baseline** agents running in your
local Python process. `sandboxed/` has the same three agents with every
network + synthesis step wrapped in a declaw Firecracker microVM.

## Threat model specific to federated analytics

Unlike the health-tech repo (where PHI to a single LLM endpoint is the
main risk), a WisdomAI-style analytics agent talks to **many** enterprise
data sources in one turn: warehouse, CRM, tickets, time-series, file
repo, CMMS. Each hop is a separate potential exfil vector:

| Attack | Without Declaw | With Declaw |
|--------|----------------|-------------|
| A compromised "CRM wrapper" tries to POST the whole account list to `attacker.example.com` | succeeds — process has unrestricted egress | iptables DROP — destination not in `wisdomai_analytics_policy()` allowlist |
| Agent reasons over a poisoned support-ticket body ("Ignore previous instructions…") | LLM may obey | opt-in `InjectionDefenseConfig(action="log_only", injection_mode="data-egress-sensitive")` runs the Tier-1 ML classifier plus a Tier-2 LLM judge and audits the detection; network allowlist prevents tool drift even if LLM is persuaded |
| Leaky join combines an `account_manager_email` into the LLM prompt | email reaches OpenAI in cleartext | tokenized to `REDACTED_EMAIL_ADDRESS_n`; agent rehydrates transparently |
| Proactive alerting agent runs overnight on a schedule with bundled secrets | any in-process code can `os.getenv("OPENAI_API_KEY")` | key brokered via the **credential vault** (opt-in) so the real value never enters the VM, or forwarded as an env var by default; microVM rootfs destroyed on exit — no persistence |

## What Declaw blocked / isolated / protected — from actual runs

Observed in stdout of `/tmp/di-runs/*.out` this session:

### In `sandboxed/verify_wisdomai_pattern.py`
- ✅ **Blocked**: outbound TCP/HTTPS to `attacker.example.com/exfil` → `URLError`.
  *How:* `NetworkPolicy(allow_out=[...], deny_out=[ALL_TRAFFIC])` — non-allowlisted domain dropped at iptables before the proxy even inspected it.
- ✅ **Blocked**: sandbox `open()` of the host's `/Users/operator/.../README.md` → `FileNotFoundError`.
  *How:* Firecracker microVM rootfs built from the `ai-agent` template image; the host path simply doesn't exist in the VM.
- ✅ **Redacted**: `Account owner Alice Example, email alice@corp.io, SSN 111-22-3333` → `Account owner REDACTED_PERSON_5, email REDACTED_EMAIL_ADDRESS_3, SSN REDACTED_US_SSN_2` on the outbound OpenAI request body.
  *How:* `PIIConfig(types=[person_name,email,ssn,...], action="redact")` — Guardrails NER for names, regex scanner for email + SSN. OpenAI received only the tokens.
- ✅ **Allowed** (positive control): GET to `httpbin.org/status/200` returned `200`. Allowlist correctly admits listed destinations while refusing all else.

### In `sandboxed/04-chat-session/run.py` (cross-session)
- ✅ **Isolated**: Alice stored `project codename is ATLAS` in her sandbox's `/home/user/history.json`; Bob's sandbox read from the same path got only Bob's turn — ZERO trace of `ATLAS`.
  *How:* Each session is a separate Firecracker microVM with its own rootfs, kernel, and process tree. Alice's sandbox ID was `sbx-5e1bb5ece788e7205fe16a1e38e47162`; Bob's was `sbx-8b968f816740fd65bf54ccf8e04e9252`.
- ✅ **Isolated**: Bob's LLM call naturally couldn't answer "what is the user's project codename?" — because Bob's history contains no memory of ATLAS, and his sandbox has no path to reach into Alice's.
  *How:* Same microVM separation. The isolation is structural, not prompt-engineered.
- ✅ **Destroyed on close**: both sandboxes `sbx.kill()`'d at the end of the demo. In-VM `history.json` + scratch files vaporised with the VM.
  *How:* Firecracker microVM destruction frees the rootfs — no persistence.

### In `sandboxed/01-kpi-qa-langgraph/run.py`
- ✅ **Partitioned**: the agent chain ran across 4 separate microVMs (`warehouse`, `crm`, `tickets`, `advisory-llm`). Each sandbox received ONLY the row set it needed.
  *How:* `run_python_in_sandbox` boots a fresh VM per step; payload is passed explicitly as `/tmp/in.json`; the VM never sees the rest of the data pipeline.

### In `sandboxed/02-telemetry-fusion-llamaindex/run.py`
- ✅ **Scanned for injection**: service-manual text fed to the LLM ran through `InjectionDefenseConfig(action="log_only", injection_mode="data-egress-sensitive")` with a Tier-2 LLM judge. Any indirect-injection attempt would have been audit-logged without breaking the workflow.
  *How:* Opt-in injection cascade on the sandbox's security proxy — Tier-1 ML classifier plus the `data-egress-sensitive` posture and an `InjectionJudgeConfig` LLM judge that tells task-aligned egress from injection-induced deviation. Enabled because untrusted content (manuals / PDFs) is the prime indirect-injection vector.

---

## What changes per workflow

### 01 — KPI Q&A (LangGraph)
- Four microVMs, one per source: `warehouse` → `crm` → `tickets` → `advisory-llm`.
- Each sandbox receives ONLY the rows it needs for its job. Even if the
  in-VM code is compromised, it can't see the rest of the warehouse
  rows — they live in a different microVM's payload.
- The `advisory-llm` sandbox runs the gpt-4.1 synthesis call under the
  same `wisdomai_analytics_policy()`: PHI / PII redacted outbound,
  rehydrated on the return path.

### 02 — Telemetry + Manuals Fusion (LlamaIndex)
- Single microVM runs the full `FunctionAgent` because LlamaIndex's
  agent loop is tightly coupled to its in-memory state.
- `InjectionDefenseConfig(enabled=True, action="log_only",
  injection_mode="data-egress-sensitive")` is turned on — service-manual
  content is untrusted by default. The cascade runs the Tier-1 ML
  classifier plus a Tier-2 LLM judge (`InjectionJudgeConfig`) whose
  policy describes the legitimate analytics task, so benign PII in the
  prompt is not false-flagged; any indirect prompt-injection attempt gets
  audit-logged.
- Network allowlist stops tool drift regardless of what the injected
  prompt tells the LLM to try.

### 03 — Proactive Alerting (AutoGen)
- Full `RoundRobinGroupChat` runs inside one microVM.
- Proactive scheduled agents hold credentials longer than interactive
  ones; microVM isolation plus brokering the OpenAI key through the
  credential vault (opt-in, see below) so it never enters the VM is the
  main win here.
- The `monitor` agent's tool calls include the `compute_metric` function
  definition; if the agent hallucinates an argument shape, the in-VM
  pydantic validation surfaces a helpful error rather than crashing the
  host process.

## Running

```bash
export DECLAW_API_KEY=...  DECLAW_DOMAIN=api.declaw.ai
export OPENAI_API_KEY=sk-...
python sandboxed/01-kpi-qa-langgraph/run.py
python sandboxed/02-telemetry-fusion-llamaindex/run.py
python sandboxed/03-proactive-alert-autogen/run.py
python sandboxed/verify_wisdomai_pattern.py
```

Without `DECLAW_API_KEY` the helper falls back to **local mock** mode —
executes in-process without a real sandbox so you can read the flow.

### Credential vault (opt-in)

By default `OPENAI_API_KEY` is forwarded into the microVM as an env var
(simple, clean-clone). For a stronger posture, provision the key into the
declaw credential vault once and switch the workflows onto the vault
path:

```bash
python sandboxed/provision_vault.py            # secret "data-intel-openai"
export DECLAW_OPENAI_VAULT_REF=data-intel-openai
```

When the ref is set, `declaw_helpers.llm_vault_refs()` passes
`vault_refs` to `Sandbox.create(...)`; the egress proxy injects the real
key on the matching outbound OpenAI request, and the in-VM env holds only
the placeholder `declaw:vault-managed`. An injected agent that dumps
`/proc` or its environment never gets the key. Unset the ref to return to
env forwarding. This vertical brokers only the OpenAI key — it is the
sole high-value secret on the analytics/BI data path.

## Defense in depth

Declaw sandboxes compose with, not replace, your existing security
posture: SSO / SCIM, source-level RBAC (row/column security preserved
from warehouse), SOC 2 / HIPAA control inheritance, BAAs with every
vendor on the data path. The sandbox adds **runtime** isolation —
the layer that plain IAM and contracts don't cover when an agent can
decide at run time which tool to call.
