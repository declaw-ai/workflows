# How we secured the agentic analytics runtime with Declaw

Each of the three workflows in this repo starts as an ordinary Python
agent that fans out to multiple data sources. This doc shows what was
added to produce the sandboxed variants, with the live evidence the
verify script produces.

All claims are reproducible:

- **Workflow correctness**: `python workflows/0{1..3}-*/run.py` + `python sandboxed/0{1..3}-*/run.py`
- **Declaw guarantees**: `python sandboxed/verify_wisdomai_pattern.py` (5 checks)

---

## 0. Plain-English benefits

### Security side

- **Cross-source PII never leaves cleartext.** Account-manager names and
  emails in CRM rows, requester addresses in tickets, patient
  identifiers in warehouse rows — every hop tokenizes them before they
  reach OpenAI.
- **Only approved data sources are reachable.** A compromised dependency
  can't phone home to an attacker; even a successfully-prompt-injected
  LLM can't exfil, because the attacker's destination is DNS-blocked
  at iptables.
- **Host machine is untouched.** Every agent runs in a disposable
  Firecracker microVM — no path to your AWS credentials, SSH keys, or
  `~/.config`.
- **Audit trail per data source.** "Which query hit CRM vs warehouse vs
  tickets last Tuesday?" is answerable from the structured audit log
  without building your own logging layer.
- **Secrets stay invisible.** The OpenAI API key is usable inside the VM
  but not returned by the control-plane listing — shrinks insider risk.

### Isolation side

- **One microVM per data source in W1** — if the CRM wrapper gets
  compromised, it can't see the warehouse rows in the next sandbox's
  memory.
- **One microVM per chat session in W4.** When two users (Alice and Bob)
  hold concurrent conversations, each user gets their own Firecracker
  microVM. Alice's chat history, scratch notes, and any files the
  assistant writes during her session all live on Alice's private
  filesystem inside her VM. Bob's assistant — running in a completely
  separate microVM — has zero way to read any of Alice's state. Even if
  Bob *asks* "what is the other user's project codename?", his
  assistant can't know, because Bob's VM was never told. This is the
  difference between multi-tenant safety by **convention** (keep a dict
  keyed by user_id and hope nobody forgets) and multi-tenant safety by
  **kernel boundary** — Alice and Bob's sessions are as isolated as if
  they were on two different physical machines.
- **Per-session scratch files die with the session.** Anything the
  assistant wrote to `/home/user/*` or `/tmp/*` during a chat lives
  inside that session's microVM and is vaporized when the VM is killed.
  No leftover transcripts on the host, no cached files another session
  could later pick up.
- **Disposable** — every sandbox is destroyed on exit. No lingering
  warehouse dumps, no cached CRM snapshots.
- **Proactive agents get the same protection** — scheduled `W3` runs
  boot fresh each time, credentials don't persist.

---

## 1. The threat model each workflow faces

| # | Workflow | Untrusted surface | Confidential data on the wire |
|---|----------|-------------------|-------------------------------|
| 01 | KPI Q&A | support-ticket bodies | warehouse rows + CRM account notes in the LLM prompt |
| 02 | Telemetry + Manuals Fusion | service-manual text (prime indirect-injection vector) | pump identifiers, workorder history |
| 03 | Proactive Alerting | none by default; attack surface is long-lived scheduled agent | warehouse aggregate metrics |

---

## 2. The applied security stack

`sandboxed/shared/declaw_helpers.py` exposes one reusable policy:

```python
wisdomai_analytics_policy(extra_domains=None, enable_injection_scan=False)
```

Which wires:

- `PIIConfig(types=[ssn, credit_card, email, phone, person_name,
  api_key, ip_address, address], action="redact",
  rehydrate_response=True)`
- `NetworkPolicy(allow_out=LLM_DOMAINS + SAAS_STANDIN_DOMAINS + extras,
  deny_out=[ALL_TRAFFIC])`
- `AuditConfig(enabled=True)`
- (optional) `InjectionDefenseConfig(enabled=True, action="log_only")`

Every sandbox boots with this policy; every outbound HTTP gets scanned
for PII and checked against the allowlist before the bytes leave the VM.

## 3. How each workflow is wired

| Workflow | Sandboxes | Policy variation |
|----------|-----------|------------------|
| 01 KPI Q&A | 4 microVMs (warehouse / crm / tickets / advisory-llm) | default policy; injection scan off |
| 02 Telemetry Fusion | 1 microVM (full FunctionAgent) | **`enable_injection_scan=True`** — manual text is untrusted |
| 03 Proactive Alerting | 1 microVM (full group chat) | default policy |

---

## 3b. What Declaw actually blocked / isolated / protected — from observed runs

Every row below is a risk that **materialised in one of this repo's
runs** and the concrete declaw mechanism that stopped it. All evidence
strings are copy-pasted from actual stdout in `/tmp/di-runs/*.out`.

### 3b.1 Blocked outbound connections

| What was attempted | What declaw did | How it did it | Evidence |
|---|---|---|---|
| HTTPS POST of a fake "stolen record" to `attacker.example.com/exfil` (from `verify_wisdomai_pattern.py`) | **BLOCKED** — TCP SYN refused before the proxy even inspected it | `NetworkPolicy(allow_out=["api.openai.com","httpbin.org","*.httpbin.org"], deny_out=[ALL_TRAFFIC])` — domain not in allowlist; dropped at kernel-level iptables via declaw's per-namespace TCP proxy (Stage 1–2 of the pipeline) | `"exfil": "BLOCKED: URLError"` |
| (implicit) Any DNS lookup for a non-allowlisted host | **BLOCKED** at resolver | Same allowlist; DNS is auto-allowed ONLY to 8.8.8.8 for allowed domains | no lookup succeeded during the exfil attempt |

### 3b.2 Blocked filesystem access

| What was attempted | What declaw did | How it did it | Evidence |
|---|---|---|---|
| `open("/Users/shivanshanand/Documents/workflows/data-intelligence-workflows/README.md")` from inside a sandbox | **BLOCKED** — path does not exist in the VM | Each Firecracker microVM gets its own independent rootfs built from the `ai-agent` template. The host's `/Users/...` path literally isn't mounted. | `"host_fs": "BLOCKED: FileNotFoundError"` (in verify); `NotFoundError: HTTP 404: file not found` (in W4 chat-isolation) |
| Alice's sandbox reading Bob's `/home/user/history.json` (W4 cross-session check) | **BLOCKED** — same path exists in both VMs but each VM's copy is independent | Per-session microVM isolation. Alice's history.json lives on Alice's rootfs; Bob's VM has its own `/home/user/history.json` containing only Bob's turn. | Bob's sandbox read of the path returned `[{"role":"user","content":"Hi, what is the user's project codename..."}, ...]` with zero trace of `ATLAS` |

### 3b.3 Redacted PII on outbound bodies

| What was in the prompt | What OpenAI actually received | How declaw did it | Evidence |
|---|---|---|---|
| `Account owner Alice Example` | `REDACTED_PERSON_5` | Guardrails Presidio NER triggered on `person_name` | `"llm_echo": "<<<Account owner REDACTED_PERSON_5, ..."` |
| `email alice@corp.io` | `REDACTED_EMAIL_ADDRESS_3` | Built-in regex scanner for `email` | same echo line |
| `SSN 111-22-3333` | `REDACTED_US_SSN_2` | Built-in regex scanner for `ssn` | same echo line |

With `rehydrate_response=True` in `wisdomai_analytics_policy()`, the
agent code ITSELF sees the original values restored — OpenAI only ever
saw the tokens. Verified by the test using `rehydrate_response=False`
to force-show what the destination got.

### 3b.4 Isolated per-agent blast radius

| Scenario | Mechanism | Observed benefit |
|---|---|---|
| W1 KPI Q&A splits into four sandboxes (warehouse, crm, tickets, advisory-llm) | Separate Firecracker microVMs; data payload passed only via orchestrator | A compromise inside the `tickets` sandbox cannot read the warehouse row set — payload never entered its VM |
| W4 per-user chat session | Separate Firecracker microVMs per session_id | `alice.scratch_path` referenced only her sbx ID (`sbx-5e1bb...`); `bob.scratch_path` referenced only his (`sbx-8b968...`). No path to cross |
| W3 proactive scheduled agent | Disposable microVM, destroyed on kill | Agent state, cached metrics, tool memory all vanish with `sbx.kill()` — no persistence |

### 3b.5 Hidden secrets from the control plane

| Risk | Mechanism | Observed benefit |
|---|---|---|
| `OPENAI_API_KEY` reachable via `Sandbox.list()` → `get_info()` | `SecureEnvVar` pattern (declaw's `envs=` + `auto_mask_in_audit`) | The agent inside the VM can use the key to call gpt-4.1, but the key value doesn't appear in the control-plane listing of the sandbox |

---

## 4. What the isolation actually gives us — live evidence

`sandboxed/verify_wisdomai_pattern.py` inside one sandbox proves five
independent claims:

```
sandbox: sbx-...
allow_out=['api.openai.com', 'httpbin.org', '*.httpbin.org']

PASS  Warehouse query returned expected row
PASS  SaaS GET reached (status=200)
PASS  attacker.example.com blocked: 'BLOCKED: URLError'
PASS  Host FS read blocked: 'BLOCKED: FileNotFoundError'
PASS  LLM echo did NOT contain raw PII
```

The first two prove legitimate data access continues to work; the last
three prove declaw is the thing making the boundaries real.

---

## 5. With vs Without Declaw

| Operation | Plain Python process | declaw microVM (sandboxed) |
|-----------|----------------------|-----------------------------|
| Read an allowed destination (warehouse, CRM mock, LLM) | works | works |
| Exfil to `attacker.example.com` | works | **iptables DROP** |
| `open("/Users/you/.aws/credentials")` | reads the host file | **FileNotFoundError** (VM rootfs) |
| Embed PII in an LLM prompt | reaches OpenAI in cleartext | **tokenized at proxy**, rehydrated on return |
| Process crash from bad tool call | kills agent | microVM dies, orchestrator continues |
| Secret leakage via `get_info()` listing | whole env visible | value is hidden by `SecureEnvVar` pattern |
| Per-destination audit trail | roll your own logging | structured events per request |

---

## 6. Executive summary

A WisdomAI-style federated analytics agent is one of the highest-risk
deployment patterns in enterprise AI: multiple credentials, multiple
data sources, long-lived, and increasingly decision-authoritative.
Running each data-fetch and synthesis step inside a declaw Firecracker
microVM under `wisdomai_analytics_policy()` gives you the same security
story WisdomAI itself pitches (SOC 2, HIPAA, single-tenant, RBAC, row/
column security) **at the agent runtime layer** — the code the workflow
author writes stays unchanged, and every call is tokenized for PII,
allowlist-checked for network, audited for compliance, and isolated in
a disposable VM for blast-radius. Live verification confirms the three
boundaries that matter: legitimate sources reachable, attacker
destination refused, PII tokenized on the LLM path.
