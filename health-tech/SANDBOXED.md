# Sandboxed Variants — declaw integration

The `workflows/` directory has the **un-sandboxed** baseline. The `sandboxed/`
directory has the same four workflows hardened with **declaw** (Firecracker
microVM sandboxes + a security proxy in front of every outbound call).

## What declaw gives us, mapped to PHI workflow risks

| declaw primitive | PHI workflow risk it neutralizes |
|------------------|----------------------------------|
| **Firecracker microVM** per sandbox | Untrusted code execution — payer-portal HTML parsers, EDI 837 builders fed by a malicious rule pack, OCR over a faxed referral PDF cannot escape into the host or other patients' charts. |
| **PII redaction with `rehydrate_response=True`** | LLM endpoint never sees raw `SSN`, `phone`, `email`, names, or addresses. Agent code receives the rehydrated response transparently — including over the OpenAI endpoint, now that the proxy gzip-decodes responses before rehydration. Lets non-BAA models be used safely for pure transformation tasks. |
| **`NetworkPolicy(allow_out=…, deny_out=ALL_TRAFFIC)`** | Locks every step to BAA-covered endpoints (OpenAI, the public health reference APIs, payer clearinghouse, FHIR server). One mis-typed URL can't ship PHI to a random domain. The cloud metadata IP `169.254.169.254` is always blocked → no SSRF-based credential exfiltration. |
| **`InjectionDefenseConfig`** (full cascade) | Indirect prompt injection coming back from a payer portal, a clinical-trial registry, or a faxed referral is scanned by the Tier-1 ML classifier (`injection_mode="data-egress-sensitive"`) **and** a Tier-2 Gemma LLM judge that reads the step's task policy, so benign PHI isn't false-flagged. Detections are audited (`log_only`) or blocked. |
| **Credential vault** (opt-in, SDK 1.3.0) | The LLM API key can be brokered via `vault_refs` instead of forwarded as an env var — the real key never enters the VM (placeholder `declaw:vault-managed`), the egress proxy injects it. An injected agent that reads `/proc` or its environment gets nothing. |
| **`CustomPolicyConfig(policy_ref="owasp-agentic@v1")`** | The multi-API tool-calling workflows attach the OWASP agentic governance pack: cmd/network gate denials (tool-misuse, SSRF, loopback, cloud-metadata) layered on declaw's non-bypassable floor, each deny audited with its OWASP/MITRE/NIST control IDs. |
| **`AuditConfig`** with structured event log | Per-action audit record (operator + agent + data + timestamp) that meets the 2026 HIPAA Security Rule update. Events are recorded server-side and surfaced via the declaw dashboard / control-plane API. |
| **Per-agent sandbox** in multi-agent workflows | A compromised "trial registry searcher" agent cannot read the chart sitting in the "clinician" agent's filesystem — they're separate microVMs. Data only flows through the orchestrator. |

## What changes in each workflow

### 01 — Prior Auth (LangGraph)
- The `submit_to_payer` node now runs **inside a sandbox** with `allow_out=["*.payer-clearinghouse.com"]`. A poisoned payer response can't read other patients' charts in the parent process.
- The `draft_appeal` LLM call goes through a sandbox with **PII redaction + rehydration**, so the raw `member_id` / patient name never reach the model endpoint.

### 02 — Trial Matching (AutoGen)
- **Each AutoGen agent runs in its own sandbox** (clinician, coordinator, checker). Filesystems are separate; the orchestrator shuttles `messages` through.
- The `search_trials` registry fetch sits in a sandbox with `injection_defense` enabled — a malicious NCT description can't override the eligibility checker.

### 03 — Medical Coding (CrewAI)
- The 837 EDI builder runs in a sandbox. Payer rule packs are untrusted blobs; sandbox isolation contains any malformed-rule code-exec attempts.
- The Coder agent's LLM call uses **PII redaction**: `MRN`, `member_id`, `phone` are tokenized before the prompt leaves the sandbox.

### 04 — Lab Result Explainer (LlamaIndex)
- The reference-document loader runs in a sandbox. In production this would pull patient-ed PDFs from third parties — sandboxing means a hostile PDF can't read FHIR client credentials.
- The patient-facing rewrite uses **PII redaction with rehydration** so the patient's name and DOB are tokenized to the LLM but appear correctly in the final reply.

### 05 — Medication Safety Copilot (LangGraph, multi-API)
- Real 4-node tool chain: FHIR meds → RxNav normalize → openFDA interactions → openFDA adverse events → gpt-4.1 synthesis.
- Each network-touching step runs in its own microVM via the new `healthcare_multi_api_policy()` — egress allowlist is `{api.openai.com, rxnav.nlm.nih.gov, api.fda.gov, clinicaltrials.gov, eutils.ncbi.nlm.nih.gov}`.
- Declaw benefit: the RxNav and openFDA calls legitimately carry only drug names (no PHI); the audit log per-destination proves this, and any attempt by a compromised wrapper to smuggle the patient record into a query parameter gets redacted at the proxy before egress.

### 06 — Live Clinical Trial Match (LlamaIndex, live ClinicalTrials.gov)
- `FunctionAgent` running entirely inside one microVM. Tools issue **live** calls to `clinicaltrials.gov/api/v2/studies` — proven by the agent returning real NCT IDs (e.g. `NCT07184970` PRISM study) that match the patient's condition.
- Declaw benefit: **per-destination network allowlist**. A drifted helper calling a look-alike domain (`attacker-fake-ctgov.com`) is SNI-blocked — proven by `verify_multi_api.py` where `attacker.example.com/exfil` returns `URLError`.

### 07 — MSL Literature Support (AutoGen, live PubMed + openFDA)
- Three-agent `RoundRobinGroupChat` — literature → label → writer — ingests untrusted external content (PubMed abstracts, FDA label text).
- Because the content source is actively adversarial-adjacent, this policy turns the injection cascade on at **`log_only`** — Tier-1 ML classifier (`injection_mode="data-egress-sensitive"`) + the Tier-2 Gemma judge. Detections are audited without blocking legit traffic.
- Declaw benefit: indirect prompt-injection surface gets audit coverage, the `owasp-agentic@v1` governance pack adds tool-misuse / SSRF gate denials around the tool calls, and the network allowlist means even a successfully-injected LLM can't exfil because the attacker's destination isn't reachable.

## Running

Same as the baseline, but install `declaw` (pinned to **>=1.3.0**) and set:

```bash
export DECLAW_API_KEY=...
export DECLAW_DOMAIN=api.declaw.ai          # or your on-prem host
pip install -r sandboxed/01-prior-auth-langgraph/requirements.txt
python sandboxed/01-prior-auth-langgraph/run.py
```

Without `DECLAW_API_KEY`, each script falls back to `local-mock` mode: it logs
what would have been sandboxed and runs the step in-process so you can read the
flow without a live declaw account.

### Optional: broker the LLM key via the credential vault

By default `OPENAI_API_KEY` is forwarded into the sandbox as an env var. To keep
the real key out of the VM entirely, provision it into the vault once and point
the workflows at it:

```bash
python sandboxed/provision_vault.py            # creates the "healthtech-openai" secret
export DECLAW_OPENAI_VAULT_REF=healthtech-openai
```

The proxy then injects the key on the matching outbound request; the in-VM env
holds only `declaw:vault-managed`. Unset the ref to return to env forwarding.

## Defense-in-depth, not defense-in-substitution

These sandboxes are **on top of**, not instead of:
- BAA with every vendor on the data path
- SMART-on-FHIR scopes for least-privilege EHR access
- Honest-broker / de-id at the data-ingest boundary for research workflows
- Standard at-rest encryption + KMS

Sandboxing buys runtime isolation. The other layers buy contractual,
cryptographic, and policy isolation. You want all of them.
