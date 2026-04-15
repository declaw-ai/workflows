# Declaw SDK — Standalone Reproducers

Seven minimal scripts reproducing issues surfaced while building the fintech
reference workflows (2026-04-16, Declaw build tagged per `DECLAW_DOMAIN=api.declaw.ai`).
Each script depends only on `declaw` + stdlib + (where noted) `openai` or
`anthropic` — no imports from the surrounding `fintech-workflows/` tree — so
the Declaw team can drop them into their own test harness unchanged.

## Run

All scripts take the same three env vars:

```bash
export DECLAW_API_KEY=dcl_...
export DECLAW_DOMAIN=api.declaw.ai
export OPENAI_API_KEY=sk-...           # needed for 01, 02, 03, 07
export ANTHROPIC_API_KEY=sk-ant-...    # needed for 01 (if you run the anthropic branch)
cd fintech-workflows/declaw-sdk-issues
python 01_gzip_rehydration_broken.py
```

## The seven

| # | Script | Summary | Severity |
|---|--------|---------|----------|
| 01 | `01_gzip_rehydration_broken.py` | `PIIConfig(rehydrate_response=True)` is a no-op on OpenAI responses because the proxy can't scan gzipped bodies. Workaround: ship an httpx `Accept-Encoding: identity` shim into the sandbox. | High — silent data leak back to agent |
| 02 | `02_outbound_json_body_mangled.py` | When the proxy redacts a PII match inside a JSON request body, it returns a body that OpenAI rejects with `400 "could not parse JSON body"`. | High — blocks legitimate traffic |
| 03 | `03_ssn_regex_missing.py` | Built-in `ssn` type in `PIIConfig(types=[..., "ssn", ...])` does not redact `123-45-6789` while `person_name` and `email` in the same request are redacted correctly. | High — regulatory (GLBA) gap |
| 04 | `04_evil_com_tcp_reaches.py` | `NetworkPolicy(allow_out=["api.openai.com"], deny_out=[ALL_TRAFFIC])` does not block a raw `socket.create_connection("evil.com", 443)`. Domain block is enforced at L7 (SNI) only; L4 handshake still completes. | Medium — misleading primitive check, not a real exfil path |
| 05 | `05_audit_log_api_renamed.py` | `AuditConfig(enabled=True)` stores events, but the client has no method to retrieve them under any of the obvious names (`get_audit_log`, `audit_log`, `get_audit_logs`). | Medium — blocks ops-side audit replay |
| 06 | `06_mock_fallback_tmpjson.py` | Reference-helpers `MockSandbox.files_write("/tmp/in.json", …)` stores in an in-memory dict instead of writing to disk, so scripts that follow the real-sandbox convention (`open("/tmp/in.json")`) crash in mock mode. | Low — affects our helpers, not the SDK directly; included so you can decide whether to ship a shim in the SDK mock mode |
| 07 | `07_shim_not_autoshipped.py` | The `ai-agent` template pre-bakes `openai` + `anthropic` but does not ship the `Accept-Encoding: identity` shim. Workflows using that template therefore silently lose rehydration unless they remember to ship the shim themselves. | Low — once #01 is fixed in the proxy, this goes away |

## Expected-output format

Each script prints a blue-border banner, runs, and ends with either:

```
EXPECTED : <what should happen if the SDK were correct>
OBSERVED : <what actually happened on this run>
VERDICT  : PASS|FAIL|DEGRADED
```

so you can grep for `VERDICT: FAIL` across a run of all seven and file one
issue per failure.

## Fix priority (my 2c)

1. **#02 outbound JSON mangling** — blocks legitimate regulated-finance
   traffic; customer-visible 400 errors.
2. **#03 SSN regex missing** — regulatory gap in US+India flows.
3. **#01 gzip rehydration** — known and documented, but the required
   client-side shim is a sharp edge that surprises every new integration.
4. **#05 audit API** — can't replay for examinations.
5. **#04 L4 vs L7** — documentation fix would be sufficient; real L4 drop
   would be nicer.
6. **#07 shim autoshipping** — mitigable downstream; becomes a no-op once
   #01 is fixed.
7. **#06 mock fallback** — not strictly a Declaw issue; we own the mock helper.
