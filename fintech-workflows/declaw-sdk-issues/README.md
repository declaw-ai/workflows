# Declaw SDK — Outstanding Issues

After the 2026-04-16 round of fixes, **two issues remain**.

## Remaining

| # | Script | Summary | Severity |
|---|--------|---------|----------|
| 03 | `03_ssn_regex_missing.py` | Built-in `ssn` type in `PIIConfig(types=[..., "ssn", ...])` does not redact `123-45-6789` on the wire, while `person_name` and `email` in the same payload redact correctly. Surfaced independently by the fintech primitive suite (check 6) and by `verify_regulatory_compliance.py` check (c) GLBA. | High — regulatory (GLBA) gap for any US fintech flow |
| 08 | `08_anthropic_nonstream_404.py` | `client.messages.create()` (non-streaming) through the Declaw proxy returns `anthropic.NotFoundError: 404 — model not found` on every Claude model tried (sonnet-4-5, haiku-4-5-20251001, 3-5-sonnet-20241022). The streaming variant `client.messages.stream()` works through the proxy (workflow 17 proves it), and non-streaming works from the host with the same key + model. So the failure is specific to `(Anthropic) × (messages.create) × (via proxy)`. | High — forces every fintech agent using Claude non-streaming to ship a streaming workaround |

## Run

```bash
export DECLAW_API_KEY=dcl_...
export DECLAW_DOMAIN=api.declaw.ai
export OPENAI_API_KEY=sk-...
cd fintech-workflows/declaw-sdk-issues
python 03_ssn_regex_missing.py
```

Expected (once fixed):
```
VERDICT  : PASS (all three types enforced on the httpbin path)
```

## Resolved

Everything else has been fixed, confirmed by design, or patched on our side:

| # | Issue | Resolution |
|---|-------|-----------|
| 01 | gzip response body breaks PII rehydration | **Fixed proxy-side.** Proxy now decodes `Content-Encoding: gzip` before the rehydration pass. Rerun of the reproducer showed `email rehydrated=True, name rehydrated=True`. |
| 02 | outbound PII redaction mangles JSON request body | **Fixed proxy-side.** Person_name substitution no longer breaks JSON validity / Content-Length. |
| 04 | NetworkPolicy L4 TCP permissive to non-allowlisted hosts | **Fixed proxy-side.** Raw `socket.create_connection("evil.com", 443)` now blocks at L4 alongside L7 SNI match. |
| 05 | Sandbox has no `get_audit_log()` method | **By design** (confirmed). Audit events flow server-side; retrieve via Declaw dashboard / control-plane API. |
| 06 | Reference `MockSandbox` doesn't write `/tmp/in.json` to host disk | **Our bug, our fix.** Patched in `sandboxed/shared/declaw_helpers.py`. |
| 07 | `ai-agent` template missing Accept-Encoding shim | **Moot** once #01 was fixed proxy-side. Shim deleted from this repo. |

The old reproducer scripts for 01/02/04/05/06/07 have been removed; their
findings are summarised above so the record lives with the fix. If you
need them back, they are in git history at commit `f2d0ed8..HEAD`.
