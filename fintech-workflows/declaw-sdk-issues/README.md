# Declaw SDK — Outstanding Issues

After the 2026-06 round of fixes (declaw Python SDK 1.3.0), **no issues remain**.
Everything previously tracked here has been fixed proxy-side, confirmed by
design, or patched on our side.

## Resolved

| # | Issue | Resolution |
|---|-------|-----------|
| 01 | gzip response body breaks PII rehydration | **Fixed proxy-side.** Proxy decodes `Content-Encoding: gzip`/`deflate` before the rehydration pass (`modifyResponseForPII`), strips `Content-Encoding`, and updates `Content-Length`. Rehydration now works with default SDK clients (no `Accept-Encoding: identity` shim). |
| 02 | outbound PII redaction mangles JSON request body | **Fixed proxy-side.** Person_name substitution no longer breaks JSON validity / Content-Length. |
| 03 | built-in `ssn` type doesn't redact `123-45-6789` on the wire | **Fixed proxy-side.** The guardrails service now ships `US_SSN` custom recognizers (`ssn_dashed` / `ssn_dotted` / `ssn_spaced`); the built-in `ssn` PII type redacts on egress like `email`/`person_name`. Closes the GLBA gap — `verify_regulatory_compliance.py` check (c) now passes via the built-in type, so the workaround `TransformationRule` is no longer needed. |
| 04 | NetworkPolicy L4 TCP permissive to non-allowlisted hosts | **Fixed proxy-side.** Raw `socket.create_connection("evil.com", 443)` blocks at L4 alongside L7 SNI match. |
| 05 | Sandbox has no `get_audit_log()` method | **By design** (confirmed). Audit events flow server-side; retrieve via the Declaw dashboard / control-plane API. The per-sandbox `AuditConfig(enabled=...)` flag gates the network/command/filesystem event categories. |
| 06 | Reference `MockSandbox` doesn't write `/tmp/in.json` to host disk | **Our bug, our fix.** Patched in `sandboxed/shared/declaw_helpers.py`. |
| 07 | `ai-agent` template missing Accept-Encoding shim | **Moot** once #01 was fixed proxy-side. Shim deleted from this repo. |
| 08 | Anthropic non-streaming `messages.create()` 404s via the proxy | **Fixed.** Root cause was the proxy mangling the gzipped/PII request body (a manifestation of #01/#02). With those fixed and the Anthropic key brokered via the credential vault (the egress proxy injects `x-api-key` + `anthropic-version`), non-streaming `messages.create()` now succeeds through the proxy. Source "Experiment 81" reports 12/12 across OpenAI non-stream, OpenAI stream, and Anthropic non-stream. Workflow 16 reverted from the `messages.stream()` workaround to a native `messages.create()` call. |

The reproducer scripts for all of the above have been removed; their findings
are summarised here so the record lives with the fix. If you need any of them
back, they are in git history.
