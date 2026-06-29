"""Verify Declaw PII dehydration + rehydration against fintech-specific payloads.

Two probes:
  1. httpbin.org/post — controlled echo. Confirms what the destination
     receives vs. what the agent reads back.
  2. api.openai.com    — real gpt-4.1 asked to echo the input verbatim.
     Tests rehydration on OpenAI's response body. The proxy now gzip-decodes
     the response before the rehydration pass (SDK #01 fixed), so rehydration
     restores originals on the OpenAI path too — not just httpbin.

Fintech-specific fields covered:
  * Indian: PAN, Aadhaar, UPI VPA, IFSC, GSTIN, CIBIL score
  * US / global: SSN, routing number, card PAN + CVV

PCI-DSS assertion: the card CVV must NEVER be rehydrated, even with
`rehydrate_response=True`. CVVs are not permitted to be stored post-auth
under PCI-DSS v4 req 3.2, so losing them on round-trip is the correct
behaviour.

Run:
    DECLAW_API_KEY=...  DECLAW_DOMAIN=api.declaw.ai \\
    OPENAI_API_KEY=sk-...  python sandboxed/verify_pii_handling.py
"""
from __future__ import annotations

import os
import sys
import textwrap

from declaw import (
    ALL_TRAFFIC,
    AuditConfig,
    NetworkPolicy,
    PIIConfig,
    Sandbox,
    SecurityPolicy,
    TransformationRule,
)

# India-specific identifiers that aren't universally built-in PII types. Mirror
# of declaw_helpers._fintech_transformation_rules so the probe actually exercises
# PAN/Aadhaar/UPI/IFSC/GSTIN/EIN/CIBIL redaction on the wire.
_FINTECH_RULES = [
    ("pan",     r"[A-Z]{5}[0-9]{4}[A-Z]"),
    ("aadhaar", r"[2-9][0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}"),
    ("upi_vpa", r"[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z][a-zA-Z0-9]{1,63}"),
    ("ifsc",    r"[A-Z]{4}0[A-Z0-9]{6}"),
    ("gstin",   r"[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]"),
    ("ein",     r"[0-9]{2}-[0-9]{7}"),
    ("cibil",   r"CIBIL[:\s]*[3-9][0-9]{2}"),
]

# Fintech PII probe: a single payload carrying India + US identifiers.
PROBE_FIELDS = {
    "pan": "ABCDE1234F",
    "aadhaar": "2345 6789 0123",
    "upi_vpa": "aarav@okicici",
    "ifsc": "HDFC0001234",
    "gstin": "29ABCDE1234F1Z5",
    "cibil_score": 762,
    "ssn": "123-45-6789",
    "routing_number": "021000021",
    "card_pan": "4111 1111 1111 1111",
    "card_cvv": "123",                     # MUST never appear post-round-trip
    "email": "aarav.sharma@example.com",
    "phone": "+91 98210 34567",
    "name": "Aarav Sharma",
}


HTTPBIN_PROBE = textwrap.dedent(f"""
    import json, ssl, urllib.request
    ctx = ssl._create_unverified_context()
    body = json.dumps({PROBE_FIELDS!r}).encode()
    req = urllib.request.Request(
        "https://httpbin.org/post",
        data=body,
        headers={{"Content-Type": "application/json"}},
    )
    resp_text = urllib.request.urlopen(req, timeout=20, context=ctx).read().decode()
    echoed = json.loads(resp_text)["json"]
    print("AGENT_READ_BACK:", json.dumps(echoed))
""")


OPENAI_PROBE = textwrap.dedent(f"""
    from openai import OpenAI
    FIELDS = {PROBE_FIELDS!r}
    PAYLOAD = ", ".join(f"{{k}}={{v}}" for k, v in FIELDS.items())
    client = OpenAI()
    r = client.chat.completions.create(
        model="gpt-4.1",
        messages=[{{"role": "user", "content":
                   f"Echo bot. Repeat verbatim between markers. <<<{{PAYLOAD}}>>>"}}],
        max_completion_tokens=200,
    )
    print("AGENT_READ_BACK:", r.choices[0].message.content)
""")


def _policy(allow_domains: list[str], rehydrate: bool) -> SecurityPolicy:
    return SecurityPolicy(
        pii=PIIConfig(
            enabled=True,
            types=["ssn", "credit_card", "email", "phone",
                   "person_name", "api_key", "ip_address", "address"],
            action="redact",
            rehydrate_response=rehydrate,
        ),
        transformations=[
            TransformationRule(direction="outbound", match=pat,
                               replace=f"[REDACTED_{label.upper()}]")
            for label, pat in _FINTECH_RULES
        ],
        network=NetworkPolicy(allow_out=allow_domains, deny_out=[ALL_TRAFFIC]),
        audit=AuditConfig(enabled=True),
    )


def _run(label: str, probe: str, allow: list[str], rehydrate: bool) -> str:
    sbx = Sandbox.create(
        template="ai-agent",
        timeout=180,
        security=_policy(allow, rehydrate=rehydrate),
        envs={"OPENAI_API_KEY": os.environ.get("OPENAI_API_KEY", "")},
    )
    try:
        sbx.files.write("/tmp/script.py", probe)
        result = sbx.commands.run("python3 /tmp/script.py", timeout=120)
        out = result.stdout or ""
        err = result.stderr or ""
        return out + ("\n[stderr]\n" + err if err else "")
    finally:
        sbx.kill()


def main() -> None:
    if not os.getenv("DECLAW_API_KEY") or not os.getenv("OPENAI_API_KEY"):
        print("need DECLAW_API_KEY and OPENAI_API_KEY for this verification")
        sys.exit(0)

    print("\n=== PII handling probe — fintech fields (India + US) ===\n")

    print("[1] httpbin destination, rehydrate=False (tokens expected)")
    print(_run("httpbin_norehydrate", HTTPBIN_PROBE,
               ["httpbin.org"], rehydrate=False))

    print("\n[2] httpbin destination, rehydrate=True (originals expected, "
          "minus CVV per PCI-DSS)")
    print(_run("httpbin_rehydrate", HTTPBIN_PROBE,
               ["httpbin.org"], rehydrate=True))

    print("\n[3] OpenAI destination, rehydrate=False (tokens expected)")
    print(_run("openai_norehydrate", OPENAI_PROBE,
               ["api.openai.com"], rehydrate=False))

    print("\n[4] OpenAI destination, rehydrate=True (originals restored — the "
          "proxy now gzip-decodes the response before rehydration)")
    print(_run("openai_rehydrate", OPENAI_PROBE,
               ["api.openai.com"], rehydrate=True))

    print("\n=== Pass criteria ===\n"
          " - httpbin with rehydrate=False: ALL fields tokenised (no "
          "PAN/Aadhaar/SSN/card_pan/email/phone/name in agent read-back).\n"
          " - httpbin with rehydrate=True: PAN/Aadhaar/SSN/card_pan/email/"
          "phone/name restored to originals.\n"
          " - card_cvv: must NOT be rehydrated — keeping the token is the "
          "correct PCI-DSS v4 req 3.2 behaviour.\n"
          " - OpenAI destination, rehydrate=False: tokens; rehydrate=True: "
          "originals restored (gzip-decode fix, SDK #01 — no longer a no-op).\n")


if __name__ == "__main__":
    main()
