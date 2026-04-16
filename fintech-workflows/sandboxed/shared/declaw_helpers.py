"""Helpers shared across the sandboxed fintech workflow demos.

Two goals, mirroring the health-tech and data-intelligence helpers:
  1. One place to build fintech-grade SecurityPolicies.
  2. A `local-mock` fallback so the demos read sensibly without a live
     DECLAW_API_KEY (they print what *would* have been sandboxed).

Fintech policies extend the health-tech PII set with fintech-specific
detectors (PAN, Aadhaar, UPI VPA, IFSC, GSTIN, EIN) via custom
TransformationRules so that regex-findable identifiers get tokenized
before leaving the microVM.
"""
from __future__ import annotations

import json
import os
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator

DECLAW_AVAILABLE = bool(os.getenv("DECLAW_API_KEY"))


def _import_declaw():
    from declaw import (  # type: ignore
        ALL_TRAFFIC,
        AuditConfig,
        InjectionDefenseConfig,
        NetworkPolicy,
        PIIConfig,
        Sandbox,
        SecurityPolicy,
        TransformationRule,
    )
    return {
        "ALL_TRAFFIC": ALL_TRAFFIC,
        "AuditConfig": AuditConfig,
        "InjectionDefenseConfig": InjectionDefenseConfig,
        "NetworkPolicy": NetworkPolicy,
        "PIIConfig": PIIConfig,
        "Sandbox": Sandbox,
        "SecurityPolicy": SecurityPolicy,
        "TransformationRule": TransformationRule,
    }


# ---------- PII categories ----------

# Built-in PII types Declaw detects out of the box. Fintech always redacts
# these before anything leaves the sandbox.
FINTECH_PII_TYPES = [
    "ssn",
    "credit_card",
    "email",
    "phone",
    "person_name",   # requires Guardrails Service in prod
    "api_key",
    "ip_address",
    "address",
]


# Fintech-specific regex identifiers that aren't universally built-in.
# Emitted as TransformationRule(outbound) so the proxy replaces matches
# with opaque tokens before egress.
def _fintech_transformation_rules():
    """Build TransformationRules for PAN, Aadhaar, UPI VPA, IFSC, GSTIN, EIN,
    and routing numbers. Each is direction=outbound so requests leaving the
    sandbox get the match replaced with a `[REDACTED_<TYPE>]` token."""
    if not DECLAW_AVAILABLE:
        return []
    d = _import_declaw()
    Rule = d["TransformationRule"]
    rules = []
    specs = [
        ("pan",      r"[A-Z]{5}[0-9]{4}[A-Z]"),
        ("aadhaar",  r"[2-9][0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}"),
        ("upi_vpa",  r"[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z][a-zA-Z0-9]{1,63}"),
        ("ifsc",     r"[A-Z]{4}0[A-Z0-9]{6}"),
        ("gstin",    r"[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]"),
        ("ein",      r"[0-9]{2}-[0-9]{7}"),
        ("cibil",    r"CIBIL[:\s]*[3-9][0-9]{2}"),
    ]
    for label, pat in specs:
        try:
            rules.append(Rule(
                direction="outbound",
                match=pat,
                replace=f"[REDACTED_{label.upper()}]",
            ))
        except Exception:
            # Older SDKs may use different kwarg names; skip silently.
            pass
    return rules


# ---------- Policy factories ----------

def _base_policy_kwargs(pii_action: str, allow_domains: list[str],
                        *, rehydrate: bool, enable_injection: bool,
                        injection_action: str = "log_only",
                        injection_threshold: float = 0.8):
    d = _import_declaw()
    kwargs: dict[str, Any] = dict(
        pii=d["PIIConfig"](
            enabled=True, types=FINTECH_PII_TYPES,
            action=pii_action, rehydrate_response=rehydrate,
        ),
        network=d["NetworkPolicy"](allow_out=allow_domains,
                                   deny_out=[d["ALL_TRAFFIC"]]),
        audit=d["AuditConfig"](enabled=True),
    )
    rules = _fintech_transformation_rules()
    if rules:
        kwargs["transformations"] = rules
    if enable_injection:
        kwargs["injection_defense"] = d["InjectionDefenseConfig"](
            enabled=True, action=injection_action, threshold=injection_threshold,
        )
    return kwargs


def _mock(kind: str, allow_domains: list[str], **extra):
    return {"_mock": True, "kind": kind, "allow_out": allow_domains, **extra}


def lending_llm_policy(allow_domains: list[str]):
    """Policy for an LLM-call sandbox in lending/underwriting.

    Redact PII outbound, rehydrate on response — agent code reads back
    the original PAN/Aadhaar/SSN/CIBIL transparently, so the sandboxed
    workflow produces the same decision text as the baseline (only the
    egress path changes). Redaction evidence lives in the audit log."""
    if not DECLAW_AVAILABLE:
        return _mock("lending_llm_policy", allow_domains)
    d = _import_declaw()
    return d["SecurityPolicy"](**_base_policy_kwargs(
        "redact", allow_domains, rehydrate=True, enable_injection=False))


def kyc_document_policy(allow_domains: list[str]):
    """Policy for KYC/doc-verification sandboxes.

    Demo posture (2026-04): PII action = 'log_only' and injection_defense
    action = 'log_only' so requests complete and the detection story reads
    via the audit log. In a production DPDP + GLBA deployment switch both
    to 'block' to hard-stop Aadhaar/SSN egress at the sandbox boundary."""
    if not DECLAW_AVAILABLE:
        return _mock("kyc_document_policy", allow_domains)
    d = _import_declaw()
    return d["SecurityPolicy"](**_base_policy_kwargs(
        "log_only", allow_domains, rehydrate=True,
        enable_injection=True, injection_action="log_only",
        injection_threshold=0.5))


def pci_payments_policy(allow_domains: list[str]):
    """Policy for payment-rail sandboxes (chargeback, refund, dispute).

    Demo posture: log_only on both PII and injection so the workflow
    completes; the audit log shows every card-PAN / CVV detection and
    every merchant-descriptor injection attempt. Production: switch back
    to 'block' on both (card CVV under PCI-DSS v4 req 3.2 must never
    leave the sandbox, even for tokenisation)."""
    if not DECLAW_AVAILABLE:
        return _mock("pci_payments_policy", allow_domains)
    d = _import_declaw()
    return d["SecurityPolicy"](**_base_policy_kwargs(
        "log_only", allow_domains, rehydrate=True,
        enable_injection=True, injection_action="log_only",
        injection_threshold=0.6))


def compliance_rag_policy(allow_domains: list[str]):
    """Policy for regulator-circular ingestion + Q&A.

    Demo posture (2026-04): PII `action="log_only"` because Declaw is
    currently fixing the Anthropic-side PII-redact path (SDK issue #08
    — redact mangles JSON body for api.anthropic.com). log_only keeps
    detections in the audit trail without modifying the body, so
    Anthropic workflows run end-to-end. Flip to 'redact' +
    rehydrate=True once Declaw patches the Anthropic redaction path."""
    if not DECLAW_AVAILABLE:
        return _mock("compliance_rag_policy", allow_domains)
    d = _import_declaw()
    return d["SecurityPolicy"](**_base_policy_kwargs(
        "log_only", allow_domains, rehydrate=True,
        enable_injection=True, injection_action="log_only",
        injection_threshold=0.5))


def collections_outreach_policy(allow_domains: list[str]):
    """RBI digital-lending + FDCPA-compliant outreach.

    PII redacted on egress to channel APIs (WhatsApp/SMS/email). Tone-rule
    enforcement handled in-workflow; this policy simply locks egress and
    audits every channel call for compliance replay."""
    if not DECLAW_AVAILABLE:
        return _mock("collections_outreach_policy", allow_domains)
    d = _import_declaw()
    return d["SecurityPolicy"](**_base_policy_kwargs(
        "redact", allow_domains, rehydrate=True, enable_injection=False))


def broker_trade_policy(allow_domains: list[str]):
    """Robo-advisor broker-tool sandbox.

    Portfolio PII redacted + rehydrated. Injection defense log_only for
    the demos (news-RAG is attacker-influenced — the forged `n-adv` item
    still gets detected and shows up in the audit trail). Allowlist must
    include only broker domains + LLM; anything else is TCP-dropped."""
    if not DECLAW_AVAILABLE:
        return _mock("broker_trade_policy", allow_domains)
    d = _import_declaw()
    return d["SecurityPolicy"](**_base_policy_kwargs(
        "redact", allow_domains, rehydrate=True,
        enable_injection=True, injection_action="log_only",
        injection_threshold=0.5))


def tax_filing_policy(allow_domains: list[str]):
    """GSTN / IRS filing sandboxes.

    Demo posture: PII action = log_only so proprietary ledger data still
    flows but detections are audited. Production: switch to 'block' for
    belt-and-braces on PAN/GSTIN/EIN egress to external LLMs."""
    if not DECLAW_AVAILABLE:
        return _mock("tax_filing_policy", allow_domains)
    d = _import_declaw()
    return d["SecurityPolicy"](**_base_policy_kwargs(
        "log_only", allow_domains, rehydrate=True, enable_injection=False))


def treasury_ops_policy(allow_domains: list[str]):
    """Treasury/cash-management sandbox.

    FX-rate + reference-data allowlist. PII redacted. Sweep/transfer tool
    calls must pass through human-review node (enforced in workflow)."""
    if not DECLAW_AVAILABLE:
        return _mock("treasury_ops_policy", allow_domains)
    d = _import_declaw()
    return d["SecurityPolicy"](**_base_policy_kwargs(
        "redact", allow_domains, rehydrate=True, enable_injection=False))


# Public fintech reference-API domains used across the multi-API workflows.
FINTECH_API_DOMAINS = [
    "data.sec.gov",              # SEC EDGAR company facts + filings
    "www.sec.gov",
    "www.rbi.org.in",            # RBI circulars + reference pages
    "www.fbil.org.in",           # FBIL reference rates
    "www.nseindia.com",          # NSE bulk deals
    "www.bseindia.com",          # BSE press releases
    "www.treasury.gov",          # OFAC SDN downloads
    "scsanctions.un.org",        # UN sanctions
    "api.alphavantage.co",       # Alpha Vantage quote + fundamentals
    "www.alphavantage.co",
    "api.openfigi.com",          # openFIGI ticker mapping
    "services.gst.gov.in",       # GSTN verify
    "api.stripe.com",            # Stripe test-mode dispute API
]


def multi_bank_api_policy(
    extra_domains: list[str] | None = None,
    enable_injection_scan: bool = False,
):
    """Policy for workflows that call the LLM PLUS several public fintech
    reference APIs in one tool chain. Egress locked to
    `LLM_DOMAINS + FINTECH_API_DOMAINS (+ extras)`. PII redacted +
    rehydrated on all of them. Injection scanning opt-in — turn on for
    RAG-over-untrusted-content workflows (05, 10, 12)."""
    allow = LLM_DOMAINS + FINTECH_API_DOMAINS + (extra_domains or [])
    if not DECLAW_AVAILABLE:
        return _mock("multi_bank_api_policy", allow)
    d = _import_declaw()
    # PII action="log_only" (2026-04) — see compliance_rag_policy docstring
    # for context on SDK issue #08. Flip to "redact" once Declaw patches
    # the Anthropic-side PII-body redaction path.
    kwargs = _base_policy_kwargs(
        "log_only", allow, rehydrate=True,
        enable_injection=enable_injection_scan,
        injection_action="log_only", injection_threshold=0.8,
    )
    return d["SecurityPolicy"](**kwargs)


# ---------- Sandbox lifecycle helper with mock fallback ----------
# (Historical note: 2026-04 this file used to ship a `declaw_openai_compat.py`
# httpx-shim into every sandbox to force Accept-Encoding: identity, working
# around a Declaw-proxy bug that couldn't decode gzipped response bodies.
# Declaw fixed that proxy-side, so the shim was removed. If you see an old
# `import declaw_openai_compat` in a sandbox script, it's safe to delete.)

@dataclass
class MockSandbox:
    """Minimal stand-in that prints what a real declaw sandbox would do."""
    sandbox_id: str
    policy: Any
    files_storage: dict[str, str]

    def files_write(self, path: str, content: str) -> None:
        self.files_storage[path] = content

    def files_read(self, path: str) -> str:
        return self.files_storage[path]

    def commands_run(self, cmd: str) -> dict[str, Any]:
        print(f"  [mock-sbx {self.sandbox_id}] would run: {cmd}")
        return {"stdout": "", "stderr": "", "exit_code": 0}

    def get_audit_log(self) -> list[dict[str, Any]]:
        return [{
            "sandbox_id": self.sandbox_id, "event_type": "mock_run",
            "policy_summary": str(self.policy),
        }]

    def kill(self) -> None:
        print(f"  [mock-sbx {self.sandbox_id}] killed")


@contextmanager
def sandbox(name: str, policy: Any, template: str = "python", timeout: int = 300) -> Iterator[Any]:
    """Yield a sandbox (real or mock) and ensure cleanup."""
    if not DECLAW_AVAILABLE:
        sbx = MockSandbox(sandbox_id=f"mock-{name}", policy=policy, files_storage={})
        kind = policy.get("kind") if isinstance(policy, dict) else "declaw_policy"
        allow = policy.get("allow_out") if isinstance(policy, dict) else "(declaw-managed)"
        print(f"  [mock-sbx {sbx.sandbox_id}] created with policy={kind} allow_out={allow}")
        try:
            yield sbx
        finally:
            sbx.kill()
        return

    d = _import_declaw()
    sbx = d["Sandbox"].create(template=template, timeout=timeout, security=policy)
    print(f"  [sbx {sbx.sandbox_id}] created with policy")
    try:
        yield sbx
    finally:
        # Audit events are not retrievable from the Sandbox object by design
        # (confirmed with the Declaw team 2026-04-16). They're recorded
        # server-side and surfaced via the Declaw dashboard / separate API.
        sbx.kill()
        print(f"  [sbx {sbx.sandbox_id}] killed")


def run_python_in_sandbox(name: str, code: str, policy: Any,
                          payload: dict | None = None,
                          pip_packages: list[str] | None = None,
                          envs: dict[str, str] | None = None,
                          timeout: int = 180,
                          template: str = "ai-agent") -> dict:
    """Run a Python snippet in a sandbox and return the JSON it writes to /tmp/out.json.

    The snippet receives the payload as JSON at /tmp/in.json. `pip_packages`
    are installed inside the sandbox before the script runs. `envs` are
    forwarded into the sandbox's environment.
    """
    if not DECLAW_AVAILABLE:
        # Mock fallback: actually write /tmp/in.json + /tmp/out.json on the host
        # so scripts using the real sandbox I/O convention work unchanged.
        # Safe on a dev machine; the script runs locally, not in a microVM.
        print(f"  [mock-sbx mock-{name}] policy={policy.get('kind') if isinstance(policy, dict) else '?'} "
              f"(no DECLAW_API_KEY — running script locally)")
        with open("/tmp/in.json", "w") as f:
            json.dump(payload or {}, f)
        try:
            os.remove("/tmp/out.json")
        except FileNotFoundError:
            pass
        local_ns: dict[str, Any] = {}
        exec(code, {"__INPUT__": payload or {}, "__name__": "__sandboxed__"}, local_ns)
        try:
            with open("/tmp/out.json") as f:
                return json.load(f)
        except FileNotFoundError:
            return local_ns.get("__OUTPUT__", {})

    d = _import_declaw()
    sbx = d["Sandbox"].create(
        template=template, timeout=timeout, security=policy, envs=envs or {},
    )
    print(f"  [sbx {sbx.sandbox_id}] created — name={name}")
    try:
        if pip_packages:
            # --trusted-host: VM clock can drift, making PyPI TLS cert appear
            # "not yet valid". Network is already locked to pypi by declaw's
            # allowlist, so trusting the host here is acceptable.
            ri = sbx.commands.run(
                "pip install --quiet --upgrade "
                "--no-cache-dir "
                "--trusted-host pypi.org "
                "--trusted-host files.pythonhosted.org "
                "--timeout 120 "
                f"{' '.join(pip_packages)}",
                timeout=480,
            )
            if ri.exit_code != 0:
                raise RuntimeError(f"pip install failed in {name}: {ri.stderr[:400]}")
        sbx.files.write("/tmp/in.json", json.dumps(payload or {}))
        sbx.files.write("/tmp/script.py", code)
        result = sbx.commands.run("python3 /tmp/script.py", timeout=timeout)
        if result.exit_code != 0:
            raise RuntimeError(f"sandbox {name} script failed:\n{result.stderr[:6000]}")
        return json.loads(sbx.files.read("/tmp/out.json"))
    finally:
        sbx.kill()
        print(f"  [sbx {sbx.sandbox_id}] killed")


# ---------- Common pip + env settings for in-sandbox LLM calls ----------

LLM_PIP: list[str] = []  # ai-agent template already has openai/langgraph/crewai etc.


def llm_envs() -> dict[str, str]:
    """Forward whichever LLM API keys are set on the host into the sandbox.

    OPENAI_API_KEY is required (every workflow at least imports shared.llm).
    ANTHROPIC_API_KEY is forwarded only when set — workflows 16 and 17 use it.
    ALPHAVANTAGE_API_KEY is forwarded for workflows 06 and 12 (live market data).
    """
    if not os.getenv("OPENAI_API_KEY"):
        raise RuntimeError("OPENAI_API_KEY required for in-sandbox LLM calls")
    envs = {"OPENAI_API_KEY": os.environ["OPENAI_API_KEY"]}
    for k in ("ANTHROPIC_API_KEY", "ALPHAVANTAGE_API_KEY"):
        if os.getenv(k):
            envs[k] = os.environ[k]
    return envs


# Domains required for an in-sandbox LLM call (OpenAI + Anthropic + pip install bootstrap).
LLM_DOMAINS = [
    "api.openai.com",
    "api.anthropic.com",
    "pypi.org",
    "*.pythonhosted.org",
    "files.pythonhosted.org",
]
