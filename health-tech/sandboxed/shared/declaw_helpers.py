"""Helpers shared across the sandboxed workflow demos.

Two goals:
  1. One place to build the healthcare-grade SecurityPolicy.
  2. A `local-mock` fallback so the demos read sensibly without a live
     DECLAW_API_KEY (they print what *would* have been sandboxed).
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
    )
    return {
        "ALL_TRAFFIC": ALL_TRAFFIC,
        "AuditConfig": AuditConfig,
        "InjectionDefenseConfig": InjectionDefenseConfig,
        "NetworkPolicy": NetworkPolicy,
        "PIIConfig": PIIConfig,
        "Sandbox": Sandbox,
        "SecurityPolicy": SecurityPolicy,
    }


# ---------- Healthcare-grade security policies ----------

# Categories of PHI we always want redacted before anything leaves the sandbox.
PHI_PII_TYPES = [
    "ssn",
    "credit_card",
    "email",
    "phone",
    "person_name",   # requires Guardrails Service in prod
    "api_key",
    "ip_address",
    "address",
]


def healthcare_llm_policy(allow_domains: list[str]):
    """Policy for an LLM-call sandbox: redact PHI, rehydrate response, audit.

    Injection defense is intentionally off — frontier models (gpt-4.1,
    claude-opus-4.x) already refuse direct-prompt-injection, and the declaw
    ML classifier was false-positive-blocking our legitimate meta-instruction
    prompts. Re-enable on sandboxes that ingest untrusted external content.
    """
    if not DECLAW_AVAILABLE:
        return {"_mock": True, "kind": "llm_policy", "allow_out": allow_domains}
    d = _import_declaw()
    return d["SecurityPolicy"](
        pii=d["PIIConfig"](
            enabled=True,
            types=PHI_PII_TYPES,
            action="redact",
            rehydrate_response=True,
        ),
        network=d["NetworkPolicy"](allow_out=allow_domains, deny_out=[d["ALL_TRAFFIC"]]),
        audit=d["AuditConfig"](enabled=True),
    )


def healthcare_untrusted_io_policy(allow_domains: list[str]):
    """Sandboxes that touch untrusted input (payer portals, PDFs, registries).
    Block on PII outright; injection defense off by default — frontier models
    handle it. Re-enable on the specific sandbox if the content source is
    known to be actively adversarial."""
    if not DECLAW_AVAILABLE:
        return {"_mock": True, "kind": "untrusted_io_policy", "allow_out": allow_domains}
    d = _import_declaw()
    return d["SecurityPolicy"](
        pii=d["PIIConfig"](enabled=True, types=PHI_PII_TYPES, action="block"),
        network=d["NetworkPolicy"](allow_out=allow_domains, deny_out=[d["ALL_TRAFFIC"]]),
        audit=d["AuditConfig"](enabled=True),
    )


# ---------- Sandbox lifecycle helper with mock fallback ----------

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
        # In mock mode we don't actually exec — just log.
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
        print(f"  [mock-sbx {sbx.sandbox_id}] created with policy={policy.get('kind')} "
              f"allow_out={policy.get('allow_out')}")
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
        # Audit log retrieval API surface varies between SDK versions;
        # try a few names and skip if none present.
        for attr in ("get_audit_log", "audit_log", "get_audit_logs"):
            fn = getattr(sbx, attr, None)
            if callable(fn):
                try:
                    entries = fn()
                    print(f"  [audit {name}] {len(entries)} event(s) via {attr}")
                except Exception as e:
                    print(f"  [audit {name}] {attr} call failed: {e}")
                break
        sbx.kill()
        print(f"  [sbx {sbx.sandbox_id}] killed")


def run_python_in_sandbox(name: str, code: str, policy: Any,
                          payload: dict | None = None,
                          pip_packages: list[str] | None = None,
                          envs: dict[str, str] | None = None,
                          timeout: int = 180,
                          template: str = "ai-agent") -> dict:
    """Run a Python snippet in a sandbox and return the JSON it writes to /tmp/out.json.

    The snippet receives the payload as JSON at /tmp/in.json.
    `pip_packages` are installed inside the sandbox before the script runs.
    `envs` are forwarded into the sandbox's environment.
    """
    if not DECLAW_AVAILABLE:
        # Mock fallback: execute locally so the workflow still produces output.
        sbx = MockSandbox(sandbox_id=f"mock-{name}", policy=policy, files_storage={})
        sbx.files_write("/tmp/in.json", json.dumps(payload or {}))
        local_ns: dict[str, Any] = {}
        exec(code, {"__INPUT__": payload or {}}, local_ns)
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
                "pip install --quiet "
                "--no-cache-dir "  # heavy dep trees (crewai) blow past sandbox disk otherwise
                "--trusted-host pypi.org "
                "--trusted-host files.pythonhosted.org "
                "--timeout 120 "  # MITM proxy makes downloads slower than pip's 15s default
                f"{' '.join(pip_packages)}",
                timeout=480,
            )
            if ri.exit_code != 0:
                raise RuntimeError(f"pip install failed in {name}: {ri.stderr[:400]}")
            # If openai was installed, drop in the rehydration shim so that
            # plain `OpenAI()` calls get Accept-Encoding: identity by default.
            if any(p.startswith("openai") for p in pip_packages):
                shim_path = os.path.join(
                    os.path.dirname(__file__), "declaw_openai_compat.py"
                )
                with open(shim_path) as f:
                    sbx.files.write("/tmp/declaw_openai_compat.py", f.read())
        sbx.files.write("/tmp/in.json", json.dumps(payload or {}))
        sbx.files.write("/tmp/script.py", code)
        result = sbx.commands.run("python3 /tmp/script.py", timeout=timeout)
        if result.exit_code != 0:
            raise RuntimeError(f"sandbox {name} script failed:\n{result.stderr[:2000]}")
        return json.loads(sbx.files.read("/tmp/out.json"))
    finally:
        sbx.kill()
        print(f"  [sbx {sbx.sandbox_id}] killed")


# ---------- Common pip + env settings for in-sandbox LLM calls ----------

# ai-agent template already ships openai / anthropic / langchain / langgraph /
# crewai. Workflows that need extra libs (AutoGen, LlamaIndex) pass their
# own pip_packages list.
LLM_PIP: list[str] = []


def llm_envs() -> dict[str, str]:
    if not os.getenv("OPENAI_API_KEY"):
        raise RuntimeError("OPENAI_API_KEY required for in-sandbox LLM calls")
    return {"OPENAI_API_KEY": os.environ["OPENAI_API_KEY"]}


# Domains required for an in-sandbox LLM call (model + pip install bootstrap).
LLM_DOMAINS = [
    "api.openai.com",
    "pypi.org",
    "*.pythonhosted.org",
    "files.pythonhosted.org",
]


# Public health reference APIs used by the multi-API workflows (W5 / W6 / W7).
HEALTHCARE_API_DOMAINS = [
    "rxnav.nlm.nih.gov",         # RxNorm / interaction checker
    "api.fda.gov",               # openFDA drug labels + adverse events
    "clinicaltrials.gov",        # live trial registry v2
    "eutils.ncbi.nlm.nih.gov",   # PubMed E-utilities
]


def healthcare_multi_api_policy(
    extra_domains: list[str] | None = None,
    enable_injection_scan: bool = False,
):
    """Policy for workflows that call the LLM PLUS several public health
    reference APIs in one tool chain. Egress is locked to
    `LLM_DOMAINS + HEALTHCARE_API_DOMAINS (+ extras)`. PHI is redacted +
    rehydrated on all of them. Injection scanning is opt-in (default off)
    because our own meta-prompts were false-positive-blocked by the ML
    classifier — turn it on for RAG-over-untrusted-content workflows."""
    if not DECLAW_AVAILABLE:
        return {"_mock": True, "kind": "multi_api_policy",
                "allow_out": (LLM_DOMAINS + HEALTHCARE_API_DOMAINS + (extra_domains or []))}
    d = _import_declaw()
    allow = LLM_DOMAINS + HEALTHCARE_API_DOMAINS + (extra_domains or [])
    kwargs = dict(
        pii=d["PIIConfig"](
            enabled=True,
            types=PHI_PII_TYPES,
            action="redact",
            rehydrate_response=True,
        ),
        network=d["NetworkPolicy"](allow_out=allow, deny_out=[d["ALL_TRAFFIC"]]),
        audit=d["AuditConfig"](enabled=True),
    )
    if enable_injection_scan:
        kwargs["injection_defense"] = d["InjectionDefenseConfig"](
            enabled=True, action="log_only", threshold=0.8,
        )
    return d["SecurityPolicy"](**kwargs)
