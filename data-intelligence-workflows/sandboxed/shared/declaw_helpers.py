"""Declaw SecurityPolicy helpers for the data-intelligence workflows.

Same shape as the sibling health-tech repo's helpers, but the policies
are tuned for WisdomAI-style federated analytics: the egress allowlist
covers OpenAI + a set of stand-in SaaS / warehouse hosts, instead of
NIH / FDA / CT.gov. PII tokenization stays on (names / emails / phones
inside CRM records or support tickets get redacted the same way).
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
        ALL_TRAFFIC, AuditConfig, InjectionDefenseConfig, NetworkPolicy,
        PIIConfig, Sandbox, SecurityPolicy,
    )
    return {
        "ALL_TRAFFIC": ALL_TRAFFIC, "AuditConfig": AuditConfig,
        "InjectionDefenseConfig": InjectionDefenseConfig,
        "NetworkPolicy": NetworkPolicy, "PIIConfig": PIIConfig,
        "Sandbox": Sandbox, "SecurityPolicy": SecurityPolicy,
    }


# Patient names, emails, phones, SSNs can all appear inside CRM notes,
# support-ticket bodies, or claim records — keep the same PII types.
ENTERPRISE_PII_TYPES = [
    "ssn", "credit_card", "email", "phone",
    "person_name", "api_key", "ip_address", "address",
]


LLM_DOMAINS = [
    "api.openai.com",
    "pypi.org", "*.pythonhosted.org", "files.pythonhosted.org",
]


# Stand-in enterprise-source domains. Real deployments would add e.g.
# `*.salesforce.com`, `*.snowflakecomputing.com`, `*.databricks.com`.
SAAS_STANDIN_DOMAINS = [
    "httpbin.org",                  # used as a controllable SaaS echo
    "api.clearbit.com",             # any real SaaS works the same way
]


def wisdomai_analytics_policy(extra_domains: list[str] | None = None,
                              enable_injection_scan: bool = False):
    """Policy for a federated analytics agent: tokenize PII at every
    outbound hop, lock egress to LLM + listed SaaS/warehouse hosts, log
    every intercepted request for per-source audit attribution."""
    allow = LLM_DOMAINS + SAAS_STANDIN_DOMAINS + (extra_domains or [])
    if not DECLAW_AVAILABLE:
        return {"_mock": True, "kind": "wisdomai_analytics",
                "allow_out": allow}
    d = _import_declaw()
    kwargs = dict(
        pii=d["PIIConfig"](
            enabled=True, types=ENTERPRISE_PII_TYPES,
            action="redact", rehydrate_response=True,
        ),
        network=d["NetworkPolicy"](allow_out=allow,
                                    deny_out=[d["ALL_TRAFFIC"]]),
        audit=d["AuditConfig"](enabled=True),
    )
    if enable_injection_scan:
        kwargs["injection_defense"] = d["InjectionDefenseConfig"](
            enabled=True, action="log_only", threshold=0.8,
        )
    return d["SecurityPolicy"](**kwargs)


def llm_envs() -> dict[str, str]:
    if not os.getenv("OPENAI_API_KEY"):
        raise RuntimeError("OPENAI_API_KEY required for in-sandbox LLM calls")
    return {"OPENAI_API_KEY": os.environ["OPENAI_API_KEY"]}


# ---------- Mock sandbox fallback ----------

@dataclass
class MockSandbox:
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

    def kill(self) -> None:
        print(f"  [mock-sbx {self.sandbox_id}] killed")


def run_python_in_sandbox(name: str, code: str, policy: Any,
                          payload: dict | None = None,
                          pip_packages: list[str] | None = None,
                          envs: dict[str, str] | None = None,
                          timeout: int = 300,
                          template: str = "ai-agent") -> dict:
    """Run a Python snippet in a declaw sandbox and return the JSON it
    writes to /tmp/out.json. The snippet receives `payload` as JSON at
    /tmp/in.json. `pip_packages` are installed inside the sandbox (should
    be empty when using the `ai-agent` template). `envs` are forwarded
    into the sandbox's environment."""
    if not DECLAW_AVAILABLE:
        # Local fallback: execute in-process so the workflow still shows
        # an answer without a live declaw account.
        local_ns: dict[str, Any] = {}
        exec(code, {"__INPUT__": payload or {}}, local_ns)
        return local_ns.get("__OUTPUT__", {})

    d = _import_declaw()
    sbx = d["Sandbox"].create(template=template, timeout=timeout,
                               security=policy, envs=envs or {})
    print(f"  [sbx {sbx.sandbox_id}] created — name={name}")
    try:
        if pip_packages:
            ri = sbx.commands.run(
                "pip install --quiet --no-cache-dir "
                "--trusted-host pypi.org --trusted-host files.pythonhosted.org "
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
            raise RuntimeError(f"sandbox {name} script failed:\n{result.stderr[:2000]}")
        return json.loads(sbx.files.read("/tmp/out.json"))
    finally:
        sbx.kill()
        print(f"  [sbx {sbx.sandbox_id}] killed")
