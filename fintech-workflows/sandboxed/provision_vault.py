"""Provision Declaw credential-vault secrets for the fintech demos (optional).

By default the sandboxed workflows forward the host's LLM API keys into the
microVM as env vars. The stronger posture is the credential vault: the real key
lives server-side in OpenBao and is injected by the egress proxy on the matching
outbound request, so the VM only ever sees the placeholder
"declaw:vault-managed". Even an injected agent that dumps /proc or exfiltrates
its environment never gets the key.

This script provisions the LLM keys (the high-value secrets) into the vault using
the built-in provider presets — the preset supplies the domain scope and header
injection rule (OpenAI: Authorization: Bearer; Anthropic: x-api-key +
anthropic-version). It then prints the env exports that switch the workflows onto
the vault path (`declaw_helpers.llm_vault_refs()` reads these):

    export DECLAW_OPENAI_VAULT_REF=fintech-openai
    export DECLAW_ANTHROPIC_VAULT_REF=fintech-anthropic

Run once:
    export DECLAW_API_KEY=dcl_...  DECLAW_DOMAIN=api.declaw.ai
    export OPENAI_API_KEY=sk-...   ANTHROPIC_API_KEY=sk-ant-...   # whichever you use
    python sandboxed/provision_vault.py

Tear down:
    python sandboxed/provision_vault.py --delete

ALPHAVANTAGE_API_KEY is intentionally left on the env path — it is a
low-sensitivity public-market-data key passed as a URL query param, not a
secret worth brokering.
"""
from __future__ import annotations

import os
import sys

# env var name (inside the sandbox) -> (vault secret name, provider preset)
SECRETS = {
    "OPENAI_API_KEY": ("fintech-openai", "openai"),
    "ANTHROPIC_API_KEY": ("fintech-anthropic", "anthropic"),
}

# env var name -> the DECLAW_*_VAULT_REF the workflows read (see declaw_helpers)
REF_ENV = {
    "OPENAI_API_KEY": "DECLAW_OPENAI_VAULT_REF",
    "ANTHROPIC_API_KEY": "DECLAW_ANTHROPIC_VAULT_REF",
}


def _client():
    try:
        from declaw import VaultClient  # type: ignore
    except Exception as e:  # noqa: BLE001
        sys.exit(f"declaw SDK not importable: {e}")
    if not os.getenv("DECLAW_API_KEY"):
        sys.exit("DECLAW_API_KEY required to manage vault secrets")
    return VaultClient(
        api_key=os.environ["DECLAW_API_KEY"],
        domain=os.getenv("DECLAW_DOMAIN", "api.declaw.ai"),
    )


def provision() -> None:
    vault = _client()
    existing = {s.name for s in vault.list_secrets()}
    exports: list[str] = []
    try:
        for env_name, (secret_name, provider) in SECRETS.items():
            key = os.getenv(env_name)
            if not key:
                print(f"- {env_name}: not set on host, skipping")
                continue
            if secret_name in existing:
                vault.rotate_secret(secret_name, key)
                print(f"- {secret_name}: rotated (provider={provider})")
            else:
                vault.create_secret(key, name=secret_name, provider=provider)
                print(f"- {secret_name}: created (provider={provider})")
            exports.append(f"export {REF_ENV[env_name]}={secret_name}")
    finally:
        vault.close()

    if exports:
        print("\nVault provisioned. Switch the workflows onto the vault path with:\n")
        for line in exports:
            print(f"    {line}")
        print("\nThe real key never enters the VM — the proxy injects it on the "
              "matching outbound request; the in-VM env holds 'declaw:vault-managed'.")
    else:
        print("\nNo host keys found to provision (set OPENAI_API_KEY / "
              "ANTHROPIC_API_KEY first).")


def delete() -> None:
    vault = _client()
    try:
        existing = {s.name for s in vault.list_secrets()}
        for _, (secret_name, _provider) in SECRETS.items():
            if secret_name in existing:
                vault.delete_secret(secret_name)
                print(f"- {secret_name}: deleted")
            else:
                print(f"- {secret_name}: not present")
    finally:
        vault.close()
    print("\nUnset the refs to return to env forwarding:")
    for ref in REF_ENV.values():
        print(f"    unset {ref}")


if __name__ == "__main__":
    if "--delete" in sys.argv[1:]:
        delete()
    else:
        provision()
