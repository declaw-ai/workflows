"""Declaw SDK issue #07 — ai-agent template bakes in openai + anthropic
but does not ship the Accept-Encoding shim.

EXPECTED: A sandbox created with `template="ai-agent"` should be
          immediately usable with `PIIConfig(rehydrate_response=True)`
          against OpenAI or Anthropic endpoints — i.e., rehydration on
          response bodies should work without the caller having to
          monkey-patch httpx.

OBSERVED: After `sbx = Sandbox.create(template="ai-agent", ...)`, the
          sandbox contains `/usr/local/lib/python3.10/dist-packages/openai/`
          and `anthropic/`, but there is no `Accept-Encoding: identity`
          override in the Python env. OpenAI/Anthropic SDKs therefore
          send `Accept-Encoding: gzip, deflate`, OpenAI/Anthropic return
          gzipped bodies, and the Declaw proxy's rehydration pass
          silently becomes a no-op (see issue #01).

WORKAROUND: The caller ships a small shim file into the sandbox and
            does `import declaw_openai_compat` at the top of their
            script. Reliable but easy to forget — 14 of our 17 fintech
            workflows need it.

FIX (server-side): Once issue #01 is resolved in the proxy, this is a
                   no-op. Until then, consider baking the shim into the
                   ai-agent template image as a `sitecustomize.py`:
                       # /etc/python/sitecustomize.py
                       import httpx
                       # ... same Accept-Encoding: identity override ...
                   so every Python process in the sandbox picks it up
                   automatically.

Env: DECLAW_API_KEY, DECLAW_DOMAIN
"""
from __future__ import annotations

import os
import sys
import textwrap

from declaw import (
    ALL_TRAFFIC, AuditConfig, NetworkPolicy, PIIConfig, Sandbox, SecurityPolicy,
)


def policy() -> SecurityPolicy:
    return SecurityPolicy(
        pii=PIIConfig(enabled=True, types=["email"], action="redact",
                      rehydrate_response=True),
        network=NetworkPolicy(
            allow_out=["api.openai.com", "pypi.org", "*.pythonhosted.org"],
            deny_out=[ALL_TRAFFIC],
        ),
        audit=AuditConfig(enabled=True),
    )


INSPECT = textwrap.dedent("""
    import os, glob, sys
    # 1. Does the template have openai + anthropic pre-installed?
    openai_here = any(
        os.path.isdir(os.path.join(p, "openai"))
        for p in sys.path if p and os.path.isdir(p)
    )
    anthropic_here = any(
        os.path.isdir(os.path.join(p, "anthropic"))
        for p in sys.path if p and os.path.isdir(p)
    )
    print(f"OPENAI_PRESENT: {openai_here}")
    print(f"ANTHROPIC_PRESENT: {anthropic_here}")

    # 2. Is there a sitecustomize.py that overrides Accept-Encoding?
    sitecustomize_paths = []
    for p in sys.path:
        sc = os.path.join(p, "sitecustomize.py")
        if os.path.isfile(sc):
            sitecustomize_paths.append(sc)
            with open(sc) as f:
                body = f.read()
            if "Accept-Encoding" in body and "identity" in body:
                print(f"SITECUSTOMIZE_SHIM: yes at {sc}")
                break
    else:
        print("SITECUSTOMIZE_SHIM: no")

    # 3. Is httpx currently injecting Accept-Encoding: identity by default?
    import httpx
    c = httpx.Client()
    try:
        ae = c.headers.get("Accept-Encoding", "")
        print(f"HTTPX_DEFAULT_ACCEPT_ENCODING: {ae!r}")
    finally:
        c.close()

    # 4. Does the shim file we'd need to ship exist anywhere already?
    found_shim = any(
        os.path.isfile(os.path.join(p, "declaw_openai_compat.py"))
        for p in sys.path + ["/tmp"] if p and os.path.isdir(p)
    )
    print(f"SHIM_FILE_PRESENT: {found_shim}")
""")


def main() -> None:
    print("=" * 72)
    print("Declaw SDK issue #07 — ai-agent template missing Accept-Encoding shim")
    print("=" * 72)

    if not os.getenv("DECLAW_API_KEY"):
        print("need DECLAW_API_KEY")
        sys.exit(0)

    sbx = Sandbox.create(template="ai-agent", timeout=60, security=policy())
    try:
        sbx.files.write("/tmp/script.py", INSPECT)
        r = sbx.commands.run("python3 /tmp/script.py", timeout=45)
        out = r.stdout or ""
        print(out)

        openai_ok = "OPENAI_PRESENT: True" in out
        shim_site = "SITECUSTOMIZE_SHIM: yes" in out
        shim_file = "SHIM_FILE_PRESENT: True" in out
        # If httpx default is identity it means someone already patched it.
        identity_default = "HTTPX_DEFAULT_ACCEPT_ENCODING: 'identity'" in out

        print("\nEXPECTED : OPENAI_PRESENT=True AND "
              "(SITECUSTOMIZE_SHIM=yes OR HTTPX_DEFAULT_ACCEPT_ENCODING=identity)")
        print(f"OBSERVED : openai_ok={openai_ok}, shim_site={shim_site}, "
              f"shim_file={shim_file}, identity_default={identity_default}")
        if openai_ok and (shim_site or identity_default):
            print("VERDICT  : PASS")
        else:
            print("VERDICT  : FAIL — template ships the SDKs but no Accept-Encoding "
                  "override; callers must ship their own shim for issue #01 "
                  "workaround.")
    finally:
        sbx.kill()


if __name__ == "__main__":
    main()
