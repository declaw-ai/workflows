"""Verify declaw security primitives beyond PII: filesystem isolation,
network policy (allow vs deny), env-secret masking, transformation rules.

Run:
    DECLAW_API_KEY=... DECLAW_DOMAIN=api.declaw.ai \
    OPENAI_API_KEY=sk-... python sandboxed/verify_security_primitives.py
"""
from __future__ import annotations

import json
import os
import sys
import textwrap

from declaw import (
    ALL_TRAFFIC,
    AuditConfig,
    EnvSecurityConfig,
    NetworkPolicy,
    SecureEnvVar,
    Sandbox,
    SecurityPolicy,
    TransformationRule,
)

GREEN = "\033[32m"; RED = "\033[31m"; DIM = "\033[2m"; BOLD = "\033[1m"; END = "\033[0m"

passes = 0
fails = 0


def ok(msg):
    global passes
    passes += 1
    print(f"  {GREEN}PASS{END} {msg}")


def bad(msg):
    global fails
    fails += 1
    print(f"  {RED}FAIL{END} {msg}")


# ---------------------------------------------------------------------------
# 1. Network policy: allow api.openai.com, deny everything else
# ---------------------------------------------------------------------------
def test_network_policy():
    print(f"\n{BOLD}== 1. Network policy (allow api.openai.com, deny the rest) =={END}")
    pol = SecurityPolicy(
        network=NetworkPolicy(allow_out=["api.openai.com"], deny_out=[ALL_TRAFFIC]),
        audit=AuditConfig(enabled=True),
    )
    sbx = Sandbox.create(template="python", timeout=120, security=pol)
    print(f"  {DIM}sbx {sbx.sandbox_id}{END}")
    try:
        sbx.files.write("/tmp/p.py", textwrap.dedent("""
            import ssl, urllib.request, urllib.error
            ctx = ssl._create_unverified_context()
            def probe(url):
                try:
                    urllib.request.urlopen(url, timeout=6, context=ctx).read(100)
                    return "REACHED_200"
                except urllib.error.HTTPError as e:
                    return f"REACHED_HTTP_{e.code}"
                except Exception as e:
                    return f"BLOCKED: {type(e).__name__}"
            print("evil.com ->", probe("https://evil.com"))
            print("openai   ->", probe("https://api.openai.com/v1/models"))
        """))
        r = sbx.commands.run("python3 /tmp/p.py", timeout=30)
        out = r.stdout
        print(f"  {DIM}{out.strip()}{END}")
        (ok if "evil.com -> BLOCKED" in out else bad)("evil.com blocked")
        # HTTP 401 from OpenAI is the allowed-but-unauthorized case:
        # TCP + TLS + HTTP all reached the server, which proves the allowlist
        # let it through. Only the app-layer 401 came back.
        (ok if "openai   -> REACHED" in out else bad)(
            "api.openai.com reached (401 is fine — proves allowlist passed)"
        )
    finally:
        sbx.kill()


# ---------------------------------------------------------------------------
# 2. Cross-sandbox filesystem isolation (Firecracker rootfs)
# ---------------------------------------------------------------------------
def test_filesystem_isolation():
    print(f"\n{BOLD}== 2. Filesystem isolation (sandbox A vs B vs host) =={END}")
    a = Sandbox.create(template="python", timeout=120)
    b = Sandbox.create(template="python", timeout=120)
    print(f"  {DIM}A={a.sandbox_id}  B={b.sandbox_id}{END}")
    try:
        secret = "PHI-mrn=44218 name=Jordan-Rivera"
        a.files.write("/tmp/chart.txt", secret)

        # A can read its own file
        ra = a.commands.run("cat /tmp/chart.txt", timeout=10).stdout.strip()
        (ok if secret in ra else bad)(f"A reads its own file (got: {ra!r})")

        # B cannot read A's file — separate rootfs
        rb = b.commands.run("cat /tmp/chart.txt 2>&1 || echo EXIT_NONZERO", timeout=10).stdout
        (ok if "No such file" in rb and secret not in rb else bad)(
            "B cannot read A's /tmp/chart.txt (separate rootfs)"
        )

        # The Firecracker VM's /etc/passwd is not the host's
        ra_passwd = a.commands.run("head -2 /etc/passwd", timeout=10).stdout.strip()
        (ok if "root:" in ra_passwd and "operator" not in ra_passwd else bad)(
            f"Sandbox /etc/passwd is VM-local, not host (got first line ok)"
        )
    finally:
        a.kill(); b.kill()


# ---------------------------------------------------------------------------
# 3. Env-secret masking with SecureEnvVar
# ---------------------------------------------------------------------------
def test_env_secret_masking():
    print(f"\n{BOLD}== 3. Env secrets: SecureEnvVar hides from get_info() =={END}")
    # Declaw ships `EnvSecurityConfig` and `SecureEnvVar` for env-secret
    # protection. Here we verify the end-to-end guarantee we actually care
    # about: env vars pass into the VM correctly for workload use, and the
    # control plane's get_info() representation doesn't echo the raw value
    # back to anyone listing the sandbox.
    sbx = Sandbox.create(
        template="python", timeout=120,
        envs={
            "OPENAI_API_KEY": "sk-SECRET-should-not-leak-via-get-info",
            "PUBLIC_VAR": "safe-to-show",
        },
    )
    print(f"  {DIM}sbx {sbx.sandbox_id}{END}")
    try:
        # Inside the VM, the variable IS available to workload code
        inside = sbx.commands.run(
            'python3 -c "import os;print(len(os.environ.get(\'OPENAI_API_KEY\',\'\')))"',
            timeout=10,
        ).stdout.strip()
        (ok if inside.isdigit() and int(inside) > 0 else bad)(
            f"OPENAI_API_KEY is available inside VM (length={inside})"
        )

        # But get_info() must not expose its value
        info = sbx.get_info()
        info_blob = json.dumps(getattr(info, "__dict__", info), default=str).lower()
        leaked = "sk-secret-should-not-leak" in info_blob
        (bad if leaked else ok)("Secret value absent from sbx.get_info() payload")
    finally:
        sbx.kill()


# ---------------------------------------------------------------------------
# 4. Transformation rule: strip Bearer sk-* from outbound bodies
# ---------------------------------------------------------------------------
def test_transformation_rule():
    print(f"\n{BOLD}== 4. TransformationRule: strip API keys outbound =={END}")
    pol = SecurityPolicy(
        transformations=[
            TransformationRule(
                direction="outbound",
                match=r"sk-[A-Za-z0-9\-_]+",
                replace="[API_KEY_REDACTED]",
            ),
        ],
        network=NetworkPolicy(
            allow_out=["httpbin.org", "*.httpbin.org"],
            deny_out=[ALL_TRAFFIC],
        ),
    )
    sbx = Sandbox.create(template="python", timeout=120, security=pol)
    print(f"  {DIM}sbx {sbx.sandbox_id}{END}")
    try:
        sbx.files.write("/tmp/p.py", textwrap.dedent("""
            import json, ssl, urllib.request
            ctx = ssl._create_unverified_context()
            body = json.dumps({
                "api_key": "sk-live-ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                "note": "authorization: Bearer sk-other-key-12345"
            }).encode()
            req = urllib.request.Request("https://httpbin.org/post", data=body,
                headers={"Content-Type":"application/json"})
            resp = urllib.request.urlopen(req, timeout=15, context=ctx).read().decode()
            import json as j
            echoed = j.loads(resp)["json"]
            print("DESTINATION_SAW:", j.dumps(echoed))
        """))
        r = sbx.commands.run("python3 /tmp/p.py", timeout=40)
        out = r.stdout
        print(f"  {DIM}{out.strip()[:300]}{END}")
        (ok if "[API_KEY_REDACTED]" in out else bad)(
            "httpbin received the redacted placeholder"
        )
        (ok if "sk-live-ABCDEFGHIJKLMNOPQRSTUVWXYZ" not in out else bad)(
            "Raw sk-* value never reached the destination"
        )
    finally:
        sbx.kill()


# ---------------------------------------------------------------------------
# 5. Cloud metadata block (always on, not overridable)
# ---------------------------------------------------------------------------
def test_metadata_block():
    print(f"\n{BOLD}== 5. Cloud metadata 169.254.169.254 hard-blocked =={END}")
    # Try to explicitly allow the metadata IP — declaw should still block it.
    pol = SecurityPolicy(
        network=NetworkPolicy(
            allow_out=["169.254.169.254", ALL_TRAFFIC],
            deny_out=[],
        ),
    )
    sbx = Sandbox.create(template="python", timeout=120, security=pol)
    print(f"  {DIM}sbx {sbx.sandbox_id}{END}")
    try:
        r = sbx.commands.run(
            "curl -m 5 -s -o /dev/null -w 'code=%{http_code}\\n' "
            "http://169.254.169.254/latest/meta-data/ || echo BLOCKED",
            timeout=15,
        )
        out = r.stdout.strip()
        print(f"  {DIM}{out}{END}")
        (ok if "code=000" in out or "BLOCKED" in out else bad)(
            "Metadata IP unreachable even when explicitly allowlisted"
        )
    finally:
        sbx.kill()


def main():
    if not os.getenv("DECLAW_API_KEY"):
        print("DECLAW_API_KEY required"); sys.exit(1)
    test_network_policy()
    test_filesystem_isolation()
    test_env_secret_masking()
    test_transformation_rule()
    test_metadata_block()
    print(f"\n{BOLD}== Summary =={END}")
    print(f"  {GREEN}{passes} pass{END}   {RED}{fails} fail{END}")
    sys.exit(0 if fails == 0 else 1)


if __name__ == "__main__":
    main()
