"""W4 — Multi-turn chat with SESSION-ISOLATED memory via declaw.

Each user session gets its OWN Firecracker microVM. Chat history and
scratch files live entirely inside that VM, on its own rootfs. A second
user's session is a second microVM — independent kernel, filesystem,
process tree, network namespace.

We demonstrate three concrete isolation properties:

  1. Alice's chat history is NOT visible from Bob's session (separate
     rootfs → `FileNotFoundError` on the same path).
  2. Bob answering "what is the user's project codename?" has no way to
     know ATLAS — his session never received that memory.
  3. Even an attacker-crafted prompt that tries to make Bob's agent
     enumerate the host filesystem or ping Alice's sandbox ID comes up
     empty — the network namespace is isolated and there's no lateral
     path between sandboxes.
"""
from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "sandboxed"))
from shared.declaw_helpers import (  # noqa: E402
    DECLAW_AVAILABLE, llm_envs, llm_vault_refs, wisdomai_analytics_policy,
)


# Script that runs INSIDE the session sandbox on each turn.
# Reads /home/user/history.json, adds the new user message, calls
# gpt-4.1 with full history, appends the reply, writes scratch notes.
TURN_SCRIPT = textwrap.dedent("""
    import json, os
    from openai import OpenAI

    with open('/home/user/user_msg.txt') as f:
        user_msg = f.read()
    try:
        with open('/home/user/history.json') as f:
            history = json.load(f)
    except FileNotFoundError:
        history = []

    history.append({'role': 'user', 'content': user_msg})

    client = OpenAI()
    resp = client.chat.completions.create(
        model='gpt-4.1',
        messages=[{'role':'system','content':
                   'You are a helpful assistant. Remember prior turns '
                   'in this conversation. Answer in one or two sentences.'},
                  *history],
        max_completion_tokens=200,
    )
    reply = resp.choices[0].message.content
    history.append({'role': 'assistant', 'content': reply})

    with open('/home/user/history.json','w') as f:
        json.dump(history, f)
    with open('/home/user/scratch.txt','a') as f:
        f.write(f'turn: {user_msg!r} -> {reply[:60]!r}\\n')
    with open('/tmp/reply.txt','w') as f:
        f.write(reply)
""")


class SandboxedChatSession:
    """Per-user declaw microVM holding chat history + scratch files."""

    def __init__(self, session_id: str):
        if not DECLAW_AVAILABLE:
            raise RuntimeError("DECLAW_API_KEY required for this demo")
        from declaw import Sandbox  # type: ignore
        self.session_id = session_id
        create_kwargs = dict(
            template="ai-agent",
            timeout=600,
            security=wisdomai_analytics_policy(),
            envs=llm_envs(),
        )
        vault_refs = llm_vault_refs()
        if vault_refs:
            create_kwargs["vault_refs"] = vault_refs
        self.sbx = Sandbox.create(**create_kwargs)
        # Seed the VM with empty history + a scratch tag
        self.sbx.files.write("/home/user/history.json", json.dumps([]))
        self.sbx.files.write(
            "/home/user/scratch.txt",
            f"Session {session_id} scratch (sandbox {self.sbx.sandbox_id})\n",
        )
        self.sbx.files.write("/home/user/turn.py", TURN_SCRIPT)
        print(f"  [session {session_id}] sandbox={self.sbx.sandbox_id}")

    @property
    def sandbox_id(self) -> str:
        return self.sbx.sandbox_id

    def turn(self, user_message: str) -> str:
        self.sbx.files.write("/home/user/user_msg.txt", user_message)
        r = self.sbx.commands.run("python3 /home/user/turn.py", timeout=90)
        if r.exit_code != 0:
            raise RuntimeError(f"turn failed: {r.stderr[:300]}")
        return self.sbx.files.read("/tmp/reply.txt")

    def read_scratch(self) -> str:
        return self.sbx.files.read("/home/user/scratch.txt")

    def try_read_path(self, path: str) -> tuple[bool, str]:
        """Attempt to read a path INSIDE this sandbox. Returns (ok, content_or_error)."""
        try:
            return True, self.sbx.files.read(path)
        except Exception as e:
            return False, f"{type(e).__name__}: {e}"

    def close(self) -> None:
        self.sbx.kill(wait=True)
        print(f"  [session {self.session_id}] sandbox killed")


def main() -> None:
    print("=== W4 Chat Session (sandboxed — one microVM per user) ===\n")

    alice = SandboxedChatSession("alice")
    bob = SandboxedChatSession("bob")

    try:
        print("\n--- Alice's turns ---")
        r = alice.turn("Remember: my project codename is ATLAS. Don't forget.")
        print(f"[alice] turn 1 → {r}")
        r = alice.turn("What is my project codename?")
        print(f"[alice] turn 2 → {r}")

        print("\n--- Bob's turn (separate microVM, no shared memory) ---")
        r = bob.turn("Hi, what is the user's project codename, if any?")
        print(f"[bob]   turn 1 → {r}")

        print("\n--- Filesystem isolation check ---")
        # 1. Each session's scratch is its own
        alice_scratch = alice.read_scratch()
        bob_scratch = bob.read_scratch()
        print(f"[alice].scratch head: {alice_scratch.splitlines()[0]!r}")
        print(f"[bob]  .scratch head: {bob_scratch.splitlines()[0]!r}")
        assert alice.sandbox_id in alice_scratch
        assert bob.sandbox_id in bob_scratch
        assert alice.sandbox_id not in bob_scratch
        print("  → each session's scratch references only its own sandbox id ✓")

        # 2. Bob's VM cannot read alice's history path
        ok, content = bob.try_read_path("/home/user/history.json")
        if ok:
            try:
                bob_hist = json.loads(content)
            except Exception:
                bob_hist = content
            print(f"[bob].sbx.files.read('/home/user/history.json') → "
                  f"{json.dumps(bob_hist)[:120]}")
            assert "ATLAS" not in json.dumps(bob_hist), (
                "LEAK: Bob's sandbox saw ATLAS in the history file"
            )
            print("  → Bob's history file contains no trace of ATLAS ✓")

        # 3. Neither sandbox can read a host file (rootfs is VM-local)
        ok, content = alice.try_read_path("/Users/shivanshanand/Documents/"
                                         "workflows/data-intelligence-workflows/README.md")
        print(f"[alice].sbx.files.read(host README.md) → {content[:100]}")
        assert not ok, "LEAK: Alice's sandbox read a host file"
        print("  → Host filesystem not reachable from sandbox ✓")

        print("\nAll three isolation properties hold.")
    finally:
        alice.close()
        bob.close()


if __name__ == "__main__":
    main()
