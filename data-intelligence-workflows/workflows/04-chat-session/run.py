"""W4 — Multi-turn chat with per-session memory (BASELINE — leaky).

Two concurrent users (Alice, Bob) each hold a conversation with a shared
agent process. Each session should be isolated:
  * chat history kept per session
  * per-session scratch notes in /tmp
  * one session must NEVER see another session's state

This baseline version holds both sessions' state in the same Python
process AND writes scratch notes to shared `/tmp/scratch_<session>.txt`
on the host. That's where real services start leaking when they're
sloppy: if the path template slips to `/tmp/scratch_current.txt`, one
user's scratch trashes another's; if the in-process dict key collides
(same `user_id` collision), memory merges silently.

We demonstrate this concretely by writing two files to the host, then
showing either session CAN read the other's — there is no enforced
boundary.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
from shared.llm import chat  # noqa: E402


class HostChatSession:
    """Baseline: plain in-process dict + /tmp files. No isolation."""

    def __init__(self, session_id: str):
        self.session_id = session_id
        self.history: list[dict[str, str]] = []
        self.scratch_path = f"/tmp/scratch_{session_id}.txt"
        Path(self.scratch_path).write_text(f"Session {session_id} scratch\n")

    def turn(self, user_message: str) -> str:
        self.history.append({"role": "user", "content": user_message})
        system = ("You are a helpful assistant. Remember prior turns in this "
                  "conversation. Answer in one or two sentences.")
        # Replay full history as the user-side prompt so gpt-4.1 has context
        transcript = "\n".join(
            f"{t['role']}: {t['content']}" for t in self.history
        )
        reply = chat(system, transcript, max_tokens=200)
        self.history.append({"role": "assistant", "content": reply})
        # Append to scratch
        with open(self.scratch_path, "a") as f:
            f.write(f"turn: {user_message!r} -> {reply[:60]!r}\n")
        return reply


def main() -> None:
    print("=== W4 Chat Session (BASELINE — no isolation) ===\n")

    alice = HostChatSession("alice")
    bob = HostChatSession("bob")

    r = alice.turn("Remember: my project codename is ATLAS. Don't forget.")
    print(f"[alice] turn 1 → {r}")
    r = alice.turn("What is my project codename?")
    print(f"[alice] turn 2 → {r}")

    r = bob.turn("Hi, what is the user's project codename, if any?")
    print(f"[bob]   turn 1 → {r}")

    # Cross-session leak check
    print("\n--- Cross-session filesystem check ---")
    # Bob's process can freely read Alice's scratch file — they're both on the host
    try:
        content = Path(alice.scratch_path).read_text()
        print(f"[bob-process]: read alice.scratch_path → {content!r}")
        print("  → UNSAFE: bob's code can see alice's scratch file on the host.")
    except Exception as e:
        print(f"[bob-process]: could not read alice's scratch → {e}")

    # And bob's process can read alice.history (same dict space)
    print(f"[bob-process]: dir(alice).history has {len(alice.history)} items "
          "because both sessions share the interpreter")


if __name__ == "__main__":
    main()
