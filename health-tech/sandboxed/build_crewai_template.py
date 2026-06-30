"""One-time builder for a declaw Template with crewai pre-installed.

After this completes, `sandboxed/03-medical-coding-crewai/run.py` can be
pointed at the new template and will start in ~1s without any pip install.

Run:
    DECLAW_API_KEY=... DECLAW_DOMAIN=api.declaw.ai \\
    python sandboxed/build_crewai_template.py
"""
from __future__ import annotations

import os
import sys
import time

from declaw import Template, TemplateBase, TemplateBuildStatus


def build_spec() -> TemplateBase:
    # NOTE: the slim python images lack `sudo` which declaw's build script
    # requires; using the default ubuntu:22.04 and installing python3 via
    # apt works. `run_cmd([...])` in the current SDK double-nests the list,
    # so `_run_cmds` is set directly as a flat list of strings.
    tb = (
        TemplateBase()
        .from_base_image("ubuntu:22.04")
        .apt_install("python3", "python3-pip", "python3-venv", "ca-certificates", "sudo")
    )
    tb._run_cmds = [  # type: ignore[attr-defined]
        "pip3 install --no-cache-dir --break-system-packages crewai || "
        "pip3 install --no-cache-dir crewai",
    ]
    return tb


def main() -> None:
    if not os.getenv("DECLAW_API_KEY"):
        print("DECLAW_API_KEY required"); sys.exit(1)

    print("Starting background build of 'crewai-ready' template…")
    alias = os.environ.get("TEMPLATE_ALIAS", f"crewai-ready-{int(time.time())}")
    print(f"  alias:    {alias}")
    info = Template.build_in_background(
        template=build_spec(),
        alias=alias,
        cpu_count=2,
        memory_mb=2048,
    )
    build_id = info.build_id
    print(f"  build_id: {build_id}")

    last_status = ""
    last_log_len = 0
    t0 = time.time()
    while True:
        info = Template.get_build_status(build_id)
        status = str(info.status)
        if status != last_status:
            print(f"  [{int(time.time() - t0):>3}s] status={status}")
            last_status = status
        # stream any new log lines
        logs = info.logs or []
        for line in logs[last_log_len:]:
            print(f"    | {line}")
        last_log_len = len(logs)

        if status.lower() in ("succeeded", "done", "completed", "finished"):
            print("\nTemplate build succeeded. Ready to use with alias='crewai-ready'.")
            return
        if status.lower() in ("failed", "error"):
            print("\nBuild failed; see logs above.")
            sys.exit(1)

        time.sleep(5)


if __name__ == "__main__":
    main()
