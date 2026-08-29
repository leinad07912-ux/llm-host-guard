"""--fix: apply recipes attached to findings. Root only. Prints every command before running it."""
from __future__ import annotations

import os
import shlex
import subprocess
import sys
from pathlib import Path

from llm_host_guard.core import Ctx, Finding

DROPIN_OLLAMA = Path("/etc/systemd/system/ollama.service.d/llm-host-guard.conf")
DROPIN_SSHD = Path("/etc/ssh/sshd_config.d/00-llm-host-guard.conf")


def write_file_cmd(path: Path, content: str) -> str:
    """Shell-safe 'create this file' command, printed verbatim so the user sees exactly what lands on disk."""
    return f"mkdir -p {shlex.quote(str(path.parent))} && printf %s {shlex.quote(content)} > {shlex.quote(str(path))}"


def rm_file_cmd(path: Path) -> str:
    return f"rm -f {shlex.quote(str(path))}"


def run_cmd(cmd: str) -> int:
    """Default runner; tests replace it."""
    return subprocess.run(cmd, shell=True).returncode


def has_ssh_key(ctx: Ctx) -> bool:
    p = ctx.home / ".ssh" / "authorized_keys"
    try:
        return p.stat().st_size > 0
    except OSError:
        return False


def sshd_reload_cmd() -> str:
    return "sshd -t && (systemctl reload ssh 2>/dev/null || systemctl reload sshd)"


def apply(ctx: Ctx, findings: list[Finding], yes: bool = False, runner=run_cmd, ask=input, out=print,
          dry_run: bool = False) -> int:
    """Walk findings with fix_cmds; confirm; run; print undo. Returns number of recipes applied."""
    if dry_run:
        yes, runner = True, (lambda c: 0)
    elif os.geteuid() != 0:
        out("--fix needs root: sudo python3 llm_host_guard.py --fix")
        return -1
    applied = 0
    for f in findings:
        if not f.fix_cmds:
            continue
        out(f"\n[{f.severity}] {f.title}")
        if f.fix_note:
            out(f"  note: {f.fix_note}")
        for c in f.fix_cmds:
            out(f"  $ {c}")
        if not yes:
            try:
                if ask("  apply? [y/N] ").strip().lower() not in ("y", "yes"):
                    out("  skipped")
                    continue
            except EOFError:
                out("  skipped (no tty; use --yes)")
                continue
        done = []
        for c in f.fix_cmds:
            rc = runner(c)
            if rc != 0:
                out(f"  FAILED (rc={rc}): {c}")
                break
            done.append(c)
        if len(done) == len(f.fix_cmds):
            applied += 1
            out("  would apply" if dry_run else "  applied")
        if f.undo_cmds:
            out("  undo:")
            for c in f.undo_cmds:
                out(f"    $ {c}")
    return applied
