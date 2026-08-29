"""Known-vulnerable runtime versions (bundled data/cves.json)."""
from __future__ import annotations

import re

from llm_host_guard.core import Ctx, Finding, sh, version_lt

NAME = "versions"


def detect(ctx: Ctx) -> dict[str, str]:
    found = {}
    if (v := sh(["ollama", "--version"])) and (m := re.search(r"(\d+\.\d+\.\d+)", v)):
        found["ollama"] = m.group(1)
    if (v := sh(["python3", "-c", "import vllm;print(vllm.__version__)"])) and (m := re.search(r"(\d+\.\d+\.\d+)", v)):
        found["vllm"] = m.group(1)
    if (v := sh(["llama-server", "--version"])) and (m := re.search(r"\bb?(\d{3,5})\b", v)):
        found["llama.cpp"] = m.group(1)
    if (v := sh(["python3", "-c", "import open_webui;print(open_webui.__version__)"])) and (m := re.search(r"(\d+\.\d+\.\d+)", v)):
        found["open-webui"] = m.group(1)
    return found


def run(ctx: Ctx) -> list[Finding]:
    found = detect(ctx)
    if not found:
        return [Finding(NAME, "INFO", "No LLM runtime CLIs found on PATH to version-check")]
    out = []
    for prod, ver in found.items():
        hits = [c for c in ctx.cves.get(prod, []) if version_lt(ver, c["fixed_in"])]
        if hits:
            worst = min(hits, key=lambda c: ["CRITICAL", "HIGH", "MED"].index(c["severity"]))
            out.append(Finding(NAME, worst["severity"], f"{prod} {ver} has {len(hits)} known CVE(s)",
                               "; ".join(f"{c['id']} ({c['desc']})" for c in hits),
                               f"Upgrade {prod} to ≥ {max(c['fixed_in'] for c in hits)}",
                               {"version": ver, "cves": [c["id"] for c in hits]}))
        else:
            out.append(Finding(NAME, "OK", f"{prod} {ver}: no bundled CVEs match"))
    return out
