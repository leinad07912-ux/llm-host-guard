"""Known-vulnerable runtime versions (bundled data/cves.json)."""
from __future__ import annotations

import re
from datetime import date

from llm_host_guard.core import SEVERITIES, Ctx, Finding, sh, version_lt, version_tuple

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


STALE_DAYS = 120   # latest_known older than this => we say so instead of claiming "up to date"
MINORS_BEHIND = 3


def agent_versions(ctx: Ctx) -> dict[str, tuple[str, str | None]]:
    """{agent name: (version_key, installed version or None if unreadable)} for installed/running agents."""
    from llm_host_guard.checks.agents import inventory
    seen = {a["name"] for a in inventory(ctx)}
    out = {}
    for t in ctx.signatures["agent_tools"]:
        if t["name"] not in seen or "version_cmd" not in t:
            continue
        m = re.search(r"(\d+\.\d+\.\d+)", sh(t["version_cmd"], timeout=3) or "")
        out[t["name"]] = (t["version_key"], m.group(1) if m else None)
    return out


def behind(installed: str, latest: str) -> bool:
    a, b = version_tuple(installed), version_tuple(latest)
    return b[0] > a[0] or (b[0] == a[0] and b[1] - a[1] >= MINORS_BEHIND)  # ponytail: release dates not known, so no 180-day rule


def agent_findings(ctx: Ctx, found: dict[str, tuple[str, str | None]], today: date | None = None) -> list[Finding]:
    today = today or date.today()
    latest_all = ctx.cves.get("latest_known", {})
    out = []
    for name, (key, ver) in found.items():
        if ver is None:
            out.append(Finding(NAME, "INFO", f"Could not read the {name} version",
                               fix="Run the tool's own --version once to check it by hand"))
            continue
        latest = latest_all.get(key)
        ev = {"version": ver, "latest_known": latest and latest["version"], "data_date": latest and latest["checked"]}
        hits = [c for c in ctx.cves.get(key, []) if version_lt(ver, c["fixed_in"])]
        if hits:
            worst = min(hits, key=lambda c: SEVERITIES.index(c["severity"]))
            out.append(Finding(NAME, worst["severity"], f"{name} {ver} has {len(hits)} known security issue(s)",
                               "; ".join(f"{c['id']} ({c['desc']})" for c in hits),
                               f"Update {name} to ≥ {max((c['fixed_in'] for c in hits), key=version_tuple)}",
                               {**ev, "cves": [c["id"] for c in hits]}))
        elif latest and behind(ver, latest["version"]):
            out.append(Finding(NAME, "LOW", f"{name} is out of date ({ver}, newest is {latest['version']})",
                               fix=f"Update {name} to the newest version", evidence=ev))
        elif not latest or (today - date.fromisoformat(latest["checked"])).days > STALE_DAYS:
            out.append(Finding(NAME, "INFO", f"{name} {ver}: our version data is old, can't confirm it is up to date",
                               fix="Update llm-host-guard (pip install -U llm-host-guard) to get fresh version data", evidence=ev))
        else:
            out.append(Finding(NAME, "OK", f"{name} {ver}: up to date, no known issues", evidence=ev))
    return out


def run(ctx: Ctx) -> list[Finding]:
    return runtime_findings(ctx) + agent_findings(ctx, agent_versions(ctx))


def runtime_findings(ctx: Ctx) -> list[Finding]:
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
