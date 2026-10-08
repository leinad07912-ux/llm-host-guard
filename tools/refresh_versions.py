#!/usr/bin/env python3
"""Refresh llm_host_guard/data/cves.json for agent tools: newest release (npm/PyPI) + published advisories (GHSA).
Run weekly by .github/workflows/refresh-versions.yml, which opens a PR. Nothing is merged automatically."""
import json
import sys
import urllib.parse
import urllib.request
from datetime import date
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / "llm_host_guard/data/cves.json"
# version_key -> (ecosystem, package name); keys must match signatures.json agent_tools[].version_key
PACKAGES = {
    "claude-code": ("npm", "@anthropic-ai/claude-code"),
    "codex": ("npm", "@openai/codex"),
    "gemini-cli": ("npm", "@google/gemini-cli"),
    "aider": ("pip", "aider-chat"),
    "open-interpreter": ("pip", "open-interpreter"),
}
SEV = {"critical": "CRITICAL", "high": "HIGH", "moderate": "MED", "medium": "MED", "low": "LOW"}


def get(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "llm-host-guard-refresh", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def latest(eco: str, pkg: str) -> str:
    if eco == "npm":
        return get("https://registry.npmjs.org/" + urllib.parse.quote(pkg, safe="@"))["dist-tags"]["latest"]
    return get(f"https://pypi.org/pypi/{pkg}/json")["info"]["version"]


def vkey(s: str) -> list[int]:
    return [int(x) for x in s.split(".") if x.isdigit()]


def advisories(eco: str, pkg: str) -> list[dict]:
    q = urllib.parse.urlencode({"ecosystem": eco, "affects": pkg, "per_page": 100, "type": "reviewed"})
    out = []
    for a in get("https://api.github.com/advisories?" + q):
        fixed = [v["first_patched_version"] for v in a.get("vulnerabilities", [])
                 if v["package"]["name"] == pkg and v.get("first_patched_version")]
        if fixed and a.get("withdrawn_at") is None:   # no patch yet => nothing to compare against
            out.append({"id": a.get("cve_id") or a["ghsa_id"], "fixed_in": max(fixed, key=vkey),
                        "severity": SEV.get(a["severity"], "MED"), "desc": a["summary"].strip()[:140]})
    return out


def dump(d: dict) -> str:
    """Keep the file diff-friendly: one advisory per line."""
    parts = []
    for k, v in d.items():
        if isinstance(v, list) and not v:
            parts.append(f"  {json.dumps(k)}: []")
        elif isinstance(v, list):
            parts.append(f"  {json.dumps(k)}: [\n" + ",\n".join("    " + json.dumps(c, ensure_ascii=False) for c in v) + "\n  ]")
        elif isinstance(v, dict):
            parts.append(f"  {json.dumps(k)}: {{\n" + ",\n".join(f"    {json.dumps(kk)}: {json.dumps(vv, ensure_ascii=False)}" for kk, vv in v.items()) + "\n  }")
        else:
            parts.append(f"  {json.dumps(k)}: {json.dumps(v, ensure_ascii=False)}")
    return "{\n" + ",\n".join(parts) + "\n}\n"


def main() -> int:
    d = json.loads(DATA.read_text())
    lk = d.setdefault("latest_known", {})
    failed = []
    for key, (eco, pkg) in PACKAGES.items():
        try:
            lk[key] = {"version": latest(eco, pkg), "checked": date.today().isoformat()}
            adv = advisories(eco, pkg)
            if adv:
                d[key] = sorted(adv, key=lambda c: c["id"])
        except Exception as e:  # noqa: BLE001 — keep the old entry, so staleness is reported honestly
            failed.append(f"{key}: {e}")
    DATA.write_text(dump(d))
    for f in failed:
        print("FAILED", f, file=sys.stderr)
    return 1 if len(failed) == len(PACKAGES) else 0


if __name__ == "__main__":
    sys.exit(main())
