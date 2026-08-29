#!/usr/bin/env python3
"""llm-host-guard — audit the attack surface of a machine running local LLMs. Stdlib only, audit-only."""
from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from core import VERSION, SEVERITIES, Ctx, Finding  # noqa: E402
import checks  # noqa: E402

STATE = Path.home() / ".llm-host-guard" / "state.json"
WEIGHT = {"CRITICAL": 3, "HIGH": 2, "MED": 1}
COLOR = {"CRITICAL": "\033[91m", "HIGH": "\033[93m", "MED": "\033[33m", "LOW": "\033[36m", "INFO": "\033[90m", "OK": "\033[92m"}


def run_checks(ctx: Ctx, names: list[str]) -> list[Finding]:
    out = []
    for n in names:
        try:
            out += checks.ALL[n].run(ctx)
        except Exception as e:  # a broken check must not kill the audit
            out.append(Finding(n, "INFO", f"check crashed: {type(e).__name__}: {e}"))
    out.sort(key=lambda f: SEVERITIES.index(f.severity))
    return out


def score(findings: list[Finding]) -> int:
    return max(0, 10 - sum(WEIGHT.get(f.severity, 0) for f in findings))


def report(ctx: Ctx, findings: list[Finding]) -> dict:
    return {"tool": "llm-host-guard", "version": VERSION, "host": ctx.host, "os": ctx.os, "lan_ip": ctx.lan_ip,
            "ts": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "score": score(findings), "findings": [f.to_dict() for f in findings]}


def print_text(rep: dict, color: bool = True) -> None:
    c = (lambda s, t: f"{COLOR[s]}{t}\033[0m") if color else (lambda s, t: t)
    print(f"llm-host-guard v{rep['version']} — {rep['host']} ({rep['os']}, {rep['lan_ip']}) {rep['ts']}\n")
    for f in rep["findings"]:
        print(f"{c(f['severity'], f['severity'].ljust(9))} {f['title']}")
        if f["detail"]:
            print(f"          {f['detail']}")
        if f["fix"]:
            print(f"          fix: {f['fix']}")
    print(f"\nscore: {rep['score']}/10")


def write_html(rep: dict, path: Path) -> None:
    e = html.escape
    rows = "".join(
        f"<tr class='{f['severity']}'><td><span class='sev'>{f['severity']}</span></td><td>{e(f['check'])}</td>"
        f"<td><b>{e(f['title'])}</b><div class='d'>{e(f['detail'])}</div>"
        + (f"<pre>{e(f['fix'])}</pre>" if f['fix'] else "") + "</td></tr>"
        for f in rep["findings"])
    counts = {s: sum(1 for f in rep["findings"] if f["severity"] == s) for s in SEVERITIES}
    tiles = "".join(f"<div class='t {s}'><b>{n}</b>{s}</div>" for s, n in counts.items() if n)
    path.write_text(f"""<!doctype html><meta charset=utf-8><title>llm-host-guard — {e(rep['host'])}</title>
<style>
:root{{--bg:#fff;--fg:#111;--mut:#666;--line:#e5e5e5;--card:#f6f6f6}}
@media(prefers-color-scheme:dark){{:root{{--bg:#0f1115;--fg:#eee;--mut:#999;--line:#2a2d35;--card:#181b22}}}}
body{{margin:0;padding:2rem;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;max-width:1100px;margin:auto}}
h1{{font-size:1.4rem;margin:0}} .meta{{color:var(--mut);margin-bottom:1.5rem}}
.score{{font-size:3rem;font-weight:700;line-height:1}} .tiles{{display:flex;gap:.6rem;flex-wrap:wrap;margin:1rem 0 2rem}}
.t{{padding:.5rem .9rem;border-radius:8px;background:var(--card);border-left:4px solid var(--line)}} .t b{{display:block;font-size:1.3rem}}
table{{width:100%;border-collapse:collapse}} td{{padding:.7rem .5rem;border-top:1px solid var(--line);vertical-align:top}}
.sev{{font-weight:700;font-size:.8rem;padding:.15rem .5rem;border-radius:4px;color:#fff;white-space:nowrap}}
.d{{color:var(--mut);margin:.2rem 0}} pre{{background:var(--card);padding:.5rem .7rem;border-radius:6px;white-space:pre-wrap;margin:.3rem 0 0;font-size:.85rem}}
.CRITICAL .sev,.t.CRITICAL{{background:#c0392b;border-color:#c0392b}} .HIGH .sev,.t.HIGH{{background:#e67e22;border-color:#e67e22}}
.MED .sev,.t.MED{{background:#b7950b;border-color:#b7950b}} .LOW .sev,.t.LOW{{background:#2e86c1;border-color:#2e86c1}}
.INFO .sev,.t.INFO{{background:#7f8c8d;border-color:#7f8c8d}} .OK .sev,.t.OK{{background:#27ae60;border-color:#27ae60}}
.t.CRITICAL,.t.HIGH,.t.MED,.t.LOW,.t.INFO,.t.OK{{background:var(--card);color:var(--fg)}}
</style>
<h1>llm-host-guard report</h1>
<div class=meta>{e(rep['host'])} · {e(rep['os'])} · {e(rep['lan_ip'])} · {e(rep['ts'])} · v{e(rep['version'])}</div>
<div class=score>{rep['score']}<span style='font-size:1.2rem;color:var(--mut)'>/10</span></div>
<div class=tiles>{tiles}</div>
<table>{rows}</table>
<p class=meta>Audit-only. Nothing was changed. <a href='https://github.com/leinad07912-ux/llm-host-guard'>llm-host-guard</a></p>
""")


def diff_state(rep: dict) -> list[dict]:
    """Findings that are new since the last run. Persists state."""
    prev = set()
    if STATE.exists():
        try:
            prev = set(json.loads(STATE.read_text()).get("keys", []))
        except (OSError, ValueError):
            pass
    keys = [f"{f['check']}:{f['severity']}:{f['title']}" for f in rep["findings"]]
    new = [f for f, k in zip(rep["findings"], keys) if k not in prev and f["severity"] in WEIGHT]
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps({"ts": rep["ts"], "keys": keys}))
    return new


def post_webhook(url: str, payload: dict) -> None:
    try:
        req = urllib.request.Request(url, json.dumps(payload).encode(), {"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10).read()
    except Exception as e:
        print(f"webhook failed: {e}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="llm-host-guard", description=__doc__)
    ap.add_argument("--json", action="store_true", help="JSON report to stdout")
    ap.add_argument("--html", metavar="PATH", help="write self-contained HTML report")
    ap.add_argument("--watch", type=float, metavar="MIN", help="rerun every N minutes, print only new findings")
    ap.add_argument("--webhook", metavar="URL", help="POST new findings here (watch mode)")
    ap.add_argument("--checks", default=",".join(checks.ALL), help=f"comma list of: {','.join(checks.ALL)}")
    ap.add_argument("--model-dir", action="append", default=[], help="extra model directory to scan")
    ap.add_argument("--no-color", action="store_true")
    a = ap.parse_args(argv)
    names = [n.strip() for n in a.checks.split(",") if n.strip() in checks.ALL]

    while True:
        ctx = Ctx(model_dirs=a.model_dir)
        rep = report(ctx, run_checks(ctx, names))
        if a.watch:
            new = diff_state(rep)
            if new:
                print(f"[{rep['ts']}] {len(new)} new finding(s):")
                for f in new:
                    print(f"  {f['severity']:<9} {f['title']}")
                if a.webhook:
                    post_webhook(a.webhook, {**rep, "findings": new})
            else:
                print(f"[{rep['ts']}] no change, score {rep['score']}/10", flush=True)
            if a.html:
                write_html(rep, Path(a.html))
            time.sleep(a.watch * 60)
            continue
        if a.json:
            print(json.dumps(rep, indent=2))
        else:
            print_text(rep, color=not a.no_color and sys.stdout.isatty())
        if a.html:
            write_html(rep, Path(a.html))
            if not a.json:
                print(f"html report: {a.html}")
        sev = {f["severity"] for f in rep["findings"]}
        return 2 if "CRITICAL" in sev else 1 if sev & {"HIGH", "MED"} else 0


if __name__ == "__main__":
    sys.exit(main())
