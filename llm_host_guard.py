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
import os  # noqa: E402
from core import VERSION, SEVERITIES, SEVERITY_HELP, Ctx, Finding  # noqa: E402
import checks  # noqa: E402

STATE = Path.home() / ".llm-host-guard" / "state.json"
WEIGHT = {"CRITICAL": 3, "HIGH": 2, "MED": 1}
COLOR = {"CRITICAL": "\033[91m", "HIGH": "\033[93m", "MED": "\033[33m", "LOW": "\033[36m", "INFO": "\033[90m", "OK": "\033[92m"}


def run_checks(ctx: Ctx, names: list[str]) -> list[Finding]:
    out = []
    for n in names:
        try:
            out += {**checks.ALL, **checks.OPTIONAL}[n].run(ctx)
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
    print(f"\nscore: {rep['score']}/10   (10 = nothing found; each CRITICAL −3, HIGH −2, MED −1)")
    print("\nwhat the levels mean:")
    for sev in SEVERITIES:
        print(f"  {c(sev, sev.ljust(9))} {SEVERITY_HELP[sev]}")


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
.legend{{margin:.5rem 0 1.5rem}} .legend td{{padding:.3rem .5rem}}
.t.CRITICAL,.t.HIGH,.t.MED,.t.LOW,.t.INFO,.t.OK{{background:var(--card);color:var(--fg)}}
</style>
<h1>llm-host-guard report</h1>
<div class=meta>{e(rep['host'])} · {e(rep['os'])} · {e(rep['lan_ip'])} · {e(rep['ts'])} · v{e(rep['version'])}</div>
<div class=score>{rep['score']}<span style='font-size:1.2rem;color:var(--mut)'>/10</span></div>
<div class=tiles>{tiles}</div>
<details><summary style='cursor:pointer;color:var(--mut)'>What do the levels mean?</summary>
<table class=legend>{''.join(f"<tr class='{s}'><td><span class='sev'>{s}</span></td><td>{e(h)}</td></tr>" for s, h in SEVERITY_HELP.items())}</table>
<p class=meta>Score starts at 10; each CRITICAL takes 3, HIGH 2, MED 1. LOW/INFO/OK cost nothing.</p></details>
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


def post_telegram(rep: dict, new: list[dict]) -> None:
    """Send new findings to a Telegram chat. Token/chat from env, never argv."""
    token = os.getenv("LLM_HOST_GUARD_TELEGRAM_BOT_TOKEN") or os.getenv("AGENT_FIREWALL_TELEGRAM_BOT_TOKEN", "")
    chat = os.getenv("LLM_HOST_GUARD_TELEGRAM_CHAT_ID") or os.getenv("AGENT_FIREWALL_TELEGRAM_CHAT_ID", "")
    if not token or not chat:
        print("telegram: set LLM_HOST_GUARD_TELEGRAM_BOT_TOKEN and _CHAT_ID", file=sys.stderr)
        return
    icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MED": "🟡"}
    lines = [f"🛡 llm-host-guard — {rep['host']} score {rep['score']}/10", f"{len(new)} new exposure(s):"]
    for f in new[:10]:
        lines.append(f"{icon.get(f['severity'], '•')} {f['severity']} {f['title']}")
        if f["fix"]:
            lines.append(f"   fix: {f['fix'][:160]}")
    body = {"chat_id": chat, "text": "\n".join(lines)[:4000], "disable_web_page_preview": True}
    try:
        req = urllib.request.Request(f"https://api.telegram.org/bot{token}/sendMessage",
                                     json.dumps(body).encode(), {"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10).read()
    except Exception as e:
        print(f"telegram failed: {e}", file=sys.stderr)


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
    ap.add_argument("--telegram", action="store_true",
                    help="send new findings to Telegram (watch mode); env LLM_HOST_GUARD_TELEGRAM_BOT_TOKEN + _CHAT_ID")
    ap.add_argument("--once", action="store_true", help="with --watch: single diff pass then exit (for cron)")
    ap.add_argument("--checks", default=",".join(checks.ALL), help=f"comma list of: {','.join(checks.ALL)}")
    ap.add_argument("--model-dir", action="append", default=[], help="extra model directory to scan")
    ap.add_argument("--internet", action="store_true",
                    help="also ask the outside: public IP (ipify), Shodan InternetDB, router UPnP mappings")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--fix", action="store_true", help="apply fix recipes (root); prints each command, asks y/N")
    ap.add_argument("--yes", action="store_true", help="with --fix: don't ask")
    ap.add_argument("--dry-run", action="store_true", help="with --fix: print recipes, run nothing, no root needed")
    a = ap.parse_args(argv)
    known = {**checks.ALL, **checks.OPTIONAL}
    names = [n.strip() for n in a.checks.split(",") if n.strip() in known]
    if a.internet and "internet" not in names:
        names.append("internet")

    while True:
        ctx = Ctx(model_dirs=a.model_dir)
        findings = run_checks(ctx, names)
        rep = report(ctx, findings)
        if a.watch:
            new = diff_state(rep)
            if new:
                print(f"[{rep['ts']}] {len(new)} new finding(s):")
                for f in new:
                    print(f"  {f['severity']:<9} {f['title']}")
                if a.webhook:
                    post_webhook(a.webhook, {**rep, "findings": new})
                if a.telegram:
                    post_telegram(rep, new)
            else:
                print(f"[{rep['ts']}] no change, score {rep['score']}/10", flush=True)
            if a.html:
                write_html(rep, Path(a.html))
            if a.once:
                return 0
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
        if a.fix:
            import fix
            n = fix.apply(ctx, findings, yes=a.yes, dry_run=a.dry_run)
            if n < 0:
                return 3
            print(f"\n{n} recipe(s) {'previewed' if a.dry_run else 'applied. Re-run the audit to confirm'}.")
            return 0
        sev = {f["severity"] for f in rep["findings"]}
        return 2 if "CRITICAL" in sev else 1 if sev & {"HIGH", "MED"} else 0


if __name__ == "__main__":
    sys.exit(main())
