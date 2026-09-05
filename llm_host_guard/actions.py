"""Telegram action buttons for --watch --telegram: Close it / Close for 1h / Remind me tomorrow / Leave it / Undo, run as root on tap.

Only the configured chat id may press. Actions are never free-form: a button maps to the finding's own
fix_cmds/undo_cmds (the same recipes --fix runs). Pending actions live in the watch state file.
"""
from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

ACTIONS_FILE = Path.home() / ".llm-host-guard" / "actions.json"
SNOOZE_FILE = Path.home() / ".llm-host-guard" / "snooze.json"
ACTION_LOG = Path.home() / ".llm-host-guard" / "actions.jsonl"   # what was tapped, shipped to the fleet collector
WAKE = threading.Event()  # set after a tap changed the host, so the watch loop re-audits now instead of in 30 min
MAX_AGE_S = 7 * 24 * 3600
SNOOZE_S = 24 * 3600
TEMP_CLOSE_S = 3600


def _creds() -> tuple[str, str]:
    return (os.getenv("LLM_HOST_GUARD_TELEGRAM_BOT_TOKEN") or os.getenv("AGENT_FIREWALL_TELEGRAM_BOT_TOKEN", ""),
            os.getenv("LLM_HOST_GUARD_TELEGRAM_CHAT_ID") or os.getenv("AGENT_FIREWALL_TELEGRAM_CHAT_ID", ""))


def tg(method: str, body: dict, timeout: float = 25) -> dict:
    token, _ = _creds()
    req = urllib.request.Request(f"https://api.telegram.org/bot{token}/{method}", json.dumps(body).encode(),
                                 {"Content-Type": "application/json"})
    try:
        return json.loads(urllib.request.urlopen(req, timeout=timeout).read())
    except Exception as e:  # noqa: BLE001
        print(f"telegram {method} failed: {e}", file=sys.stderr)
        return {}


def _load() -> dict:
    try:
        return json.loads(ACTIONS_FILE.read_text())
    except (OSError, ValueError):
        return {}


def _save(d: dict) -> None:
    ACTIONS_FILE.parent.mkdir(parents=True, exist_ok=True)
    now = time.time()
    d = {k: v for k, v in d.items() if now - v.get("ts", now) < MAX_AGE_S}
    ACTIONS_FILE.write_text(json.dumps(d))


def finding_key(f: dict) -> str:
    return f"{f.get('check', '?')}:{f.get('severity', '?')}:{f['title']}"


def _put(entry: dict) -> str:
    d = _load()
    aid = secrets.token_hex(4)
    d[aid] = {**entry, "ts": time.time()}
    _save(d)
    return aid


def register(finding: dict) -> str | None:
    """Store a finding's recipe; return a short id for callback_data, or None if it has no recipe."""
    if not finding.get("fix_cmds"):
        return None
    return _put({"title": finding["title"], "fix": finding["fix_cmds"], "undo": finding.get("undo_cmds", []),
                 "note": finding.get("fix_note", ""), "applied": False, "keys": [finding_key(finding)]})


def register_summary(findings: list[dict]) -> str | None:
    """Buttons for a batch of findings without a recipe: snooze / leave it."""
    if not findings:
        return None
    return _put({"title": f"{len(findings)} finding(s)", "keys": [finding_key(f) for f in findings]})


def keyboard(aid: str | None, applied: bool = False, summary: bool = False) -> dict | None:
    if not aid:
        return None
    snooze = {"text": "⏰ Remind me tomorrow", "callback_data": f"lhg:snz:{aid}"}
    if summary:
        return {"inline_keyboard": [[snooze, {"text": "✓ Leave it", "callback_data": f"lhg:ok:{aid}"}]]}
    if applied:
        return {"inline_keyboard": [[{"text": "↩ Undo (reopen)", "callback_data": f"lhg:undo:{aid}"}]]}
    return {"inline_keyboard": [[{"text": "🔒 Close it", "callback_data": f"lhg:fix:{aid}"},
                                 {"text": "🔒 Close for 1h", "callback_data": f"lhg:tmp:{aid}"}],
                                [snooze, {"text": "✓ Leave it", "callback_data": f"lhg:ok:{aid}"}]]}


def _snooze_load() -> dict:
    try:
        return json.loads(SNOOZE_FILE.read_text())
    except (OSError, ValueError):
        return {}


def snooze(keys: list[str], seconds: int = SNOOZE_S) -> None:
    d = _snooze_load()
    until = time.time() + seconds
    d.update({k: until for k in keys})
    SNOOZE_FILE.parent.mkdir(parents=True, exist_ok=True)
    SNOOZE_FILE.write_text(json.dumps(d))


def snoozed_due(now: float | None = None) -> set[str]:
    """Keys whose snooze expired; they are dropped from the file so they alert again once."""
    d = _snooze_load()
    now = now or time.time()
    due = {k for k, t in d.items() if t <= now}
    if due:
        SNOOZE_FILE.write_text(json.dumps({k: t for k, t in d.items() if k not in due}))
    return due


def log_action(what: str, title: str, ok: bool = True, wake: bool = False) -> None:
    """Append one line to the action log (best effort) and optionally wake the watch loop."""
    try:
        ACTION_LOG.parent.mkdir(parents=True, exist_ok=True)
        with ACTION_LOG.open("a") as fh:
            fh.write(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()), "what": what, "title": title, "ok": ok}) + "\n")
    except OSError:
        pass
    if wake:
        WAKE.set()


def pending_actions(limit: int = 50) -> list[dict]:
    """Unshipped action-log lines, oldest first."""
    try:
        lines = ACTION_LOG.read_text().splitlines()
    except OSError:
        return []
    out = []
    for ln in lines[:limit]:
        try:
            out.append(json.loads(ln))
        except ValueError:
            pass
    return out


def clear_actions(n: int) -> None:
    """Drop the first n lines after the collector accepted them."""
    try:
        lines = ACTION_LOG.read_text().splitlines()
        ACTION_LOG.write_text("".join(ln + "\n" for ln in lines[n:]))
    except OSError:
        pass


def expire_temp(runner=None, now: float | None = None) -> list[str]:
    """Reopen anything closed with 'Close for 1h' whose hour is up. Returns messages sent. Call every watch pass."""
    runner = runner or run_cmds
    d = _load()
    now = now or time.time()
    out = []
    for a in d.values():
        if a.get("applied") and a.get("reopen_at") and a["reopen_at"] <= now:
            ok, msg = runner(a["undo"]) if a["undo"] else (False, "no undo for this one")
            a["applied"] = not ok
            a.pop("reopen_at", None)
            out.append(f"⏰ hour is up — reopened: {a['title']}" if ok else f"❌ could not reopen {a['title']}: {msg}")
            log_action("reopened after 1h", a["title"], ok)
    if out:
        _save(d)
        _, chat = _creds()
        for t in out:
            tg("sendMessage", {"chat_id": chat, "text": t})
    return out


def run_cmds(cmds: list[str]) -> tuple[bool, str]:
    for c in cmds:
        r = subprocess.run(c, shell=True, capture_output=True, text=True)
        if r.returncode != 0:
            return False, f"failed at: {c}\n{(r.stderr or r.stdout).strip()[:300]}"
    return True, "done"


def handle_callback(cq: dict, runner=run_cmds) -> str:
    """Process one callback_query. Returns the text to show the user."""
    _, chat = _creds()
    if str(cq.get("from", {}).get("id")) != str(chat):
        return "not authorised"
    data = cq.get("data", "")
    if not data.startswith("lhg:"):
        return ""
    _, kind, aid = data.split(":", 2)
    d = _load()
    a = d.get(aid)
    if not a:
        return "this button has expired"
    if kind == "ok":
        log_action("left as is", a["title"])
        return f"left as is: {a['title']}"
    if kind == "snz":
        snooze(a.get("keys", []))
        log_action("snoozed 24h", a["title"])
        return f"⏰ will remind you tomorrow: {a['title']}"
    if not a.get("fix"):
        return "nothing to run for this one"
    if os.geteuid() != 0:
        return "the watch service isn't running as root, so it can't apply fixes — run it with sudo"
    if kind in ("fix", "tmp"):
        ok, msg = runner(a["fix"])
        a["applied"] = ok
        if kind == "tmp" and ok:
            a["reopen_at"] = time.time() + TEMP_CLOSE_S
        _save(d)
        log_action("closed for 1h" if kind == "tmp" else "closed", a["title"], ok, wake=ok)
        if not ok:
            return f"❌ {msg}"
        when = " — reopens in 1h, while the watch service is running" if kind == "tmp" else ""
        return f"✅ closed: {a['title']}{when}" + (f"\n{a['note']}" if a["note"] else "")
    if kind == "undo":
        ok, msg = runner(a["undo"]) if a["undo"] else (False, "no undo for this one")
        a["applied"] = not ok
        _save(d)
        log_action("reopened (undo)", a["title"], ok, wake=ok)
        return f"↩ undone: {a['title']}" if ok else f"❌ {msg}"
    return ""


SOCKET_PATH = os.getenv("LLM_HOST_GUARD_ACTIONS_SOCKET", "/run/llm-host-guard/actions.sock")


def serve_socket(stop, runner=run_cmds, path: str = SOCKET_PATH, group: str | None = None) -> None:
    """Shared-bot mode: another program (e.g. agent-firewall's Kill Switch bot) owns getUpdates and forwards
    our callback_query JSON here, one per connection; we reply {"text": ..., "keyboard": ...}."""
    import grp, socket as _s
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    srv = _s.socket(_s.AF_UNIX, _s.SOCK_STREAM)
    srv.bind(path)
    os.chmod(path, 0o660)
    g = group or os.getenv("SUDO_USER") or os.getenv("LLM_HOST_GUARD_ACTIONS_GROUP")
    if g:
        try:
            os.chown(path, -1, grp.getgrnam(g).gr_gid)
        except (KeyError, PermissionError):
            pass
    srv.listen(4)
    srv.settimeout(1.0)
    while not stop():
        try:
            conn, _ = srv.accept()
        except _s.timeout:
            continue
        with conn:
            try:
                cq = json.loads(conn.makefile("rb").readline() or b"{}")
                text = handle_callback(cq, runner)
                aid = cq.get("data", "").split(":", 2)[-1]
                kind = cq.get("data", "").split(":")[1] if cq.get("data", "").count(":") >= 2 else ""
                kb = keyboard(aid, _load().get(aid, {}).get("applied", False)) if kind in ("fix", "tmp", "undo") else None
                conn.sendall((json.dumps({"text": text, "keyboard": kb}) + "\n").encode())
            except Exception as e:  # noqa: BLE001
                conn.sendall((json.dumps({"text": f"error: {e}"}) + "\n").encode())


def poll_loop(stop, runner=run_cmds) -> None:
    """Long-poll getUpdates for our buttons. Runs in a thread; exits when stop() is true."""
    offset = 0
    while not stop():
        r = tg("getUpdates", {"offset": offset, "timeout": 20, "allowed_updates": ["callback_query"]}, timeout=30)
        for u in r.get("result", []) if isinstance(r, dict) else []:
            offset = u["update_id"] + 1
            cq = u.get("callback_query")
            if not cq:
                continue
            text = handle_callback(cq, runner)
            tg("answerCallbackQuery", {"callback_query_id": cq["id"], "text": text[:180]})
            if text and cq.get("message"):
                msg = cq["message"]
                aid = cq["data"].split(":", 2)[-1]
                applied = _load().get(aid, {}).get("applied", False)
                kb = keyboard(aid, applied) if cq["data"].split(":")[1] not in ("ok", "snz") else None
                tg("editMessageText", {"chat_id": msg["chat"]["id"], "message_id": msg["message_id"],
                                       "text": msg.get("text", "")[:3800] + f"\n\n→ {text}",
                                       "reply_markup": kb or {"inline_keyboard": []}})
        if not r:
            time.sleep(5)  # network hiccup; don't spin
