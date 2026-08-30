"""Telegram action buttons for --watch --telegram: Apply fix / Ignore / Undo, executed as root on tap.

Only the configured chat id may press. Actions are never free-form: a button maps to the finding's own
fix_cmds/undo_cmds (the same recipes --fix runs). Pending actions live in the watch state file.
"""
from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ACTIONS_FILE = Path.home() / ".llm-host-guard" / "actions.json"
MAX_AGE_S = 7 * 24 * 3600


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


def register(finding: dict) -> str | None:
    """Store a finding's recipe; return a short id for callback_data, or None if it has no recipe."""
    if not finding.get("fix_cmds"):
        return None
    d = _load()
    aid = secrets.token_hex(4)
    d[aid] = {"title": finding["title"], "fix": finding["fix_cmds"], "undo": finding.get("undo_cmds", []),
              "note": finding.get("fix_note", ""), "ts": time.time(), "applied": False}
    _save(d)
    return aid


def keyboard(aid: str | None, applied: bool = False) -> dict | None:
    if not aid:
        return None
    if applied:
        return {"inline_keyboard": [[{"text": "↩ Undo", "callback_data": f"lhg:undo:{aid}"}]]}
    return {"inline_keyboard": [[{"text": "🔧 Apply fix", "callback_data": f"lhg:fix:{aid}"},
                                 {"text": "✓ Ignore", "callback_data": f"lhg:ok:{aid}"}]]}


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
        return f"ignored: {a['title']}"
    if os.geteuid() != 0:
        return "the watch service isn't running as root, so it can't apply fixes — run it with sudo"
    if kind == "fix":
        ok, msg = runner(a["fix"])
        a["applied"] = ok
        _save(d)
        return (f"✅ applied: {a['title']}" + (f"\n{a['note']}" if a["note"] else "")) if ok else f"❌ {msg}"
    if kind == "undo":
        ok, msg = runner(a["undo"]) if a["undo"] else (False, "no undo for this one")
        a["applied"] = not ok
        _save(d)
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
                kb = keyboard(aid, _load().get(aid, {}).get("applied", False)) if kind in ("fix", "undo") else None
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
                kb = keyboard(aid, applied) if cq["data"].split(":")[1] != "ok" else None
                tg("editMessageText", {"chat_id": msg["chat"]["id"], "message_id": msg["message_id"],
                                       "text": msg.get("text", "")[:3800] + f"\n\n→ {text}",
                                       "reply_markup": kb or {"inline_keyboard": []}})
        if not r:
            time.sleep(5)  # network hiccup; don't spin
