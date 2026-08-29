"""Exposed inference ports: enumerate listeners, match LLM signatures, probe for no-auth."""
from __future__ import annotations

import http.client
import json

from core import Ctx, Finding, Listener

NAME = "ports"


def probe(host: str, port: int, paths: list[str], timeout: float = 2.0) -> dict:
    """Return {path: status} for paths that answered 200 with a body. Local host only."""
    hits = {}
    for p in paths:
        try:
            c = http.client.HTTPConnection(host, port, timeout=timeout)
            c.request("GET", p)
            r = c.getresponse()
            body = r.read(4096)
            if r.status == 200 and body:
                try:
                    j = json.loads(body)
                    n = len(j.get("models", j.get("data", []))) if isinstance(j, dict) else 0
                    hits[p] = {"status": 200, "models": n}
                except ValueError:
                    hits[p] = {"status": 200}
            c.close()
        except (OSError, http.client.HTTPException):
            pass
    return hits


def run(ctx: Ctx) -> list[Finding]:
    out = []
    seen = set()
    for l in ctx.listeners:
        sig = ctx.sig_for(l)
        if not sig or l.loopback:
            continue
        if (sig["name"], l.port) in seen:
            continue
        seen.add((sig["name"], l.port))
        hits = probe(ctx.lan_ip, l.port, sig.get("probe", [])) if sig.get("probe") else {}
        models = max((h.get("models", 0) for h in hits.values()), default=0)
        if hits:
            out.append(Finding(
                NAME, "CRITICAL",
                f"{sig['name']} on {l.addr}:{l.port} reachable from LAN with no auth"
                + (f" ({models} models listed)" if models else ""),
                f"Unauthenticated {', '.join(hits)} answered 200 from {ctx.lan_ip}. Anyone on your network "
                f"(guest WiFi, IoT, a compromised phone) gets free inference, can list/pull/delete models, "
                f"and can hit known parser CVEs.",
                f"{sig['bind_fix']}  — or restrict: `ufw allow from <LAN>/24 to any port {l.port}` "
                f"and put an authenticating reverse proxy in front.",
                {"port": l.port, "addr": l.addr, "proc": l.proc, "probe": hits},
            ))
        elif l.proc:  # process-confirmed LLM server; port-only guesses without probe hit are dropped
            out.append(Finding(
                NAME, "HIGH",
                f"{sig['name']} on {l.addr}:{l.port} bound to non-loopback",
                "Listening on a LAN-reachable address. Probe did not confirm an open API (auth, non-HTTP, "
                "or firewall in the way) but the bind is wider than needed.",
                sig["bind_fix"],
                {"port": l.port, "addr": l.addr, "proc": l.proc},
            ))
    if not out:
        llm = [l for l in ctx.listeners if ctx.sig_for(l)]
        out.append(Finding(NAME, "OK", f"{len(llm)} LLM listener(s) found, all loopback-only" if llm
                           else "No known LLM servers listening"))
    return out
