"""Inference-server behaviour: unexpected child processes, outbound connections to public IPs.

Snapshot from /proc (Linux) or ps + lsof (macOS). No root. Rides --watch for near-real-time diffs.
"""
from __future__ import annotations

import fnmatch
import re
import socket
import struct
from pathlib import Path

from llm_host_guard.core import Ctx, Finding, is_private, sh, vendor_for_ip

NAME = "runtime"
HISTORY = Path.home() / ".llm-host-guard" / "outbound.json"   # last-5-min snapshots, watch mode
SCAN_NEW_PER_MIN = 10        # distinct NEW public destinations per minute over the window → scan
BRUTE_SAME_PER_WINDOW = 20   # connects to one public host:port seen across snapshots in the window → brute force
WINDOW_S = 300
ALWAYS_BAD = {"sh", "bash", "dash", "zsh", "fish", "curl", "wget", "nc", "ncat", "netcat", "socat",
              "perl", "base64", "ssh", "scp", "sftp", "telnet", "busybox"}


def proc_table() -> dict[int, tuple[int, str]]:
    """{pid: (ppid, comm)} via ps — works on Linux and macOS."""
    out = {}
    for line in (sh(["ps", "-axo", "pid=,ppid=,comm="]) or "").splitlines():
        parts = line.split(None, 2)
        if len(parts) == 3 and parts[0].isdigit():
            out[int(parts[0])] = (int(parts[1]), Path(parts[2]).name)
    return out


def descendants(table: dict[int, tuple[int, str]], root: int) -> list[int]:
    kids, out = {}, []
    for pid, (ppid, _) in table.items():
        kids.setdefault(ppid, []).append(pid)
    stack = list(kids.get(root, []))
    while stack:
        p = stack.pop()
        out.append(p)
        stack += kids.get(p, [])
    return out


def _hex_addr(h: str) -> tuple[str, int]:
    ip_hex, port_hex = h.split(":")
    port = int(port_hex, 16)
    raw = bytes.fromhex(ip_hex)
    if len(raw) == 4:
        return socket.inet_ntoa(struct.pack("<I", int(ip_hex, 16))), port
    # IPv6: four little-endian 32-bit words
    words = struct.unpack("<IIII", raw)
    ip = socket.inet_ntop(socket.AF_INET6, struct.pack(">IIII", *words))
    return (ip[7:] if ip.startswith("::ffff:") else ip), port


def parse_proc_net_tcp(text: str) -> list[tuple[int, str, int]]:
    """[(inode, remote_ip, remote_port)] for ESTABLISHED (st=01) sockets."""
    out = []
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) > 9 and f[3] == "01":
            ip, port = _hex_addr(f[2])
            out.append((int(f[9]), ip, port))
    return out


def socket_inodes(pid: int) -> set[int]:
    out = set()
    try:
        for fd in Path(f"/proc/{pid}/fd").iterdir():
            try:
                m = re.match(r"socket:\[(\d+)\]", str(fd.readlink()))
            except OSError:
                continue
            if m:
                out.add(int(m.group(1)))
    except OSError:
        pass
    return out


def outbound_linux(pids: list[int]) -> list[tuple[int, str, int]]:
    """[(pid, remote_ip, remote_port)] established, for the given pids."""
    conns = []
    for f in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            conns += parse_proc_net_tcp(Path(f).read_text())
        except OSError:
            pass
    by_inode = {ino: (ip, port) for ino, ip, port in conns}
    out = []
    for pid in pids:
        for ino in socket_inodes(pid):
            if ino in by_inode:
                out.append((pid, *by_inode[ino]))
    return out


def outbound_mac(pids: list[int]) -> list[tuple[int, str, int]]:
    out = []
    txt = sh(["lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED", "-a", "-p", ",".join(map(str, pids))]) or ""
    for line in txt.splitlines():
        m = re.search(r"^\S+\s+(\d+)\s.*->\[?([0-9a-f.:]+?)\]?:(\d+)\s", line)
        if m:
            out.append((int(m.group(1)), m.group(2), int(m.group(3))))
    return out


def child_allowed(comm: str, parent_comm: str, allow: list[str]) -> bool:
    c = comm.lower()
    if c in ALWAYS_BAD:
        return False
    return c == parent_comm.lower() or any(fnmatch.fnmatch(c, a.lower()) for a in allow)


def scan_signals(name: str, conns: list[tuple[int, str, int]], now: float | None = None,
                 history_path: Path | None = None) -> list[Finding]:
    """Compare this snapshot's public destinations with the last 5 min of snapshots (persisted per server name).
    Returns CRITICAL 'looks like a scan' / HIGH 'looks like brute force' findings, or []."""
    import json, time
    now = time.time() if now is None else now
    hp = history_path or HISTORY
    try:
        hist = json.loads(hp.read_text())
    except (OSError, ValueError):
        hist = {}
    snaps = [s for s in hist.get(name, []) if now - s["ts"] <= WINDOW_S]
    dests = sorted({f"{ip}:{port}" for _, ip, port in conns if not is_private(ip)})
    seen_before = {d for s in snaps for d in s["dests"]}
    new = [d for d in dests if d not in seen_before]
    snaps.append({"ts": now, "dests": dests, "new": new})
    hist[name] = snaps[-60:]
    try:
        hp.parent.mkdir(parents=True, exist_ok=True)
        hp.write_text(json.dumps(hist))
    except OSError:
        pass
    span_min = max(1.0, (now - snaps[0]["ts"]) / 60) if len(snaps) > 1 else 1.0
    total_new = sum(len(s["new"]) for s in snaps)
    per_min = total_new / span_min
    out = []
    if per_min >= SCAN_NEW_PER_MIN:
        out.append(Finding(NAME, "CRITICAL", f"{name} opened connections to {total_new} different internet hosts in {span_min:.0f} min — looks like a scan",
                           "A program that is probing the internet: many new destinations in a short time. A hijacked AI does exactly this.",
                           "Unplug this machine from the network now, then stop the server and read the host page before reconnecting.",
                           {"signal": "scan", "new_dests": total_new, "minutes": round(span_min, 1), "per_min": round(per_min, 1), "sample": new[:10]},
                           risk="Risk: this machine may be attacking other systems right now."))
    counts: dict[str, int] = {}
    for s in snaps:
        for d in s["dests"]:
            counts[d] = counts.get(d, 0) + 1
    hot = [(d, c) for d, c in counts.items() if c >= BRUTE_SAME_PER_WINDOW]
    if hot:
        d, c = max(hot, key=lambda x: x[1])
        out.append(Finding(NAME, "HIGH", f"{name} hammered {d} {c} times in {span_min:.0f} min — looks like brute force",
                           "Repeated connections to one internet host and port — the pattern of password guessing or a stuck retry loop.",
                           "If you didn't start a download or sync to that host: stop the server and block the address with ufw.",
                           {"signal": "bruteforce", "dest": d, "count": c, "minutes": round(span_min, 1)},
                           risk="Risk: either this machine is attacking that host, or something is stuck — both need a look."))
    return out


def run(ctx: Ctx, table: dict | None = None, outbound=None, history_path: Path | None = None) -> list[Finding]:
    table = table if table is not None else proc_table()
    outbound = outbound or (outbound_mac if ctx.os == "Darwin" else outbound_linux)
    servers = []
    for pid, (ppid, comm) in table.items():
        for sig in ctx.signatures["products"]:
            if any(p in comm.lower() for p in sig.get("procs", [])):
                servers.append((pid, comm, sig))
                break
    # a server's descendant that also matches (ollama → llama-server runner) belongs to the parent, not itself
    roots = {pid for pid, _, _ in servers}
    servers = [(pid, comm, sig) for pid, comm, sig in servers
               if not any(pid in descendants(table, r) for r in roots if r != pid)]
    if not servers:
        return [Finding(NAME, "OK", "No LLM server processes running")]
    out = []
    for pid, comm, sig in servers:
        kids = descendants(table, pid)
        bad = [(k, table[k][1]) for k in kids if not child_allowed(table[k][1], comm, sig.get("children", []))]
        for k, kcomm in bad:
            out.append(Finding(NAME, "CRITICAL", f"{sig['name']} (pid {pid}) spawned '{kcomm}' (pid {k})",
                               f"cmdline: {ctx.cmdline_of_pid(k)[:200] or '?'}. An inference server has no business "
                               "running this. Poisoned model → parser exploit → shell is exactly this shape.",
                               f"kill -9 {k}; stop {sig['name']}; check which model was loaded last and delete it; "
                               "inspect the server binary hash against a fresh download.",
                               {"server_pid": pid, "child_pid": k, "child": kcomm}))
        conns = outbound([pid] + kids)
        out += scan_signals(sig["name"], conns, history_path=history_path)
        pub = [(p, ip, port) for p, ip, port in conns if not is_private(ip)]
        vendor = [(ip, port, vendor_for_ip(ip)) for _, ip, port in pub if vendor_for_ip(ip)]
        unknown = [(ip, port) for _, ip, port in pub if not vendor_for_ip(ip)]
        if vendor:
            names = sorted({v for _, _, v in vendor})
            out.append(Finding(NAME, "INFO", f"{sig['name']} talked to {', '.join(names)} (update check or model download)",
                               "Expected: that is the vendor's own server.", "",
                               {"server_pid": pid, "remotes": sorted({f"{ip}:{port}" for ip, port, _ in vendor})},
                               risk="Risk: none — this is the software checking for updates or fetching a model."))
        if unknown:
            dests = sorted({f"{ip}:{port}" for ip, port in unknown})
            out.append(Finding(NAME, "HIGH", f"{sig['name']} (pid {pid}) connected to an unrecognised internet address: {', '.join(dests[:5])}",
                               "Not a known vendor server. Normal only if you are pulling a model from a custom source. Otherwise: "
                               "telemetry you didn't opt into, or data leaving after a compromise. In --watch mode only new destinations alert.",
                               "If no download is running: stop the server, note the address, block it with ufw "
                               "(`ufw deny out to <ip>`), review recently loaded models.",
                               {"server_pid": pid, "remotes": dests},
                               risk="Risk: your AI server is sending something to a computer you don't know. Could be harmless telemetry, could be a leak."))
    return out or [Finding(NAME, "OK", f"{len(servers)} LLM server(s): children as expected, no public outbound")]
