"""Inference-server behaviour: unexpected child processes, outbound connections to public IPs.

Snapshot from /proc (Linux) or ps + lsof (macOS). No root. Rides --watch for near-real-time diffs.
"""
from __future__ import annotations

import fnmatch
import re
import socket
import struct
from pathlib import Path

from core import Ctx, Finding, is_private, sh

NAME = "runtime"
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


def run(ctx: Ctx, table: dict | None = None, outbound=None) -> list[Finding]:
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
        pub = [(p, ip, port) for p, ip, port in outbound([pid] + kids) if not is_private(ip)]
        if pub:
            dests = sorted({f"{ip}:{port}" for _, ip, port in pub})
            out.append(Finding(NAME, "HIGH", f"{sig['name']} (pid {pid}) connected to public IP(s): {', '.join(dests[:5])}",
                               "Normal only during a model pull/update. Anything else — telemetry you didn't opt into, "
                               "or exfiltration after a compromise. In --watch mode only new destinations alert.",
                               "If no pull is running: stop the server, note the destination, block outbound with ufw "
                               "(`ufw deny out to <ip>`), review recently loaded models.",
                               {"server_pid": pid, "remotes": dests}))
    return out or [Finding(NAME, "OK", f"{len(servers)} LLM server(s): children as expected, no public outbound")]
