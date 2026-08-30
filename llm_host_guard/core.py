"""Shared primitives for llm-host-guard checks. Stdlib only."""
from __future__ import annotations

import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import subprocess
from dataclasses import dataclass, field, asdict
from pathlib import Path

VERSION = "0.3.3"
SEVERITIES = ["CRITICAL", "HIGH", "MED", "LOW", "INFO", "OK"]
SEVERITY_HELP = {
    "CRITICAL": "Wide open right now. Anyone on your network (or the internet) can use or damage your LLM today. Fix first.",
    "HIGH": "A real hole, but an attacker needs one more thing (be on your WiFi, get you to open a file). Fix this week.",
    "MED": "Exposed on purpose but wider than it needs to be. Tighten when convenient.",
    "LOW": "Looks exposed but something else already blocks it. Just be aware.",
    "INFO": "Not a problem, just something you should know exists.",
    "OK": "Checked, nothing wrong.",
}
DATA_DIR = Path(__file__).parent / "data"


@dataclass
class Finding:
    check: str
    severity: str
    title: str
    detail: str = ""
    fix: str = ""
    evidence: dict = field(default_factory=dict)
    fix_cmds: list = field(default_factory=list)   # --fix recipe, run in order as root
    undo_cmds: list = field(default_factory=list)
    fix_note: str = ""                              # why a recipe is absent / caveat shown before applying

    def key(self) -> str:
        return f"{self.check}:{self.severity}:{self.title}"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Listener:
    proto: str
    addr: str
    port: int
    proc: str = ""
    pid: int = 0

    @property
    def wildcard(self) -> bool:
        return self.addr in ("0.0.0.0", "::", "*", "[::]")

    @property
    def loopback(self) -> bool:
        return self.addr.startswith("127.") or self.addr in ("::1", "[::1]")


def sh(args: list[str], timeout: int = 10) -> str | None:
    """Run a command; None if missing/fails. Never raises."""
    if shutil.which(args[0]) is None:
        return None
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.stdout if r.returncode == 0 or r.stdout else None
    except (subprocess.TimeoutExpired, OSError):
        return None


def load_data(name: str) -> dict:
    return json.loads((DATA_DIR / name).read_text())


def is_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
        return a.is_private or a.is_loopback or a.is_link_local
    except ValueError:
        return True


def lan_ip() -> str:
    """Best-effort primary LAN IP without sending packets."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


_SS_RE = re.compile(r"^(?:LISTEN\s+\S+\s+\S+\s+)?(\S+):(\d+)\s+\S+(?:\s+users:\(\(\"([^\"]+)\",pid=(\d+))?")


def parse_ss(text: str) -> list[Listener]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("State"):
            continue
        m = _SS_RE.match(line)
        if not m:
            continue
        addr, port, proc, pid = m.groups()
        addr = addr.strip("[]")
        out.append(Listener("tcp", addr, int(port), proc or "", int(pid or 0)))
    return out


_LSOF_RE = re.compile(r"^(\S+)\s+(\d+)\s+\S+\s+\S+\s+IPv[46]\s+\S+\s+\S+\s+TCP\s+(\S+):(\d+)\s+\(LISTEN\)")


def parse_lsof(text: str) -> list[Listener]:
    out = []
    for line in text.splitlines():
        m = _LSOF_RE.match(line)
        if m:
            proc, pid, addr, port = m.groups()
            out.append(Listener("tcp", addr.strip("[]"), int(port), proc, int(pid)))
    return out


_NETSTAT_RE = re.compile(r"^\s*TCP\s+(\S+):(\d+)\s+\S+\s+LISTENING\s+(\d+)")


def parse_netstat_win(text: str) -> list[Listener]:
    out = []
    for line in text.splitlines():
        m = _NETSTAT_RE.match(line)
        if m:
            addr, port, pid = m.groups()
            out.append(Listener("tcp", addr.strip("[]"), int(port), "", int(pid)))
    return out


def listeners() -> list[Listener]:
    if (t := sh(["ss", "-tlnpH"])) is not None:
        return parse_ss(t)
    if (t := sh(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"])) is not None:
        return parse_lsof(t)
    if (t := sh(["netstat", "-ano"])) is not None:
        return parse_netstat_win(t)
    return []


class Ctx:
    """Lazily-computed system facts shared across checks."""

    def __init__(self, model_dirs: list[str] | None = None):
        self.os = platform.system()
        self.host = socket.gethostname()
        # under sudo, audit the invoking user's model dirs / agent configs, not /root
        su = os.environ.get("SUDO_USER")
        self.home = Path(f"~{su}").expanduser() if su else Path.home()
        self.extra_model_dirs = [Path(p).expanduser() for p in (model_dirs or [])]
        self._listeners: list[Listener] | None = None
        self._lan_ip: str | None = None
        self.signatures = load_data("signatures.json")
        self.cves = load_data("cves.json")

    @property
    def listeners(self) -> list[Listener]:
        if self._listeners is None:
            self._listeners = listeners()
        return self._listeners

    @property
    def lan_ip(self) -> str:
        if self._lan_ip is None:
            self._lan_ip = lan_ip()
        return self._lan_ip

    def sig_for(self, l: Listener) -> dict | None:
        """Match listener to a known LLM product by port or process name."""
        for sig in self.signatures["products"]:
            if l.proc and any(p in l.proc.lower() for p in sig.get("procs", [])):
                return sig
        for sig in self.signatures["products"]:
            if l.port in sig["ports"] and not l.proc:  # unknown proc: port hint only, must be probe-confirmed
                return sig
        return None

    _ufw: str | None = None
    _docker_user: str | None = None
    _iface: str | None = None

    @property
    def lan_cidr(self) -> str:
        return ".".join(self.lan_ip.split(".")[:3]) + ".0/24"

    def default_iface(self) -> str:
        if self._iface is None:
            txt = sh(["ip", "route"]) or ""
            m = re.search(r"^default .* dev (\S+)", txt, re.M)
            self._iface = m.group(1) if m else "eth0"
        return self._iface

    def ufw_sources(self, port: int) -> list[str]:
        """Sources allowed by ufw for a port (needs root; [] if unreadable or no rule)."""
        if self._ufw is None:
            self._ufw = sh(["ufw", "status"]) or ""
        return [m.group(1) for m in re.finditer(rf"^{port}(?:/tcp)?\s+ALLOW(?: IN)?\s+(\S+)", self._ufw, re.M)]

    def docker_user_drops(self, port: int) -> bool:
        """True if DOCKER-USER has a DROP rule covering this port (needs root)."""
        if self._docker_user is None:
            self._docker_user = sh(["iptables", "-S", "DOCKER-USER"]) or ""
        for line in self._docker_user.splitlines():
            if "-j DROP" not in line:
                continue
            if (m := re.search(r"--dport (\d+)", line)) and int(m.group(1)) == port:
                return True
            if (m := re.search(r"--dports ([\d:,]+)", line)):
                for part in m.group(1).split(","):
                    lo, _, hi = part.partition(":")
                    if int(lo) <= port <= int(hi or lo):
                        return True
        return False

    def env_of_pid(self, pid: int) -> dict:
        try:
            raw = Path(f"/proc/{pid}/environ").read_bytes()
            return dict(kv.split("=", 1) for kv in raw.decode(errors="ignore").split("\0") if "=" in kv)
        except OSError:
            return {}

    def cmdline_of_pid(self, pid: int) -> str:
        try:
            return Path(f"/proc/{pid}/cmdline").read_bytes().decode(errors="ignore").replace("\0", " ")
        except OSError:
            return sh(["ps", "-o", "command=", "-p", str(pid)]) or ""


def form_factor() -> str:
    """laptop | desktop — battery presence. Fleet uses it for the silence threshold."""
    if platform.system() == "Darwin":
        return "laptop" if "Battery" in (sh(["pmset", "-g", "batt"]) or "") else "desktop"
    if platform.system() == "Windows":
        out = sh(["wmic", "path", "Win32_Battery", "get", "BatteryStatus"]) or ""
        return "laptop" if any(ch.isdigit() for ch in out) else "desktop"
    try:
        return "laptop" if any(p.name.startswith("BAT") for p in Path("/sys/class/power_supply").iterdir()) else "desktop"
    except OSError:
        return "desktop"


def version_tuple(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4]) or (0,)


def version_lt(a: str, b: str) -> bool:
    return version_tuple(a) < version_tuple(b)
