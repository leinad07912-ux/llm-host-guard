"""Internet-side view (opt-in, --internet): what does the outside already see, and is the router forwarding?

Makes three kinds of outbound calls, all announced in the finding: ipify (public IP), Shodan InternetDB
(free, keyless, per-IP open ports + CVEs), and SSDP/UPnP to the local router.
"""
from __future__ import annotations

import json
import re
import socket
import urllib.request
import xml.etree.ElementTree as ET

from llm_host_guard.core import Ctx, Finding

NAME = "internet"
SSDP = ("239.255.255.250", 1900)
MSEARCH = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
           "MX: 1\r\nST: urn:schemas-upnp-org:service:WANIPConnection:1\r\n\r\n").encode()


def _get(url: str, timeout: float = 6.0) -> str | None:
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "llm-host-guard"}), timeout=timeout) as r:
            return r.read().decode(errors="ignore")
    except Exception:
        return None


def public_ip() -> str | None:
    t = _get("https://api.ipify.org")
    return t.strip() if t and re.fullmatch(r"[\d.]+", t.strip()) else None


def internetdb(ip: str) -> dict | None:
    t = _get(f"https://internetdb.shodan.io/{ip}")
    try:
        return json.loads(t) if t else None
    except ValueError:
        return None


def parse_internetdb(d: dict, llm_ports: set[int]) -> tuple[list[int], list[int], list[str]]:
    ports = sorted(int(p) for p in d.get("ports", []))
    return ports, [p for p in ports if p in llm_ports], list(d.get("vulns", []))[:10]


def ssdp_discover(timeout: float = 2.0) -> str | None:
    """Return LOCATION url of first IGD that answers, or None."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(MSEARCH, SSDP)
        data, _ = s.recvfrom(2048)
        m = re.search(r"^LOCATION:\s*(\S+)", data.decode(errors="ignore"), re.I | re.M)
        return m.group(1) if m else None
    except OSError:
        return None
    finally:
        s.close()


def control_url(desc_xml: str, base: str) -> str | None:
    """Find WANIPConnection controlURL in a device description."""
    try:
        root = ET.fromstring(desc_xml)
    except ET.ParseError:
        return None
    for svc in root.iter():
        if svc.tag.endswith("service"):
            st = "".join(c.text or "" for c in svc if c.tag.endswith("serviceType"))
            if "WANIPConnection" in st or "WANPPPConnection" in st:
                cu = "".join(c.text or "" for c in svc if c.tag.endswith("controlURL"))
                return cu if cu.startswith("http") else base.rstrip("/") + "/" + cu.lstrip("/")
    return None


def parse_mapping(soap: str) -> dict | None:
    """One GetGenericPortMappingEntry response → {ext, internal, host, proto, desc}."""
    def g(tag):
        m = re.search(rf"<{tag}>([^<]*)</{tag}>", soap)
        return m.group(1) if m else ""
    if not g("NewExternalPort"):
        return None
    return {"ext": int(g("NewExternalPort")), "internal": int(g("NewInternalPort") or 0),
            "host": g("NewInternalClient"), "proto": g("NewProtocol"), "desc": g("NewPortMappingDescription")}


def upnp_mappings(max_entries: int = 64) -> list[dict]:
    loc = ssdp_discover()
    if not loc:
        return []
    desc = _get(loc, 4)
    if not desc:
        return []
    base = re.match(r"(https?://[^/]+)", loc).group(1)
    cu = control_url(desc, base)
    if not cu:
        return []
    out = []
    for i in range(max_entries):
        body = (f'<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
                f's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
                f'<u:GetGenericPortMappingEntry xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">'
                f'<NewPortMappingIndex>{i}</NewPortMappingIndex></u:GetGenericPortMappingEntry></s:Body></s:Envelope>')
        req = urllib.request.Request(cu, body.encode(), {
            "Content-Type": 'text/xml; charset="utf-8"',
            "SOAPAction": '"urn:schemas-upnp-org:service:WANIPConnection:1#GetGenericPortMappingEntry"'})
        try:
            with urllib.request.urlopen(req, timeout=4) as r:
                m = parse_mapping(r.read().decode(errors="ignore"))
        except Exception:
            break
        if not m:
            break
        out.append(m)
    return out


def run(ctx: Ctx) -> list[Finding]:
    out = []
    llm_ports = {p for sig in ctx.signatures["products"] for p in sig["ports"]}
    ip = public_ip()
    if not ip:
        return [Finding(NAME, "INFO", "Could not determine public IP (offline, or ipify blocked)")]
    d = internetdb(ip)
    if d is None:
        out.append(Finding(NAME, "INFO", f"Public IP {ip}: Shodan InternetDB has no record (not scanned, or nothing open)"))
    else:
        ports, hits, vulns = parse_internetdb(d, llm_ports)
        if hits:
            out.append(Finding(NAME, "CRITICAL", f"Shodan sees LLM port(s) {hits} open on your public IP {ip}",
                               "The internet has already indexed this. Assume every model is public and being used.",
                               "Close the port-forward / tunnel now; bind the server to 127.0.0.1; rotate any keys it could reach.",
                               {"ip": ip, "ports": ports, "vulns": vulns}))
        elif ports:
            out.append(Finding(NAME, "HIGH", f"Shodan sees {len(ports)} open port(s) on your public IP {ip}: {ports[:12]}",
                               ("Known CVEs on this IP: " + ", ".join(vulns)) if vulns else "",
                               "Confirm each is intended; anything you don't recognise is a router/ISP CPE service or a forgotten forward.",
                               {"ip": ip, "ports": ports, "vulns": vulns}))
        else:
            out.append(Finding(NAME, "OK", f"Public IP {ip}: Shodan InternetDB shows no open ports"))
    maps = upnp_mappings()
    bad = [m for m in maps if m["internal"] in llm_ports or m["ext"] in llm_ports]
    mine = [m for m in maps if m["host"] == ctx.lan_ip]
    if bad:
        targets = ", ".join(f"{m['host']}:{m['internal']}" for m in bad)
        out.append(Finding(NAME, "CRITICAL", f"Router UPnP forwards LLM port(s) to {targets}",
                           "Any app on the LAN can open these silently; this one exposes an inference server to the internet.",
                           "Delete the mapping in the router UI and disable UPnP; use a VPN (Tailscale/WireGuard) for remote access.",
                           {"mappings": bad}))
    elif mine:
        out.append(Finding(NAME, "MED", f"Router UPnP forwards {len(mine)} port(s) to this host: {[m['ext'] for m in mine]}",
                           "; ".join(f"{m['ext']}→{m['internal']} {m['desc']}" for m in mine[:5]),
                           "Review in router UI; disable UPnP if you don't rely on it.", {"mappings": mine}))
    elif maps:
        out.append(Finding(NAME, "INFO", f"Router UPnP has {len(maps)} mapping(s), none to this host or LLM ports", "", "", {"mappings": maps}))
    else:
        out.append(Finding(NAME, "OK", "No UPnP port mappings found (UPnP off, or router didn't answer)"))
    return out
