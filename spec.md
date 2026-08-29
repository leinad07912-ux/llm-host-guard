# llm-host-guard — spec (v0.1)

## What

A single-command, stdlib-only Python audit tool for machines running local LLM servers (Ollama, LM Studio, vLLM, llama.cpp, Open WebUI, text-generation-webui, Jan, koboldcpp, LocalAI, Xinference). It reports how an attacker on the network — or a poisoned model file — could reach or abuse the LLM host, ranked by severity, with the exact fix for each finding.

Audit-only. It never changes the system.

## Why

Local LLM adoption is rising fast. The servers ship with no auth, bind to 0.0.0.0 by default, pull arbitrary model files that can execute code on load, and sit on laptops/desktops with no perimeter. Tens of thousands of open Ollama instances are already indexed by Shodan. Existing tools cover agents (agent-firewall, mcp-sentinel) or generic host hardening (lynis) — none cover the LLM-host gap specifically.

## Threat model

| # | Vector | Covered |
|---|---|---|
| 1 | Inference API exposed on LAN/internet, no auth | yes |
| 1b | Firewall absent / too permissive / bypassed by Docker | yes |
| 1c | Host directly on internet or behind a tunnel | yes (public IP + tunnel process detection; Shodan/UPnP = v1.1) |
| 2 | Poisoned / malformed model files | yes (pickle weights, GGUF/safetensors header, perms) |
| 2b | Known-vulnerable runtime version | yes (bundled CVE table) |
| 3 | Weak config (CORS `*`, 0.0.0.0, open signup, password SSH) | yes |
| 4 | Agent tooling on host exposing tool servers | detect + refer (no duplication of agent-firewall) |
| 5 | Ongoing abuse | `--watch` diff mode |

Out of scope v1: blocking/fixing (`--fix` = v2), prompt-injection detection, MCP static scanning, hosted fleet dashboard.

## Interface

```
python3 llm_host_guard.py [--json] [--html out.html] [--watch N] [--checks a,b,c] [--webhook URL]
```

- default: human-readable terminal report + score
- `--json`: machine-readable to stdout (schema below), for cron/CI
- `--html PATH`: write self-contained static HTML report (no server, no external assets)
- `--watch MINUTES`: rerun every N minutes, print only diffs (new listener, new model file, new inbound peer on LLM port), POST diff to `--webhook` if set. State in `~/.llm-host-guard/state.json`
- `--checks`: subset, default all
- exit code: 0 clean, 1 findings ≥ MED, 2 any CRITICAL

## Checks (one module each, `checks/<name>.py`, function `run(ctx) -> list[Finding]`)

- `ports` — enumerate TCP listeners (ss → lsof → netstat fallback), match `data/signatures.json` by port and process name, flag non-loopback binds; actively probe `/api/tags`, `/v1/models`, `/` on the host's LAN IP to prove reachability and no-auth.
- `firewall` — ufw / firewalld / nftables / pf / Windows Firewall presence and default policy; whether LLM ports have rules wider than RFC1918.
- `docker` — `docker ps` port mappings published on 0.0.0.0 for LLM-signature ports or any port; empty DOCKER-USER chain noted.
- `exposure` — public IP on any interface; cloudflared/ngrok/tailscale-funnel/bore processes present; router UPnP = v1.1.
- `models` — walk Ollama, HF cache, LM Studio, Jan, custom `--model-dir`. Pickle formats (`.pt .bin .pkl .ckpt .pth`) = HIGH; GGUF magic `GGUF` + version ≤ 3 sanity, safetensors 8-byte header length ≤ file size; world-writable files/dirs = MED.
- `versions` — `ollama --version`, vllm, llama-server, LM Studio app bundle; compare to `data/cves.json` (semver ranges).
- `config` — Ollama env (`OLLAMA_HOST`, `OLLAMA_ORIGINS`), Open WebUI `ENABLE_SIGNUP`, vLLM missing `--api-key` in cmdline, sshd `PasswordAuthentication`/`PermitRootLogin` from `sshd_config` (read-only, no sudo).
- `agents` — presence of `~/.claude`, `~/.cursor`, `.mcp.json`, OpenClaw, and any of their servers listening non-loopback. INFO with pointer to agent-firewall / mcp-sentinel.

## Finding schema

```json
{"check":"ports","severity":"CRITICAL","title":"...","detail":"...","fix":"...","evidence":{}}
```
Severity ∈ CRITICAL, HIGH, MED, LOW, INFO, OK. Score = 10 − (3·CRIT + 2·HIGH + 1·MED), floored at 0.

## Report JSON

```json
{"tool":"llm-host-guard","version":"0.1.0","host":"...","os":"...","ts":"...","score":3,"findings":[...]}
```
HTML report and future `--serve`/hosted dashboard consume this exact object.

## Non-goals / constraints

- Python ≥ 3.9, stdlib only, no sudo required (degrades gracefully, says what it couldn't read).
- Linux + macOS first-class; Windows best-effort.
- Never writes outside `~/.llm-host-guard/` and the `--html` path.
- No network calls except probing the local host's own LAN IP and optional `--webhook`.

## Acceptance

- On a box with Ollama on 0.0.0.0 and no ufw scoping: CRITICAL finding with the two fixes (bind loopback / ufw allow from LAN).
- On a hardened box (loopback bind, ufw default deny, no pickle weights): score ≥ 8, no CRITICAL.
- `--json` validates against the schema; `--html` opens offline with no console errors.
- `--watch` detects a newly started listener within one interval.
- `python3 -m unittest` passes using fixture outputs (no live system needed).
