# llm-host-guard

Audit the attack surface of a machine running local LLMs. Stdlib only, changes nothing.

```
git clone https://github.com/leinad07912-ux/llm-host-guard && cd llm-host-guard
python3 llm_host_guard.py
```

```
llm-host-guard v0.1.0 — neo (Linux, 192.168.50.156)

CRITICAL  Ollama on *:11434 reachable from LAN with no auth (7 models listed)
          fix: OLLAMA_HOST=127.0.0.1 … or `ufw allow from <LAN>/24 to any port 11434`
CRITICAL  container web publishes 0.0.0.0:8080 — bypasses host firewall
HIGH      sshd PasswordAuthentication yes
HIGH      3 pickle-format weight file(s) — execute code on load
OK        ufw active, default deny incoming

score: 2/10
```

## Why

Ollama, LM Studio, vLLM, llama.cpp and friends ship with **no authentication**, often bind to **0.0.0.0**, load model files that can **execute code on open**, and run on laptops with no perimeter. Tens of thousands of open Ollama servers are already on Shodan. Tooling exists for agent safety ([agent-firewall](https://github.com/leinad07912-ux/agent-firewall), mcp-sentinel) and generic host hardening (lynis) — nothing covers the LLM-host gap specifically.

## What it checks

| Check | Finds |
|---|---|
| `ports` | LLM servers (Ollama, LM Studio, vLLM, llama.cpp, Open WebUI, text-gen-webui, Jan, koboldcpp, LocalAI, Xinference, SGLang, GPT4All, TabbyAPI) bound non-loopback; **probes them from your LAN IP to prove they answer without auth** |
| `firewall` | ufw / firewalld / nftables / pf / Windows Firewall missing, disabled, not default-deny, or allowing LLM ports from Anywhere |
| `docker` | Containers publishing on 0.0.0.0 — these **bypass ufw** |
| `exposure` | Public IP on an interface; cloudflared / ngrok / frp / bore tunnels running |
| `models` | Pickle weights (`.pt .bin .ckpt`) = RCE on load; malformed GGUF / safetensors headers (parser-CVE bait); world-writable model dirs |
| `versions` | Ollama / vLLM / llama.cpp / Open WebUI against a bundled CVE table |
| `config` | `OLLAMA_ORIGINS=*` (any website can drive your LLM from your browser), `OLLAMA_HOST=0.0.0.0`, vLLM / llama-server without `--api-key`, Open WebUI signup, sshd password auth |
| `agents` | Claude Code / Cursor / Codex / MCP configs present → points you to agent-side tooling |

Each finding carries the exact fix.

## What the levels mean

| Level | Plain English |
|---|---|
| **CRITICAL** | Wide open right now. Anyone on your network (or the internet) can use or damage your LLM today. Fix first. |
| **HIGH** | A real hole, but an attacker needs one more thing — be on your WiFi, or get you to open a file. Fix this week. |
| **MED** | Exposed on purpose but wider than it needs to be. Tighten when convenient. |
| **LOW** | Looks exposed but something else already blocks it. Just be aware. |
| **INFO** | Not a problem, just something you should know exists. |
| **OK** | Checked, nothing wrong. |

Score starts at 10; each CRITICAL takes 3, HIGH 2, MED 1. Run with `sudo` so firewall rules that already protect a port get credited (a LAN-scoped Ollama drops from CRITICAL to MED, a DOCKER-USER-blocked container to LOW).

## Usage

```
python3 llm_host_guard.py                 # terminal report, exit 2=critical 1=high/med 0=clean
python3 llm_host_guard.py --json          # machine-readable
python3 llm_host_guard.py --html report.html
python3 llm_host_guard.py --watch 15 --webhook https://…   # rerun every 15 min, alert on new findings
python3 llm_host_guard.py --watch 30 --telegram           # same, to Telegram (token/chat via env, see below)
python3 llm_host_guard.py --watch 1 --once --telegram     # single diff pass, for cron
python3 llm_host_guard.py --checks ports,docker --model-dir /data/models
sudo python3 llm_host_guard.py            # optional: reads ufw rules + effective sshd config
```

Run `--watch 30` under systemd / launchd for continuous monitoring; `--html` in watch mode keeps the report fresh.

Telegram: create a bot with @BotFather, DM it once, get your chat id from `https://api.telegram.org/bot<TOKEN>/getUpdates`, then export `LLM_HOST_GUARD_TELEGRAM_BOT_TOKEN` and `LLM_HOST_GUARD_TELEGRAM_CHAT_ID` (a systemd `EnvironmentFile=` keeps them off the command line). `examples/llm-host-guard-watch.service` is a ready user unit.

## What it does not do

- Change anything (`--fix` is planned for v2, opt-in)
- Replace a firewall or IDS — it tells you when you're missing one
- Detect prompt injection or scan MCP servers — see agent-firewall / mcp-sentinel

## Platforms

Linux and macOS first-class. Windows best-effort (`netstat -ano`, `netsh advfirewall`). Python ≥ 3.9. No dependencies.

## Contributing

`python3 -m unittest` — tests use fixtures, no live system needed.
New server signatures → `data/signatures.json`. New CVEs → `data/cves.json` (include vendor advisory link in PR).

MIT.
