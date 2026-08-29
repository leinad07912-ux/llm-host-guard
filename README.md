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

Each finding carries the exact fix. Score = 10 − 3·CRITICAL − 2·HIGH − 1·MED.

## Usage

```
python3 llm_host_guard.py                 # terminal report, exit 2=critical 1=high/med 0=clean
python3 llm_host_guard.py --json          # machine-readable
python3 llm_host_guard.py --html report.html
python3 llm_host_guard.py --watch 15 --webhook https://…   # rerun every 15 min, alert on new findings
python3 llm_host_guard.py --checks ports,docker --model-dir /data/models
sudo python3 llm_host_guard.py            # optional: reads ufw rules + effective sshd config
```

Run `--watch 30` under systemd / launchd for continuous monitoring; `--html` in watch mode keeps the report fresh.

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
