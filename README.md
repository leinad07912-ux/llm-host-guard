# llm-host-guard

Site: **https://leinad07912-ux.github.io/llm-host-guard/** (what it is, install, Telegram setup)

**Is my Ollama / LM Studio / vLLM box open to the world?** One command tells you, in plain English, and fixes it if you say yes.

## 30-second start

```
pipx install llm-host-guard          # or: pip install llm-host-guard
llm-host-guard
```

No pipx? `git clone https://github.com/leinad07912-ux/llm-host-guard && cd llm-host-guard && python3 llm_host_guard.py` — no dependencies, Python 3.9+.

You get a verdict line, a ranked list with a fix under every item, and the next command to run:

```
llm-host-guard v0.2.0 — neo (Linux, 192.168.50.156)

🔴 2 thing(s) to fix NOW, 2 this week   score 2/10

CRITICAL  Ollama on *:11434 reachable from LAN with no auth (7 models listed)
          fix: OLLAMA_HOST=127.0.0.1 … or `ufw allow from <LAN>/24 to any port 11434`
CRITICAL  container web publishes 0.0.0.0:8080 — bypasses host firewall
HIGH      sshd PasswordAuthentication yes
HIGH      3 pickle-format weight file(s) — execute code on load
OK        ufw active, default deny incoming

score: 2/10

next: preview the fixes →  llm-host-guard --fix --dry-run
      apply them        →  sudo llm-host-guard --fix
```

Then: `sudo llm-host-guard --fix` walks each fix, shows the exact command, asks y/N, prints the undo. `llm-host-guard --open` gives the same report as a page in your browser. `sudo llm-host-guard --watch 30 --telegram` keeps watching and messages you only when something new opens up.

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
| `runtime` | **Behaviour of the running server**: an LLM process that spawned a shell/downloader/unexpected child (the shape of a poisoned-model exploit) → CRITICAL; server or its children connected to a public IP (fine during a pull, otherwise not) → HIGH. `/proc` on Linux, `ps`+`lsof` on macOS, no root. `--checks runtime --watch 0.1` for a 6-second loop. |
| `internet` (opt-in `--internet`) | What the outside already sees: your public IP's open ports + CVEs via Shodan InternetDB (free, keyless), and router UPnP port-forwards to LLM ports. The only check that makes outbound calls. |

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
llm-host-guard                 # terminal report, exit 2=critical 1=high/med 0=clean
llm-host-guard --json          # machine-readable
llm-host-guard --html report.html         # self-contained page; --open writes it and opens your browser
llm-host-guard --watch 15 --webhook https://…   # rerun every 15 min, alert on new findings
llm-host-guard --watch 30 --telegram           # same, to Telegram (token/chat via env, see below)
llm-host-guard --watch 1 --once --telegram     # single diff pass, for cron
llm-host-guard --internet          # + Shodan InternetDB + router UPnP (outbound calls)
llm-host-guard --checks ports,docker --model-dir /data/models
sudo llm-host-guard            # optional: reads ufw rules + effective sshd config
```

Run `--watch 30` under systemd / launchd for continuous monitoring; `--html` in watch mode keeps the report fresh.

Telegram: create a bot with @BotFather, DM it once, get your chat id from `https://api.telegram.org/bot<TOKEN>/getUpdates`, then export `LLM_HOST_GUARD_TELEGRAM_BOT_TOKEN` and `LLM_HOST_GUARD_TELEGRAM_CHAT_ID` (a systemd `EnvironmentFile=` keeps them off the command line). `examples/llm-host-guard-watch.service` is a ready user unit.

## Many machines? (fleet)

```
llm-host-guard --report-to https://fleet.yourcompany.example --enrol-key lhg_…   # or env LLM_HOST_GUARD_FLEET_URL / _KEY
```

Every run also posts its JSON to a [llm-host-guard-fleet](https://github.com/leinad07912-ux/llm-host-guard-fleet) collector: one table for all hosts, history, alerts when any host goes red or silent. Best-effort — if the collector is down the local report and exit code are unchanged. Refuses plain `http://` to non-local hosts.

## `--fix` (v2)

```
llm-host-guard --fix --dry-run     # preview every recipe, no root, runs nothing
sudo llm-host-guard --fix          # prints each command, asks y/N per finding
sudo llm-host-guard --fix --yes    # unattended
```

Recipes exist for: open LLM port → scoped ufw rule; ufw "Anywhere" rule on an LLM port → re-scoped; `OLLAMA_HOST=0.0.0.0` under systemd → loopback drop-in; container on 0.0.0.0 → DOCKER-USER drop; sshd password auth → `sshd_config.d/00-…` drop-in (only if you already have an SSH key installed — it will not lock you out).

Every recipe only *adds* a rule or a drop-in file, never edits an existing file, and prints its undo command. Findings without a safe automatic recipe say why.

## What it does not do

- Edit config files in place (`--fix` only adds drop-ins/rules)
- Replace a firewall or IDS — it tells you when you're missing one
- Detect prompt injection or scan MCP servers — see agent-firewall / mcp-sentinel
- Kill anything: `runtime` detects and tells you the pid; agent-firewall's eBPF guard is the kill layer

## Platforms

Linux and macOS first-class. Windows best-effort (`netstat -ano`, `netsh advfirewall`; use `py -m llm_host_guard` if `llm-host-guard` isn't on PATH). Python ≥ 3.9. No dependencies.

Running from a clone without installing: `python3 llm_host_guard.py` or `python3 -m llm_host_guard` — identical.

## Contributing

`python3 -m unittest` — tests use fixtures, no live system needed.
New server signatures → `data/signatures.json`. New CVEs → `data/cves.json` (include vendor advisory link in PR).

MIT.
