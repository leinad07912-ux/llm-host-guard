# Changelog

## 0.5.0 — 2026-10-08

From "is this box open?" to "what are the AI agents on this box allowed to do?"

New checks (all local; they read config paths and setting names, never file contents or secret values):

- **Agent inventory** — which AI agents are installed or running (Claude Code, Cursor, Codex, Gemini CLI, Aider, Open Interpreter, OpenClaw, Claude desktop, …), what they can do, which MCP servers they load.
- **Permission audit** — risky settings: file access rooted at your whole home folder, shell with no approval prompts, "allow everything" modes. HIGH or MED.
- **Idle agents** — an agent nobody has used for 3 days (1 day for ones that control the screen or keyboard). MED, or HIGH for screen/keyboard control agents and for AI servers open to the network. Reported once, clears when you use it or close it.
- **Prompt-injection exposure** — flags agents that read untrusted content (web, email, files) *and* can act (shell, write files, send mail). This shows where a hidden instruction would hurt most; it does not detect injections. Approval prompts on = INFO, off = HIGH.
- **Agent version status** — `--version` for the agents above, compared to bundled advisories and the newest known release. Out of date by 3+ minor versions = LOW. Version data older than 120 days is reported as INFO, never "up to date". A weekly GitHub Action refreshes the data and opens a PR.
- Reports use `schema: 2`; fleet collectors accept schema 1 and 2.

### Your score may drop after upgrading

The new checks count toward the score with the usual weights (CRITICAL 3, HIGH 2, MED 1; LOW and INFO cost nothing, and the score never goes below 0). A machine that scored 9/10 on 0.4.x can score lower on 0.5.0 **without anything on it having changed**, because we now look at things we did not look at before. Typical causes:

| Finding | Cost |
|---|---|
| Agent with shell or file access and no approval prompts (HIGH) | -2 |
| File server rooted at your home folder (HIGH) | -2 |
| Agent that reads untrusted content and can act, prompts off (HIGH) | -2 |
| Smaller permission issues (MED) | -1 |
| Agent unused for days (MED) | -1 |
| Screen-control agent idle for a day, or an AI server open to the network and unused (HIGH) | -2 |
| Out-of-date agent, old version data, approval prompts on (LOW/INFO) | 0 |

Run `llm-host-guard` before and after upgrading to see the difference; each new finding says what to change.
