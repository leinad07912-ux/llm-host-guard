"""Plain-English layer. Every finding that a person reads or reacts to (Telegram, fleet table, host page) gets:
  say  - one short sentence, no jargon, what is wrong (or fine)
  todo - one short sentence, what to do about it
  risk - why it matters (only filled when the check did not already set one)
The technical title/detail stay untouched: they are the finding key and the 'technical details' view.
Rule of thumb: a 12-year-old should understand it. test_plain.py fails on jargon words. Stdlib only."""
from __future__ import annotations

import re

NET = "your WiFi or office network"

# (check, title regex, say, todo, risk). {1}, {2}... are regex groups. First match wins.
RULES: list[tuple[str, str, str, str, str]] = [
    # ---- AI servers (ports) ----
    ("ports", r"^(.+?) on \S+:\d+ reachable from LAN with no auth", "{1} has no password, and anyone on " + NET + " can use it.",
     "Let only the computers you pick reach it, or put a password in front of it.",
     "Risk: anyone nearby can use your AI, see your models and delete them."),
    ("ports", r"^(.+?) on \S+:\d+ open without auth, ufw-scoped", "{1} has no password. Only a few computers you picked can reach it.",
     "If you trust all of them, nothing to do. If not, let fewer computers in.", "Risk: low. Only computers you allowed can use it."),
    ("ports", r"^(.+?) on \S+:\d+ non-loopback, ufw-scoped", "{1} is shared on your network, but only with computers you picked.", "Nothing to do.", ""),
    ("ports", r"^(.+?) on \S+:\d+ bound to non-loopback", "{1} is set up so other computers can reach it, not just this one.",
     "Make it reachable from this computer only, unless you really need to share it.", "Risk: other people on your network may be able to use it."),
    ("ports", r"all loopback-only|LLM listener", "Your AI servers can only be reached from this computer. Good.", "Nothing to do.", ""),
    # ---- apps in containers ----
    ("docker", r"^container (\S+) publishes .* but DOCKER-USER drops it", "The app '{1}' looks open to the network, but a block is already in place.", "Nothing to do.", ""),
    ("docker", r"^container (\S+) publishes .* bypasses host firewall", "The app '{1}' is open to the whole network, and your normal protection does not cover it.",
     "Make it reachable from this computer only, or add a block for it.", "Risk: anyone on the network can reach this app."),
    ("docker", r"DOCKER-USER chain unreadable", "I could not check the protection around your apps. I need admin rights.", "Run the checker again as admin.", ""),
    ("docker", r"DOCKER-USER chain is empty", "Apps in containers have no extra protection from the network.", "Add a block for any app you do not want shared.", "Risk: an app you forgot about may be open to everyone."),
    ("docker", r"No containers publishing", "No apps are open to the network. Good.", "Nothing to do.", ""),
    # ---- internet exposure ----
    ("exposure", r"^Host has a public IP", "This computer is directly on the internet.",
     "Keep your AI servers private. Use a private link (VPN) when you need them from outside.", "Risk: anyone in the world can try to reach it."),
    ("exposure", r"^Tunnel daemon running", "A tunnel is running that can open this computer to the internet.",
     "Check what it shares. Add a password, or turn it off.", "Risk: a tunnel can make a private AI server public."),
    ("exposure", r"^No public IP", "This computer is not directly on the internet. Good.", "Nothing to do.", ""),
    # ---- network guard (firewall) ----
    ("firewall", r"ufw default policy is not deny", "The network guard on this computer lets connections in by default.",
     "Set it to block incoming connections unless you allow them.", "Risk: nothing stops other computers from trying to connect."),
    ("firewall", r"ufw allows port \d+ \(LLM\) from Anywhere", "Your AI server is open to everyone who can reach this computer.",
     "Allow only your own network, or only the computers you pick.", "Risk: anyone nearby can use your AI."),
    ("firewall", r"rules unreadable without sudo", "The network guard is on. I need admin rights to read its rules.", "Run the checker again as admin.", ""),
    ("firewall", r"disabled|not running|no input hook|OFF on|No host firewall", "The network guard on this computer is switched off.",
     "Switch it on. Ask your IT person if you are not sure how.", "Risk: nothing stops other computers from trying to connect."),
    ("firewall", r"ufw active", "The network guard is on and your AI servers are protected.", "Nothing to do.", ""),
    ("firewall", r"running$|input chain present|^pf enabled|Firewall on$", "The network guard is on.", "Nothing to do.", ""),
    # ---- settings ----
    ("config", r"sshd PasswordAuthentication", "Anyone can try to log in to this computer by guessing passwords.",
     "Turn off password login and use a secure key instead.", "Risk: password guessers never sleep."),
    ("config", r"sshd PermitRootLogin", "The main admin account can log in from another computer.", "Turn that off. Log in as a normal user instead.", ""),
    ("config", r"^OLLAMA_ORIGINS=", "Any website you visit could control your Ollama.", "Limit Ollama to the websites you trust.",
     "Risk: a bad web page could use your AI or your files through it."),
    ("config", r"^OLLAMA_HOST=", "Ollama is set to accept connections from other computers.", "Set it to this computer only, unless you really share it.", ""),
    ("config", r"^(vLLM|llama-server) on :\d+ without --api-key", "{1} has no password, so anyone who reaches it can use it.",
     "Set a password when you start it.", "Risk: anyone who can reach it can use your AI."),
    ("config", r"Open WebUI signup", "Anyone who finds Open WebUI can sign up, and the first person becomes the boss.", "Turn off public sign-up.", ""),
    ("config", r"No config weaknesses", "Your settings look fine.", "Nothing to do.", ""),
    # ---- internet scan ----
    ("internet", r"Shodan sees LLM port", "Anyone on the internet can see your AI server right now.",
     "Fix it today: close the opening in your router and in the computer's network guard.", "Risk: strangers can use your AI and see your models."),
    ("internet", r"Shodan sees (\d+) open port", "Strangers on the internet can see {1} open door(s) on your network.", "Close the ones you do not need.", "Risk: each open door is a way in."),
    ("internet", r"Shodan InternetDB (has no record|shows no open)", "From the internet, nothing of yours is visible. Good.", "Nothing to do.", ""),
    ("internet", r"Router UPnP forwards LLM", "Your router has opened your AI server to the whole internet.",
     "Switch off your router's automatic door-opening feature, then remove that opening.", "Risk: strangers can use your AI."),
    ("internet", r"Router UPnP forwards (\d+) port", "Your router has opened {1} door(s) to this computer from the internet.",
     "Switch off your router's automatic door-opening feature, or remove the doors you do not need.", "Risk: open doors let strangers try to get in."),
    ("internet", r"Router UPnP has", "Your router has opened doors for other devices. None lead to this computer.", "Nothing to do.", ""),
    ("internet", r"No UPnP port mappings", "Your router has not opened any doors to the internet. Good.", "Nothing to do.", ""),
    ("internet", r"Could not determine public IP", "I could not check how you look from the internet. Maybe no connection.", "Run the checker again when online.", ""),
    # ---- what AI servers are doing ----
    ("runtime", r"^(.+?) opened connections to (\d+) different internet hosts .*scan", "{1} is knocking on {2} different internet addresses within minutes. It looks like it is attacking others.",
     "Unplug this computer from the network now, then check it.", "Risk: a hijacked AI does exactly this."),
    ("runtime", r"^(.+?) hammered (.+?) \d+ times .*brute force", "{1} keeps trying {2} again and again, like someone guessing passwords.",
     "If you did not start this, stop the AI server and block that address.", "Risk: it may be attacking, or stuck in a loop."),
    ("runtime", r"^(.+?) \(pid \d+\) spawned '(.+)'", "{1} started a program ('{2}') that an AI server should never start.",
     "Stop {1}, then delete the last model you loaded.", "Risk: a hijacked AI server does this."),
    ("runtime", r"talked to .*update check or model download", "{1} contacted its maker's website, probably to update or fetch a model.", "Nothing to do.", ""),
    ("runtime", r"^(.+?) \(pid \d+\) connected to an unrecognised", "{1} is sending data to an internet address we do not know.",
     "If you do not know why, stop it and check what it is running.", "Risk: it could be sending your data out."),
    ("runtime", r"No LLM server processes", "No AI servers are running.", "Nothing to do.", ""),
    ("runtime", r"children as expected", "Your AI servers are behaving normally.", "Nothing to do.", ""),
    # ---- model files ----
    ("models", r"^(\d+) pickle-format", "{1} AI model file(s) can run hidden programs when opened.", "Get a safer version of the model, or delete these files.",
     "Risk: opening one could run a criminal's program."),
    ("models", r"^(\d+) malformed model", "{1} AI model file(s) look damaged or fake.", "Delete them and download again from the official site.", ""),
    ("models", r"^(\d+) world-writable model", "{1} model folder(s) can be changed by anyone with an account on this computer.", "Make those folders private to you.", ""),
    ("models", r"^Scanned \d+ files", "Your AI model files look safe.", "Nothing to do.", ""),
    ("models", r"No model directories", "No AI model files found to check.", "Nothing to do.", ""),
    # ---- out-of-date software ----
    ("versions", r"^(.+?) \S+ has (\d+) known (security issue|CVE)", "{1} is out of date and has {2} known security hole(s).", "Update {1} to the newest version.",
     "Risk: criminals already know how to break in through these holes."),
    ("versions", r"^(.+?) is out of date", "{1} is out of date.", "Update {1} to the newest version.", ""),
    ("versions", r"^Could not read the (.+) version", "I could not tell which version of {1} you have.", "Nothing to do.", ""),
    ("versions", r"^(.+?) \S+: our version data is old", "I could not confirm {1} is up to date.", "Update the checker, then run it again.", ""),
    ("versions", r"^(.+?) \S+: (up to date|no bundled)", "{1} is up to date.", "Nothing to do.", ""),
    ("versions", r"No LLM runtime CLIs", "No AI programs found to check for updates.", "Nothing to do.", ""),
    # ---- AI helpers (agents) ----
    ("agents", r"^(\d+) AI agent\(s\)", "{1} AI helper(s) are installed on this computer.", "Nothing to do. Close the ones you do not use.", ""),
    ("agents", r"No AI agent tooling", "No AI helpers found on this computer.", "Nothing to do.", ""),
    ("agent_risk", r"^(.+?) can control the screen and has been idle for (\d+)", "{1} can use your mouse and keyboard, and has sat unused for {2} day(s).",
     "Close {1} when you are not using it.", "Risk: a hidden message could make it click and type on your computer while you are away."),
    ("agent_risk", r"^(.+?) has been running but unused for (\d+)", "{1} has been left running for {2} day(s) and nobody is using it.", "Close it until you need it.", ""),
    ("agent_risk", r"^(.+?) is open to the network and nobody has used it for (\d+)", "{1} is open to your network and has sat unused for {2} day(s).",
     "Turn it off, or make it reachable from this computer only.", "Risk: other computers could use it."),
    ("agent_risk", r"^(.+?) reads web or email content .*no approval step", "{1} reads web pages or email and can act on your computer without asking you first.",
     "Turn the 'ask me first' prompts back on.", "Risk: a hidden message in a web page could trick it into acting on your computer."),
    ("agent_risk", r"^(.+?) reads web or email content .*prompts are on", "{1} reads web pages or email and can act on your computer, but it still asks you first. Good.",
     "Keep 'ask me first' on, and read each request before you say yes.", ""),
    ("agent_risk", r"No idle or injection", "No forgotten or easily-tricked AI helpers found.", "Nothing to do.", ""),
    # ---- AI helper settings (permissions) ----
    ("permissions", r"^(.+) is set to act without asking", "{1} will do things on your computer without asking you first.", "Turn the 'ask me first' prompts back on.",
     "Risk: if it is tricked, it acts before you can say no."),
    ("permissions", r"^(.+) may run any command without asking", "{1} is allowed to run any command without asking.", "Allow only the few commands you really use.",
     "Risk: if it is tricked, it can run anything."),
    ("permissions", r"^(.+): the '(.+)' file tool can reach your whole home", "{1}'s '{2}' tool can read all your files.", "Limit it to one project folder.",
     "Risk: if it is tricked, it can read or change anything, including your passwords and documents."),
    ("permissions", r"^(.+): a secret \((.+)\) is saved in plain text", "{1} has a password key ({2}) saved where anyone can read it.",
     "Move the key somewhere safer, not in the settings file.", "Risk: anything that can read the file gets the key."),
    ("permissions", r"^(.+): the '(.+)' tool downloads '(.+)' fresh", "{1} fetches the newest '{3}' every time it starts. A bad version swapped in by a criminal would run on your computer.",
     "Fix it to one version you have checked.", ""),
    ("permissions", r"^(.+): the '(.+)' tool talks to a remote server over unencrypted", "{1}'s '{2}' tool sends its data over the internet without scrambling it.",
     "Switch to the secure address (it starts with https).", "Risk: others on the way can read it."),
    ("permissions", r"^(.+): its config file with a saved secret can be read", "{1} has a saved password key in a file that other users on this computer can read.",
     "Make the file private to you.", ""),
    ("permissions", r"No risky agent permissions", "No risky settings found in your AI helpers.", "Nothing to do.", ""),
    ("*", r"not checked on Windows yet", "This check does not work on Windows yet.", "Nothing to do.", ""),
]
_COMPILED = [(c, re.compile(p), s, t, r) for c, p, s, t, r in RULES]

GENERIC = {
    "CRITICAL": ("Something on this computer is wide open right now.", "Open the details and follow the fix steps."),
    "HIGH": ("Something on this computer is not safe.", "Open the details and follow the fix steps."),
    "MED": ("Something on this computer could be safer.", "Open the details when you have a minute."),
}


def say_for(f: dict) -> tuple[str, str, str]:
    """(say, todo, risk) for a finding dict. Falls back to a generic sentence by severity, or '' for fine/info."""
    for check, rx, say, todo, risk in _COMPILED:
        if check not in ("*", f.get("check")):
            continue
        m = rx.search(f.get("title", ""))
        if m:
            g = m.groups()
            fill = lambda s: re.sub(r"\{(\d)\}", lambda n: g[int(n.group(1)) - 1] if int(n.group(1)) <= len(g) else "", s)
            return fill(say), fill(todo), risk
    gen = GENERIC.get(f.get("severity", ""))
    return (gen[0], gen[1], "") if gen else ("", "", "")


def apply(f: dict) -> dict:
    """Fill say/todo (and risk when empty) on a finding dict, in place."""
    say, todo, risk = say_for(f)
    f["say"], f["todo"] = say, todo
    if risk and not f.get("risk"):
        f["risk"] = risk
    return f
