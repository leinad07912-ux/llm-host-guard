"""agents / permissions / agent_risk: fixture home dirs and injected proc tables, nothing live."""
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from llm_host_guard import core  # noqa: E402
from llm_host_guard.checks import agent_risk, agents, permissions  # noqa: E402

DAY = 86400
SECRET = "ghp_SUPERSECRETVALUE123456"


def make_ctx(home: Path, listeners=None):
    c = core.Ctx()
    c.home, c.os, c._lan_ip = home, "Linux", "192.168.50.156"
    c._listeners = listeners or []
    return c


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, rel: str, obj, mode: int | None = None):
        p = self.home / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(obj))
        if mode is not None:
            os.chmod(p, mode)
        return p

    def ctx(self, **kw):
        return make_ctx(self.home, **kw)


class Inventory(Base):
    def test_two_mcp_servers_and_running(self):
        self.write(".claude.json", {"mcpServers": {"a": {"command": "node"}, "b": {"command": "python3"}}})
        ag = agents.inventory(self.ctx(), {10: (1, "claude")})
        cc = next(a for a in ag if a["name"] == "Claude Code")
        self.assertTrue(cc["running"])
        self.assertEqual(len(cc["mcp_servers"]), 2)

    def test_empty_home(self):
        f = agents.run(self.ctx(), {})
        self.assertEqual(f[0].severity, "OK")
        self.assertEqual(f[0].evidence["agents"], [])

    def test_report_view_drops_private_fields(self):
        self.write(".claude.json", {"mcpServers": {"a": {"command": "node", "env": {"X_TOKEN": SECRET}}}})
        f = agents.run(self.ctx(), {})[0]
        self.assertNotIn(SECRET, json.dumps(f.to_dict()))
        self.assertFalse(any(k.startswith("_") for a in f.evidence["agents"] for k in a))

    def test_windows_degrades(self):
        c = self.ctx()
        c.os = "Windows"
        for m in (agents, permissions, agent_risk):
            self.assertEqual(m.run(c)[0].severity, "INFO")

    def test_bad_json_never_crashes(self):
        (self.home / ".claude.json").write_text("{not json")
        self.assertEqual(agents.run(self.ctx(), {})[0].check, "agents")


class Permissions(Base):
    def rules(self):
        return {f.evidence.get("rule"): f for f in permissions.run(self.ctx())}

    def test_home_rooted_filesystem_server(self):
        self.write(".claude.json", {"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@1.0.0", str(self.home)]}}})
        r = self.rules()
        self.assertEqual(r["fs_scope_broad"].severity, "HIGH")

    def test_project_scoped_filesystem_is_ok(self):
        self.write(".claude.json", {"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@1.0.0", str(self.home / "proj")]}}})
        self.assertNotIn("fs_scope_broad", self.rules())

    def test_bypass_and_shell_wildcard(self):
        self.write(".claude/settings.json", {"permissions": {"defaultMode": "bypassPermissions", "allow": ["Bash(*)"]}})
        r = self.rules()
        self.assertEqual(r["bypass_prompts"].severity, "HIGH")
        self.assertEqual(r["shell_wildcard"].severity, "HIGH")

    def test_narrow_allow_is_ok(self):
        self.write(".claude/settings.json", {"permissions": {"allow": ["Bash(git status)"]}})
        self.assertEqual(permissions.run(self.ctx())[0].severity, "OK")

    def test_secret_reports_name_not_value(self):
        self.write(".claude.json", {"mcpServers": {"gh": {"command": "node", "env": {"GITHUB_TOKEN": SECRET, "OK_REF": "${X}", "PATH_X": "/bin"}}}}, mode=0o644)
        fs = permissions.run(self.ctx())
        r = {f.evidence["rule"]: f for f in fs}
        self.assertEqual(r["secret_in_config"].evidence["var"], "GITHUB_TOKEN")
        self.assertEqual(r["config_world_readable"].severity, "MED")
        blob = json.dumps([f.to_dict() for f in fs])
        self.assertNotIn(SECRET, blob)
        self.assertEqual(len([f for f in fs if f.evidence["rule"] == "secret_in_config"]), 1)

    def test_unpinned_and_http(self):
        self.write(".claude.json", {"mcpServers": {
            "a": {"command": "npx", "args": ["-y", "some-mcp"]},
            "b": {"command": "npx", "args": ["-y", "@scope/pkg@1.2.3"]},
            "c": {"command": "uvx", "args": ["tool==1.0"]},
            "d": {"url": "http://example.com/mcp"}, "e": {"url": "http://localhost:3000/mcp"}}})
        fs = permissions.run(self.ctx())
        unp = [f.evidence["server"] for f in fs if f.evidence["rule"] == "unpinned_runner"]
        http = [f.evidence["server"] for f in fs if f.evidence["rule"] == "http_remote"]
        self.assertEqual(unp, ["a"])
        self.assertEqual(http, ["d"])

    def test_codex_toml_never_approval(self):
        (self.home / ".codex").mkdir()
        (self.home / ".codex/config.toml").write_text('approval_policy = "never"\n')
        self.assertIn("bypass_prompts", self.rules())


class IdleAndInjection(Base):
    def setUp(self):
        super().setUp()
        self.now = time.time()

    def agent_home(self, age_days: float):
        p = self.home / ".claude/history.jsonl"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x")
        t = self.now - age_days * DAY
        os.utime(p, (t, t))

    def run_risk(self, table, uptime_days=20, **kw):
        return agent_risk.run(self.ctx(), now=self.now, state_path=self.home / "clients.json",
                              uptime=lambda pid: int(uptime_days * DAY), **kw)

    def test_idle_normal_agent_over_threshold(self):
        self.agent_home(10)
        agents.inventory(self.ctx(), {})  # no-op cache check below uses fresh ctx
        c = self.ctx()
        agents.inventory(c, {5: (1, "claude")})
        fs = agent_risk.idle_agents(c, self.now, lambda pid: 20 * DAY)
        self.assertEqual(fs[0].severity, "MED")

    def test_recent_activity_no_finding(self):
        self.agent_home(1)
        c = self.ctx()
        agents.inventory(c, {5: (1, "claude")})
        self.assertEqual(agent_risk.idle_agents(c, self.now, lambda pid: 20 * DAY), [])

    def test_unknown_activity_or_uptime_never_guessed(self):
        c = self.ctx()
        (self.home / ".claude").mkdir()
        agents.inventory(c, {5: (1, "claude")})
        self.assertEqual(agent_risk.idle_agents(c, self.now, lambda pid: 20 * DAY), [])
        self.agent_home(10)
        c = self.ctx()
        agents.inventory(c, {5: (1, "claude")})
        self.assertEqual(agent_risk.idle_agents(c, self.now, lambda pid: None), [])

    def test_only_uptime_counts_when_just_started(self):
        self.agent_home(10)
        c = self.ctx()
        agents.inventory(c, {5: (1, "claude")})
        self.assertEqual(agent_risk.idle_agents(c, self.now, lambda pid: 3600), [])

    def test_screen_control_agent_one_day_threshold(self):
        p = self.home / ".config/open-interpreter/x"
        p.parent.mkdir(parents=True)
        p.write_text("x")
        t = self.now - 2 * DAY
        os.utime(p, (t, t))
        c = self.ctx()
        agents.inventory(c, {7: (1, "interpreter")})
        fs = agent_risk.idle_agents(c, self.now, lambda pid: 20 * DAY)
        self.assertEqual(fs[0].severity, "HIGH")

    def test_model_server_open_with_no_clients(self):
        l = core.Listener("tcp", "0.0.0.0", 11434, "ollama", 100)
        c = self.ctx(listeners=[l])
        st = self.home / "clients.json"
        st.write_text(json.dumps({"11434": {"first": self.now - 5 * DAY, "last_client": 0}}))
        fs = agent_risk.idle_model_servers(c, self.now, st, clients=lambda port: 0)
        self.assertEqual(fs[0].severity, "HIGH")
        # first run only records, no finding
        st.unlink()
        self.assertEqual(agent_risk.idle_model_servers(c, self.now, st, clients=lambda port: 0), [])
        # a client resets the clock
        st.write_text(json.dumps({"11434": {"first": self.now - 5 * DAY, "last_client": 0}}))
        self.assertEqual(agent_risk.idle_model_servers(c, self.now, st, clients=lambda port: 2), [])

    def test_injection_high_when_prompts_off(self):
        self.write(".claude.json", {"mcpServers": {"browser": {"command": "node", "args": ["playwright-mcp"]}}})
        self.write(".claude/settings.json", {"permissions": {"defaultMode": "bypassPermissions"}})
        c = self.ctx()
        agents.inventory(c, {})
        fs = [f for f in agent_risk.injection_exposure(c, permissions.audit(c)[1]) if f.evidence["tool"] == "Claude Code"]
        self.assertEqual(fs[0].severity, "HIGH")
        self.assertEqual(fs[0].evidence["prompts"], "off")

    def test_injection_med_when_prompts_on(self):
        self.write(".claude.json", {"mcpServers": {}})
        c = self.ctx()
        agents.inventory(c, {})
        fs = [f for f in agent_risk.injection_exposure(c, permissions.audit(c)[1]) if f.evidence["tool"] == "Claude Code"]
        self.assertEqual(fs[0].severity, "MED")

    def test_injection_none_without_both_halves(self):
        (self.home / ".aider.conf.yml").write_text("x")      # shell+fs_write but no untrusted-input capability
        c = self.ctx()
        agents.inventory(c, {})
        self.assertEqual(agent_risk.injection_exposure(c, {}), [])

    def test_injection_copy_never_overclaims(self):
        self.write(".claude/settings.json", {"permissions": {"defaultMode": "bypassPermissions"}})
        (self.home / ".claude.json").write_text("{}")
        c = self.ctx()
        agents.inventory(c, {})
        for f in agent_risk.injection_exposure(c, permissions.audit(c)[1]):
            text = " ".join([f.title, f.detail, f.fix, f.risk]).lower()
            for w in ("protect", "prevent", "block", "secure", "detected"):
                self.assertNotIn(w, text)


if __name__ == "__main__":
    unittest.main()
