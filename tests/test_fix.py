"""--fix tests: mocked runner, no root, no live system."""
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from llm_host_guard import core  # noqa: E402
from llm_host_guard import fix  # noqa: E402
from llm_host_guard.checks import config, docker, firewall, ports  # noqa: E402


def ctx_with(listeners, ufw="", lan="192.168.1.10"):
    c = core.Ctx()
    c._listeners = listeners
    c._lan_ip = lan
    c._ufw = ufw
    c._docker_user = ""
    c._iface = "eth0"
    return c


class Runner:
    def __init__(self, fail_on=None):
        self.ran, self.fail_on = [], fail_on

    def __call__(self, cmd):
        self.ran.append(cmd)
        return 1 if self.fail_on and self.fail_on in cmd else 0


class Apply(unittest.TestCase):
    def test_refuses_without_root(self):
        r = Runner()
        with mock.patch("os.geteuid", return_value=1000):
            rc = fix.apply(ctx_with([]), [core.Finding("x", "HIGH", "t", fix_cmds=["echo hi"])], yes=True, runner=r, out=lambda *a: None)
        self.assertEqual((rc, r.ran), (-1, []))

    def test_yes_runs_exactly_printed_commands_and_prints_undo(self):
        r, lines = Runner(), []
        f = core.Finding("x", "HIGH", "t", fix_cmds=["cmd one", "cmd two"], undo_cmds=["undo it"])
        with mock.patch("os.geteuid", return_value=0):
            n = fix.apply(ctx_with([]), [f, core.Finding("y", "OK", "no recipe")], yes=True, runner=r, out=lines.append)
        self.assertEqual((n, r.ran), (1, ["cmd one", "cmd two"]))
        self.assertIn("    $ undo it", lines)

    def test_prompt_no_skips(self):
        r = Runner()
        f = core.Finding("x", "HIGH", "t", fix_cmds=["cmd"])
        with mock.patch("os.geteuid", return_value=0):
            n = fix.apply(ctx_with([]), [f], yes=False, runner=r, ask=lambda _: "n", out=lambda *a: None)
        self.assertEqual((n, r.ran), (0, []))

    def test_failure_stops_recipe(self):
        r, lines = Runner(fail_on="two"), []
        f = core.Finding("x", "HIGH", "t", fix_cmds=["one", "two", "three"], undo_cmds=["u"])
        with mock.patch("os.geteuid", return_value=0):
            n = fix.apply(ctx_with([]), [f], yes=True, runner=r, out=lines.append)
        self.assertEqual((n, r.ran), (0, ["one", "two"]))
        self.assertTrue(any("FAILED" in l for l in lines))


class Recipes(unittest.TestCase):
    def test_open_llm_port_gets_scoped_ufw_recipe(self):
        c = ctx_with([core.Listener("tcp", "*", 11434, "ollama", 1)])
        with mock.patch.object(ports, "probe", return_value={"/api/tags": {"status": 200, "models": 1}}), \
             mock.patch("shutil.which", return_value="/usr/sbin/ufw"):
            f = ports.run(c)[0]
        self.assertEqual(f.severity, "CRITICAL")
        self.assertIn("ufw allow from 192.168.1.0/24 to any port 11434 proto tcp", f.fix_cmds[0])
        self.assertIn("ufw delete allow from 192.168.1.0/24 to any port 11434 proto tcp", f.undo_cmds[0])

    def test_no_ufw_no_recipe(self):
        c = ctx_with([core.Listener("tcp", "*", 11434, "ollama", 1)])
        with mock.patch.object(ports, "probe", return_value={"/api/tags": {"status": 200}}), \
             mock.patch("shutil.which", return_value=None):
            self.assertEqual(ports.run(c)[0].fix_cmds, [])

    def test_docker_recipe_uses_default_iface(self):
        c = ctx_with([])
        ps = "web\t0.0.0.0:8080->80/tcp\n"
        with mock.patch.object(docker, "sh", side_effect=lambda a, **k: ps if a[0] == "docker" else "x\n"):
            f = [x for x in docker.run(c) if x.evidence.get("port") == 8080][0]
        self.assertEqual(f.fix_cmds, ["iptables -I DOCKER-USER -i eth0 -p tcp --dport 8080 -j DROP"])
        self.assertEqual(f.undo_cmds, ["iptables -D DOCKER-USER -i eth0 -p tcp --dport 8080 -j DROP"])

    def test_sshd_recipe_requires_key(self):
        with mock.patch.object(config, "sh", return_value="passwordauthentication yes\n"), \
             mock.patch.object(config, "_sshd_files_text", return_value="x"):
            with mock.patch.object(fix, "has_ssh_key", return_value=False):
                f = [x for x in config._sshd(ctx_with([])) if "PasswordAuthentication" in x.title][0]
                self.assertEqual(f.fix_cmds, [])
                self.assertIn("authorized", f.fix_note)
            with mock.patch.object(fix, "has_ssh_key", return_value=True):
                f = [x for x in config._sshd(ctx_with([])) if "PasswordAuthentication" in x.title][0]
                self.assertIn("00-llm-host-guard.conf", f.fix_cmds[0])
                self.assertIn("sshd -t", f.fix_cmds[1])

    def test_ollama_dropin_only_when_unscoped_and_systemd(self):
        c = ctx_with([core.Listener("tcp", "*", 11434, "ollama", 1)])
        with mock.patch.object(config, "_ollama_env", return_value={"OLLAMA_HOST": "0.0.0.0:11434"}), \
             mock.patch.object(config, "_ollama_is_systemd", return_value=True), \
             mock.patch.object(config, "_sshd", return_value=[]):
            f = [x for x in config.run(c) if "OLLAMA_HOST" in x.title][0]
        self.assertIn("ollama.service.d/llm-host-guard.conf", f.fix_cmds[0])
        self.assertIn("systemctl restart ollama", f.fix_cmds[-1])
        self.assertIn("daemon-reload", f.undo_cmds[1])

    def test_ufw_anywhere_rule_recipe(self):
        c = ctx_with([core.Listener("tcp", "*", 11434, "ollama", 1)],
                     ufw="Status: active\n\nTo   Action   From\n11434/tcp   ALLOW   Anywhere\n")
        with mock.patch.object(firewall, "sh", return_value="Default: deny (incoming), allow (outgoing)\n11434/tcp                  ALLOW IN    Anywhere\n"), \
             mock.patch("pathlib.Path.exists", return_value=True), \
             mock.patch("pathlib.Path.read_text", return_value="ENABLED=yes"):
            f = [x for x in firewall.run(c) if "Anywhere" in x.title][0]
        self.assertEqual(f.fix_cmds, ["ufw delete allow 11434/tcp",
                                      "ufw allow from 192.168.1.0/24 to any port 11434 proto tcp comment llm-host-guard"])


if __name__ == "__main__":
    unittest.main()
