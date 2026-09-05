"""Fixture-based tests: no live system needed. Run: python3 -m unittest"""
import json
import struct
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from llm_host_guard import core  # noqa: E402
from llm_host_guard.checks import docker, models, ports, versions  # noqa: E402
from llm_host_guard import cli as g  # noqa: E402

SS = """LISTEN 0 4096 *:11434 *:* users:(("ollama",pid=1234,fd=3))
LISTEN 0 4096 127.0.0.1:1234 0.0.0.0:* users:(("lms",pid=5,fd=3))
LISTEN 0 511 0.0.0.0:80 0.0.0.0:*
"""
LSOF = """ollama  1234 daniel  3u  IPv6 0x1 0t0 TCP *:11434 (LISTEN)
node    99 daniel  20u IPv4 0x2 0t0 TCP 127.0.0.1:3000 (LISTEN)
"""
DOCKER_PS = "crawl4ai\t0.0.0.0:11235->11235/tcp, [::]:11235->11235/tcp\nvoice\t127.0.0.1:3900->3900/tcp\nweb\t0.0.0.0:8080->80/tcp\n"


def ctx_with(listeners):
    c = core.Ctx()
    c._listeners = listeners
    c._lan_ip = "192.168.1.10"
    return c


class Parsers(unittest.TestCase):
    def test_ss(self):
        ls = core.parse_ss(SS)
        self.assertEqual([(l.addr, l.port, l.proc) for l in ls],
                         [("*", 11434, "ollama"), ("127.0.0.1", 1234, "lms"), ("0.0.0.0", 80, "")])
        self.assertTrue(ls[0].wildcard and ls[1].loopback)

    def test_lsof(self):
        ls = core.parse_lsof(LSOF)
        self.assertEqual((ls[0].port, ls[0].proc, ls[0].pid), (11434, "ollama", 1234))
        self.assertTrue(ls[1].loopback)

    def test_docker_ps(self):
        self.assertEqual(docker.parse_ps(DOCKER_PS), [("crawl4ai", "0.0.0.0", 11235), ("crawl4ai", "[::]", 11235),
                                                      ("voice", "127.0.0.1", 3900), ("web", "0.0.0.0", 8080)])

    def test_version_lt(self):
        self.assertTrue(core.version_lt("0.1.33", "0.1.34"))
        self.assertFalse(core.version_lt("0.5.8", "0.5.8"))
        self.assertTrue(core.version_lt("b3500", "b3561"))


class Ports(unittest.TestCase):
    def test_open_ollama_is_critical(self):
        c = ctx_with(core.parse_ss(SS))
        with mock.patch.object(ports, "probe", return_value={"/api/tags": {"status": 200, "models": 7}}):
            f = ports.run(c)
        self.assertEqual(f[0].severity, "CRITICAL")
        self.assertIn("7 models", f[0].title)

    def test_loopback_only_is_ok(self):
        c = ctx_with([core.Listener("tcp", "127.0.0.1", 11434, "ollama", 1)])
        self.assertEqual(ports.run(c)[0].severity, "OK")

    def test_bound_but_not_probeable_is_high(self):
        c = ctx_with(core.parse_ss(SS))
        with mock.patch.object(ports, "probe", return_value={}):
            self.assertEqual(ports.run(c)[0].severity, "HIGH")


class Docker(unittest.TestCase):
    def test_llm_port_critical_other_high(self):
        c = ctx_with([])
        with mock.patch.object(docker, "sh", side_effect=lambda a, **k: DOCKER_PS if a[0] == "docker" else None):
            f = docker.run(c)
        sev = {x.evidence.get("port"): x.severity for x in f if x.evidence}
        self.assertEqual(sev[8080], "CRITICAL")  # 8080 is an LLM signature port
        self.assertEqual(sev[11235], "HIGH")
        self.assertEqual(len([x for x in f if x.evidence.get("port") == 8080]), 1)  # v4+v6 deduped

    def test_port_only_guess_dropped_without_probe(self):
        c = ctx_with([core.Listener("tcp", "0.0.0.0", 8000, "", 0)])  # plausible/nginx on a vLLM port
        with mock.patch.object(ports, "probe", return_value={}):
            self.assertEqual(ports.run(c)[0].severity, "OK")


class Scoping(unittest.TestCase):
    def test_ufw_scoped_downgrades_to_med(self):
        c = ctx_with(core.parse_ss(SS))
        c._ufw = "11434/tcp                  ALLOW       192.168.50.0/24            # Ollama for HA\n"  # plain `ufw status` says ALLOW, verbose says ALLOW IN
        with mock.patch.object(ports, "probe", return_value={"/api/tags": {"status": 200, "models": 2}}):
            f = ports.run(c)[0]
        self.assertEqual(f.severity, "MED")
        self.assertEqual(f.evidence["ufw_sources"], ["192.168.50.0/24"])

    def test_ufw_single_host_is_low(self):
        c = ctx_with(core.parse_ss(SS))
        c._ufw = "11434/tcp                  ALLOW       192.168.50.47              # Ollama for HA\n"
        with mock.patch.object(ports, "probe", return_value={"/api/tags": {"status": 200, "models": 2}}):
            f = ports.run(c)[0]
        self.assertEqual(f.severity, "LOW")
        self.assertTrue(all(ports._single_host(x) for x in ("10.0.0.1", "10.0.0.1/32", "fd00::1/128")))
        self.assertFalse(ports._single_host("10.0.0.0/24"))

    def test_docker_user_drop_downgrades(self):
        c = ctx_with([])
        c._docker_user = "-A DOCKER-USER -i wlp98s0 -p tcp -m multiport --dports 54321:54327 -j DROP\n-A DOCKER-USER -i wlp98s0 -p tcp --dport 11235 -j DROP\n"
        self.assertTrue(c.docker_user_drops(54323) and c.docker_user_drops(11235))
        self.assertFalse(c.docker_user_drops(8000))
        ps = "kong\t0.0.0.0:54321->8000/tcp\nweb\t0.0.0.0:8000->80/tcp\n"
        with mock.patch.object(docker, "sh", side_effect=lambda a, **k: ps if a[0] == "docker" else "x\n"):
            sev = {x.evidence.get("port"): x.severity for x in docker.run(c) if x.evidence}
        self.assertEqual((sev[54321], sev[8000]), ("LOW", "CRITICAL"))


class Models(unittest.TestCase):
    def test_pickle_and_bad_gguf(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "a.bin").write_bytes(b"\x80\x04")
            (Path(d) / "bad.gguf").write_bytes(b"GGUX" + b"\0" * 20)
            (Path(d) / "ok.gguf").write_bytes(b"GGUF" + struct.pack("<IQQ", 3, 10, 5))
            (Path(d) / "ok.safetensors").write_bytes(struct.pack("<Q", 2) + b"{}")
            (Path(d) / "bad.safetensors").write_bytes(struct.pack("<Q", 99999) + b"{}")
            c = core.Ctx(model_dirs=[d])
            with mock.patch.object(models, "default_dirs", return_value=[Path(d)]):
                f = models.run(c)
            titles = " | ".join(x.title for x in f)
            self.assertIn("1 pickle", titles)
            self.assertIn("2 malformed", titles)


class Versions(unittest.TestCase):
    def test_old_ollama_flagged(self):
        c = ctx_with([])
        with mock.patch.object(versions, "detect", return_value={"ollama": "0.1.30"}):
            f = versions.run(c)[0]
        self.assertEqual(f.severity, "CRITICAL")
        self.assertIn("CVE-2024-37032", f.evidence["cves"])


class Report(unittest.TestCase):
    def test_score_and_html(self):
        fs = [core.Finding("ports", "CRITICAL", "x"), core.Finding("docker", "HIGH", "y"), core.Finding("models", "OK", "z")]
        self.assertEqual(g.score(fs), 5)
        c = ctx_with([])
        rep = g.report(c, fs)
        json.dumps(rep)
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "r.html"
            g.write_html(rep, p)
            t = p.read_text()
            self.assertIn("5<span", t)
            self.assertNotIn("<script", t)


class Actions(unittest.TestCase):
    def setUp(self):
        from llm_host_guard import actions
        self.actions = actions
        self.tmp = tempfile.TemporaryDirectory()
        actions.ACTIONS_FILE = Path(self.tmp.name) / "actions.json"
        actions.SNOOZE_FILE = Path(self.tmp.name) / "snooze.json"
        actions.ACTION_LOG = Path(self.tmp.name) / "actions.jsonl"

    def cq(self, data, uid="340307380"):
        return {"id": "1", "from": {"id": uid}, "data": data, "message": {"chat": {"id": uid}, "message_id": 5, "text": "alert"}}

    def test_register_keyboard_apply_undo(self):
        ran = []
        runner = lambda cmds: (ran.extend(cmds), (True, "done"))[1]
        with mock.patch.dict("os.environ", {"LLM_HOST_GUARD_TELEGRAM_BOT_TOKEN": "t", "LLM_HOST_GUARD_TELEGRAM_CHAT_ID": "340307380"}), \
             mock.patch("os.geteuid", return_value=0):
            aid = self.actions.register({"title": "Ollama open", "fix_cmds": ["ufw allow x"], "undo_cmds": ["ufw delete allow x"]})
            self.assertIsNone(self.actions.register({"title": "no recipe"}))
            kb = self.actions.keyboard(aid)
            self.assertEqual([b["text"] for b in kb["inline_keyboard"][0]], ["🔒 Close it", "🔒 Close for 1h"])
            self.assertIn("closed", self.actions.handle_callback(self.cq(f"lhg:fix:{aid}"), runner))
            self.assertEqual(ran, ["ufw allow x"])
            self.assertIn("undone", self.actions.handle_callback(self.cq(f"lhg:undo:{aid}"), runner))
            self.assertEqual(ran[-1], "ufw delete allow x")
            self.assertEqual(self.actions.handle_callback(self.cq(f"lhg:fix:{aid}", uid="999"), runner), "not authorised")
            self.assertIn("expired", self.actions.handle_callback(self.cq("lhg:fix:deadbeef"), runner))

    def test_snooze_and_temp_close(self):
        ran = []
        runner = lambda cmds: (ran.extend(cmds), (True, "done"))[1]
        f = {"check": "ports", "severity": "MED", "title": "Ollama scoped", "fix_cmds": ["ufw allow x"], "undo_cmds": ["ufw delete allow x"]}
        with mock.patch.dict("os.environ", {"LLM_HOST_GUARD_TELEGRAM_BOT_TOKEN": "t", "LLM_HOST_GUARD_TELEGRAM_CHAT_ID": "1"}), \
             mock.patch("os.geteuid", return_value=0), mock.patch.object(self.actions, "tg", return_value={}):
            # snooze via summary keyboard: key hidden until 24h passes, then due exactly once
            sid = self.actions.register_summary([f])
            self.assertEqual([b["text"] for b in self.actions.keyboard(sid, summary=True)["inline_keyboard"][0]], ["⏰ Remind me tomorrow", "✓ Leave it"])
            self.assertIn("tomorrow", self.actions.handle_callback(self.cq(f"lhg:snz:{sid}", uid="1"), runner))
            self.assertEqual(self.actions.snoozed_due(), set())
            self.assertEqual(self.actions.snoozed_due(now=time.time() + 25 * 3600), {"ports:MED:Ollama scoped"})
            self.assertEqual(self.actions.snoozed_due(now=time.time() + 25 * 3600), set())
            # temp close: fix runs now, undo runs once the hour is up
            aid = self.actions.register(f)
            self.assertIn("reopens in 1h", self.actions.handle_callback(self.cq(f"lhg:tmp:{aid}", uid="1"), runner))
            self.assertEqual(ran, ["ufw allow x"])
            self.assertEqual(self.actions.expire_temp(runner), [])
            msgs = self.actions.expire_temp(runner, now=time.time() + 3601)
            self.assertEqual(len(msgs), 1); self.assertIn("reopened", msgs[0])
            self.assertEqual(ran[-1], "ufw delete allow x")
            self.assertEqual(self.actions.expire_temp(runner, now=time.time() + 7200), [])  # not twice
            self.assertFalse(self.actions._load()[aid]["applied"])
            # every tap was logged; closing woke the watch loop; shipping clears the log
            log = self.actions.pending_actions()
            self.assertEqual([e["what"] for e in log], ["snoozed 24h", "closed for 1h", "reopened after 1h"])
            self.assertTrue(self.actions.WAKE.is_set())
            self.actions.clear_actions(2)
            self.assertEqual([e["what"] for e in self.actions.pending_actions()], ["reopened after 1h"])

    def test_socket_roundtrip(self):
        import json, socket, threading, time
        path = str(Path(self.tmp.name) / "a.sock")
        ran = []
        with mock.patch.dict("os.environ", {"LLM_HOST_GUARD_TELEGRAM_BOT_TOKEN": "t", "LLM_HOST_GUARD_TELEGRAM_CHAT_ID": "7"}), \
             mock.patch("os.geteuid", return_value=0):
            aid = self.actions.register({"title": "x", "fix_cmds": ["echo hi"], "undo_cmds": ["echo undo"]})
            stop = {"v": False}
            th = threading.Thread(target=self.actions.serve_socket, args=(lambda: stop["v"], lambda c: (ran.extend(c), (True, ""))[1], path), daemon=True)
            th.start(); time.sleep(0.3)
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(path)
            s.sendall((json.dumps({"id": "1", "from": {"id": "7"}, "data": f"lhg:fix:{aid}"}) + "\n").encode())
            reply = json.loads(s.makefile("rb").readline()); s.close(); stop["v"] = True
        self.assertIn("closed", reply["text"]); self.assertEqual(ran, ["echo hi"])
        self.assertEqual(reply["keyboard"]["inline_keyboard"][0][0]["text"], "↩ Undo (reopen)")

    def test_needs_root(self):
        with mock.patch.dict("os.environ", {"LLM_HOST_GUARD_TELEGRAM_BOT_TOKEN": "t", "LLM_HOST_GUARD_TELEGRAM_CHAT_ID": "1"}), \
             mock.patch("os.geteuid", return_value=1000):
            aid = self.actions.register({"title": "x", "fix_cmds": ["true"]})
            self.assertIn("root", self.actions.handle_callback(self.cq(f"lhg:fix:{aid}", uid="1"), lambda c: (True, "")))


class Fleet(unittest.TestCase):
    def test_report_to_posts_with_bearer_and_host_id(self):
        sent = {}
        class R:
            def read(self): return b"{}"
        def fake_open(req, timeout=0):
            sent["url"], sent["auth"] = req.full_url, req.get_header("Authorization")
            sent["body"] = json.loads(req.data)
            return R()
        with mock.patch("urllib.request.urlopen", fake_open), \
             mock.patch.object(g, "host_id", return_value="11111111-1111-4111-8111-111111111111"):
            ok = g.report_to_fleet({"tool": "llm-host-guard", "score": 7}, "https://fleet.example", "lhg_abc")
        self.assertTrue(ok)
        self.assertEqual(sent["url"], "https://fleet.example/api/report")
        self.assertEqual(sent["auth"], "Bearer lhg_abc")
        self.assertEqual(sent["body"]["host_id"], "11111111-1111-4111-8111-111111111111")

    def test_host_id_from_machine_id_is_stable(self):
        with mock.patch("pathlib.Path.read_text", return_value="0123456789abcdef0123456789abcdef\n"):
            a, b = g.host_id(), g.host_id()
        self.assertEqual(a, b)
        self.assertRegex(a, r"^[0-9a-f-]{36}$")

    def test_refuses_plain_http_offsite(self):
        with mock.patch("urllib.request.urlopen") as u:
            self.assertFalse(g.report_to_fleet({}, "http://fleet.example", "lhg_abc"))
            u.assert_not_called()

    def test_failure_is_swallowed(self):
        with mock.patch("urllib.request.urlopen", side_effect=OSError("down")), mock.patch("time.sleep"):
            self.assertFalse(g.report_to_fleet({}, "https://fleet.example", "lhg_abc"))


if __name__ == "__main__":
    unittest.main()
