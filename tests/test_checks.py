"""Fixture-based tests: no live system needed. Run: python3 -m unittest"""
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import core  # noqa: E402
from checks import docker, models, ports, versions  # noqa: E402
import llm_host_guard as g  # noqa: E402

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
        c._ufw = "11434/tcp                  ALLOW IN    192.168.50.0/24            # Ollama for HA\n"
        with mock.patch.object(ports, "probe", return_value={"/api/tags": {"status": 200, "models": 2}}):
            f = ports.run(c)[0]
        self.assertEqual(f.severity, "MED")
        self.assertEqual(f.evidence["ufw_sources"], ["192.168.50.0/24"])

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


if __name__ == "__main__":
    unittest.main()
