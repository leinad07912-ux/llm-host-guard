"""runtime check: process tree + connection fixtures, nothing live."""
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from llm_host_guard import core  # noqa: E402
from llm_host_guard.checks import runtime  # noqa: E402

# pid: (ppid, comm)
BASE = {1: (0, "systemd"), 100: (1, "ollama"), 101: (100, "ollama"), 200: (1, "llama-server"), 300: (1, "sshd")}

PROC_NET_TCP = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 9C32A8C0:2CAA 2F32A8C0:C4B0 01 00000000:00000000 00:00000000 00000000  1000        0 41111 1 0
   1: 9C32A8C0:B1F2 0574D0CB:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 42222 1 0
   2: 00000000:2CAA 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 43333 1 0
"""


def ctx():
    c = core.Ctx()
    c._listeners = []
    c._lan_ip = "192.168.50.156"
    c.os = "Linux"
    return c


class Parsers(unittest.TestCase):
    def test_descendants(self):
        self.assertEqual(sorted(runtime.descendants(BASE, 100)), [101])
        self.assertEqual(len(runtime.descendants({**BASE, 102: (101, "sh")}, 100)), 2)

    def test_proc_net_tcp_established_only(self):
        rows = runtime.parse_proc_net_tcp(PROC_NET_TCP)
        self.assertEqual(rows, [(41111, "192.168.50.47", 50352), (42222, "203.208.116.5", 443)])

    def test_child_allowed(self):
        self.assertTrue(runtime.child_allowed("ollama", "ollama", []))
        self.assertTrue(runtime.child_allowed("python3.12", "vllm", ["python*"]))
        self.assertFalse(runtime.child_allowed("sh", "ollama", ["sh"]))  # shells never allowed
        self.assertFalse(runtime.child_allowed("curl", "llama-server", []))


class Run(unittest.TestCase):
    def test_healthy_ollama_with_runner_and_lan_client(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            f = runtime.run(ctx(), table=BASE, outbound=lambda pids: [(100, "192.168.50.47", 50352)], history_path=Path(d) / "h.json")
        self.assertEqual([x.severity for x in f], ["OK"])

    def test_shell_child_is_critical(self):
        table = {**BASE, 102: (101, "sh")}
        c = ctx()
        with mock.patch.object(c, "cmdline_of_pid", return_value="sh -c id"):
            import tempfile
            with tempfile.TemporaryDirectory() as d:
                f = runtime.run(c, table=table, outbound=lambda pids: [], history_path=Path(d) / "h.json")
        self.assertEqual(f[0].severity, "CRITICAL")
        self.assertIn("'sh' (pid 102)", f[0].title)
        self.assertIn("kill -9 102", f[0].fix)

    def test_vendor_outbound_is_info(self):
        import tempfile
        with mock.patch.object(runtime, "vendor_for_ip", side_effect=lambda ip: "ollama.com" if ip == "34.36.133.15" else None), tempfile.TemporaryDirectory() as d:
            f = runtime.run(ctx(), table=BASE, outbound=lambda pids: [(100, "34.36.133.15", 443)] if 100 in pids else [], history_path=Path(d) / "h.json")
        info = [x for x in f if x.severity == "INFO"]
        self.assertEqual(len(info), 1); self.assertIn("ollama.com", info[0].title); self.assertIn("none", info[0].risk)
        self.assertFalse([x for x in f if x.severity == "HIGH"])

    def test_public_outbound_is_high(self):
        import tempfile
        with mock.patch.object(runtime, "vendor_for_ip", return_value=None), tempfile.TemporaryDirectory() as d:
            f = runtime.run(ctx(), table=BASE, outbound=lambda pids: [(200, "203.208.116.5", 443)] if 200 in pids else [], history_path=Path(d) / "h.json")
        hi = [x for x in f if x.severity == "HIGH"]
        self.assertEqual(len(hi), 1)
        self.assertIn("llama.cpp server", hi[0].title)
        self.assertEqual(hi[0].evidence["remotes"], ["203.208.116.5:443"])

    def test_ollama_runner_named_llama_server_is_one_server(self):
        import tempfile
        table = {1: (0, "systemd"), 100: (1, "ollama"), 101: (100, "llama-server")}
        with tempfile.TemporaryDirectory() as d:
            f = runtime.run(ctx(), table=table, outbound=lambda pids: [], history_path=Path(d) / "h.json")
        self.assertEqual([x.severity for x in f], ["OK"])
        self.assertIn("1 LLM server", f[0].title)

    def test_scan_detected_across_snapshots(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d, mock.patch.object(runtime, "vendor_for_ip", return_value=None):
            hp = Path(d) / "h.json"
            f = []
            for i in range(4):  # 4 snapshots over 3 min, 12 new public hosts each = 16/min
                conns = [(200, f"8.{i+1}.{j+1}.9", 443) for j in range(12)]
                f = runtime.scan_signals("llama.cpp server", conns, now=1000 + i * 60, history_path=hp)
            crit = [x for x in f if x.severity == "CRITICAL"]
            self.assertEqual(len(crit), 1); self.assertEqual(crit[0].evidence["signal"], "scan"); self.assertIn("looks like a scan", crit[0].title)

    def test_bruteforce_detected(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            hp = Path(d) / "h.json"
            f = []
            for i in range(25):  # same host:port present in 25 snapshots over 4 min
                f = runtime.scan_signals("Ollama", [(100, "8.8.4.7", 22)], now=1000 + i * 10, history_path=hp)
            hi = [x for x in f if x.evidence.get("signal") == "bruteforce"]
            self.assertEqual(len(hi), 1); self.assertEqual(hi[0].severity, "HIGH"); self.assertIn("brute force", hi[0].title)

    def test_steady_state_no_scan(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            hp = Path(d) / "h.json"
            f = []
            for i in range(5):  # same 3 hosts every snapshot = 3 new total, then 0
                f = runtime.scan_signals("Ollama", [(100, "8.8.4.1", 443), (100, "8.8.4.2", 443), (100, "8.8.4.3", 443)], now=1000 + i * 30, history_path=hp)
            self.assertEqual(f, [])

    def test_no_servers(self):
        self.assertEqual(runtime.run(ctx(), table={1: (0, "systemd")}, outbound=lambda p: [])[0].severity, "OK")


if __name__ == "__main__":
    unittest.main()
