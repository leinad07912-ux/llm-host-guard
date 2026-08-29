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
        f = runtime.run(ctx(), table=BASE, outbound=lambda pids: [(100, "192.168.50.47", 50352)])
        self.assertEqual([x.severity for x in f], ["OK"])

    def test_shell_child_is_critical(self):
        table = {**BASE, 102: (101, "sh")}
        c = ctx()
        with mock.patch.object(c, "cmdline_of_pid", return_value="sh -c id"):
            f = runtime.run(c, table=table, outbound=lambda pids: [])
        self.assertEqual(f[0].severity, "CRITICAL")
        self.assertIn("'sh' (pid 102)", f[0].title)
        self.assertIn("kill -9 102", f[0].fix)

    def test_public_outbound_is_high(self):
        f = runtime.run(ctx(), table=BASE, outbound=lambda pids: [(200, "203.208.116.5", 443)] if 200 in pids else [])
        hi = [x for x in f if x.severity == "HIGH"]
        self.assertEqual(len(hi), 1)
        self.assertIn("llama.cpp server", hi[0].title)
        self.assertEqual(hi[0].evidence["remotes"], ["203.208.116.5:443"])

    def test_ollama_runner_named_llama_server_is_one_server(self):
        table = {1: (0, "systemd"), 100: (1, "ollama"), 101: (100, "llama-server")}
        f = runtime.run(ctx(), table=table, outbound=lambda pids: [])
        self.assertEqual([x.severity for x in f], ["OK"])
        self.assertIn("1 LLM server", f[0].title)

    def test_no_servers(self):
        self.assertEqual(runtime.run(ctx(), table={1: (0, "systemd")}, outbound=lambda p: [])[0].severity, "OK")


if __name__ == "__main__":
    unittest.main()
