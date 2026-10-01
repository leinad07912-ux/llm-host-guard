"""DOCKER-USER crediting: interface-aware, NAT-aware, port-range aware.

Reproduces a real host (evo-x1, 2026-10-01) where the tool reported local Supabase as safe ("DOCKER-USER drops
it") while it was reachable over Ethernet: the rule named only the Wi-Fi interface, matched the published port
although Docker rewrites it to the container's port, and Qdrant's published port RANGE was not parsed at all.
"""
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from llm_host_guard import core  # noqa: E402
from llm_host_guard.checks import docker  # noqa: E402

IP_BR_ADDR = """lo               UNKNOWN        127.0.0.1/8 ::1/128
eno1             DOWN
enp100s0         UP             192.168.50.196/24 fe80::caff/64
wlp98s0          UP             192.168.50.156/24 fe80::ee8e/64
docker0          DOWN           172.17.0.1/16
br-32643f75c572  UP             172.18.0.1/16
veth1234@if2     UP
"""
PS = (
    "supabase_db_claify\t0.0.0.0:54322->5432/tcp, [::]:54322->5432/tcp\n"
    "supabase_kong_claify\t0.0.0.0:54321->8000/tcp\n"
    "supabase_studio_claify\t0.0.0.0:54323->3000/tcp\n"
    "qdrant\t0.0.0.0:6333-6334->6333-6334/tcp, [::]:6333-6334->6333-6334/tcp\n"
    "fix-pg\t127.0.0.1:54331->5432/tcp\n"
)
ORIGINAL = ("-N DOCKER-USER\n-A DOCKER-USER -i wlp98s0 -p tcp -m multiport --dports 54321:54327 -j DROP\n"
            "-A DOCKER-USER -i wlp98s0 -p tcp -m tcp --dport 11235 -j DROP\n-A DOCKER-USER -j RETURN\n")
PARTIAL_FIX = ORIGINAL.replace("-A DOCKER-USER -j RETURN\n", (
    "-A DOCKER-USER -i enp100s0 -p tcp -m multiport --dports 54321:54327 -j DROP\n"
    "-A DOCKER-USER -i enp100s0 -p tcp -m multiport --dports 6333:6334 -j DROP\n"
    "-A DOCKER-USER -i wlp98s0 -p tcp -m multiport --dports 6333:6334 -j DROP\n-A DOCKER-USER -j RETURN\n"))
FINAL = PARTIAL_FIX.replace("-A DOCKER-USER -j RETURN\n", (
    "-A DOCKER-USER -i wlp98s0 -p tcp -m conntrack --ctorigdstport 54321:54327 --ctdir ORIGINAL -j DROP\n"
    "-A DOCKER-USER -i enp100s0 -p tcp -m conntrack --ctorigdstport 54321:54327 --ctdir ORIGINAL -j DROP\n"
    "-A DOCKER-USER -j RETURN\n"))


def host(chain):
    c = core.Ctx()
    c._listeners = []
    c._lan_ip = "192.168.50.196"
    c._docker_user = chain
    with mock.patch.object(core, "sh", side_effect=lambda a, **k: IP_BR_ADDR if a[:2] == ["ip", "-br"] else None):
        c.external_ifaces()  # cache
    return c


def findings(chain):
    c = host(chain)
    with mock.patch.object(docker, "sh", side_effect=lambda a, **k: PS if a[0] == "docker" else "x\n" * 3):
        return {f.evidence["port"]: f for f in docker.run(c) if f.evidence}


class RealHost(unittest.TestCase):
    def test_external_interfaces_exclude_loopback_down_and_container_bridges(self):
        self.assertEqual(host("").external_ifaces(), ["enp100s0", "wlp98s0"])

    def test_original_rules_were_not_protecting_supabase_or_qdrant(self):
        f = findings(ORIGINAL)
        for port in (54321, 54322, 54323, 6333, 6334):
            self.assertEqual(f[port].severity, "HIGH", port)  # never the LOW "drops it"
        self.assertIn("enp100s0", f[54322].detail)
        self.assertIn("5432", f[54322].detail)  # explains the NAT rewrite

    def test_first_attempt_fixed_qdrant_only(self):
        """Port-for-port rules match Qdrant (6333 -> 6333) but not Supabase (54322 -> 5432)."""
        f = findings(PARTIAL_FIX)
        self.assertEqual({p: f[p].severity for p in (6333, 6334)}, {6333: "LOW", 6334: "LOW"})
        self.assertEqual({p: f[p].severity for p in (54321, 54322, 54323)}, {54321: "HIGH", 54322: "HIGH", 54323: "HIGH"})

    def test_conntrack_rules_protect_everything(self):
        f = findings(FINAL)
        self.assertEqual({p: x.severity for p, x in f.items()}, {p: "LOW" for p in (54321, 54322, 54323, 6333, 6334)})

    def test_coverage_of_only_one_interface_is_reported_as_partial_with_a_fix_for_the_other(self):
        chain = "-A DOCKER-USER -i wlp98s0 -p tcp -m conntrack --ctorigdstport 54322 --ctdir ORIGINAL -j DROP\n"
        f = findings(chain)[54322]
        self.assertEqual(f.severity, "HIGH")
        self.assertIn("covers wlp98s0 only", f.title)
        self.assertEqual(f.fix_cmds, ["iptables -I DOCKER-USER -i enp100s0 -p tcp -m conntrack --ctorigdstport 54322 --ctdir ORIGINAL -j DROP"])
        self.assertEqual(f.undo_cmds[0].replace("-D ", "-I "), f.fix_cmds[0])

    def test_suggested_fix_covers_every_uncovered_interface_with_the_right_match(self):
        f = findings("-N DOCKER-USER\n-A DOCKER-USER -j RETURN\n")[54322]
        self.assertEqual(len(f.fix_cmds), 2)
        self.assertTrue(all("--ctorigdstport 54322 --ctdir ORIGINAL" in c and "--dport" not in c for c in f.fix_cmds))

    def test_loopback_only_publication_is_not_reported(self):
        self.assertNotIn(54331, findings(ORIGINAL))


class PortRanges(unittest.TestCase):
    def test_a_published_range_is_expanded_port_by_port(self):
        m = docker.parse_ps_full("qdrant\t0.0.0.0:6333-6334->6333-6334/tcp\n")
        self.assertEqual([(x[2], x[3]) for x in m], [(6333, 6333), (6334, 6334)])

    def test_ranges_with_an_offset_keep_their_pairing(self):
        m = docker.parse_ps_full("x\t0.0.0.0:8000-8002->9000-9002/tcp\n")
        self.assertEqual([(x[2], x[3]) for x in m], [(8000, 9000), (8001, 9001), (8002, 9002)])

    def test_udp_is_parsed_but_not_reported_as_tcp(self):
        self.assertEqual(docker.parse_ps("dns\t0.0.0.0:53->53/udp\n"), [])


class RuleParsing(unittest.TestCase):
    def covers(self, rule, hp, cp=None, proto="tcp"):
        rules = core.parse_drop_rules(rule)
        return any(core.rule_covers(r, hp, cp or hp, proto) for r in rules)

    def test_conditional_rules_are_not_credited(self):
        for r in ("-A DOCKER-USER -s 10.0.0.0/8 -p tcp --dport 80 -j DROP",
                  "-A DOCKER-USER ! -s 192.168.1.0/24 -p tcp --dport 80 -j DROP",
                  "-A DOCKER-USER -d 172.18.0.2 -p tcp --dport 80 -j DROP",
                  "-A DOCKER-USER ! -i lo -p tcp --dport 80 -j DROP"):
            self.assertFalse(self.covers(r, 80), r)

    def test_an_earlier_accept_or_return_stops_crediting_later_drops(self):
        self.assertFalse(self.covers("-A DOCKER-USER -j RETURN\n-A DOCKER-USER -i eth0 -p tcp --dport 80 -j DROP", 80))
        self.assertFalse(self.covers("-A DOCKER-USER -s 10.0.0.1 -j ACCEPT\n-A DOCKER-USER -i eth0 -p tcp --dport 80 -j DROP", 80))

    def test_reject_counts_and_other_jumps_do_not(self):
        self.assertTrue(self.covers("-A DOCKER-USER -i eth0 -p tcp --dport 80 -j REJECT --reject-with icmp-port-unreachable", 80))
        self.assertFalse(self.covers("-A DOCKER-USER -i eth0 -p tcp --dport 80 -j LOG", 80))
        self.assertFalse(self.covers("-A DOCKER-USER -i eth0 -p tcp --dport 80 -j SOMECHAIN", 80))

    def test_a_bare_interface_drop_covers_every_port_on_it(self):
        self.assertTrue(self.covers("-A DOCKER-USER -i eth0 -j DROP", 12345))

    def test_protocol_must_match(self):
        self.assertFalse(self.covers("-A DOCKER-USER -p udp -m udp --dport 53 -j DROP", 53))
        self.assertTrue(self.covers("-A DOCKER-USER -p udp -m udp --dport 53 -j DROP", 53, proto="udp"))

    def test_both_original_and_container_port_must_match_when_both_given(self):
        r = "-A DOCKER-USER -p tcp -m tcp --dport 5432 -m conntrack --ctorigdstport 54322 --ctdir ORIGINAL -j DROP"
        self.assertTrue(self.covers(r, 54322, 5432))
        self.assertFalse(self.covers(r, 54322, 9999))
        self.assertFalse(self.covers(r, 7777, 5432))

    def test_comma_lists_and_ranges(self):
        r = "-A DOCKER-USER -p tcp -m multiport --dports 80,443,8000:8002 -j DROP"
        self.assertTrue(all(self.covers(r, p) for p in (80, 443, 8001)))
        self.assertFalse(self.covers(r, 8003))

    def test_the_default_rule_set_text_is_harmless(self):
        self.assertEqual(core.parse_drop_rules("-N DOCKER-USER\n-A DOCKER-USER -j RETURN\n"), [])
        self.assertEqual(core.parse_drop_rules(""), [])

    def test_unreadable_chain_credits_nothing(self):
        c = core.Ctx()
        c._docker_user = ""
        c._ext_ifaces = ["eth0"]
        self.assertFalse(c.docker_user_drops(80))


if __name__ == "__main__":
    unittest.main()
