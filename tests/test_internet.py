"""--internet check: parsers + run() with all network calls mocked."""
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import core  # noqa: E402
from checks import internet  # noqa: E402

BASE = "http://router.local:5000"
DESC = """<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device><deviceList><device>
<serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
<controlURL>/ctl/IPConn</controlURL></service></serviceList></device></deviceList></device></root>"""
SOAP = """<s:Envelope><s:Body><u:GetGenericPortMappingEntryResponse><NewRemoteHost></NewRemoteHost>
<NewExternalPort>11434</NewExternalPort><NewProtocol>TCP</NewProtocol><NewInternalPort>11434</NewInternalPort>
<NewInternalClient>192.168.1.10</NewInternalClient><NewEnabled>1</NewEnabled>
<NewPortMappingDescription>ollama</NewPortMappingDescription></u:GetGenericPortMappingEntryResponse></s:Body></s:Envelope>"""


def ctx():
    c = core.Ctx()
    c._listeners = []
    c._lan_ip = "192.168.1.10"
    return c


class Parsers(unittest.TestCase):
    def test_internetdb(self):
        ports, hits, vulns = internet.parse_internetdb({"ports": [22, 11434, 443], "vulns": ["CVE-2024-1"]}, {11434})
        self.assertEqual((ports, hits, vulns), ([22, 443, 11434], [11434], ["CVE-2024-1"]))

    def test_control_url(self):
        self.assertEqual(internet.control_url(DESC, BASE), BASE + "/ctl/IPConn")
        self.assertIsNone(internet.control_url("<notxml", BASE))

    def test_parse_mapping(self):
        m = internet.parse_mapping(SOAP)
        self.assertEqual((m["ext"], m["internal"], m["host"], m["desc"]), (11434, 11434, "192.168.1.10", "ollama"))
        self.assertIsNone(internet.parse_mapping("<s:Envelope><s:Body/></s:Envelope>"))


class Run(unittest.TestCase):
    def test_shodan_llm_port_and_upnp_forward_are_critical(self):
        with mock.patch.object(internet, "public_ip", return_value="203.0.113.5"), \
             mock.patch.object(internet, "internetdb", return_value={"ports": [11434, 22], "vulns": []}), \
             mock.patch.object(internet, "upnp_mappings", return_value=[internet.parse_mapping(SOAP)]):
            f = internet.run(ctx())
        self.assertEqual([x.severity for x in f], ["CRITICAL", "CRITICAL"])
        self.assertIn("11434", f[0].title)
        self.assertIn("192.168.1.10:11434", f[1].title)

    def test_clean(self):
        with mock.patch.object(internet, "public_ip", return_value="203.0.113.5"), \
             mock.patch.object(internet, "internetdb", return_value={"ports": []}), \
             mock.patch.object(internet, "upnp_mappings", return_value=[]):
            f = internet.run(ctx())
        self.assertEqual([x.severity for x in f], ["OK", "OK"])

    def test_offline(self):
        with mock.patch.object(internet, "public_ip", return_value=None):
            self.assertEqual(internet.run(ctx())[0].severity, "INFO")


if __name__ == "__main__":
    unittest.main()
