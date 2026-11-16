#!/usr/bin/env python3
"""Offline integration tests using synthetic DNS, TLS and HTTP packet captures.

Python standard library only. No real service names or captured user traffic.
"""
import ipaddress
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
ZEEK = os.environ.get("ZEEK", "zeek")


def u16(n):
    return struct.pack("!H", n)


def checksum(data):
    data += b"\0" * (len(data) % 2)
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return ~total & 65535


class Capture:
    def __init__(self):
        self.packets = []
        self.flow = 0

    def packet(self, payload, proto, reverse=False):
        a, b = map(lambda x: ipaddress.ip_address(x).packed,
                   ("192.0.2.10", "198.51.100.20"))
        if reverse:
            a, b = b, a
        if proto == 6:
            pseudo = a + b + struct.pack("!BBH", 0, 6, len(payload))
            payload = payload[:16] + u16(checksum(pseudo + payload)) + payload[18:]
        header = struct.pack("!BBHHHBBH4s4s", 69, 0, 20 + len(payload),
                             len(self.packets), 0, 64, proto, 0, a, b)
        header = header[:10] + u16(checksum(header)) + header[12:]
        self.packets.append(bytes.fromhex("00112233445566778899aabb0800") + header + payload)

    def tcp(self, chunks, port):
        self.flow += 1
        seq = [100, 900]
        ports = [40000 + self.flow, port]

        def send(direction, payload=b"", flags=24):
            tcp = struct.pack("!HHIIBBHHH", ports[direction], ports[1-direction],
                              seq[direction], seq[1-direction] if flags & 16 else 0,
                              80, flags, 65535, 0, 0) + payload
            self.packet(tcp, 6, bool(direction))
            seq[direction] += len(payload) + bool(flags & 3)

        send(0, flags=2)
        send(1, flags=18)
        send(0, flags=16)
        for direction, payload in chunks:
            send(direction, payload)
            send(1-direction, flags=16)
        send(0, flags=17)
        send(1, flags=17)
        send(0, flags=16)

    def dns(self, hostname, rcode=0, response_only=False):
        self.flow += 1
        question = b"".join(bytes([len(label)]) + label.encode()
                            for label in hostname.rstrip(".").split(".")) + b"\0\0\1\0\1"
        for reverse in ([True] if response_only else [False, True]):
            message = struct.pack("!HHHHHH", self.flow,
                                  (0x8180 | rcode) if reverse else 0x0100,
                                  1, 0, 0, 0) + question
            ports = (53, 41000 + self.flow) if reverse else (41000 + self.flow, 53)
            self.packet(struct.pack("!HHHH", *ports, 8 + len(message), 0) + message,
                        17, reverse)

    def http(self, host="agent.example.invalid", path="/", ua=None):
        request = b"GET " + path.encode() + b" HTTP/1.1\r\n"
        if host is not None:
            request += b"Host: " + host.encode() + b"\r\n"
        if ua is not None:
            request += b"User-Agent: " + ua.encode() + b"\r\n"
        self.tcp([(0, request + b"\r\n"),
                  (1, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")], 80)

    def tls(self, hostname=None, segmented=False):
        extensions = b""
        if hostname is not None:
            name = hostname.encode()
            names = b"\0" + u16(len(name)) + name
            sni = u16(len(names)) + names
            extensions = b"\0\0" + u16(len(sni)) + sni
        hello = (b"\x03\x03" + bytes(range(32)) + b"\0\0\2\0\x2f\1\0"
                 + u16(len(extensions)) + extensions)
        handshake = b"\1" + len(hello).to_bytes(3, "big") + hello
        record = b"\x16\x03\x01" + u16(len(handshake)) + handshake
        chunks = [(0, record[:7]), (0, record[7:])] if segmented else [(0, record)]
        self.tcp(chunks, 443)

    def bytes(self):
        output = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        for i, packet in enumerate(self.packets):
            output += struct.pack("<IIII", 1700000000 + i // 1000,
                                  (i % 1000) * 1000, len(packet), len(packet)) + packet
        return output


def run(capture, config=""):
    with tempfile.TemporaryDirectory(prefix="muse-detector-") as name:
        tmp = Path(name)
        (tmp / "package").symlink_to(ROOT / "scripts", target_is_directory=True)
        (tmp / "input.pcap").write_bytes(capture.bytes())
        (tmp / "local.zeek").write_text(
            '@load ./package\nredef LogAscii::use_json = T;\n' + config)
        proc = subprocess.run([ZEEK, "-r", "input.pcap", "local.zeek"],
                              cwd=tmp, text=True, capture_output=True)
        logs = {p.stem: [json.loads(line) for line in p.read_text().splitlines()]
                for p in tmp.glob("*.log")}
        return proc, logs


def rule(sources="DNS_Query, TLS_Server_Name, HTTP_Request", extra="", domain="agent.example.invalid"):
    sources = ", ".join("MuseDetector::" + x.strip() for x in sources.split(","))
    return ('redef MuseDetector::indicators += { ["test-rule"] = '
            f'[$domain="{domain}", $sources=set({sources}){extra}] }};\n')


class DetectorTests(unittest.TestCase):
    def check_run(self, capture, config, count):
        proc, logs = run(capture, config)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        errors = [x for x in logs.get("reporter", []) if x.get("level") == "Reporter::ERROR"]
        self.assertFalse(errors, errors)
        self.assertEqual(len(logs.get("muse", [])), count, logs)
        return logs

    def test_empty_ruleset_is_inactive_and_warns(self):
        c = Capture()
        c.dns("agent.example.invalid")
        c.tls("agent.example.invalid")
        c.http()
        proc, logs = run(c)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse(logs.get("muse"))
        self.assertIn("no active indicators", proc.stderr + str(logs.get("reporter")))

    def test_dns_query_and_failed_lookup_are_evidence_only(self):
        c = Capture()
        c.dns("AGENT.EXAMPLE.INVALID")
        c.dns("agent.example.invalid", rcode=3)
        logs = self.check_run(c, rule(), 2)
        self.assertEqual([x["dns_rcode"] for x in logs["muse"]], [0, 3])
        self.assertTrue(all(x["assessment"] == "possible_muse_activity" for x in logs["muse"]))
        self.assertTrue(all(x["hostname"] == "agent.example.invalid" for x in logs["muse"]))
        self.assertFalse(logs.get("notice"))

    def test_dns_reply_without_query_is_not_client_lookup(self):
        c = Capture()
        c.dns("agent.example.invalid", response_only=True)
        self.check_run(c, rule(), 0)

    def test_exact_domain_and_label_boundary(self):
        c = Capture()
        for host in ("agent.example.invalid", "sub.agent.example.invalid",
                     "evilagent.example.invalid", "agent.example.invalid.evil.invalid"):
            c.dns(host)
        self.check_run(c, rule(), 1)
        self.check_run(c, rule(extra=", $include_subdomains=T"), 2)

    def test_tls_segmented_clienthello_and_missing_sni(self):
        c = Capture()
        c.tls("AGENT.EXAMPLE.INVALID.", segmented=True)
        c.tls("www.facebook.com")
        c.tls()
        logs = self.check_run(c, rule("TLS_Server_Name"), 1)
        self.assertFalse(logs["muse"][0]["tls_established"])
        self.assertEqual(logs["muse"][0]["evidence"], "MuseDetector::TLS_Server_Name")
        matching_ssl = [x for x in logs["ssl"] if x.get("server_name") == "AGENT.EXAMPLE.INVALID."]
        self.assertEqual(logs["muse"][0]["uid"], matching_ssl[0]["uid"])

    def test_source_restriction(self):
        c = Capture()
        c.dns("agent.example.invalid")
        c.http()
        self.check_run(c, rule("TLS_Server_Name"), 0)

    def test_http_host_normalization_and_missing_host(self):
        c = Capture()
        c.http("AGENT.EXAMPLE.INVALID.:80")
        c.http(None)
        logs = self.check_run(c, rule("HTTP_Request"), 1)
        self.assertEqual(logs["muse"][0]["http_status_code"], 200)

    def test_http_requires_domain_path_and_exact_user_agent(self):
        c = Capture()
        for host, path, ua in (
            ("agent.example.invalid", "/api/agent/run?secret=TOKEN", "Lab/1.0"),
            ("agent.example.invalid", "/api/agent/run", "Other/1.0"),
            ("agent.example.invalid", "/api/agent/run", None),
            ("agent.example.invalid", "/api/agents/", "Lab/1.0"),
            ("agent.example.invalid", "/?next=/api/agent/", "Lab/1.0"),
            ("agent.example.invalid.evil.invalid", "/api/agent/run", "Lab/1.0"),
        ):
            c.http(host, path, ua)
        config = rule("HTTP_Request", ', $http_path_prefix="/api/agent/", $http_user_agent="Lab/1.0"')
        logs = self.check_run(c, config, 1)
        self.assertNotIn("TOKEN", json.dumps(logs["muse"]))
        self.assertNotIn("Lab/1.0", json.dumps(logs["muse"]))

    def test_shared_meta_traffic_is_not_an_indicator(self):
        c = Capture()
        for host in ("www.facebook.com", "graph.facebook.com", "www.instagram.com", "meta.ai"):
            c.dns(host)
            c.tls(host)
            c.http(host)
        self.check_run(c, rule(), 0)

    def test_notice_suppression_preserves_evidence_rows(self):
        c = Capture()
        c.http()
        c.http()
        logs = self.check_run(c, rule("HTTP_Request") + "redef MuseDetector::enable_notices=T;\n", 2)
        self.assertEqual(len(logs.get("notice", [])), 1, logs)

    def test_rule_labels_are_explicit_not_inferred(self):
        c = Capture()
        c.http()
        logs = self.check_run(c, rule("HTTP_Request"), 1)
        self.assertEqual(logs["muse"][0]["access_context"], "MuseDetector::Unknown")
        extra = ", $access_context=MuseDetector::Standalone_App, $status=MuseDetector::Capture_Validated"
        logs = self.check_run(c, rule("HTTP_Request", extra), 1)
        self.assertEqual(logs["muse"][0]["access_context"], "MuseDetector::Standalone_App")
        self.assertEqual(logs["muse"][0]["assessment"], "possible_muse_activity")
        facebook = extra.replace("Standalone_App", "Facebook")
        logs = self.check_run(c, rule("HTTP_Request", facebook), 1)
        self.assertEqual(logs["muse"][0]["access_context"], "MuseDetector::Facebook")

    def test_invalid_configuration_fails_closed(self):
        c = Capture()
        c.dns("agent.example.invalid")
        c.http()
        configs = [rule(domain=x) for x in ("", "*.example.invalid", "https://agent.example.invalid",
                   "example..invalid", "192.0.2.1", "-agent.example.invalid")]
        configs += [rule(extra=', $http_path_prefix="/api/"'),
                    rule("HTTP_Request", ', $http_path_prefix=""'),
                    rule("HTTP_Request", ', $http_path_prefix="/?token="'),
                    rule("HTTP_Request", ', $http_user_agent=""')]
        for config in configs:
            with self.subTest(config=config):
                proc, logs = run(c, config)
                self.assertFalse(logs.get("muse"), logs)
                self.assertIn("invalid indicator configuration", proc.stderr + str(logs.get("reporter")))


if __name__ == "__main__":
    unittest.main(verbosity=2)
