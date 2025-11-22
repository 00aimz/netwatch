import json
import tempfile
import unittest
from unittest import mock

import netwatch
import netwatch_scan
from netwatch_scan import HostResult, TargetParseError


class ParseTargetsTests(unittest.TestCase):
    def test_parse_cidr(self):
        hosts = netwatch_scan.parse_targets("192.168.1.0/30")
        self.assertEqual(hosts, ["192.168.1.1", "192.168.1.2"])

    def test_parse_range(self):
        hosts = netwatch_scan.parse_targets("10.0.0.1-10.0.0.3")
        self.assertEqual(hosts, ["10.0.0.1", "10.0.0.2", "10.0.0.3"])

    def test_parse_invalid(self):
        with self.assertRaises(TargetParseError):
            netwatch_scan.parse_targets("not_an_ip")


class ScanNetworkSchedulingTests(unittest.TestCase):
    def test_workers_value_used(self):
        submitted = []

        class DummyExecutor:
            def __init__(self, max_workers):
                self.max_workers = max_workers

            def submit(self, fn, *args, **kwargs):
                future = mock.Mock()
                future.result.return_value = HostResult(ip="10.0.0.1", latency_ms=1.0, open_ports=[])
                submitted.append(self.max_workers)
                return future

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with mock.patch("netwatch_scan.ThreadPoolExecutor", DummyExecutor), mock.patch(
            "netwatch_scan.as_completed", lambda futures: futures
        ), mock.patch("netwatch_scan.parse_targets", return_value=["10.0.0.1"]):
            results = netwatch_scan.scan_network("10.0.0.1", workers=3)

        self.assertEqual(submitted, [3])
        self.assertEqual(len(results), 1)


class JSONSerializationTests(unittest.TestCase):
    def test_json_output(self):
        sample_results = [HostResult(ip="192.168.0.10", latency_ms=5.0, open_ports=[80, 443])]
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            path = tmp.name

        with mock.patch("netwatch.scan_network", return_value=sample_results):
            exit_code = netwatch.main(["192.168.0.0/30", "--json", path, "--summary"])
        self.assertEqual(exit_code, 0)

        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        self.assertEqual(payload, [{"ip": "192.168.0.10", "latency_ms": 5.0, "open_ports": [80, 443]}])

    def test_invalid_input_exit_code(self):
        with mock.patch("netwatch.scan_network", side_effect=TargetParseError("bad")):
            code = netwatch.main(["bad_range"])
        self.assertEqual(code, 1)


class PortParsingTests(unittest.TestCase):
    def test_parse_port_list(self):
        ports = netwatch.parse_port_list("22, 80,443")
        self.assertEqual(ports, [22, 80, 443])

    def test_parse_port_list_invalid(self):
        exit_code = netwatch.main(["192.168.1.0/30", "--ports", "invalid"])
        self.assertEqual(exit_code, 1)


if __name__ == "__main__":
    unittest.main()
