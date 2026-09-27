import contextlib
import io
import ipaddress
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, MagicMock
from urllib.error import HTTPError
from urllib.parse import parse_qs, unquote, urlsplit

import ip_quality as iq
from scripts.build_launcher import build, ROOT


class InputTests(unittest.TestCase):
    def run_cli(self, args, stdin="", provider=None):
        output, errors = io.StringIO(), io.StringIO()
        provider = provider or {"name": "IPinfo", "status": "ok", "info": {"country": "US"},
                                "scores": {}, "factors": {}}
        with patch("sys.stdin", io.StringIO(stdin)), contextlib.redirect_stdout(output), \
                contextlib.redirect_stderr(errors), patch.object(iq, "query_provider", return_value=provider):
            result = iq.main(args)
        return result, output.getvalue(), errors.getvalue()

    def test_valid_and_invalid_addresses(self):
        for value in ("1.1.1.1", "2606:4700:4700::1111", " 8.8.8.8 ", "::ffff:1.1.1.1"):
            self.assertIsInstance(iq.validate_ip(value), (ipaddress.IPv4Address, ipaddress.IPv6Address))
        for value in ("host.example", "1.2.3.999", "1.2.3.4;echo bad", "1.2.3.4/24",
                      "fe80::1%eth0", "2001:::1", "", "01.2.3.4"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                iq.validate_ip(value)

    def test_manual_input_never_discovers_local_ip(self):
        with patch.object(iq, "detect_local_ips") as detect:
            code, output, _ = self.run_cli(["--json", "--no-dnsbl"], "1.1.1.1\n")
        detect.assert_not_called()
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)["reports"][0]["target_ip"], "1.1.1.1")

    def test_empty_enter_detects_both_local_families(self):
        addresses = [iq.validate_ip(ip) for ip in ("8.8.8.8", "2606:4700:4700::1111")]
        with patch.object(iq, "detect_local_ips", return_value=(addresses, [])) as detect:
            code, output, _ = self.run_cli(["--json", "--no-dnsbl"], "\n")
        detect.assert_called_once()
        bundle = json.loads(output)
        self.assertEqual(code, 0)
        self.assertEqual(bundle["mode"], "local_public_ip")
        self.assertEqual([report["target_ip"] for report in bundle["reports"]], list(map(str, addresses)))

    def test_invalid_interactive_input_can_be_retried(self):
        code, output, errors = self.run_cli(["-j", "--no-dnsbl"], "nope\n1.1.1.1\n")
        self.assertEqual(code, 0)
        self.assertIn("Invalid", errors)
        self.assertEqual(json.loads(output)["reports"][0]["target_ip"], "1.1.1.1")

    def test_eof_does_not_implicitly_query_local_ip(self):
        with patch.object(iq, "detect_local_ips") as detect, self.assertRaises(SystemExit) as error:
            self.run_cli([], "")
        self.assertEqual(error.exception.code, 2)
        detect.assert_not_called()

    def test_invalid_arguments_make_no_requests(self):
        for args in (["bad"], ["--local", "1.1.1.1"], ["--timeout", "nan"],
                     ["-i", "1.1.1.1", "8.8.8.8"], ["--timeout", "0"]):
            with self.subTest(args=args), patch.object(iq, "fetch_json") as fetch, self.assertRaises(SystemExit):
                self.run_cli(args)
            fetch.assert_not_called()

    def test_local_file_is_valid_json_and_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "report space.json"
            code, _, _ = self.run_cli(["1.1.1.1", "--no-dnsbl", "-o", str(destination)])
            self.assertEqual(code, 0)
            first = destination.read_bytes()
            self.assertEqual(json.loads(first)["reports"][0]["target_ip"], "1.1.1.1")
            with self.assertRaises(SystemExit), patch.object(iq, "fetch_json") as fetch:
                self.run_cli(["8.8.8.8", "-o", str(destination)])
            fetch.assert_not_called()
            self.assertEqual(destination.read_bytes(), first)

    def test_all_unavailable_returns_failure(self):
        provider = {"name": "IPinfo", "status": "unavailable", "error": "HTTP 403",
                    "info": {}, "factors": {}, "scores": {}}
        code, output, _ = self.run_cli(["1.1.1.1", "--no-dnsbl", "-j"], provider=provider)
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(output)["reports"][0]["status"], "unavailable")


class ProviderTests(unittest.TestCase):
    def test_unknown_is_not_false_or_zero(self):
        self.assertIsNone(iq.score(None))
        self.assertEqual(iq.score(0), 0)
        self.assertIsNone(iq.score("nan"))
        self.assertIsNone(iq.score(True))
        self.assertIsNone(iq.any_flag(False, None))
        self.assertIs(iq.any_flag(False, False), False)
        for name in iq.PROVIDER_NAMES:
            result = iq.normalize(name, {})
            self.assertTrue(all(value is None for section in result.values() for value in section.values()))

    def test_each_provider_mapping(self):
        cases = {
            "MaxMind": ({"ASN": {"AutonomousSystemNumber": 13335}}, "info", "asn", 13335),
            "IPinfo": ({"data": {"privacy": {"hosting": True}}}, "factors", "hosting", True),
            "Scamalytics": ({"scamalytics": {"scamalytics_score": 42}}, "scores", "fraud_score_0_100", 42),
            "ipapi": ({"company": {"abuser_score": "0.1 (High)"}}, "scores", "company_abuse_ratio", "0.1 (High)"),
            "AbuseIPDB": ({"data": {"abuseConfidenceScore": 0}}, "scores", "abuse_confidence_0_100", 0),
            "IP2Location": ({"proxy": {"is_vpn": True}}, "factors", "vpn", True),
            "ipdata": ({"threat": {"is_known_attacker": True}}, "factors", "abuser", True),
            "IPQS": ({"bot_status": False}, "factors", "bot", False),
        }
        for name, (data, section, key, expected) in cases.items():
            with self.subTest(name=name):
                self.assertEqual(iq.normalize(name, data)[section][key], expected)

    def test_ipv6_is_passed_as_query_data_not_network_interface(self):
        target = "2606:4700:4700::1111"
        urls = []
        def fake_fetch(url, timeout):
            urls.append(url)
            return {"data": {"ip": target, "country": "US"}}
        with patch.object(iq, "fetch_json", side_effect=fake_fetch):
            result = iq.collect_report(iq.validate_ip(target), dnsbl=True)
        self.assertEqual(result["target_ip"], target)
        self.assertTrue(all(target in unquote(url) for url in urls))
        self.assertEqual(result["skipped"]["dnsbl"], "ipv4_only")

    def test_wrong_target_and_empty_response_rejected(self):
        for data in ({"data": {"ip": "8.8.8.8", "country": "US"}}, {"notice": "limit"}):
            with patch.object(iq, "fetch_json", return_value=data):
                result = iq.query_provider("IPinfo", "1.1.1.1", "cn", 1)
            self.assertEqual(result["status"], "unavailable")

    def test_ipapi_fallback_does_not_invent_security_data(self):
        with patch.object(iq, "fetch_json", side_effect=[iq.QueryError("HTTP 403"),
                {"ip": "1.1.1.1", "asn": "AS13335", "company": "Cloudflare"}]):
            result = iq.query_provider("ipapi", "1.1.1.1", "cn", 1)
        self.assertEqual(result["status"], "ok")
        self.assertIsNone(result["factors"]["vpn"])
        self.assertEqual(result["scores"], {})

    def test_non_public_targets_do_not_leave_machine(self):
        for target in ("127.0.0.1", "192.168.1.1", "::1", "fe80::1", "224.0.0.1", "ff02::1", "100.64.0.1"):
            with self.subTest(target=target), patch.object(iq, "fetch_json") as fetch:
                result = iq.collect_report(iq.validate_ip(target))
            fetch.assert_not_called()
            self.assertEqual(result["status"], "not_applicable")

    def test_local_detection_single_stack_and_failure(self):
        def single_stack(url, timeout):
            if "api4" in url:
                return {"ip": "8.8.8.8"}
            raise iq.QueryError("IPv6 unavailable")
        with patch.object(iq, "fetch_json", side_effect=single_stack):
            addresses, errors = iq.detect_local_ips(1)
        self.assertEqual(list(map(str, addresses)), ["8.8.8.8"])
        self.assertEqual(len(errors), 1)
        with patch.object(iq, "fetch_json", side_effect=iq.QueryError("offline")), self.assertRaises(iq.QueryError):
            iq.detect_local_ips(1)

    def test_terminal_text_has_no_control_characters(self):
        self.assertNotIn("\x1b", iq.safe_text("\x1b[2Jhello\nworld"))


class NetworkTests(unittest.TestCase):
    def test_every_outbound_request_is_get_without_report_payload(self):
        requests = []
        def open_request(request, timeout):
            requests.append(request)
            response = MagicMock()
            response.__enter__.return_value.read.return_value = b'{"data":{"ip":"1.1.1.1","country":"AU"}}'
            return response
        with patch.object(iq, "build_opener") as opener:
            opener.return_value.open.side_effect = open_request
            report = iq.collect_report(iq.validate_ip("1.1.1.1"))
        self.assertFalse(report["upload_enabled"])
        self.assertGreater(len(requests), 8)
        allowed_hosts = {"ipinfo.check.place", "ipinfo.io", "api.ipapi.is", "dns.google"}
        for request in requests:
            self.assertEqual(request.get_method(), "GET")
            self.assertIsNone(request.data)
            self.assertIn(urlsplit(request.full_url).hostname, allowed_hosts)
            self.assertNotIn("report", request.full_url)

    def test_http_error_and_bad_json_are_query_failures(self):
        with patch.object(iq, "build_opener") as opener:
            opener.return_value.open.side_effect = HTTPError("https://example.test", 403, "Forbidden", {}, None)
            with self.assertRaisesRegex(iq.QueryError, "HTTP 403"):
                iq.fetch_json("https://example.test", 1)
        with patch.object(iq, "build_opener") as opener:
            opener.return_value.open.return_value.__enter__.return_value.read.return_value = b'<html>blocked</html>'
            with self.assertRaises(iq.QueryError):
                iq.fetch_json("https://example.test", 1)

    def test_redirects_are_not_followed(self):
        self.assertIsNone(iq.NoRedirect().redirect_request(None, None, 302, "", {}, "https://example.test"))

    def test_dnsbl_error_codes_and_servfail_are_unknown(self):
        for data in ({"Status": 2}, {"Status": 0, "Answer": [{"type": 1, "data": "127.255.255.254"}]}):
            with patch.object(iq, "fetch_json", return_value=data):
                result = iq.query_dnsbl("zen.spamhaus.org", "1.1.1.1", 1)
            self.assertEqual(result["status"], "unavailable")

    def test_dnsbl_failed_positive_control_is_not_clean(self):
        with patch.object(iq, "fetch_json", return_value={"Status": 3}):
            result = iq.query_dnsbl("zen.spamhaus.org", "1.1.1.1", 1)
        self.assertEqual(result["status"], "unavailable")

    def test_dnsbl_uses_reversed_target_after_controls(self):
        urls = []
        def answer(url, timeout):
            name = parse_qs(urlsplit(url).query)["name"][0]
            urls.append(name)
            if name.startswith("1.0.0.127."):
                return {"Status": 3}
            return {"Status": 0, "Answer": [{"type": 1, "data": "127.0.0.2"}]}
        with patch.object(iq, "fetch_json", side_effect=answer):
            result = iq.query_dnsbl("bl.spamcop.net", "1.2.3.4", 1)
        self.assertEqual(result["status"], "listed")
        self.assertEqual(urls[-1], "4.3.2.1.bl.spamcop.net")

    def test_launcher_contains_current_source_and_no_remote_loader(self):
        self.assertEqual((ROOT / "NodeQuality.sh").read_text(encoding="utf-8"), build())
        self.assertNotIn("curl -", build())


if __name__ == "__main__":
    unittest.main()
