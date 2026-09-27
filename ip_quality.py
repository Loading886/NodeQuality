#!/usr/bin/env python3
"""IP-only NodeQuality. Reports stay local; all network requests are lookups.

Provider field mappings follow xykt/IPQuality v2026-09-16 (AGPL-3.0).
This modified implementation always queries explicit target addresses.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from http.client import HTTPException
import ipaddress
import json
import math
from pathlib import Path
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener


class QueryError(Exception):
    """An unavailable response, never a clean bill of health."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch_json(url, timeout):
    request = Request(url, headers={"User-Agent": "NodeQuality-IP/1.0",
                                    "Accept": "application/json"}, method="GET")
    try:
        with build_opener(NoRedirect).open(request, timeout=timeout) as response:
            payload = response.read(2 * 1024 * 1024 + 1)
        if len(payload) > 2 * 1024 * 1024:
            raise QueryError("response too large")
        data = json.loads(payload)
    except HTTPError as exc:
        raise QueryError(f"HTTP {exc.code}") from exc
    except (URLError, OSError, ValueError, HTTPException) as exc:
        raise QueryError("network timeout/error or invalid JSON") from exc
    if not isinstance(data, dict) or not data:
        raise QueryError("empty or invalid response")
    if data.get("error") or data.get("errors") or data.get("success") is False:
        raise QueryError("provider rejected the query")
    return data


def get(data, path):
    for key in path.split("."):
        if not isinstance(data, dict):
            return None
        data = data.get(key)
    if data is None or data == "" or data == "null":
        return None
    return data if isinstance(data, (str, bool, int, float)) else None


def flag(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in ("true", "false"):
        return value.lower() == "true"
    return None


def any_flag(*values):
    values = [flag(value) for value in values]
    if True in values:
        return True
    return False if values and all(value is False for value in values) else None


def score(value):
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) and 0 <= number <= 100 else None


def validate_ip(value):
    value = value.strip()
    if "%" in value:
        raise ValueError("请输入完整 IPv4/IPv6 地址，不支持接口后缀 / IP address only")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError("IP 地址格式无效 / Invalid IPv4 or IPv6 address") from exc
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return address


def public_ip(address):
    return address.is_global and not address.is_multicast


def detect_local_ips(timeout):
    """Probe each family independently; never substitute one for the other."""
    def detect(version):
        try:
            data = fetch_json(f"https://api{version}.ipify.org?format=json", timeout)
            address = validate_ip(str(data.get("ip", "")))
            if address.version != version or not public_ip(address):
                raise QueryError("unexpected IP address")
            return address, None
        except (QueryError, ValueError) as exc:
            return None, f"IPv{version}: {exc}"
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(detect, (4, 6)))
    addresses = [address for address, _ in results if address is not None]
    errors = [error for _, error in results if error is not None]
    if not addresses:
        raise QueryError("无法识别本机公网 IP，请手动输入 / Could not detect a public IP: " + "; ".join(errors))
    return addresses, errors


PROVIDER_NAMES = ("MaxMind", "IPinfo", "Scamalytics", "ipapi",
                  "AbuseIPDB", "IP2Location", "ipdata", "IPQS")
DATABASES = {"Scamalytics": "scamalytics", "ipapi": "ipapi",
             "AbuseIPDB": "abuseipdb", "IP2Location": "ip2location",
             "ipdata": "ipdata", "IPQS": "ipqualityscore"}
FACTOR_NAMES = ("proxy", "vpn", "tor", "hosting", "abuser", "bot")


def provider_url(name, target, language):
    target_path = quote(target, safe=":")
    if name == "IPinfo":
        return f"https://ipinfo.io/widget/demo/{target_path}"
    query = {"lang": language} if name == "MaxMind" else {"db": DATABASES[name]}
    return f"https://ipinfo.check.place/{target_path}?{urlencode(query)}"


def normalize(name, data):
    """Keep source values independent. Missing flags and scores stay null."""
    info, factors, scores = {}, {}, {}
    info_paths, factor_paths = {}, {}
    if name == "MaxMind":
        info_paths = {"country": "City.Country.Name", "city": "City.Name",
                      "asn": "ASN.AutonomousSystemNumber",
                      "organization": "ASN.AutonomousSystemOrganization",
                      "timezone": "City.Location.TimeZone"}
    elif name == "IPinfo":
        info_paths = {"country": "data.country", "region": "data.region",
                      "city": "data.city", "asn": "data.asn.asn",
                      "organization": "data.asn.name", "usage_type": "data.asn.type",
                      "company_type": "data.company.type", "timezone": "data.timezone"}
        factor_paths = {key: f"data.privacy.{key}" for key in ("proxy", "vpn", "tor", "hosting")}
    elif name == "Scamalytics":
        info_paths = {"country": "external_datasources.maxmind_geolite2.ip_country_code"}
        factor_paths = {"proxy": "external_datasources.firehol.is_proxy",
                        "vpn": "scamalytics.scamalytics_proxy.is_vpn",
                        "tor": "external_datasources.x4bnet.is_tor",
                        "hosting": "scamalytics.scamalytics_proxy.is_datacenter",
                        "abuser": "scamalytics.is_blacklisted_external"}
        factors["bot"] = any_flag(*(get(data, path) for path in (
            "external_datasources.x4bnet.is_blacklisted_spambot",
            "external_datasources.x4bnet.is_bot_operamini",
            "external_datasources.x4bnet.is_bot_semrush")))
        scores["fraud_score_0_100"] = score(get(data, "scamalytics.scamalytics_score"))
    elif name == "ipapi":
        info_paths = {"country": "location.country", "region": "location.state",
                      "city": "location.city", "asn": "asn.asn",
                      "organization": "asn.org", "usage_type": "asn.type",
                      "company_type": "company.type", "timezone": "location.timezone"}
        factor_paths = {"proxy": "is_proxy", "vpn": "is_vpn", "tor": "is_tor",
                        "hosting": "is_datacenter", "abuser": "is_abuser", "bot": "is_crawler"}
        value = get(data, "company.abuser_score")
        # A company's abuse ratio is not an individual IP's fraud score.
        if isinstance(value, str) and re.fullmatch(r"[01](?:\.\d+)?(?: \([^\n]*\))?", value):
            if float(value.split()[0]) <= 1:
                scores["company_abuse_ratio"] = value
        # The anonymous official API returns a smaller, flat response.
        if isinstance(data.get("asn"), str):
            info_paths = {key: key for key in ("country", "region", "city", "asn", "timezone")}
            info_paths["organization"] = "company"
    elif name == "AbuseIPDB":
        info_paths = {"country": "data.countryCode", "usage_type": "data.usageType",
                      "organization": "data.isp"}
        factor_paths = {"tor": "data.isTor"}
        scores["abuse_confidence_0_100"] = score(get(data, "data.abuseConfidenceScore"))
    elif name == "IP2Location":
        info_paths = {"country": "country_code", "usage_type": "usage_type",
                      "company_type": "as_info.as_usage_type"}
        factor_paths = {"vpn": "proxy.is_vpn", "tor": "proxy.is_tor",
                        "hosting": "proxy.is_data_center", "abuser": "proxy.is_spammer"}
        factors["proxy"] = any_flag(*(get(data, path) for path in (
            "is_proxy", "proxy.is_public_proxy", "proxy.is_web_proxy")))
        factors["bot"] = any_flag(*(get(data, path) for path in (
            "proxy.is_web_crawler", "proxy.is_scanner", "proxy.is_botnet")))
        scores["fraud_score_0_100"] = score(get(data, "fraud_score"))
    elif name == "ipdata":
        info_paths = {"country": "country_code"}
        factor_paths = {"proxy": "threat.is_proxy", "tor": "threat.is_tor",
                        "hosting": "threat.is_datacenter"}
        factors["abuser"] = any_flag(*(get(data, path) for path in (
            "threat.is_threat", "threat.is_known_abuser", "threat.is_known_attacker")))
    elif name == "IPQS":
        info_paths = {"country": "country_code"}
        factor_paths = {"proxy": "proxy", "vpn": "vpn", "tor": "tor",
                        "abuser": "recent_abuse", "bot": "bot_status"}
        scores["fraud_score_0_100"] = score(get(data, "fraud_score"))
    info.update({key: get(data, path) for key, path in info_paths.items()})
    factors.update({key: flag(get(data, path)) for key, path in factor_paths.items()})
    return {"info": info, "factors": factors, "scores": scores}


def query_provider(name, target, language, timeout):
    urls = [provider_url(name, target, language)]
    if name == "ipapi":
        urls.append("https://api.ipapi.is/?" + urlencode({"q": target}))
    errors = []
    for url in urls:
        try:
            data = fetch_json(url, timeout)
            returned_ip = get(data, "data.ip") if name == "IPinfo" else (
                get(data, "data.ipAddress") or get(data, "ip") or get(data, "ipAddress"))
            if returned_ip is not None:
                try:
                    matches = validate_ip(str(returned_ip)) == validate_ip(target)
                except ValueError:
                    matches = False
                if not matches:
                    raise QueryError("response IP differs from the requested IP")
            result = normalize(name, data)
            if not any(value is not None for section in result.values() for value in section.values()):
                raise QueryError("no recognized data for this IP")
            result.update({"name": name, "status": "ok", "source": url})
            if errors:
                result["fallback_reason"] = "; ".join(errors)
            return result
        except QueryError as exc:
            errors.append(str(exc))
    return {"name": name, "status": "unavailable", "error": "; ".join(errors),
            "info": {}, "factors": {}, "scores": {}}


# Public resolvers may be blocked by DNSBLs: test both controls first.
DNSBL_ZONES = {"zen.spamhaus.org": {f"127.0.0.{n}" for n in (2, 3, 4, 9, 10, 11)},
               "bl.spamcop.net": {"127.0.0.2"}}


def dnsbl_answer(host, codes, timeout):
    data = fetch_json("https://dns.google/resolve?" + urlencode(
        {"name": host, "type": "A", "edns_client_subnet": "0.0.0.0/0"}), timeout)
    if data.get("TC") or data.get("Status") not in (0, 3):
        raise QueryError("DNS failure or truncated response")
    answer = data.get("Answer", [])
    if not isinstance(answer, list) or not all(isinstance(item, dict) for item in answer):
        raise QueryError("invalid DNS answer")
    addresses = [item.get("data") for item in answer if item.get("type") == 1]
    if any(address not in codes for address in addresses):
        raise QueryError("DNSBL refused the resolver or returned an unknown code")
    if data.get("Status") == 3 and answer:
        raise QueryError("inconsistent DNS answer")
    return bool(addresses)


def query_dnsbl(zone, target, timeout):
    try:
        codes = DNSBL_ZONES[zone]
        if not dnsbl_answer("2.0.0.127." + zone, codes, timeout):
            raise QueryError("DNSBL positive control failed; resolver may be blocked")
        if dnsbl_answer("1.0.0.127." + zone, codes, timeout):
            raise QueryError("DNSBL negative control failed")
        reversed_ip = ".".join(reversed(target.split(".")))
        listed = dnsbl_answer(reversed_ip + "." + zone, codes, timeout)
        return {"name": zone, "status": "listed" if listed else "not_listed"}
    except QueryError as exc:
        return {"name": zone, "status": "unavailable", "error": str(exc)}


def collect_report(address, language="cn", timeout=10, dnsbl=True):
    target = str(address)
    report = {"target_ip": target, "ip_version": address.version,
              "generated_at": datetime.now(timezone.utc).isoformat(),
              "upload_enabled": False, "providers": [], "dnsbl": [],
              "skipped": {"media_unlock": "requires_target_egress",
                          "smtp_connectivity": "requires_target_egress",
                          "DB-IP": "upstream_endpoint_uses_requester_ip"}}
    if not public_ip(address):
        report.update({"status": "not_applicable", "reason": "non_public_ip"})
        return report
    # Transport family is independent of the queried IP's address family.
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(query_provider, name, target, language, timeout)
                   for name in PROVIDER_NAMES]
        blacklist_futures = []
        if dnsbl and address.version == 4:
            blacklist_futures = [executor.submit(query_dnsbl, zone, target, timeout)
                                 for zone in DNSBL_ZONES]
        else:
            report["skipped"]["dnsbl"] = "disabled" if not dnsbl else "ipv4_only"
        report["providers"] = [future.result() for future in futures]
        report["dnsbl"] = [future.result() for future in blacklist_futures]
    available = sum(provider["status"] == "ok" for provider in report["providers"])
    report["status"] = "ok" if available == len(PROVIDER_NAMES) else (
        "partial" if available else "unavailable")
    return report


def safe_text(value, unknown="未知"):
    if value is None:
        return unknown
    return "".join(char for char in str(value) if char.isprintable())[:250]


def render_report(report, language="cn"):
    en = language == "en"
    unknown = "Unknown" if en else "未知"
    yes, no = ("Yes", "No") if en else ("是", "否")
    lines = ["=" * 72, "NodeQuality — IP Quality" if en else "NodeQuality — IP 质量查询",
             f"IP: {report['target_ip']} (IPv{report['ip_version']})",
             f"UTC: {report['generated_at']}",
             "Results stay local; no report upload." if en else "报告仅保留在本地，不上传结果。"]
    if report["status"] == "not_applicable":
        lines.append("Non-public address: public reputation queries do not apply; no requests sent."
                     if en else "此地址不属于公网单播 IP，公网信誉查询不适用；未发送外部请求。")
        return "\n".join(lines) + "\n"
    lines.extend(["", "Source availability:" if en else "数据源状态："])
    for provider in report["providers"]:
        state = ("Available" if en else "可用") if provider["status"] == "ok" else (
            ("Unavailable: " if en else "不可用：") + provider["error"])
        if "fallback_reason" in provider:
            state += " (fallback API)" if en else "（使用备用接口）"
        lines.append(f"  {provider['name']}: {state}")
    lines.extend(["", "Basic information and IP type (per source):" if en else "基础信息与 IP 类型（各数据源独立显示）："])
    labels = {"country": "国家/地区", "region": "省/州", "city": "城市", "asn": "ASN",
              "organization": "机构", "usage_type": "使用类型", "company_type": "公司类型",
              "timezone": "时区"}
    for provider in report["providers"]:
        values = [f"{key if en else labels[key]}={safe_text(value, unknown)}"
                  for key, value in provider["info"].items() if value is not None]
        if values:
            lines.append(f"  {provider['name']}: " + "; ".join(values))
    lines.extend(["", "Risk scores (different scales; no combined score):" if en else "风险评分（量表不同，不合并评分）："])
    score_labels = {"fraud_score_0_100": "欺诈评分 0–100",
                    "abuse_confidence_0_100": "滥用置信度 0–100",
                    "company_abuse_ratio": "公司网段滥用比例"}
    for provider in report["providers"]:
        if provider["name"] in ("Scamalytics", "ipapi", "AbuseIPDB", "IP2Location", "IPQS"):
            values = [f"{key if en else score_labels[key]}={safe_text(value, unknown)}"
                      for key, value in provider["scores"].items() if value is not None]
            lines.append(f"  {provider['name']}: " + ("; ".join(values) or unknown))
    lines.extend(["", "Risk factors (Yes / No / Unknown):" if en else "风险因子（是 / 否 / 未知）：",
                  "  Source        Proxy     VPN       Tor       Hosting   Abuser    Bot"])
    for provider in report["providers"]:
        if provider["name"] == "MaxMind":
            continue
        values = [yes if provider["factors"].get(key) is True else
                  no if provider["factors"].get(key) is False else unknown for key in FACTOR_NAMES]
        lines.append(f"  {provider['name']:<14}" + " / ".join(values))
    lines.extend(["", "DNS blacklists (listed / not listed / unavailable):" if en else "DNS 黑名单（列入 / 未列入 / 不可用）："])
    states = {"listed": "列入", "not_listed": "未列入", "unavailable": "不可用"}
    for item in report["dnsbl"]:
        state = item["status"] if en else states[item["status"]]
        lines.append(f"  {item['name']}: {state}" + (f" ({item['error']})" if "error" in item else ""))
    if not report["dnsbl"]:
        lines.append("  Skipped (disabled or IPv6)." if en else "  已跳过（用户禁用或目标为 IPv6）。")
    lines.extend(["", "Media unlock / SMTP connectivity: not applicable; target egress is required."
                  if en else "流媒体解锁 / 邮局连通性：未执行，必须从目标 IP 发起连接才能判断。",
                  "DB-IP: skipped because the original endpoint measures the requester's IP."
                  if en else "DB-IP：原接口仅检测请求出口 IP，已跳过。",
                  "Missing/blocked data is unknown, not low risk. DNSBL results cover only the listed zones."
                  if en else "缺失或被拦截的数据表示未知，不代表低风险；黑名单结果仅覆盖上面列出的库。",
                  "Queries send the target IP to data providers; the assembled report is never sent."
                  if en else "查询会将目标 IP 发送给数据源；生成的整份报告不会发送。", "=" * 72])
    return "\n".join(lines) + "\n"


def timeout_value(value):
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be 1–60 seconds") from exc
    if not math.isfinite(number) or not 1 <= number <= 60:
        raise argparse.ArgumentTypeError("timeout must be 1–60 seconds")
    return number


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(prog="NodeQuality.sh", description="IP 质量查询，结果不上传 / Local IP quality lookup")
    parser.add_argument("ip", nargs="?", help="IPv4 / IPv6；省略时手动输入，回车检测本机")
    parser.add_argument("-i", "--ip", dest="option_ip", help="指定待查询 IP（不是绑定网卡）")
    parser.add_argument("--local", action="store_true", help="直接检测本机公网 IPv4/IPv6")
    parser.add_argument("-o", "--output", type=Path, help="保存到本地文件；.json 为 JSON，否则为纯文本")
    parser.add_argument("-j", "--json", action="store_true", help="输出 JSON")
    parser.add_argument("-E", "-e", "--english", action="store_true", help="英文报告 / English report")
    parser.add_argument("--timeout", type=timeout_value, default=10, help="每次请求超时秒数，默认 10")
    parser.add_argument("--no-dnsbl", action="store_true", help="跳过 DNS 黑名单查询")
    args = parser.parse_args(argv)
    if sum((args.ip is not None, args.option_ip is not None, args.local)) > 1:
        parser.error("请只指定一个 IP 或 --local / Specify one target only")
    target = args.option_ip if args.option_ip is not None else args.ip
    interactive = target is None and not args.local
    if args.local:
        target = ""
    while True:
        if target is None:
            prompt = "Enter the IP to check (press Enter for this machine's public IP): " if args.english else "输入你要检测的 IP，直接回车检测本机 IP："
            print(prompt, end="", file=sys.stderr, flush=True)
            target = sys.stdin.readline()
            if not target:
                parser.error("未读取到输入，请使用 --local 或指定 IP / No input; use --local or specify an IP")
        target = target.strip()
        if not target:
            break
        try:
            address = validate_ip(target)
            break
        except ValueError as exc:
            if not interactive:
                parser.error(str(exc))
            print(str(exc), file=sys.stderr)
            target = None
    if args.output and (args.output.exists() or args.output.is_symlink()):
        parser.error("输出文件已存在，请换一个路径 / Output file already exists")
    language = "en" if args.english else "cn"
    try:
        addresses, detection_errors = ([address], []) if target else detect_local_ips(args.timeout)
        for error in detection_errors:
            print(error, file=sys.stderr)
        reports = []
        for address in addresses:
            print(f"Querying {address}..." if args.english else f"正在查询 {address}…", file=sys.stderr)
            reports.append(collect_report(address, language, args.timeout, not args.no_dnsbl))
        bundle = {"mode": "specified_ip" if target else "local_public_ip", "upload_enabled": False,
                  "detection_errors": detection_errors, "reports": reports}
        report_text = "\n".join(render_report(report, language) for report in reports)
        report_json = json.dumps(bundle, ensure_ascii=False, indent=2) + "\n"
        print(report_json if args.json else report_text, end="")
        if args.output:
            contents = report_json if args.output.suffix.lower() == ".json" else report_text
            with args.output.open("x", encoding="utf-8", newline="\n") as output:
                output.write(contents)
            print(f"Saved locally: {args.output.resolve()}" if args.english else
                  f"已保存到本地：{args.output.resolve()}", file=sys.stderr)
    except (OSError, QueryError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0 if any(report["status"] in ("ok", "partial") for report in reports) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n已取消 / Cancelled", file=sys.stderr)
        sys.exit(130)
