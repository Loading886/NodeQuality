// NodeQuality: IP-only queries without report uploads. AGPL-3.0.
// Provider field mappings reference xykt/IPQuality v2026-09-16.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

var version = "dev"

type object = map[string]any
type provider struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	Source   string `json:"source,omitempty"`
	Error    string `json:"error,omitempty"`
	Fallback string `json:"fallback_reason,omitempty"`
	Info     object `json:"info"`
	Factors  object `json:"factors"`
	Scores   object `json:"scores"`
}
type blacklist struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}
type report struct {
	Target    string            `json:"target_ip"`
	IPVersion int               `json:"ip_version"`
	Generated string            `json:"generated_at"`
	Upload    bool              `json:"upload_enabled"`
	Status    string            `json:"status"`
	Reason    string            `json:"reason,omitempty"`
	Providers []provider        `json:"providers"`
	DNSBL     []blacklist       `json:"dnsbl"`
	Skipped   map[string]string `json:"skipped"`
}
type bundle struct {
	Version         string   `json:"version"`
	Mode            string   `json:"mode"`
	Upload          bool     `json:"upload_enabled"`
	DetectionErrors []string `json:"detection_errors"`
	Reports         []report `json:"reports"`
}
type fetchFunc func(context.Context, string) (object, error)

func fetcher(seconds int) fetchFunc {
	client := &http.Client{Timeout: time.Duration(seconds) * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return func(ctx context.Context, address string) (object, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "NodeQuality-IP/"+version)
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return nil, errors.New("network timeout/error")
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		payload, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024+1))
		if err != nil || len(payload) > 2*1024*1024 {
			return nil, errors.New("invalid/oversized response")
		}
		var data object
		if json.Unmarshal(payload, &data) != nil || len(data) == 0 {
			return nil, errors.New("empty or invalid JSON")
		}
		if data["error"] != nil || data["errors"] != nil || data["success"] == false {
			return nil, errors.New("provider rejected the query")
		}
		return data, nil
	}
}

func value(data object, path string) any {
	var item any = data
	for _, key := range strings.Split(path, ".") {
		m, ok := item.(map[string]any)
		if !ok {
			return nil
		}
		item = m[key]
	}
	switch v := item.(type) {
	case string:
		if v != "" && v != "null" {
			return v
		}
	case bool:
		return v
	case float64:
		if !math.IsNaN(v) && !math.IsInf(v, 0) {
			return v
		}
	}
	return nil
}
func boolean(v any) any {
	if b, ok := v.(bool); ok {
		return b
	}
	if s, ok := v.(string); ok {
		if strings.EqualFold(s, "true") {
			return true
		}
		if strings.EqualFold(s, "false") {
			return false
		}
	}
	return nil
}
func anyFlag(data object, paths ...string) any {
	missing := false
	for _, p := range paths {
		b := boolean(value(data, p))
		if b == true {
			return true
		}
		if b == nil {
			missing = true
		}
	}
	if missing {
		return nil
	}
	return false
}
func score(v any) any {
	var n float64
	var err error
	switch x := v.(type) {
	case float64:
		n = x
	case string:
		n, err = strconv.ParseFloat(x, 64)
	default:
		return nil
	}
	if err == nil && !math.IsNaN(n) && !math.IsInf(n, 0) && n >= 0 && n <= 100 {
		return n
	}
	return nil
}
func parseIP(s string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || ip.Zone() != "" {
		return netip.Addr{}, errors.New("IP 地址格式无效 / Invalid IPv4 or IPv6 address")
	}
	return ip.Unmap(), nil
}

var excluded = func() []netip.Prefix {
	var result []netip.Prefix
	for _, s := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "::/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20", "5f00::/16", "fc00::/7", "fe80::/10"} {
		result = append(result, netip.MustParsePrefix(s))
	}
	return result
}()

func publicIP(ip netip.Addr) bool {
	if !ip.IsGlobalUnicast() {
		return false
	}
	if ip.String() == "192.0.0.9" || ip.String() == "192.0.0.10" {
		return true
	}
	for _, p := range excluded {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

var names = []string{"MaxMind", "IPinfo", "Scamalytics", "ipapi", "AbuseIPDB", "IP2Location", "ipdata", "IPQS"}
var databases = map[string]string{"Scamalytics": "scamalytics", "ipapi": "ipapi", "AbuseIPDB": "abuseipdb", "IP2Location": "ip2location", "ipdata": "ipdata", "IPQS": "ipqualityscore"}
var infoPaths = map[string]map[string]string{
	"MaxMind":     {"country": "City.Country.Name", "city": "City.Name", "asn": "ASN.AutonomousSystemNumber", "organization": "ASN.AutonomousSystemOrganization", "timezone": "City.Location.TimeZone"},
	"IPinfo":      {"country": "data.country", "region": "data.region", "city": "data.city", "asn": "data.asn.asn", "organization": "data.asn.name", "usage_type": "data.asn.type", "company_type": "data.company.type", "timezone": "data.timezone"},
	"Scamalytics": {"country": "external_datasources.maxmind_geolite2.ip_country_code"},
	"ipapi":       {"country": "location.country", "region": "location.state", "city": "location.city", "asn": "asn.asn", "organization": "asn.org", "usage_type": "asn.type", "company_type": "company.type", "timezone": "location.timezone"},
	"AbuseIPDB":   {"country": "data.countryCode", "usage_type": "data.usageType", "organization": "data.isp"},
	"IP2Location": {"country": "country_code", "usage_type": "usage_type", "company_type": "as_info.as_usage_type"},
	"ipdata":      {"country": "country_code"}, "IPQS": {"country": "country_code"},
}
var factorPaths = map[string]map[string]string{
	"IPinfo":      {"proxy": "data.privacy.proxy", "vpn": "data.privacy.vpn", "tor": "data.privacy.tor", "hosting": "data.privacy.hosting"},
	"Scamalytics": {"proxy": "external_datasources.firehol.is_proxy", "vpn": "scamalytics.scamalytics_proxy.is_vpn", "tor": "external_datasources.x4bnet.is_tor", "hosting": "scamalytics.scamalytics_proxy.is_datacenter", "abuser": "scamalytics.is_blacklisted_external"},
	"ipapi":       {"proxy": "is_proxy", "vpn": "is_vpn", "tor": "is_tor", "hosting": "is_datacenter", "abuser": "is_abuser", "bot": "is_crawler"},
	"AbuseIPDB":   {"tor": "data.isTor"},
	"IP2Location": {"vpn": "proxy.is_vpn", "tor": "proxy.is_tor", "hosting": "proxy.is_data_center", "abuser": "proxy.is_spammer"},
	"ipdata":      {"proxy": "threat.is_proxy", "tor": "threat.is_tor", "hosting": "threat.is_datacenter"},
	"IPQS":        {"proxy": "proxy", "vpn": "vpn", "tor": "tor", "abuser": "recent_abuse", "bot": "bot_status"},
}

func normalize(name string, data object) provider {
	r := provider{Name: name, Info: object{}, Factors: object{}, Scores: object{}}
	for k, p := range infoPaths[name] {
		r.Info[k] = value(data, p)
	}
	for k, p := range factorPaths[name] {
		r.Factors[k] = boolean(value(data, p))
	}
	switch name {
	case "Scamalytics":
		r.Factors["bot"] = anyFlag(data, "external_datasources.x4bnet.is_blacklisted_spambot", "external_datasources.x4bnet.is_bot_operamini", "external_datasources.x4bnet.is_bot_semrush")
		r.Scores["fraud_score_0_100"] = score(value(data, "scamalytics.scamalytics_score"))
	case "ipapi":
		if s, ok := value(data, "company.abuser_score").(string); ok {
			fields := strings.Fields(s)
			if len(fields) > 0 {
				n, e := strconv.ParseFloat(fields[0], 64)
				if e == nil && n >= 0 && n <= 1 {
					r.Scores["company_abuse_ratio"] = s
				}
			}
		}
		if _, ok := data["asn"].(string); ok {
			r.Info = object{}
			for _, k := range []string{"country", "region", "city", "asn", "timezone"} {
				r.Info[k] = value(data, k)
			}
			r.Info["organization"] = value(data, "company")
		}
	case "AbuseIPDB":
		r.Scores["abuse_confidence_0_100"] = score(value(data, "data.abuseConfidenceScore"))
	case "IP2Location":
		r.Factors["proxy"] = anyFlag(data, "is_proxy", "proxy.is_public_proxy", "proxy.is_web_proxy")
		r.Factors["bot"] = anyFlag(data, "proxy.is_web_crawler", "proxy.is_scanner", "proxy.is_botnet")
		r.Scores["fraud_score_0_100"] = score(value(data, "fraud_score"))
	case "ipdata":
		r.Factors["abuser"] = anyFlag(data, "threat.is_threat", "threat.is_known_abuser", "threat.is_known_attacker")
	case "IPQS":
		r.Scores["fraud_score_0_100"] = score(value(data, "fraud_score"))
	}
	return r
}
func queryProvider(ctx context.Context, fetch fetchFunc, name, target, language string) provider {
	endpoint := "https://ipinfo.check.place/" + target + "?db=" + databases[name]
	if name == "MaxMind" {
		endpoint = "https://ipinfo.check.place/" + target + "?lang=" + language
	}
	if name == "IPinfo" {
		endpoint = "https://ipinfo.io/widget/demo/" + target
	}
	urls := []string{endpoint}
	if name == "ipapi" {
		urls = append(urls, "https://api.ipapi.is/?q="+url.QueryEscape(target))
	}
	var failures []string
	for _, address := range urls {
		data, err := fetch(ctx, address)
		if err == nil {
			paths := []string{"data.ipAddress", "ip", "ipAddress"}
			if name == "IPinfo" {
				paths = []string{"data.ip"}
			}
			for _, p := range paths {
				if v := value(data, p); v != nil {
					ip, e := parseIP(fmt.Sprint(v))
					if e != nil || ip.String() != target {
						err = errors.New("response IP differs from target")
					}
				}
			}
		}
		if err == nil {
			r := normalize(name, data)
			found := false
			for _, section := range []object{r.Info, r.Factors, r.Scores} {
				for _, v := range section {
					if v != nil {
						found = true
					}
				}
			}
			if found {
				r.Status = "ok"
				r.Source = address
				r.Fallback = strings.Join(failures, "; ")
				return r
			}
			err = errors.New("no recognized data for target IP")
		}
		failures = append(failures, err.Error())
	}
	r := normalize(name, object{})
	r.Status = "unavailable"
	r.Error = strings.Join(failures, "; ")
	return r
}

var zones = []string{"zen.spamhaus.org", "bl.spamcop.net"}

func dnsAnswer(ctx context.Context, fetch fetchFunc, host, zone string) (bool, error) {
	data, err := fetch(ctx, "https://dns.google/resolve?"+url.Values{"name": {host}, "type": {"A"}, "edns_client_subnet": {"0.0.0.0/0"}}.Encode())
	if err != nil {
		return false, err
	}
	status, ok := data["Status"].(float64)
	if !ok || (status != 0 && status != 3) || data["TC"] == true {
		return false, errors.New("DNS failure")
	}
	answers, ok := data["Answer"].([]any)
	if data["Answer"] != nil && !ok {
		return false, errors.New("invalid DNS answer")
	}
	if status == 3 && len(answers) > 0 {
		return false, errors.New("inconsistent DNS answer")
	}
	listed := false
	for _, a := range answers {
		m, ok := a.(map[string]any)
		if !ok {
			return false, errors.New("invalid DNS answer")
		}
		if m["type"] != float64(1) {
			continue
		}
		code, _ := m["data"].(string)
		accepted := code == "127.0.0.2"
		if zone == "zen.spamhaus.org" {
			for _, n := range []string{"3", "4", "9", "10", "11"} {
				if code == "127.0.0."+n {
					accepted = true
				}
			}
		}
		if !accepted {
			return false, errors.New("DNSBL refused resolver or returned unknown code")
		}
		listed = true
	}
	return listed, nil
}
func queryDNSBL(ctx context.Context, fetch fetchFunc, zone, target string) blacklist {
	r := blacklist{Name: zone, Status: "unavailable"}
	positive, err := dnsAnswer(ctx, fetch, "2.0.0.127."+zone, zone)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	if !positive {
		r.Error = "positive control failed; resolver may be blocked"
		return r
	}
	negative, err := dnsAnswer(ctx, fetch, "1.0.0.127."+zone, zone)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	if negative {
		r.Error = "negative control failed"
		return r
	}
	octets := strings.Split(target, ".")
	reversed := octets[3] + "." + octets[2] + "." + octets[1] + "." + octets[0]
	listed, err := dnsAnswer(ctx, fetch, reversed+"."+zone, zone)
	if err != nil {
		r.Error = err.Error()
	} else if listed {
		r.Status = "listed"
	} else {
		r.Status = "not_listed"
	}
	return r
}
func localIPs(ctx context.Context, fetch fetchFunc) ([]netip.Addr, []string, error) {
	ips := make([]netip.Addr, 2)
	failures := make([]string, 2)
	var wg sync.WaitGroup
	for i, family := range []int{4, 6} {
		wg.Add(1)
		go func(i, family int) {
			defer wg.Done()
			data, err := fetch(ctx, fmt.Sprintf("https://api%d.ipify.org?format=json", family))
			var ip netip.Addr
			if err == nil {
				ip, err = parseIP(fmt.Sprint(data["ip"]))
				if err == nil && (!publicIP(ip) || ip.Is4() != (family == 4)) {
					err = errors.New("unexpected IP address")
				}
			}
			if err != nil {
				failures[i] = fmt.Sprintf("IPv%d: %v", family, err)
			} else {
				ips[i] = ip
			}
		}(i, family)
	}
	wg.Wait()
	result := []netip.Addr{}
	notes := []string{}
	for i, ip := range ips {
		if ip.IsValid() {
			result = append(result, ip)
		}
		if failures[i] != "" {
			notes = append(notes, failures[i])
		}
	}
	if len(result) == 0 {
		return result, notes, errors.New("无法识别本机公网 IP，请手动输入 / Public IP detection failed")
	}
	return result, notes, nil
}
func collect(ctx context.Context, fetch fetchFunc, ip netip.Addr, language string, dnsbl bool) report {
	r := report{Target: ip.String(), IPVersion: 6, Generated: time.Now().UTC().Format(time.RFC3339), Providers: []provider{}, DNSBL: []blacklist{}, Skipped: map[string]string{"media_unlock": "requires_target_egress", "smtp_connectivity": "requires_target_egress", "DB-IP": "upstream_endpoint_uses_requester_ip"}}
	if ip.Is4() {
		r.IPVersion = 4
	}
	if !publicIP(ip) {
		r.Status = "not_applicable"
		r.Reason = "non_public_ip"
		return r
	}
	r.Providers = make([]provider, len(names))
	var wg sync.WaitGroup
	for i, name := range names {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			r.Providers[i] = queryProvider(ctx, fetch, name, ip.String(), language)
		}(i, name)
	}
	if dnsbl && ip.Is4() {
		r.DNSBL = make([]blacklist, len(zones))
		for i, zone := range zones {
			wg.Add(1)
			go func(i int, zone string) { defer wg.Done(); r.DNSBL[i] = queryDNSBL(ctx, fetch, zone, ip.String()) }(i, zone)
		}
	} else if !dnsbl {
		r.Skipped["dnsbl"] = "disabled"
	} else {
		r.Skipped["dnsbl"] = "ipv4_only"
	}
	wg.Wait()
	count := 0
	for _, p := range r.Providers {
		if p.Status == "ok" {
			count++
		}
	}
	r.Status = "unavailable"
	if count == len(names) {
		r.Status = "ok"
	} else if count > 0 {
		r.Status = "partial"
	}
	return r
}

func clean(v any, en bool) string {
	if v == nil {
		if en {
			return "Unknown"
		}
		return "未知"
	}
	if b, ok := v.(bool); ok {
		if en {
			if b {
				return "Yes"
			}
			return "No"
		}
		if b {
			return "是"
		}
		return "否"
	}
	s := strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return -1
	}, fmt.Sprint(v))
	r := []rune(s)
	if len(r) > 250 {
		s = string(r[:250])
	}
	return s
}
func render(r report, en bool) string {
	var out strings.Builder
	text := func(cn, eng string) string {
		if en {
			return eng
		}
		return cn
	}
	fmt.Fprintf(&out, "%s\nNodeQuality %s — %s\nIP: %s (IPv%d)\nUTC: %s\n%s\n", strings.Repeat("=", 72), version, text("IP 质量查询", "IP quality"), r.Target, r.IPVersion, r.Generated, text("报告仅返回当前终端，不上传到报告网站。", "Report returned to this terminal; no report-site uploads."))
	if r.Status == "not_applicable" {
		return out.String() + text("非公网 IP，公网信誉查询不适用；未发送外部请求。\n", "Non-public IP; no external requests sent.\n")
	}
	labels := map[string]string{"country": "国家/地区", "region": "省/州", "city": "城市", "asn": "ASN", "organization": "机构", "usage_type": "使用类型", "company_type": "公司类型", "timezone": "时区", "fraud_score_0_100": "欺诈评分 0–100", "abuse_confidence_0_100": "滥用置信度 0–100", "company_abuse_ratio": "公司网段滥用比例"}
	for _, p := range r.Providers {
		fmt.Fprintf(&out, "\n[%s]\n", p.Name)
		if p.Status != "ok" {
			fmt.Fprintf(&out, "  %s: %s\n", text("不可用", "Unavailable"), clean(p.Error, en))
			continue
		}
		if p.Fallback != "" {
			fmt.Fprintln(&out, text("  使用备用接口；缺失的安全字段为未知。", "  Fallback API; missing security fields remain unknown."))
		}
		for _, section := range []object{p.Info, p.Scores} {
			keys := []string{}
			for key := range section {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				if section[key] == nil && key != "fraud_score_0_100" && key != "abuse_confidence_0_100" {
					continue
				}
				label := key
				if !en {
					label = labels[key]
				}
				fmt.Fprintf(&out, "  %s: %s\n", label, clean(section[key], en))
			}
		}
		if p.Name != "MaxMind" {
			values := []string{}
			for _, key := range []string{"proxy", "vpn", "tor", "hosting", "abuser", "bot"} {
				values = append(values, clean(p.Factors[key], en))
			}
			fmt.Fprintf(&out, "  %s: %s\n", text("代理 / VPN / Tor / 机房 / 滥用 / 机器人", "Proxy / VPN / Tor / Hosting / Abuser / Bot"), strings.Join(values, " / "))
		}
	}
	fmt.Fprintln(&out, "\n"+text("DNS 黑名单：", "DNS blacklists:"))
	states := map[string]string{"listed": "列入", "not_listed": "未列入", "unavailable": "不可用"}
	for _, b := range r.DNSBL {
		status := b.Status
		if !en {
			status = states[status]
		}
		fmt.Fprintf(&out, "  %s: %s", b.Name, status)
		if b.Error != "" {
			fmt.Fprintf(&out, " (%s)", clean(b.Error, en))
		}
		fmt.Fprintln(&out)
	}
	if len(r.DNSBL) == 0 {
		fmt.Fprintln(&out, text("  已跳过（用户禁用或目标为 IPv6）。", "  Skipped (disabled or IPv6)."))
	}
	fmt.Fprintln(&out, text("\n流媒体/SMTP 连通性未执行，必须从目标 IP 发起连接才能判断。", "\nMedia/SMTP connectivity skipped; target egress is required."))
	fmt.Fprintln(&out, text("缺失数据表示未知，不代表低风险；黑名单仅覆盖上面列出的库。", "Missing data is unknown, not low risk; only the listed DNSBL zones are checked."))
	fmt.Fprintln(&out, text("查询会将目标 IP 发送给数据源；整份报告不会发送给数据源。", "Lookups send the target IP to providers; the assembled report is not sent to providers."))
	return out.String() + strings.Repeat("=", 72) + "\n"
}

func run(ctx context.Context, args []string, in io.Reader, out, errOut io.Writer, fetch fetchFunc) int {
	fs := flag.NewFlagSet("nodequality", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var target, output string
	var local, jsonMode, en, noDNS, showVersion bool
	var seconds int
	fs.StringVar(&target, "i", "", "待查询 IPv4/IPv6")
	fs.StringVar(&target, "ip", "", "待查询 IPv4/IPv6")
	fs.BoolVar(&local, "local", false, "直接查询本机公网 IP")
	fs.BoolVar(&jsonMode, "j", false, "输出 JSON")
	fs.BoolVar(&jsonMode, "json", false, "输出 JSON")
	fs.BoolVar(&en, "E", false, "English report")
	fs.BoolVar(&en, "english", false, "English report")
	fs.BoolVar(&noDNS, "no-dnsbl", false, "跳过 DNS 黑名单")
	fs.StringVar(&output, "o", "", "本地输出文件（.json 或文本）")
	fs.StringVar(&output, "output", "", "本地输出文件")
	fs.IntVar(&seconds, "timeout", 10, "每次请求超时 1–60 秒")
	fs.BoolVar(&showVersion, "version", false, "显示版本")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if showVersion {
		fmt.Fprintln(out, "NodeQuality", version)
		return 0
	}
	if fs.NArg() > 1 || (fs.NArg() == 1 && target != "") || (local && (target != "" || fs.NArg() != 0)) || seconds < 1 || seconds > 60 {
		fmt.Fprintln(errOut, "参数无效 / Invalid arguments")
		return 2
	}
	if fs.NArg() == 1 {
		target = fs.Arg(0)
	}
	target = strings.TrimSpace(target)
	var address netip.Addr
	if target == "" && !local {
		reader := bufio.NewReader(in)
		for {
			if en {
				fmt.Fprint(errOut, "Enter IP (press Enter for this machine's public IP): ")
			} else {
				fmt.Fprint(errOut, "输入你要检测的 IP，直接回车检测本机 IP：")
			}
			line, e := reader.ReadString('\n')
			if e != nil && len(line) == 0 {
				fmt.Fprintln(errOut, "未读取到输入，请使用 --local 或 -i IP / No input")
				return 2
			}
			target = strings.TrimSpace(line)
			if target == "" {
				break
			}
			address, e = parseIP(target)
			if e == nil {
				break
			}
			fmt.Fprintln(errOut, e)
		}
	} else if target != "" {
		var e error
		address, e = parseIP(target)
		if e != nil {
			fmt.Fprintln(errOut, e)
			return 2
		}
	}
	if output != "" {
		if _, e := os.Lstat(output); e == nil {
			fmt.Fprintln(errOut, "输出文件已存在 / Output file already exists")
			return 2
		} else if !os.IsNotExist(e) {
			fmt.Fprintln(errOut, e)
			return 1
		}
	}
	if fetch == nil {
		fetch = fetcher(seconds)
	}
	addresses := []netip.Addr{address}
	notes := []string{}
	mode := "specified_ip"
	if !address.IsValid() {
		var e error
		mode = "local_public_ip"
		addresses, notes, e = localIPs(ctx, fetch)
		for _, note := range notes {
			fmt.Fprintln(errOut, note)
		}
		if e != nil {
			fmt.Fprintln(errOut, e)
			return 1
		}
	}
	b := bundle{Version: version, Mode: mode, DetectionErrors: notes, Reports: []report{}}
	language := "cn"
	if en {
		language = "en"
	}
	code := 1
	for _, ip := range addresses {
		fmt.Fprintln(errOut, "Querying", ip, "...")
		r := collect(ctx, fetch, ip, language, !noDNS)
		b.Reports = append(b.Reports, r)
		if r.Status == "ok" || r.Status == "partial" {
			code = 0
		}
	}
	if ctx.Err() != nil {
		fmt.Fprintln(errOut, "已取消 / Cancelled")
		return 130
	}
	data, e := json.MarshalIndent(b, "", "  ")
	if e != nil {
		fmt.Fprintln(errOut, e)
		return 1
	}
	data = append(data, '\n')
	var text strings.Builder
	for _, r := range b.Reports {
		text.WriteString(render(r, en))
		text.WriteByte('\n')
	}
	if jsonMode {
		_, e = out.Write(data)
	} else {
		_, e = io.WriteString(out, text.String())
	}
	if e != nil {
		fmt.Fprintln(errOut, e)
		return 1
	}
	if output != "" {
		file, e := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			fmt.Fprintln(errOut, e)
			return 1
		}
		if strings.EqualFold(filepath.Ext(output), ".json") {
			_, e = file.Write(data)
		} else {
			_, e = io.WriteString(file, text.String())
		}
		closeErr := file.Close()
		if e != nil || closeErr != nil {
			fmt.Fprintln(errOut, "保存失败 / Save failed", e, closeErr)
			return 1
		}
		fmt.Fprintln(errOut, "Saved locally:", output)
	}
	return code
}
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if len(os.Args) > 1 && os.Args[1] == "serve" {
		os.Exit(serverMain(ctx, os.Args[2:], os.Stderr))
	}
	os.Exit(run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr, nil))
}
