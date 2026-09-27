package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func fixture(s string) object {
	var data object
	if err := json.Unmarshal([]byte(s), &data); err != nil {
		panic(err)
	}
	return data
}
func basicFetch(_ context.Context, address string) (object, error) {
	if strings.Contains(address, "ipinfo.io/widget/demo/") {
		return fixture(`{"data":{"ip":"1.1.1.1","country":"AU","privacy":{"proxy":false,"hosting":true}}}`), nil
	}
	return nil, errors.New("HTTP 403")
}
func TestAddressValidation(t *testing.T) {
	for _, s := range []string{"1.1.1.1", "2606:4700:4700::1111", " ::ffff:1.1.1.1 "} {
		if _, e := parseIP(s); e != nil {
			t.Fatal(e)
		}
	}
	for _, s := range []string{"1", "01.2.3.4", "1.2.3.999", "example.com", "1.2.3.4/24", "fe80::1%eth0", "1.2.3.4;echo bad", "2001:::1"} {
		if _, e := parseIP(s); e == nil {
			t.Fatalf("accepted %q", s)
		}
	}
}
func TestNonPublicMakesNoRequests(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "192.168.1.1", "::1", "fe80::1", "224.0.0.1", "ff02::1", "100.64.0.1", "203.0.113.1"} {
		r := collect(context.Background(), func(context.Context, string) (object, error) {
			t.Error("unexpected network query")
			return nil, errors.New("blocked")
		}, netip.MustParseAddr(s), "cn", true)
		if r.Status != "not_applicable" {
			t.Fatal(s, r.Status)
		}
	}
}
func TestProviderMappingsAndUnknown(t *testing.T) {
	tests := []struct {
		name, data, section, key string
		want                     any
	}{
		{"MaxMind", `{"ASN":{"AutonomousSystemNumber":13335}}`, "info", "asn", float64(13335)},
		{"IPinfo", `{"data":{"privacy":{"hosting":true}}}`, "factor", "hosting", true},
		{"Scamalytics", `{"scamalytics":{"scamalytics_score":42}}`, "score", "fraud_score_0_100", float64(42)},
		{"ipapi", `{"company":{"abuser_score":"0.1 (High)"}}`, "score", "company_abuse_ratio", "0.1 (High)"},
		{"AbuseIPDB", `{"data":{"abuseConfidenceScore":0}}`, "score", "abuse_confidence_0_100", float64(0)},
		{"IP2Location", `{"proxy":{"is_vpn":true}}`, "factor", "vpn", true},
		{"ipdata", `{"threat":{"is_known_attacker":true}}`, "factor", "abuser", true},
		{"IPQS", `{"bot_status":false}`, "factor", "bot", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := normalize(tt.name, fixture(tt.data))
			m := r.Info
			if tt.section == "factor" {
				m = r.Factors
			}
			if tt.section == "score" {
				m = r.Scores
			}
			if m[tt.key] != tt.want {
				t.Fatalf("got %v want %v", m[tt.key], tt.want)
			}
			empty := normalize(tt.name, object{})
			for _, m := range []object{empty.Info, empty.Factors, empty.Scores} {
				for _, v := range m {
					if v != nil {
						t.Fatal("fabricated data", v)
					}
				}
			}
		})
	}
	if anyFlag(fixture(`{"a":false}`), "a", "b") != nil {
		t.Fatal("missing flag treated as false")
	}
	if score(nil) != nil || score("NaN") != nil || score(true) != nil || score(float64(0)) != float64(0) {
		t.Fatal("invalid score handling")
	}
}
func TestWrongIPRejected(t *testing.T) {
	r := queryProvider(context.Background(), func(context.Context, string) (object, error) {
		return fixture(`{"data":{"ip":"8.8.8.8","country":"US"}}`), nil
	}, "IPinfo", "1.1.1.1", "cn")
	if r.Status != "unavailable" {
		t.Fatal("accepted wrong target")
	}
}
func TestFallbackHasNoInventedSecurityData(t *testing.T) {
	r := queryProvider(context.Background(), func(_ context.Context, address string) (object, error) {
		if strings.Contains(address, "check.place") {
			return nil, errors.New("HTTP 403")
		}
		return fixture(`{"ip":"1.1.1.1","asn":"AS13335","company":"Cloudflare"}`), nil
	}, "ipapi", "1.1.1.1", "cn")
	if r.Status != "ok" || r.Fallback == "" || r.Factors["vpn"] != nil {
		t.Fatal(r)
	}
}
func TestIPv6IsQueryData(t *testing.T) {
	ip := "2606:4700:4700::1111"
	r := collect(context.Background(), func(_ context.Context, address string) (object, error) {
		if !strings.Contains(address, ip) && !strings.Contains(address, "2606%3A4700%3A4700%3A%3A1111") {
			t.Error("target omitted", address)
		}
		return nil, errors.New("offline")
	}, netip.MustParseAddr(ip), "cn", true)
	if r.Skipped["dnsbl"] != "ipv4_only" {
		t.Fatal(r)
	}
}
func TestDNSFailuresAreUnknown(t *testing.T) {
	for _, data := range []string{`{"Status":2}`, `{"Status":3}`, `{"Status":0,"Answer":[{"type":1,"data":"127.255.255.254"}]}`} {
		r := queryDNSBL(context.Background(), func(context.Context, string) (object, error) { return fixture(data), nil }, "zen.spamhaus.org", "1.1.1.1")
		if r.Status != "unavailable" {
			t.Fatal("invalid response counted", r)
		}
	}
}
func TestDNSUsesReversedTarget(t *testing.T) {
	var last string
	r := queryDNSBL(context.Background(), func(_ context.Context, address string) (object, error) {
		last = address
		if strings.Contains(address, "name=1.0.0.127.") {
			return fixture(`{"Status":3}`), nil
		}
		return fixture(`{"Status":0,"Answer":[{"type":1,"data":"127.0.0.2"}]}`), nil
	}, "bl.spamcop.net", "1.2.3.4")
	if r.Status != "listed" || !strings.Contains(last, "4.3.2.1.bl.spamcop.net") {
		t.Fatal(r, last)
	}
}
func TestHTTPBoundary(t *testing.T) {
	var mu sync.Mutex
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		if r.Method != "GET" || len(body) != 0 {
			t.Error("request uploaded data")
		}
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "/data", http.StatusFound)
		case "/blocked":
			w.WriteHeader(403)
		default:
			io.WriteString(w, `{"data":{"country":"US"}}`)
		}
	}))
	defer server.Close()
	fetch := fetcher(2)
	if _, e := fetch(context.Background(), server.URL+"/data"); e != nil {
		t.Fatal(e)
	}
	if _, e := fetch(context.Background(), server.URL+"/redirect"); e == nil {
		t.Fatal("redirect followed")
	}
	if _, e := fetch(context.Background(), server.URL+"/blocked"); e == nil {
		t.Fatal("HTTP failure accepted")
	}
	mu.Lock()
	defer mu.Unlock()
	if requests != 3 {
		t.Fatal(requests)
	}
}
func TestManualInteractiveAndEOF(t *testing.T) {
	for _, input := range []string{"1.1.1.1\n", "bad\n1.1.1.1\n"} {
		var out, stderr bytes.Buffer
		code := run(context.Background(), []string{"-j", "--no-dnsbl"}, strings.NewReader(input), &out, &stderr, basicFetch)
		var b bundle
		if code != 0 || json.Unmarshal(out.Bytes(), &b) != nil || b.Reports[0].Target != "1.1.1.1" || b.Upload {
			t.Fatal(code, out.String(), stderr.String())
		}
	}
	if code := run(context.Background(), nil, strings.NewReader(""), io.Discard, io.Discard, basicFetch); code != 2 {
		t.Fatal("EOF queried local IP")
	}
}
func TestEnterDiscoversLocalFamilies(t *testing.T) {
	fetch := func(ctx context.Context, address string) (object, error) {
		if strings.Contains(address, "api4.ipify") {
			return fixture(`{"ip":"1.1.1.1"}`), nil
		}
		if strings.Contains(address, "api6.ipify") {
			return fixture(`{"ip":"2606:4700:4700::1111"}`), nil
		}
		return basicFetch(ctx, address)
	}
	var out bytes.Buffer
	code := run(context.Background(), []string{"-j", "--no-dnsbl"}, strings.NewReader("\n"), &out, io.Discard, fetch)
	var b bundle
	if code != 0 || json.Unmarshal(out.Bytes(), &b) != nil || b.Mode != "local_public_ip" || len(b.Reports) != 2 {
		t.Fatal(code, out.String())
	}
}
func TestOutputNoOverwriteAndInvalidNoNetwork(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report space.json")
	if run(context.Background(), []string{"-i", "1.1.1.1", "--no-dnsbl", "-o", path}, strings.NewReader(""), io.Discard, io.Discard, basicFetch) != 0 {
		t.Fatal("save failed")
	}
	before, _ := os.ReadFile(path)
	for _, args := range [][]string{{"-i", "8.8.8.8", "-o", path}, {"-i", "bad"}, {"--timeout", "0"}, {"--local", "-i", "1.1.1.1"}} {
		code := run(context.Background(), args, strings.NewReader(""), io.Discard, io.Discard, func(context.Context, string) (object, error) {
			t.Error("unexpected request")
			return nil, errors.New("offline")
		})
		if code != 2 {
			t.Fatal(args, code)
		}
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("overwrote report")
	}
}
