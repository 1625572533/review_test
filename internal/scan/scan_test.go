package scan

import (
	"strings"
	"testing"

	"review_test/internal/filter"
	"review_test/internal/mdns"
)

func TestAssetsFromMessagesBuildsDeepBannersAndFiltersPorts(t *testing.T) {
	cidr, err := filter.ParseCIDR("192.168.1.0/24")
	requireNoErr(t, err)
	ports, err := filter.ParsePorts("5000")
	requireNoErr(t, err)

	assets := AssetsFromMessages([]mdns.Message{{
		Records: []mdns.Record{
			{Name: "_http._tcp.local", Type: mdns.TypePTR, TTL: 10, PTR: "slw-nas._http._tcp.local"},
			{Name: "_qdiscover._tcp.local", Type: mdns.TypePTR, TTL: 10, PTR: "slw-nas._qdiscover._tcp.local"},
			{Name: "_smb._tcp.local", Type: mdns.TypePTR, TTL: 10, PTR: "slw-nas._smb._tcp.local"},
			{Name: "slw-nas._http._tcp.local", Type: mdns.TypeSRV, TTL: 10, SRV: &mdns.SRV{Port: 5000, Target: "slw-nas.local"}},
			{Name: "slw-nas._http._tcp.local", Type: mdns.TypeTXT, TTL: 10, TXT: []string{"path=/"}},
			{Name: "slw-nas._qdiscover._tcp.local", Type: mdns.TypeSRV, TTL: 10, SRV: &mdns.SRV{Port: 5000, Target: "slw-nas.local"}},
			{Name: "slw-nas._qdiscover._tcp.local", Type: mdns.TypeTXT, TTL: 10, TXT: []string{"accessType=https", "model=TS-X64", "fwVer=5.2.9"}},
			{Name: "slw-nas._smb._tcp.local", Type: mdns.TypeSRV, TTL: 10, SRV: &mdns.SRV{Port: 445, Target: "slw-nas.local"}},
			{Name: "slw-nas.local", Type: mdns.TypeA, TTL: 10, IP: "192.168.1.10"},
			{Name: "slw-nas.local", Type: mdns.TypeAAAA, TTL: 10, IP: "fe80::265e:beff:fe69:a313"},
		},
	}}, cidr, ports)

	if len(assets) != 1 {
		t.Fatalf("assets=%d, want 1", len(assets))
	}
	asset := assets[0]
	if asset.IP != "192.168.1.10" {
		t.Fatalf("IP=%q", asset.IP)
	}
	if asset.Hostname != "slw-nas.local" {
		t.Fatalf("Hostname=%q", asset.Hostname)
	}
	if len(asset.Services) != 2 {
		t.Fatalf("services=%d, want 2", len(asset.Services))
	}

	var foundHTTP, foundQDiscover bool
	for _, service := range asset.Services {
		if service.Port != 5000 {
			t.Fatalf("unexpected retained port %d", service.Port)
		}
		switch service.Type {
		case "http":
			foundHTTP = true
			assertContainsAll(t, service.Banner, []string{
				"Name=slw-nas",
				"IPv4=192.168.1.10",
				"IPv6=fe80::265e:beff:fe69:a313",
				"Hostname=slw-nas.local",
				"TTL=10",
				"path=/",
			})
		case "qdiscover":
			foundQDiscover = true
			assertContainsAll(t, service.Banner, []string{
				"Name=slw-nas",
				"IPv4=192.168.1.10",
				"Hostname=slw-nas.local",
				"accessType=https",
				"model=TS-X64",
				"fwVer=5.2.9",
			})
		default:
			t.Fatalf("unexpected service type %q", service.Type)
		}
	}
	if !foundHTTP || !foundQDiscover {
		t.Fatalf("found http=%v qdiscover=%v", foundHTTP, foundQDiscover)
	}
}

func requireNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func assertContainsAll(t *testing.T, text string, values []string) {
	t.Helper()
	for _, value := range values {
		if !strings.Contains(text, value) {
			t.Fatalf("%q does not contain %q", text, value)
		}
	}
}
