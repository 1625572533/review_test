package output

import (
	"strings"
	"testing"

	"review_test/internal/model"
)

func TestTextRendersServicesAndPTRs(t *testing.T) {
	got := Text([]model.Asset{{
		IP:       "192.168.1.10",
		Hostname: "slw-nas.local",
		PTRs:     []string{"_smb._tcp.local", "_http._tcp.local"},
		Services: []model.Service{
			{Port: 5000, Proto: "tcp", Type: "http", Banner: "Name=slw-nas IPv4=192.168.1.10 IPv6=fe80::265e:beff:fe69:a313 Hostname=slw-nas.local TTL=10 path=/"},
			{Port: 445, Proto: "tcp", Type: "smb", Banner: "Name=slw-nas IPv4=192.168.1.10 Hostname=slw-nas.local TTL=10"},
		},
	}})

	for _, want := range []string{
		"services:\n",
		"5000/tcp http: Name=slw-nas IPv4=192.168.1.10 IPv6=fe80::265e:beff:fe69:a313 Hostname=slw-nas.local TTL=10 path=/",
		"445/tcp smb: Name=slw-nas IPv4=192.168.1.10 Hostname=slw-nas.local TTL=10",
		"answers:\n",
		"PTR: _http._tcp.local _smb._tcp.local",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("output missing %q:\n%s", want, got)
		}
	}
}
