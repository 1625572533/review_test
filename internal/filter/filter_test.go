package filter

import "testing"

func requireNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParsePorts(t *testing.T) {
	ports, err := ParsePorts("80,443,5000-5002")
	requireNoErr(t, err)

	for _, port := range []int{80, 443, 5000, 5001, 5002} {
		if !ports.Contains(port) {
			t.Fatalf("expected port %d", port)
		}
	}
	if ports.Contains(22) {
		t.Fatal("did not expect port 22")
	}
}

func TestParsePortsRejectsInvalidInput(t *testing.T) {
	for _, input := range []string{"", "abc", "0", "65536", "90-80", "80,,443"} {
		if _, err := ParsePorts(input); err == nil {
			t.Fatalf("expected error for %q", input)
		}
	}
}

func TestCIDRContainsIPv4(t *testing.T) {
	matcher, err := ParseCIDR("192.168.1.0/24")
	requireNoErr(t, err)

	if !matcher.Contains("192.168.1.23") {
		t.Fatal("expected IP in CIDR")
	}
	if matcher.Contains("192.168.2.23") {
		t.Fatal("did not expect IP outside CIDR")
	}
	if matcher.Contains("not-an-ip") {
		t.Fatal("did not expect invalid IP to match")
	}
}
