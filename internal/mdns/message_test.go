package mdns

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestBuildQuery(t *testing.T) {
	query, err := BuildQuery("_http._tcp.local")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(query) < 12 {
		t.Fatalf("query too short: %d", len(query))
	}
	if got := binary.BigEndian.Uint16(query[4:6]); got != 1 {
		t.Fatalf("QDCOUNT=%d, want 1", got)
	}
	if got := binary.BigEndian.Uint16(query[len(query)-4 : len(query)-2]); got != TypePTR {
		t.Fatalf("QTYPE=%d, want PTR", got)
	}
	if got := binary.BigEndian.Uint16(query[len(query)-2:]); got != ClassIN {
		t.Fatalf("QCLASS=%d, want IN", got)
	}
}

func TestParseMessageDecodesCommonMDNSRecords(t *testing.T) {
	packet := dnsHeader(5)
	httpNameOffset := len(packet)
	packet = append(packet, dnsName("_http._tcp.local")...)
	packet = appendRecordSuffix(packet, TypePTR, 10, dnsName("slw-nas._http._tcp.local"))

	instanceOffset := len(packet)
	packet = append(packet, dnsName("slw-nas._http._tcp.local")...)
	packet = appendRecordSuffix(packet, TypeSRV, 10, srvData(0, 0, 5000, "slw-nas.local"))

	packet = append(packet, pointer(instanceOffset)...)
	packet = appendRecordSuffix(packet, TypeTXT, 10, txtData("path=/"))

	hostOffset := len(packet)
	packet = append(packet, dnsName("slw-nas.local")...)
	packet = appendRecordSuffix(packet, TypeA, 10, net.ParseIP("192.168.1.10").To4())

	packet = append(packet, pointer(hostOffset)...)
	packet = appendRecordSuffix(packet, TypeAAAA, 10, net.ParseIP("fe80::265e:beff:fe69:a313").To16())

	if httpNameOffset == 0 {
		t.Fatal("offset guard")
	}

	msg, err := ParseMessage(packet)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msg.Records) != 5 {
		t.Fatalf("records=%d, want 5", len(msg.Records))
	}

	assertRecord(t, msg.Records[0], "_http._tcp.local", TypePTR)
	if msg.Records[0].PTR != "slw-nas._http._tcp.local" {
		t.Fatalf("PTR=%q", msg.Records[0].PTR)
	}
	if msg.Records[1].SRV == nil || msg.Records[1].SRV.Port != 5000 || msg.Records[1].SRV.Target != "slw-nas.local" {
		t.Fatalf("bad SRV: %+v", msg.Records[1].SRV)
	}
	if len(msg.Records[2].TXT) != 1 || msg.Records[2].TXT[0] != "path=/" {
		t.Fatalf("bad TXT: %#v", msg.Records[2].TXT)
	}
	if msg.Records[3].IP != "192.168.1.10" {
		t.Fatalf("bad A: %q", msg.Records[3].IP)
	}
	if msg.Records[4].IP != "fe80::265e:beff:fe69:a313" {
		t.Fatalf("bad AAAA: %q", msg.Records[4].IP)
	}
}

func TestParseMessageRejectsCompressionLoop(t *testing.T) {
	packet := dnsHeader(1)
	packet = append(packet, pointer(12)...)
	packet = appendRecordSuffix(packet, TypePTR, 10, dnsName("target.local"))

	if _, err := ParseMessage(packet); err == nil {
		t.Fatal("expected compression loop error")
	}
}

func assertRecord(t *testing.T, rec Record, name string, typ uint16) {
	t.Helper()
	if rec.Name != name {
		t.Fatalf("name=%q, want %q", rec.Name, name)
	}
	if rec.Type != typ {
		t.Fatalf("type=%d, want %d", rec.Type, typ)
	}
}

func dnsHeader(answerCount uint16) []byte {
	packet := make([]byte, 12)
	binary.BigEndian.PutUint16(packet[2:4], 0x8400)
	binary.BigEndian.PutUint16(packet[6:8], answerCount)
	return packet
}

func dnsName(name string) []byte {
	var out []byte
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			label := name[start:i]
			out = append(out, byte(len(label)))
			out = append(out, label...)
			start = i + 1
		}
	}
	return append(out, 0)
}

func pointer(offset int) []byte {
	return []byte{0xc0 | byte(offset>>8), byte(offset)}
}

func appendRecordSuffix(packet []byte, typ uint16, ttl uint32, data []byte) []byte {
	var suffix [10]byte
	binary.BigEndian.PutUint16(suffix[0:2], typ)
	binary.BigEndian.PutUint16(suffix[2:4], ClassIN)
	binary.BigEndian.PutUint32(suffix[4:8], ttl)
	binary.BigEndian.PutUint16(suffix[8:10], uint16(len(data)))
	packet = append(packet, suffix[:]...)
	return append(packet, data...)
}

func srvData(priority, weight, port uint16, target string) []byte {
	data := make([]byte, 6)
	binary.BigEndian.PutUint16(data[0:2], priority)
	binary.BigEndian.PutUint16(data[2:4], weight)
	binary.BigEndian.PutUint16(data[4:6], port)
	return append(data, dnsName(target)...)
}

func txtData(values ...string) []byte {
	var data []byte
	for _, value := range values {
		data = append(data, byte(len(value)))
		data = append(data, value...)
	}
	return data
}
