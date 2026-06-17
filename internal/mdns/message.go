package mdns

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

const (
	TypeA    uint16 = 1
	TypePTR  uint16 = 12
	TypeTXT  uint16 = 16
	TypeAAAA uint16 = 28
	TypeSRV  uint16 = 33

	ClassIN uint16 = 1
)

type Message struct {
	Records []Record
}

type Record struct {
	Name string
	Type uint16
	TTL  uint32
	PTR  string
	SRV  *SRV
	TXT  []string
	IP   string
}

type SRV struct {
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   string
}

func BuildQuery(service string) ([]byte, error) {
	name, err := encodeName(service)
	if err != nil {
		return nil, err
	}

	packet := make([]byte, 12, 12+len(name)+4)
	binary.BigEndian.PutUint16(packet[4:6], 1)
	packet = append(packet, name...)
	var question [4]byte
	binary.BigEndian.PutUint16(question[0:2], TypePTR)
	binary.BigEndian.PutUint16(question[2:4], ClassIN)
	return append(packet, question[:]...), nil
}

func ParseMessage(packet []byte) (Message, error) {
	if len(packet) < 12 {
		return Message{}, fmt.Errorf("dns packet too short")
	}

	qd := int(binary.BigEndian.Uint16(packet[4:6]))
	an := int(binary.BigEndian.Uint16(packet[6:8]))
	ns := int(binary.BigEndian.Uint16(packet[8:10]))
	ar := int(binary.BigEndian.Uint16(packet[10:12]))

	off := 12
	var err error
	for i := 0; i < qd; i++ {
		_, off, err = decodeName(packet, off)
		if err != nil {
			return Message{}, err
		}
		if off+4 > len(packet) {
			return Message{}, fmt.Errorf("truncated question")
		}
		off += 4
	}

	msg := Message{}
	for i := 0; i < an+ns+ar; i++ {
		var rec Record
		rec.Name, off, err = decodeName(packet, off)
		if err != nil {
			return Message{}, err
		}
		if off+10 > len(packet) {
			return Message{}, fmt.Errorf("truncated resource record")
		}
		rec.Type = binary.BigEndian.Uint16(packet[off : off+2])
		rec.TTL = binary.BigEndian.Uint32(packet[off+4 : off+8])
		rdLen := int(binary.BigEndian.Uint16(packet[off+8 : off+10]))
		off += 10
		if off+rdLen > len(packet) {
			return Message{}, fmt.Errorf("truncated resource data")
		}
		rdataStart := off
		rdataEnd := off + rdLen

		switch rec.Type {
		case TypePTR:
			rec.PTR, _, err = decodeName(packet, rdataStart)
		case TypeSRV:
			if rdLen < 6 {
				err = fmt.Errorf("truncated srv record")
				break
			}
			target, _, targetErr := decodeName(packet, rdataStart+6)
			if targetErr != nil {
				err = targetErr
				break
			}
			rec.SRV = &SRV{
				Priority: binary.BigEndian.Uint16(packet[rdataStart : rdataStart+2]),
				Weight:   binary.BigEndian.Uint16(packet[rdataStart+2 : rdataStart+4]),
				Port:     binary.BigEndian.Uint16(packet[rdataStart+4 : rdataStart+6]),
				Target:   target,
			}
		case TypeTXT:
			rec.TXT, err = decodeTXT(packet[rdataStart:rdataEnd])
		case TypeA:
			if rdLen == net.IPv4len {
				rec.IP = net.IP(packet[rdataStart:rdataEnd]).String()
			}
		case TypeAAAA:
			if rdLen == net.IPv6len {
				rec.IP = net.IP(packet[rdataStart:rdataEnd]).String()
			}
		}
		if err != nil {
			return Message{}, err
		}

		msg.Records = append(msg.Records, rec)
		off = rdataEnd
	}

	return msg, nil
}

func encodeName(name string) ([]byte, error) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" {
		return []byte{0}, nil
	}
	var out []byte
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("invalid dns label %q", label)
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0), nil
}

func decodeName(packet []byte, off int) (string, int, error) {
	var labels []string
	next := off
	jumped := false
	visited := map[int]struct{}{}

	for {
		if off < 0 || off >= len(packet) {
			return "", 0, fmt.Errorf("name offset out of range")
		}
		if _, ok := visited[off]; ok {
			return "", 0, fmt.Errorf("dns compression loop")
		}
		visited[off] = struct{}{}

		length := packet[off]
		if length&0xc0 == 0xc0 {
			if off+1 >= len(packet) {
				return "", 0, fmt.Errorf("truncated compression pointer")
			}
			ptr := int(binary.BigEndian.Uint16(packet[off:off+2]) & 0x3fff)
			if !jumped {
				next = off + 2
				jumped = true
			}
			off = ptr
			continue
		}
		if length&0xc0 != 0 {
			return "", 0, fmt.Errorf("unsupported dns label type")
		}
		off++
		if length == 0 {
			if !jumped {
				next = off
			}
			return strings.Join(labels, "."), next, nil
		}
		if off+int(length) > len(packet) {
			return "", 0, fmt.Errorf("truncated dns label")
		}
		labels = append(labels, string(packet[off:off+int(length)]))
		off += int(length)
		if !jumped {
			next = off
		}
	}
}

func decodeTXT(data []byte) ([]string, error) {
	var values []string
	for off := 0; off < len(data); {
		length := int(data[off])
		off++
		if off+length > len(data) {
			return nil, fmt.Errorf("truncated txt record")
		}
		values = append(values, string(data[off:off+length]))
		off += length
	}
	return values, nil
}
