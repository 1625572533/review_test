package filter

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

type Ports map[int]struct{}

func ParsePorts(expr string) (Ports, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, fmt.Errorf("ports expression is required")
	}

	ports := Ports{}
	for _, part := range strings.Split(expr, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("empty port segment")
		}

		if strings.Contains(part, "-") {
			bounds := strings.Split(part, "-")
			if len(bounds) != 2 {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
			start, err := parsePort(bounds[0])
			if err != nil {
				return nil, err
			}
			end, err := parsePort(bounds[1])
			if err != nil {
				return nil, err
			}
			if start > end {
				return nil, fmt.Errorf("invalid descending port range %q", part)
			}
			for port := start; port <= end; port++ {
				ports[port] = struct{}{}
			}
			continue
		}

		port, err := parsePort(part)
		if err != nil {
			return nil, err
		}
		ports[port] = struct{}{}
	}

	return ports, nil
}

func (p Ports) Contains(port int) bool {
	_, ok := p[port]
	return ok
}

func parsePort(raw string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("invalid port %q", raw)
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("port out of range %d", port)
	}
	return port, nil
}

type CIDR struct {
	network *net.IPNet
}

func ParseCIDR(raw string) (CIDR, error) {
	ip, network, err := net.ParseCIDR(strings.TrimSpace(raw))
	if err != nil {
		return CIDR{}, err
	}
	if ip.To4() == nil {
		return CIDR{}, fmt.Errorf("only IPv4 CIDR is supported")
	}
	return CIDR{network: network}, nil
}

func (c CIDR) Contains(rawIP string) bool {
	if c.network == nil {
		return false
	}
	ip := net.ParseIP(strings.TrimSpace(rawIP))
	if ip == nil || ip.To4() == nil {
		return false
	}
	return c.network.Contains(ip)
}
