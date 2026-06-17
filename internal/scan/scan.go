package scan

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"review_test/internal/filter"
	"review_test/internal/mdns"
	"review_test/internal/model"
)

var DefaultServices = []string{
	"_services._dns-sd._udp.local",
	"_workstation._tcp.local",
	"_http._tcp.local",
	"_smb._tcp.local",
	"_qdiscover._tcp.local",
	"_device-info._tcp.local",
	"_afpovertcp._tcp.local",
}

type Scanner struct {
	Timeout  time.Duration
	Services []string
}

func (s Scanner) Scan(ctx context.Context, cidr filter.CIDR, ports filter.Ports) ([]model.Asset, error) {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	services := s.Services
	if len(services) == 0 {
		services = DefaultServices
	}

	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	dst := &net.UDPAddr{IP: net.ParseIP("224.0.0.251"), Port: 5353}
	for _, service := range services {
		query, err := mdns.BuildQuery(service)
		if err != nil {
			return nil, err
		}
		if _, err := conn.WriteToUDP(query, dst); err != nil {
			return nil, err
		}
	}

	deadline := time.Now().Add(timeout)
	_ = conn.SetReadDeadline(deadline)
	var messages []mdns.Message
	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return AssetsFromMessages(messages, cidr, ports), nil
		default:
		}

		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				break
			}
			return nil, err
		}
		msg, err := mdns.ParseMessage(buf[:n])
		if err == nil {
			messages = append(messages, msg)
		}
	}

	return AssetsFromMessages(messages, cidr, ports), nil
}

func AssetsFromMessages(messages []mdns.Message, cidr filter.CIDR, ports filter.Ports) []model.Asset {
	instances := map[string]*instanceInfo{}
	hostIPv4 := map[string]string{}
	hostIPv6 := map[string][]string{}
	ptrSet := map[string]struct{}{}

	for _, msg := range messages {
		for _, rec := range msg.Records {
			switch rec.Type {
			case mdns.TypePTR:
				if rec.PTR == "" {
					continue
				}
				ptrSet[rec.Name] = struct{}{}
				info := getInstance(instances, rec.PTR)
				info.instance = rec.PTR
				info.service = serviceType(rec.Name)
				info.name = instanceName(rec.PTR, rec.Name)
				if rec.TTL > 0 {
					info.ttl = rec.TTL
				}
			case mdns.TypeSRV:
				if rec.SRV == nil {
					continue
				}
				info := getInstance(instances, rec.Name)
				info.instance = rec.Name
				if info.service == "" {
					info.service = serviceTypeFromInstance(rec.Name)
				}
				if info.name == "" {
					info.name = instanceBaseName(rec.Name)
				}
				info.port = int(rec.SRV.Port)
				info.host = rec.SRV.Target
				if rec.TTL > 0 {
					info.ttl = rec.TTL
				}
			case mdns.TypeTXT:
				info := getInstance(instances, rec.Name)
				info.instance = rec.Name
				if info.service == "" {
					info.service = serviceTypeFromInstance(rec.Name)
				}
				if info.name == "" {
					info.name = instanceBaseName(rec.Name)
				}
				info.txt = append(info.txt, rec.TXT...)
				if rec.TTL > 0 {
					info.ttl = rec.TTL
				}
			case mdns.TypeA:
				if rec.IP != "" {
					hostIPv4[rec.Name] = rec.IP
				}
			case mdns.TypeAAAA:
				if rec.IP != "" {
					hostIPv6[rec.Name] = appendUnique(hostIPv6[rec.Name], rec.IP)
				}
			}
		}
	}

	assetsByKey := map[string]*model.Asset{}
	for _, info := range instances {
		if info.port == 0 || !ports.Contains(info.port) || info.host == "" {
			continue
		}
		ip := hostIPv4[info.host]
		if ip == "" || !cidr.Contains(ip) {
			continue
		}
		key := ip
		asset := assetsByKey[key]
		if asset == nil {
			asset = &model.Asset{
				IP:       ip,
				IPv6:     append([]string(nil), hostIPv6[info.host]...),
				Hostname: info.host,
			}
			assetsByKey[key] = asset
		}
		service := model.Service{
			Port:     info.port,
			Proto:    "tcp",
			Type:     info.service,
			Name:     info.name,
			Hostname: info.host,
			TTL:      info.ttl,
			TXT:      append([]string(nil), info.txt...),
		}
		service.Banner = BuildBanner(*asset, service)
		asset.Services = append(asset.Services, service)
	}

	var ptrs []string
	for ptr := range ptrSet {
		ptrs = append(ptrs, ptr)
	}
	sort.Strings(ptrs)

	var assets []model.Asset
	for _, asset := range assetsByKey {
		sort.Strings(asset.IPv6)
		asset.PTRs = append([]string(nil), ptrs...)
		sort.Slice(asset.Services, func(i, j int) bool {
			if asset.Services[i].Port != asset.Services[j].Port {
				return asset.Services[i].Port < asset.Services[j].Port
			}
			return asset.Services[i].Type < asset.Services[j].Type
		})
		assets = append(assets, *asset)
	}
	sort.Slice(assets, func(i, j int) bool {
		return assets[i].IP < assets[j].IP
	})
	return assets
}

func BuildBanner(asset model.Asset, service model.Service) string {
	var parts []string
	if service.Name != "" {
		parts = append(parts, "Name="+service.Name)
	}
	if asset.IP != "" {
		parts = append(parts, "IPv4="+asset.IP)
	}
	for _, ip := range asset.IPv6 {
		parts = append(parts, "IPv6="+ip)
	}
	if service.Hostname != "" {
		parts = append(parts, "Hostname="+service.Hostname)
	} else if asset.Hostname != "" {
		parts = append(parts, "Hostname="+asset.Hostname)
	}
	if service.TTL > 0 {
		parts = append(parts, fmt.Sprintf("TTL=%d", service.TTL))
	}
	parts = append(parts, service.TXT...)
	return strings.Join(parts, " ")
}

func getInstance(instances map[string]*instanceInfo, key string) *instanceInfo {
	info := instances[key]
	if info == nil {
		info = &instanceInfo{}
		instances[key] = info
	}
	return info
}

type instanceInfo struct {
	instance string
	service  string
	name     string
	ttl      uint32
	port     int
	host     string
	txt      []string
}

func serviceType(name string) string {
	name = strings.TrimSuffix(name, ".")
	parts := strings.Split(name, ".")
	if len(parts) == 0 {
		return name
	}
	return strings.TrimPrefix(parts[0], "_")
}

func serviceTypeFromInstance(instance string) string {
	parts := strings.Split(strings.TrimSuffix(instance, "."), ".")
	for i, part := range parts {
		if strings.HasPrefix(part, "_") && i+1 < len(parts) && parts[i+1] == "_tcp" {
			return strings.TrimPrefix(part, "_")
		}
	}
	return ""
}

func instanceName(instance, service string) string {
	suffix := "." + strings.TrimSuffix(service, ".")
	return strings.TrimSuffix(strings.TrimSuffix(instance, "."), suffix)
}

func instanceBaseName(instance string) string {
	parts := strings.Split(strings.TrimSuffix(instance, "."), ".")
	if len(parts) == 0 {
		return instance
	}
	return parts[0]
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
