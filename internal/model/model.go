package model

type Asset struct {
	IP       string
	IPv6     []string
	Hostname string
	Services []Service
	PTRs     []string
}

type Service struct {
	Port     int
	Proto    string
	Type     string
	Name     string
	Hostname string
	TTL      uint32
	TXT      []string
	Banner   string
}
