# mdnsmap Design

## Goal

Build a Golang CLI named `mdnsmap` that discovers mDNS-advertised assets for a user-provided IPv4 CIDR and TCP port range. The output must include at least IP, port, host, service, and a deep banner comparable to the prompt example.

## Scope

The tool uses mDNS discovery as the source of truth. It sends multicast DNS queries to `224.0.0.251:5353`, parses responses, and filters discovered services by CIDR and port range. It does not perform a full TCP connect scan of every address and port.

## CLI

Example:

```bash
go run ./cmd/mdnsmap --cidr 192.168.1.0/24 --ports 1-10000 --timeout 5s
```

Flags:

- `--cidr`: required IPv4 CIDR such as `192.168.1.0/24`.
- `--ports`: required port expression such as `80`, `80,443`, or `1-10000`.
- `--timeout`: optional scan wait duration, default `5s`.
- `--format`: optional output format. Initial implementation supports `text`.

## Discovery Behavior

The scanner sends queries for:

- `_services._dns-sd._udp.local`
- `_workstation._tcp.local`
- `_http._tcp.local`
- `_smb._tcp.local`
- `_qdiscover._tcp.local`
- `_device-info._tcp.local`
- `_afpovertcp._tcp.local`

The fixed service list is intentional for the initial implementation because it covers the prompt example and keeps behavior deterministic. The parser should still preserve additional PTR answers found in responses.

## Data Model

`Asset`:

- `IP string`
- `IPv6 []string`
- `Hostname string`
- `Services []Service`
- `PTRs []string`

`Service`:

- `Port int`
- `Proto string`
- `Type string`
- `Name string`
- `Hostname string`
- `TTL uint32`
- `TXT []string`
- `Banner string`

Banner construction includes:

- `Name=<instance name>` when known.
- `IPv4=<ip>` when known.
- `IPv6=<ip>` for each IPv6 address when known.
- `Hostname=<hostname>` when known.
- `TTL=<ttl>` when known.
- TXT key-value pairs in response order, for example `path=/`, `model=TS-X64`, `fwVer=5.2.9`.

## Protocol Parser

The implementation parses enough DNS wire format for mDNS responses:

- Header and section counts.
- Compressed domain names.
- Resource records in answer, authority, and additional sections.
- `PTR`, `SRV`, `TXT`, `A`, and `AAAA`.

Unsupported record types are skipped safely. Malformed packets return errors without crashing the scan.

## Output

Default text output groups services similarly to the prompt:

```text
services:
5000/tcp http: Name=slw-nas IPv4=192.168.1.10 IPv6=fe80::265e:beff:fe69:a313 Hostname=slw-nas.local TTL=10 path=/
445/tcp smb: Name=slw-nas IPv4=192.168.1.10 Hostname=slw-nas.local TTL=10
answers:
PTR: _http._tcp.local _smb._tcp.local
```

This format includes the required `ip`, `port`, `host`, and deep banner information through the service line.

## Error Handling

- Invalid CIDR or port expression exits with a clear message and non-zero status.
- UDP listen or multicast send failures exit with a clear message and non-zero status.
- Individual malformed responses are ignored after recording a debug-level parse error internally; the CLI remains usable for other responses.
- Empty discovery results print an empty `services:` block and still exit successfully.

## Tests

Unit tests cover:

- Port range parsing.
- CIDR filtering.
- DNS name compression parsing.
- Parsing synthetic mDNS responses containing PTR, SRV, TXT, A, and AAAA records.
- Banner construction at the depth required by the prompt example.
- Text output formatting.

Integration against real LAN devices is out of scope for automated tests because it depends on local network state.
