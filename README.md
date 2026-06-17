# review_test
面试题目

## mdnsmap

`mdnsmap` 是一个 Golang 编写的 mDNS 资产测绘 CLI。它向局域网 mDNS 组播地址 `224.0.0.251:5353` 查询常见服务类型，解析响应中的 `PTR`、`SRV`、`TXT`、`A`、`AAAA` 记录，并按输入的 IPv4 网段和端口范围过滤输出。

### 使用方式

```bash
go run ./cmd/mdnsmap --cidr 192.168.1.0/24 --ports 1-10000 --timeout 5s
```

参数：

- `--cidr`：必填，IPv4 CIDR，例如 `192.168.1.0/24`
- `--ports`：必填，端口表达式，例如 `80`、`80,443`、`1-10000`
- `--timeout`：可选，等待 mDNS 响应的时间，默认 `5s`
- `--format`：可选，目前支持 `text`

### 输出示例

```text
services:
445/tcp smb: Name=slw-nas IPv4=192.168.1.10 Hostname=slw-nas.local TTL=10
5000/tcp http: Name=slw-nas IPv4=192.168.1.10 IPv6=fe80::265e:beff:fe69:a313 Hostname=slw-nas.local TTL=10 path=/
5000/tcp qdiscover: Name=slw-nas IPv4=192.168.1.10 IPv6=fe80::265e:beff:fe69:a313 Hostname=slw-nas.local TTL=10 accessType=https model=TS-X64 fwVer=5.2.9
answers:
PTR: _http._tcp.local _qdiscover._tcp.local _smb._tcp.local
```

说明：mDNS 发现依赖当前局域网内设备主动响应。如果目标设备或网络环境禁用了 mDNS，输出可能为空。
