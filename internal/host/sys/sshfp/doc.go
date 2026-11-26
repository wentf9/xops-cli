// Package sshfp 实现 XOps v2 DNS SSHFP（RFC 4255 / RFC 6594）只读查询出站适配器（ports.SSHFPLookupPort，P4-T4）。
//
// 安全与协议特性：
//   - 零外部网络依赖：内置边界严密检查的纯 Go RFC 1035 / EDNS0（UDP=1232, DO=1）DNS 客户端，
//     支持 UDP 首选与 TC=1 截断自动回退 TCP 以及 CNAME 链跟随（最多 8 跳防环）；
//   - 严格失败关闭 DNSSEC 认证语义：仅当应答置位 AD=1 且解析器配置信任本地校验解析器（TrustAD=true，
//     如 Unix /etc/resolv.conf 显式配置 options trust-ad 或显式注入配置）时，SSHFPRecord.Authenticated() 才为 true；
//   - 零 osboundary 豁免：Unix 通过注入的 ports.OperatorReadFS 读取 /etc/resolv.conf，
//     Windows 通过 golang.org/x/sys/windows.GetAdaptersAddresses 枚举活跃网卡 DNS 服务器。
package sshfp

import "time"

const (
	dnsHeaderBytes      = 12
	dnsTypeCNAME        = 5
	dnsTypeOPT          = 41
	dnsTypeSSHFP        = 44
	dnsClassIN          = 1
	dnsEDNSUDPPayload   = 1232
	dnsFlagRD           = 0x0100
	dnsFlagQR           = 0x8000
	dnsFlagTC           = 0x0200
	dnsFlagAD           = 0x0020
	dnsRcodeMask        = 0x000f
	dnsRcodeNoError     = 0
	dnsRcodeNXDomain    = 3
	dnsEDNSDOBit        = 0x8000
	maxDNSServers       = 3
	maxDNSNameJumps     = 16
	maxCNAMEHops        = 8
	maxDNSTCPMessageLen = 65535
	defaultPerTryWait   = 2 * time.Second
)
