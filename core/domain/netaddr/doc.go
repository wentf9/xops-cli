// Package netaddr 提供 XOps v2 纯函数领域核使用的网络主机与端点值对象。
//
// 本包恪守 100% 纯数学与零副作用铁律（仅使用 net/netip，严禁导入 net、os、sync 或 context），
// 提供三个职责正交、全字段私有且零值失败关闭的规范化不透明值对象：
//   - CanonicalHost：经严格校验与规范化的网络主机（IPv4、保留区段与 IPv4-mapped 区分的 RFC 5952 IPv6、
//     小写 RFC 1123 DNS 主机名）；
//   - HostPort：协议无关的严格 (CanonicalHost, Port) 组合，端口必须显式指定于 [1, 65535] 且禁止前导零；
//   - Endpoint：面向 SSH 目标、Tier-4 OpenSSH 作用域（INV-E2）与 known_hosts 的规范化连接端点，
//     在 ParseEndpoint 省略端口时显式补全默认 SSH 端口 22，同时拒绝显式 ":0" 等非法端口。
//
// 三个类型均以值接收者实现 encoding.TextAppender 与 encoding.TextMarshaler，并实现 encoding.TextUnmarshaler，
// 以原生支持 Go 1.27 encoding/json/v2 与 YAML 的确定性往返序列化。
package netaddr

import "errors"

// DefaultSSHPort 是 SSH 协议默认 TCP 端口（仅在 Endpoint 省略端口时由显式入口补全）。
const DefaultSSHPort uint16 = 22

// ErrInvalidHost 表示网络主机为空、包含控制/空白字符、IP 语法错误或不符合 RFC 1123 主机名规范。
var ErrInvalidHost = errors.New("netaddr: 无效的网络主机")

// ErrInvalidZone 表示 IPv6 区段标识（%zone）超长或不符合严格 ASCII 白名单规范。
var ErrInvalidZone = errors.New("netaddr: 无效的 IPv6 区段标识")

// ErrInvalidPort 表示 TCP 端口缺失、非十进制纯数字、含前导零或超出 [1, 65535] 合法范围。
var ErrInvalidPort = errors.New("netaddr: 无效的端口号")

// ErrInvalidHostPort 表示 HostPort 文本格式不合法（缺失显式端口、未加方括号的 IPv6 或主机/端口无效）。
var ErrInvalidHostPort = errors.New("netaddr: 无效的 HostPort")

// ErrInvalidEndpoint 表示 SSH Endpoint 构造参数或文本表示无效。
var ErrInvalidEndpoint = errors.New("netaddr: 无效的 SSH Endpoint")

// ErrNilReceiver 表示在 nil 指针接收者上调用反序列化方法。
var ErrNilReceiver = errors.New("netaddr: 反序列化目标接收者不能为 nil")
