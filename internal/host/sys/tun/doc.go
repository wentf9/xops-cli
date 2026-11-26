// Package tun 实现 XOps v2 本机 TUN/TAP 虚拟网卡出站适配器（ports.TUNDevicePort，ADR-002 / P4-T4）。
//
// 平台实现策略（严格按构建标签物理拆分，零不可达 runtime.GOOS 分支）：
//   - Linux（tun_linux.go）：受控直开 /dev/net/tun（O_RDWR|O_NONBLOCK|O_CLOEXEC）并经 TUNSETIFF 配置
//     IFF_TUN|IFF_NO_PI（L3）或 IFF_TAP|IFF_NO_PI（L2），底层 I/O 采用 unix.Poll + self-pipe 取消；
//   - macOS（tun_darwin.go）：基于 AF_SYSTEM / utun_control（L3 utun，自动封装/剥离 4 字节 AF 头），
//     L2 以太网模式显式失败关闭返回 ports.ErrUnsupported；
//   - Windows / FreeBSD 等其他平台（tun_other.go）：显式失败关闭返回 ports.ErrUnsupported。
package tun
