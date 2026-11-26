// Package secretservice 实现基于 Linux FreeDesktop Secret Service（D-Bus 协议，github.com/godbus/dbus/v5）
// 的本机凭据存储适配器（ADR-011 / P4-T4）。
//
// 安全与架构约束：
//   - 仅连接经注入的 ports.EnvPort 提供的本地 Unix 域 D-Bus 会话总线（拒绝 TCP、多地址与自动拉起）；
//   - 优先协商 dh-ietf1024-sha256-aes128-cbc-pkcs7 传输加密会话，并在服务端不支持 DH 时按策略支持 plain 回退；
//   - 全部明文机密消费受 tools/xopsvet/analyzers/secrettaint 的 vault/secretservice 窄钩子审计（0 //nolint:）。
package secretservice

import (
	"fmt"
	"net/url"
	"strings"
)

// ParseSessionBusUnixSocket 校验并解析 DBUS_SESSION_BUS_ADDRESS 为本地 Unix 套接字地址（拒绝 TCP 与多地址）。
func ParseSessionBusUnixSocket(address string) (string, error) {
	if !strings.HasPrefix(address, "unix:") || strings.Contains(address, ";") {
		return "", fmt.Errorf("仅允许单个本地 unix: D-Bus 地址")
	}
	var sock string
	for field := range strings.SplitSeq(strings.TrimPrefix(address, "unix:"), ",") {
		key, raw, ok := strings.Cut(field, "=")
		if !ok {
			return "", fmt.Errorf("D-Bus 地址字段非法")
		}
		val, err := url.PathUnescape(raw)
		if err != nil || val == "" || strings.ContainsRune(val, 0) {
			return "", fmt.Errorf("D-Bus 地址字段值非法")
		}
		next, err := applyDBusUnixField(sock, key, val)
		if err != nil {
			return "", err
		}
		sock = next
	}
	if sock == "" {
		return "", fmt.Errorf("D-Bus 地址缺少 path 或 abstract 字段")
	}
	return sock, nil
}

func applyDBusUnixField(cur, key, val string) (string, error) {
	switch key {
	case "path":
		if cur != "" || !strings.HasPrefix(val, "/") {
			return "", fmt.Errorf("D-Bus unix path 重复或非绝对路径")
		}
		return val, nil
	case "abstract":
		if cur != "" {
			return "", fmt.Errorf("D-Bus unix abstract 与 path 冲突")
		}
		return "\x00" + val, nil
	case "guid", "tmpdir", "runtime":
		return cur, nil
	default:
		return "", fmt.Errorf("不支持的 D-Bus 地址参数 %q", key)
	}
}
