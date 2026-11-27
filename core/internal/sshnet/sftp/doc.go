// Package sftp 实现 XOps v2 基于纯 Go SFTP v3（draft-ietf-secsh-filexfer-02）与 OpenSSH 扩展的
// 远端安全文件系统出站适配器（ports.RemoteFSPort，ADR-008 / ADR-015 / ADR-016）。
//
// 核心安全、并发与协议边界不变量：
//   - 全包 0 裸 go 语句，所有读循环与取消看门狗均受 core/conc.Nursery 监督，关闭时确定性零协程泄漏；
//   - 经 dial.TransportConn.OpenSubsystem(ctx, "sftp") 建立的通道天然封装于 ADR-015 chanconn.WatchedConn
//     看门狗之下，黑洞对端或上下文取消时立即解阻而不破坏健康连接池；
//   - 严格遵守 ADR-016 SFTP v3 纵深防护边界：写路径与分片写一律禁止截断打开，先以非截断只读打开执行
//     SSH_FXP_FSTAT 校验文件类型与可选 (dev, ino) 锚点，再写入同目录随机临时文件并调用 fsync@openssh.com
//     与 posix-rename@openssh.com（NoClobber 优先采用内核原子 hardlink@openssh.com 或 SFTP v3 独占 RENAME）；
//   - 全包（含全部测试）严禁对 pathalg.RemotePath 调用 path/filepath.*，全部路径代数严格走标准库 path；
//   - 全包 0 行内 lint 豁免，零值 Client 恒失败关闭。
package sftp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial"
	"github.com/wentf9/xops-cli/core/ports"
)

const (
	// sftpProtocolVersion 表示客户端声明的 SFTP 协议主版本号（SFTP v3）。
	sftpProtocolVersion uint32 = 3
	// defaultChunkBytes 为未协商 limits@openssh.com 时的默认单次读写分片上限（32 KiB）。
	defaultChunkBytes = 32 * 1024
	// minChunkBytes 与 maxChunkBytes 约束单次 SFTP 读写分片的安全上下界。
	minChunkBytes = 4 * 1024
	maxChunkBytes = 256 * 1024
	// maxInboundPacketBytes 限制单个入站 SFTP 报文体最大字节数（4 MiB），防止恶意服务端触发 OOM。
	maxInboundPacketBytes = 4 * 1024 * 1024
	// maxReadDirEntries 为单目录枚举的防御性条目总数上限，避免恶意服务端无限循环应答耗尽内存。
	maxReadDirEntries = 1_000_000
	// extPosixRename / extHardlink / extFsync / extLimits 对应 OpenSSH sftp-server 标准扩展名。
	extPosixRename = "posix-rename@openssh.com"
	extHardlink    = "hardlink@openssh.com"
	extFsync       = "fsync@openssh.com"
	extLimits      = "limits@openssh.com"
	// extStatDev / extStatIno 为可选的扩展属性键，供支持 (dev, ino) 锚定的服务端透传设备号与 inode 号。
	extStatDev = "stat-dev@xops.dev"
	extStatIno = "stat-ino@xops.dev"
)

// Config 描述 SFTP 客户端的可选运行期调优与注入参数（零值即安全默认配置）。
type Config struct {
	// MaxPacketSize 可选覆写单次读写分片上限（字节），超出 [4 KiB, 256 KiB] 时自动钳位。
	MaxPacketSize int
	// Entropy 可选注入随机熵源用于生成同目录临时文件后缀；为空时回退 crypto/rand.Reader。
	Entropy ports.Entropy
	// WaitDone 可选绑定上游 SSH 传输断开通知通道（如 (*dial.TransportConn).WaitDone()），
	// 一旦底层传输关闭即刻终止客户端等待。
	WaitDone <-chan struct{}
}

// Open 在已认证的 *dial.TransportConn 上启动 "sftp" 子系统并返回满足 ports.RemoteFSPort 的客户端。
// 本函数签名与 dial.RemoteFSFactory 完全一致，可直接注入 dial.Config.OpenRemoteFS 供核心引擎装配。
func Open(ctx context.Context, conn *dial.TransportConn) (ports.RemoteFSPort, error) {
	if ctx == nil {
		return nil, ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if conn == nil || !conn.IsAlive() {
		return nil, ports.ErrClosed
	}
	wc, err := conn.OpenSubsystem(ctx, "sftp")
	if err != nil {
		return nil, err
	}
	client, err := OpenStream(ctx, wc, Config{WaitDone: conn.WaitDone()})
	if err != nil {
		_ = wc.Close()
		return nil, err
	}
	return client, nil
}

// OpenStream 在任意双向字节流（如 *chanconn.WatchedConn、net.Pipe 或多路复用子系统流）上完成
// SFTP v3 握手并构造不可变客户端；若握手失败，调用方仍负责或由本函数安全关闭错误路径上的内部状态。
func OpenStream(ctx context.Context, rw io.ReadWriteCloser, cfg Config) (*Client, error) {
	if ctx == nil {
		return nil, ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if rw == nil {
		return nil, domi18n.EF(ports.ErrInvalidArgument, domi18n.KeyCommonFieldNil, domi18n.Str("field", "SFTP stream"))
	}
	return newClient(ctx, rw, cfg)
}

func randomTempSuffix(entropy ports.Entropy) (string, error) {
	src := rand.Reader
	if entropy != nil {
		src = entropy
	}
	var raw [8]byte
	if _, err := io.ReadFull(src, raw[:]); err != nil {
		return "", domi18n.WrapS(ports.ErrEntropyShortRead, err, domi18n.KeyCommonOpFailed, domi18n.Str("op", "generate remote temp suffix"))
	}
	return ".xops-tmp-" + hex.EncodeToString(raw[:]), nil
}

func clampChunkSize(n int) int {
	if n <= 0 {
		return defaultChunkBytes
	}
	if n < minChunkBytes {
		return minChunkBytes
	}
	if n > maxChunkBytes {
		return maxChunkBytes
	}
	return n
}

func zeroVal[T any]() (z T) { return z }
