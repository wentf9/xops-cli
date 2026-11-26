// Package offline 实现 XOps v2 离线加密 dirfd 凭据库适配器（ADR-007 / ADR-011 / ADR-016 / P4-T4）。
//
// 核心安全与架构特性：
//   - 算法栈：Argon2id（默认 3 轮 / 64 MiB / 1 线程，支持通过 vault/helper 隔离 KDF 子进程派生）
//     包装随机 32 字节 DEK，条目正文采用 XChaCha20-Poly1305 AEAD + 域分离 AAD 加密落盘；
//   - 零 v1 兼容/迁移代码：采用全新版本化 v2 格式（format_version=2）；
//   - 物理存储：100% 经由注入的 ports.ScopedRootFS（core/osfs *os.Root）与旁路文件锁（<name>.lock）
//     执行原子替换落盘，零裸 OS 文件调用；
//   - 零 unsafe / 零 reflect：确保 secrettaint/sinks_vault.go 的私有 cipher.AEAD 字段静态信任链完好无损。
package offline

import (
	"io/fs"
)

const (
	vaultFormatVersion             = 2
	vaultMetaFileName              = "vault.meta.json"
	vaultItemsDirName              = "items"
	vaultDirPerm       fs.FileMode = 0o700
	vaultFilePerm      fs.FileMode = 0o600
	vaultMetaMaxBytes  int64       = 64 * 1024
	vaultItemMaxBytes  int64       = 1 << 20
	vaultSaltBytes                 = 16
	vaultDEKBytes                  = 32
	vaultNonceBytes                = 24
	dekAAD                         = "xops-vault-v2:dek"
	itemAADPrefix                  = "xops-vault-v2:item:"
	defaultStoreName               = "offline"
)
