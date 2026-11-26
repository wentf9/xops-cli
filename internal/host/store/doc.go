// Package store 实现 XOps v2 本机配置与传输 WAL 持久化适配器及统一配置导入器
// （ports.InventoryStore、ports.JournalStore、ports.FormatImporter，ADR-006 / ADR-007）。
//
// 核心工程与安全不变量：
//   - YAML vNext 持久化强制锁定 schema version: 2（100% 零 v1 迁移、读取或兼容垫片代码），
//     解码强制开启 KnownFields(true) 并拒绝多文档尾随垃圾、重复键与非法/零值字段；
//   - 全包持久化 DTO 严禁裸用 time.Duration，所有时长统一使用 core/domain/algebraic.Duration；
//   - 所有磁盘读写与锁协调严格经由 ports.ScopedRootFS + core/osfs 完成，写锁一律加在同目录
//     旁路锁文件 <name>.lock，绝不对数据文件本身加锁后再执行 Root.Rename（兼容 Windows 共享语义）；
//   - 双代 WAL JournalStore 为每条记录附加 CRC32-IEEE 校验并结合 TransferJournalRecord 自校验摘要，
//     单侧损坏严格按世代隔离并保留损坏前有效前缀（PartialRecords），支撑 10 GiB 传输安全恢复；
//   - 全包零裸 os.*、零裸 go 语句、零 init()、零可变包级 var、零 nolint 抑制指令。
package store

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/ports"
)

const (
	// SchemaVersionV2 是 XOps v2 YAML vNext 唯一接受的配置版本号（100% 零 v1 兼容）。
	SchemaVersionV2 = 2

	defaultConfigFileName    = "config.yaml"
	defaultJournalDirName    = "journals"
	storeDirPerm             = fs.FileMode(0o700)
	storeFilePerm            = fs.FileMode(0o600)
	defaultMaxConfigBytes    = int64(8 << 20)  // 默认配置单文件读取上限 8 MiB
	maxAllowedConfigBytes    = int64(32 << 20) // 配置读取硬上限 32 MiB
	defaultMaxJournalBytes   = int64(16 << 20) // 默认单世代 WAL 文件读取上限 16 MiB
	maxAllowedJournalBytes   = int64(64 << 20) // 单世代 WAL 文件硬上限 64 MiB
	defaultMaxImportBytes    = int64(8 << 20)  // 默认导入流读取上限 8 MiB
	maxAllowedImportBytes    = int64(32 << 20) // 导入流硬上限 32 MiB
	defaultMaxCSVRecords     = 10000           // 单次 CSV 导入最大记录行数上限
	walFrameVersionPrefix    = "v1:"
	walCRC32HexLen           = 8
	emptyRevisionTokenPrefix = "v2-0-empty"
)

// 本包导出的规范化哨兵错误，供调用方与诊断层以 errors.Is 精确区分配置/WAL/导入故障。
var (
	// ErrUnsupportedSchemaVersion 表示配置文件缺失 version 字段或版本不是唯一合法的 version: 2。
	ErrUnsupportedSchemaVersion = errors.New("store: 不受支持的配置 schema 版本（仅支持 version: 2）")
	// ErrPlaintextSecretForbidden 表示输入中出现严禁持久化的明文密码/机密列或字段（ADR-006）。
	ErrPlaintextSecretForbidden = errors.New("store: 禁止在配置或导入源中携带明文密码或机密")
	// ErrInvalidCSV 表示 CSV 导入流格式非法、列结构错误或缺失有效记录。
	ErrInvalidCSV = errors.New("store: CSV 导入格式或记录字段非法")
	// ErrCorruptJournalFrame 表示 WAL 单行帧头、CRC32 校验和或载荷完整性校验失败。
	ErrCorruptJournalFrame = errors.New("store: WAL 记录帧格式或 CRC32 校验失败")
)

// InventoryStoreSpec 是构造 YAMLInventoryStore（ports.InventoryStore）的显式入参规格。
type InventoryStoreSpec struct {
	// ScopedFS 为必选沙箱文件系统端口（生产注入 osfs.NewScopedRootFS()）。
	ScopedFS ports.ScopedRootFS
	// RootDir 为必选私有状态根目录（通常为 ~/.xops）。
	RootDir pathalg.LocalDir
	// ConfigFile 可选覆盖配置文件相对路径（默认 "config.yaml"）。
	ConfigFile algebraic.Option[pathalg.LocalRootedDest]
	// MaxFileBytes 限制配置文件读取上限（0 使用默认 8 MiB，负数或超过硬上限失败关闭）。
	MaxFileBytes int64
}

// JournalStoreSpec 是构造 WALJournalStore（ports.JournalStore）的显式入参规格。
type JournalStoreSpec struct {
	// ScopedFS 为必选沙箱文件系统端口。
	ScopedFS ports.ScopedRootFS
	// RootDir 为必选私有状态根目录（通常为 ~/.xops）。
	RootDir pathalg.LocalDir
	// JournalDir 可选覆盖 WAL 子目录相对路径（默认 "journals"）。
	JournalDir algebraic.Option[pathalg.LocalRootedDest]
	// MaxFileBytes 限制单个世代 WAL 文件读取上限（0 使用默认 16 MiB，负数或超过硬上限失败关闭）。
	MaxFileBytes int64
}

// CSVImporterSpec 是构造 CSVImporter（ports.FormatImporter）的显式入参规格。
type CSVImporterSpec struct {
	// MaxImportBytes 限制单次导入流最大读取字节数（0 使用默认 8 MiB，负数或超上限失败关闭）。
	MaxImportBytes int64
	// DefaultPort 为 CSV 省略端口列时的默认端口（0 使用 22）。
	DefaultPort uint16
}

// OpenSSHImporterSpec 是构造 OpenSSHImporter（ports.FormatImporter）的显式入参规格。
type OpenSSHImporterSpec struct {
	// MaxImportBytes 限制单次导入流最大读取字节数（0 使用默认 8 MiB，负数或超上限失败关闭）。
	MaxImportBytes int64
	// LocalIdentity 可选提供本机身份信息以供 Match user / localuser 求值与缺省用户名回退。
	LocalIdentity algebraic.Option[ports.LocalIdentityInfo]
	// DefaultUser 可选提供当 OpenSSH Host 块未显式声明 User 时的回退用户名。
	DefaultUser algebraic.Option[option.Username]
}

func zeroVal[T any]() (z T) { return z }

func checkCtxReady(ctx context.Context, valid bool, name string) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !valid {
		return fmt.Errorf("%w: %s 未初始化", ports.ErrInvalidArgument, name)
	}
	return nil
}

func normalizeBoundedLimit(val, defVal, maxVal int64, label string) (int64, error) {
	if val == 0 {
		return defVal, nil
	}
	if val < 0 || val > maxVal {
		return 0, fmt.Errorf("%w: %s=%d 超出允许范围 (0..%d]", ports.ErrInvalidArgument, label, val, maxVal)
	}
	return val, nil
}

func resolveRootedPath(opt algebraic.Option[pathalg.LocalRootedDest], defRel, label string) (pathalg.LocalRootedDest, error) {
	if d, ok := opt.Get(); ok {
		if !d.IsValid() {
			return zeroVal[pathalg.LocalRootedDest](), fmt.Errorf("%w: %s 路径无效", ports.ErrInvalidArgument, label)
		}
		return d, nil
	}
	return pathalg.ParseLocalRootedDest(defRel)
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func readBoundedStream(r io.Reader, maxBytes int64) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maxBytes {
		return nil, fmt.Errorf("%w: 输入大小超过上限 %d 字节", ports.ErrLimitExceeded, maxBytes)
	}
	return raw, nil
}
