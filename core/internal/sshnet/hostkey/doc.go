// Package hostkey 实现 XOps v2 的 SSH 主机密钥信任库适配器（ports.HostTrustPort，INV-C5 / INV-E2）。
//
// 本包完全构建于 ports.ScopedRootFS 与 core/osfs 旁路锁原语之上：
//   - 严禁绕过 core/osfs 直接调用裸 os.Open/os.Rename 或 path/filepath；
//   - 单次核验/查询在共享旁路锁 <name>.lock 与 O_NOFOLLOW 约束下读取单一 known_hosts 快照，
//     拒绝符号链接、目录与特殊文件；
//   - 持久化写入在独占旁路锁 <name>.lock 内完成读-合并-原子替换（绝不对数据文件本身加锁后 Rename，
//     彻底规避 Windows ERROR_SHARING_VIOLATION）；
//   - 主机匹配严格按 netaddr.Endpoint (Host, Port) 隔离（INV-E2），支持 OpenSSH 明文、
//     通配符/否定模式、|1|<salt>|<hmac-sha1> 哈希条目、@revoked 吊销标记、
//     @cert-authority 主机证书验签（拒绝 TOFU 落盘原始证书）与可选 DNSSEC SSHFP。
package hostkey

import (
	"fmt"
	"io/fs"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/ports"
)

const (
	defaultKnownHostsFileName             = "known_hosts"
	defaultMaxKnownHostsBytes int64       = 16 << 20 // 单个 known_hosts 文件读取上限（16 MiB）
	knownHostsDirPerm         fs.FileMode = 0o700
	externalParentDirPerm     fs.FileMode = 0o755
	knownHostsFilePerm        fs.FileMode = 0o600
	sshHashSaltBytes                      = 20
)

// Config 描述 KnownHostsDB 的显式出站依赖与默认路径配置（全依赖注入，零隐式环境变量）。
type Config struct {
	// RootFS 是必填的沙箱本地文件系统端口，用于全部 O_NOFOLLOW 读取、旁路锁与原子替换。
	RootFS ports.ScopedRootFS
	// DefaultDir 是未显式指定 UserKnownHostsFile 时的默认沙箱根目录（如 ~/.ssh）。
	DefaultDir pathalg.LocalDir
	// DefaultFileName 是默认目录内的 known_hosts 文件名，留空时默认 "known_hosts"。
	DefaultFileName string
	// HomeDir 可选提供本机主目录，用于展开 UserKnownHostsFile 中的 "~/" 或 "%d" 模板。
	HomeDir algebraic.Option[pathalg.LocalDir]
	// MaxFileBytes 可选指定单个 known_hosts 文件的读取字节上限，<= 0 时默认 16 MiB。
	MaxFileBytes int64
	// SSHFPLookup 可选注入 DNS SSHFP 只读查询端口（仅信任 Authenticated==true 的 DNSSEC 记录）。
	SSHFPLookup ports.SSHFPLookupPort
	// HashHostnames 为 true 时，RecordHostKey 以 OpenSSH |1|<salt>|<hmac-sha1> 哈希格式写入主机名。
	HashHostnames bool
	// Entropy 在 HashHostnames 为 true 时提供显式密码学随机字节，用于生成 20 字节哈希盐。
	Entropy ports.Entropy
	// Clock 可选注入时钟端口，用于校验 @cert-authority SSH 主机证书有效期；为 nil 时回退真实 UTC 时钟。
	Clock ports.Clock
}

// KnownHostsDB 是基于单旁路锁 O_NOFOLLOW known_hosts 快照的 ports.HostTrustPort 生产实现。
// 零值恒未初始化且所有方法均严格失败关闭。
//
//xops:opaque
//xops:failclosed
type KnownHostsDB struct {
	rootFS        ports.ScopedRootFS
	defaultDir    pathalg.LocalDir
	defaultDest   pathalg.LocalRootedDest
	homeDir       algebraic.Option[pathalg.LocalDir]
	readLimits    ports.ReadLimits
	sshfpLookup   ports.SSHFPLookupPort
	hashHostnames bool
	entropy       ports.Entropy
	clock         ports.Clock
	valid         bool
}

// NewKnownHostsDB 校验配置依赖、默认目录/文件名、读取上限及可选哈希熵源并构造不可变 KnownHostsDB。
func NewKnownHostsDB(cfg Config) (*KnownHostsDB, error) {
	if cfg.RootFS == nil {
		return nil, fmt.Errorf("%w: RootFS 不能为 nil", ports.ErrInvalidArgument)
	}
	if !cfg.DefaultDir.IsValid() {
		return nil, fmt.Errorf("%w: DefaultDir 必须有效", ports.ErrInvalidArgument)
	}
	if home, ok := cfg.HomeDir.Get(); ok && !home.IsValid() {
		return nil, fmt.Errorf("%w: HomeDir 无效", ports.ErrInvalidArgument)
	}
	fileName := cfg.DefaultFileName
	if fileName == "" {
		fileName = defaultKnownHostsFileName
	}
	defaultDest, err := pathalg.ParseLocalRootedDest(fileName)
	if err != nil {
		return nil, fmt.Errorf("%w: DefaultFileName %q 非法: %w", ports.ErrInvalidArgument, fileName, err)
	}
	maxBytes := cfg.MaxFileBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxKnownHostsBytes
	}
	limits, err := ports.NewReadLimits(maxBytes)
	if err != nil {
		return nil, err
	}
	if cfg.HashHostnames && cfg.Entropy == nil {
		return nil, fmt.Errorf("%w: 启用 HashHostnames 时必须注入 Entropy", ports.ErrInvalidArgument)
	}
	return &KnownHostsDB{
		rootFS:        cfg.RootFS,
		defaultDir:    cfg.DefaultDir,
		defaultDest:   defaultDest,
		homeDir:       cfg.HomeDir,
		readLimits:    limits,
		sshfpLookup:   cfg.SSHFPLookup,
		hashHostnames: cfg.HashHostnames,
		entropy:       cfg.Entropy,
		clock:         cfg.Clock,
		valid:         true,
	}, nil
}
