// Package openssh 实现 XOps v2 本机只读 OpenSSH 配置适配器（ports.OpenSSHConfigSource，ADR-004）。
//
// 核心工程与安全不变量：
//   - 所有 ~/.ssh/config 与递归 Include 文件读取严格通过 ports.OperatorReadFS 完成，
//     glob 目录枚举仅通过可选 ports.ScopedRootFS 执行，全包零裸 os.Open / os.ReadDir 与零 //nolint:；
//   - 递归 Include 强制执行祖先路径环路检测、最大嵌套深度上限、最大文件数上限与单文件字节上限；
//   - 单份配置（含递归 Include）中全部命中的 Host / Match 块指令严格按遭遇序自上而下经
//     option.OptionLayer.ApplyParsedOption 折叠进同一个 t4 OptionLayer，绝不按块构造再
//     FoldOptionLayers，确保 SendEnv / -PATTERN 与 IdentityFile 封口序与 ssh -G 完全一致；
//   - Match exec 与未知 Match 条件严格失败关闭（永不执行外部命令、永不静默放行）。
package openssh

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/ports"
)

const (
	defaultMaxFileBytes     int64 = 4 << 20  // 单个 OpenSSH 配置文件默认上限 4 MiB
	maxAllowedFileBytes     int64 = 32 << 20 // 单个 OpenSSH 配置文件硬上限 32 MiB
	defaultMaxIncludeDepth        = 16       // 默认递归 Include 最大深度
	maxAllowedIncludeDepth        = 32       // 递归 Include 硬上限
	defaultMaxIncludedFiles       = 256      // 默认单次加载最多 Include 文件数
	maxAllowedIncludedFiles       = 1024     // Include 文件数硬上限
)

// 本包导出的规范化哨兵错误，供上层以 errors.Is 精确识别 OpenSSH 配置故障。
var (
	// ErrIncludeCycle 表示 OpenSSH Include 存在直接或间接循环引用。
	ErrIncludeCycle = errors.New("openssh: 检测到 Include 循环引用")
	// ErrIncludeDepthExceeded 表示 OpenSSH Include 嵌套深度超过安全上限。
	ErrIncludeDepthExceeded = errors.New("openssh: Include 嵌套深度超出上限")
	// ErrInvalidConfig 表示 OpenSSH 配置文件语法或已注册选项值非法。
	ErrInvalidConfig = errors.New("openssh: 无效的 OpenSSH 配置文件或指令")
)

// SourceSpec 是构造只读 OpenSSHConfigSource 的显式入参规格。
type SourceSpec struct {
	// ConfigPath 指定主配置文件路径（如 ~/.ssh/config）；必须有效。
	ConfigPath pathalg.LocalSourcePath
	// IncludeBaseDir 指定相对 Include 路径的解析基准目录；未提供时回退至 ConfigPath.Dir()。
	IncludeBaseDir algebraic.Option[pathalg.LocalDir]
	// HomeDir 指定展开 Include 中 ~/ 前缀的本机主目录；留空时尝试取 LocalIdentity.HomeDir()。
	HomeDir string
	// LocalIdentity 指定本机用户/主机元信息，用于 Match user / localuser 判定（可选）。
	LocalIdentity algebraic.Option[ports.LocalIdentityInfo]
	// Reader 为必选的操作员只读源端口，承载所有实际文件读取。
	Reader ports.OperatorReadFS
	// ScopedFS 为沙箱目录端口，用于在 Include 含通配符时安全枚举目录项（零裸 os.ReadDir）；
	// 若配置中出现通配符 Include 而 ScopedFS 为 nil，则严格失败关闭返回 ports.ErrInvalidArgument。
	ScopedFS ports.ScopedRootFS
	// SymlinkPolicy 控制读取配置文件时的符号链接策略（零值为最严 SymlinkReject）。
	SymlinkPolicy pathalg.SymlinkPolicy
	// MaxFileBytes 限制单文件最大读取字节数（0 使用默认 4 MiB，负数失败关闭）。
	MaxFileBytes int64
	// MaxIncludeDepth 限制递归 Include 最大深度（0 使用默认 16，负数失败关闭）。
	MaxIncludeDepth int
	// MaxIncludedFiles 限制单次展开最多加载的配置文件总数（0 使用默认 256，负数失败关闭）。
	MaxIncludedFiles int
}

// ConfigSource 实现 ports.OpenSSHConfigSource，提供 ~/.ssh/config 只读虚拟节点列举与 Tier-4 选项折叠。
// 其零值恒无效并失败关闭；所有配置均在每次调用时实时只读解析，不持有可变全局缓存。
//
//xops:opaque
//xops:failclosed
type ConfigSource struct {
	configPath       pathalg.LocalSourcePath
	includeBaseDir   pathalg.LocalDir
	homeDir          string
	localIdentity    algebraic.Option[ports.LocalIdentityInfo]
	reader           ports.OperatorReadFS
	scopedFS         ports.ScopedRootFS
	symlinkPolicy    pathalg.SymlinkPolicy
	maxFileBytes     int64
	maxIncludeDepth  int
	maxIncludedFiles int
	valid            bool
}

// NewConfigSource 严格校验所有入参边界后构造只读 OpenSSH ConfigSource。
func NewConfigSource(spec SourceSpec) (*ConfigSource, error) {
	if !spec.ConfigPath.IsValid() || spec.Reader == nil || !spec.SymlinkPolicy.IsValid() {
		return nil, fmt.Errorf("%w: ConfigPath、Reader 或 SymlinkPolicy 无效", ports.ErrInvalidArgument)
	}
	baseDir, err := resolveIncludeBaseDir(spec.ConfigPath, spec.IncludeBaseDir)
	if err != nil {
		return nil, err
	}
	if id, ok := spec.LocalIdentity.Get(); ok && !id.IsValid() {
		return nil, fmt.Errorf("%w: LocalIdentity 无效", ports.ErrInvalidArgument)
	}
	maxBytes, maxDepth, maxFiles, err := normalizeSourceLimits(spec)
	if err != nil {
		return nil, err
	}
	home := strings.TrimSpace(spec.HomeDir)
	if home == "" {
		if id, ok := spec.LocalIdentity.Get(); ok {
			home = id.HomeDir()
		}
	}
	return &ConfigSource{
		configPath:       spec.ConfigPath,
		includeBaseDir:   baseDir,
		homeDir:          home,
		localIdentity:    spec.LocalIdentity,
		reader:           spec.Reader,
		scopedFS:         spec.ScopedFS,
		symlinkPolicy:    spec.SymlinkPolicy,
		maxFileBytes:     maxBytes,
		maxIncludeDepth:  maxDepth,
		maxIncludedFiles: maxFiles,
		valid:            true,
	}, nil
}

func zeroVal[T any]() (z T) { return z }

func resolveIncludeBaseDir(cfgPath pathalg.LocalSourcePath, optBase algebraic.Option[pathalg.LocalDir]) (pathalg.LocalDir, error) {
	if base, ok := optBase.Get(); ok {
		if !base.IsValid() {
			return zeroVal[pathalg.LocalDir](), fmt.Errorf("%w: IncludeBaseDir 无效", ports.ErrInvalidArgument)
		}
		return base, nil
	}
	dir := cfgPath.Dir()
	if !dir.IsValid() {
		return zeroVal[pathalg.LocalDir](), fmt.Errorf("%w: 无法推导 ConfigPath 所在目录", ports.ErrInvalidArgument)
	}
	return dir, nil
}

func normalizeSourceLimits(spec SourceSpec) (maxBytes int64, maxDepth, maxFiles int, err error) {
	maxBytes = spec.MaxFileBytes
	if maxBytes == 0 {
		maxBytes = defaultMaxFileBytes
	}
	if maxBytes < 0 || maxBytes > maxAllowedFileBytes {
		return 0, 0, 0, fmt.Errorf("%w: MaxFileBytes=%d 超出范围", ports.ErrInvalidArgument, spec.MaxFileBytes)
	}
	maxDepth = spec.MaxIncludeDepth
	if maxDepth == 0 {
		maxDepth = defaultMaxIncludeDepth
	}
	if maxDepth < 0 || maxDepth > maxAllowedIncludeDepth {
		return 0, 0, 0, fmt.Errorf("%w: MaxIncludeDepth=%d 超出范围", ports.ErrInvalidArgument, spec.MaxIncludeDepth)
	}
	maxFiles = spec.MaxIncludedFiles
	if maxFiles == 0 {
		maxFiles = defaultMaxIncludedFiles
	}
	if maxFiles < 0 || maxFiles > maxAllowedIncludedFiles {
		return 0, 0, 0, fmt.Errorf("%w: MaxIncludedFiles=%d 超出范围", ports.ErrInvalidArgument, spec.MaxIncludedFiles)
	}
	return maxBytes, maxDepth, maxFiles, nil
}

// ListVirtualHosts 实时只读扫描主配置与无条件 Include，按首次出现顺序列举全部具体 Host 别名虚拟节点。
// 若主配置文件不存在则返回空切片与 nil；其他 I/O、策略或语法故障均严格失败关闭。
func (s *ConfigSource) ListVirtualHosts(ctx context.Context) ([]ports.OpenSSHVirtualHost, error) {
	if err := s.checkReady(ctx); err != nil {
		return nil, err
	}
	doc, exists, err := s.loadRootDocument(ctx)
	if err != nil || !exists {
		return nil, err
	}
	aliases := collectConcreteAliases(doc)
	if len(aliases) == 0 {
		return nil, nil
	}
	out := make([]ports.OpenSSHVirtualHost, 0, len(aliases))
	for _, cand := range aliases {
		vh, vErr := s.buildVirtualHost(doc, cand)
		if vErr != nil {
			return nil, vErr
		}
		out = append(out, vh)
	}
	return out, nil
}

// ResolveTier4 针对显式原始主机 target 与可选规范端点 endpoint，
// 将配置树中所有命中的指令自上而下经 ApplyParsedOption 折叠进单一 t4 OptionLayer 并返回。
func (s *ConfigSource) ResolveTier4(ctx context.Context, target option.OriginalHostSpec, endpoint algebraic.Option[netaddr.Endpoint]) (option.OptionLayer, error) {
	if err := s.checkReady(ctx); err != nil {
		return option.UnsetOptionLayer(), err
	}
	if !target.IsValid() {
		return option.UnsetOptionLayer(), fmt.Errorf("%w: target OriginalHostSpec 无效", ports.ErrInvalidArgument)
	}
	if ep, hasEP := endpoint.Get(); hasEP && !ep.IsValid() {
		return option.UnsetOptionLayer(), fmt.Errorf("%w: endpoint 无效", ports.ErrInvalidArgument)
	}
	doc, exists, err := s.loadRootDocument(ctx)
	if err != nil || !exists {
		return option.UnsetOptionLayer(), err
	}
	return s.evaluateDocument(doc, target, endpoint)
}

func (s *ConfigSource) checkReady(ctx context.Context) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || !s.valid {
		return fmt.Errorf("%w: OpenSSH ConfigSource 未初始化", ports.ErrInvalidArgument)
	}
	return nil
}

func (s *ConfigSource) buildVirtualHost(doc *parsedFile, cand aliasCandidate) (ports.OpenSSHVirtualHost, error) {
	layer, err := s.evaluateDocument(doc, cand.origHost, algebraic.None[netaddr.Endpoint]())
	if err != nil {
		return zeroVal[ports.OpenSSHVirtualHost](), err
	}
	ep := deriveVirtualHostEndpoint(cand.origHost, layer)
	return ports.NewOpenSSHVirtualHost(ports.OpenSSHVirtualHostSpec{
		Alias:      cand.alias,
		SourceFile: cand.sourceFile,
		Endpoint:   ep,
		User:       layer.User(),
		Proxy:      layer.Proxy(),
		Layer:      layer,
	})
}

func deriveVirtualHostEndpoint(orig option.OriginalHostSpec, layer option.OptionLayer) algebraic.Option[netaddr.Endpoint] {
	var host netaddr.CanonicalHost
	var hasHost bool
	if hnSpec, ok := layer.HostName().Get(); ok {
		if resolved, err := hnSpec.ResolveHostFor(orig); err == nil {
			host, hasHost = resolved, true
		}
	} else if canon, ok := orig.CanonicalHost(); ok {
		host, hasHost = canon, true
	}
	if !hasHost {
		return algebraic.None[netaddr.Endpoint]()
	}
	port := layer.Port().OrElse(netaddr.DefaultSSHPort)
	ep, err := netaddr.NewEndpoint(host, port)
	if err != nil {
		return algebraic.None[netaddr.Endpoint]()
	}
	return algebraic.Some(ep)
}
