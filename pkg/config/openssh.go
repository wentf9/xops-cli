package config

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/models"
)

const (
	OpenSSHNodePrefix = "openssh:"
	maxIncludeDepth   = 16
)

// OpenSSHParser 提供针对 ~/.ssh/config 的解析和模型映射功能
type OpenSSHParser struct {
	cfg *sshConfigDoc
	err error
}

// NewBrokenOpenSSHParser returns an OpenSSHParser that records a load or parse
// failure so callers falling back to OpenSSH fail closed rather than silently degrading.
func NewBrokenOpenSSHParser(err error) *OpenSSHParser {
	return &OpenSSHParser{err: err}
}

// Err returns the load or parse error recorded on p, if any.
func (p *OpenSSHParser) Err() error {
	if p == nil {
		return nil
	}
	return p.err
}

// NewOpenSSHParser 尝试从标准路径加载用户的 ~/.ssh/config 配置文件。
// 如果文件不存在，返回空的 OpenSSHParser 和 nil 错误；其他错误返回具体包装错误。
func NewOpenSSHParser() (*OpenSSHParser, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("get user home directory failed: %w", err)
	}
	userConfigPath := filepath.Join(homeDir, ".ssh", "config")
	return NewOpenSSHParserFromPath(userConfigPath)
}

// NewOpenSSHParserFromPath 从指定路径加载 SSH 配置文件。如果文件不存在，返回空的 OpenSSHParser 和 nil 错误。
func NewOpenSSHParserFromPath(path string) (parser *OpenSSHParser, retErr error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &OpenSSHParser{cfg: nil}, nil
		}
		return nil, fmt.Errorf("open ssh config %q failed: %w", path, err)
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil && !errors.Is(closeErr, os.ErrClosed) {
			retErr = errors.Join(retErr, fmt.Errorf("close ssh config %q failed: %w", path, closeErr))
		}
	}()

	cfg, decodeErr := decodeOpenSSHConfig(f, path)
	if decodeErr != nil {
		return nil, fmt.Errorf("decode ssh config %q failed: %w", path, decodeErr)
	}
	return &OpenSSHParser{cfg: cfg}, nil
}

// NewOpenSSHParserFromReader 从任意 io.Reader 加载 SSH 配置
func NewOpenSSHParserFromReader(r io.Reader) (*OpenSSHParser, error) {
	if r == nil {
		return &OpenSSHParser{cfg: nil}, nil
	}
	cfg, err := decodeOpenSSHReader(r)
	if err != nil {
		return nil, fmt.Errorf("decode ssh config failed: %w", err)
	}
	return &OpenSSHParser{cfg: cfg}, nil
}

// WithOpenSSHConfigOverride returns a read-only ConfigProvider whose OpenSSH
// configuration is overridden by configPath:
//   - "" returns base unchanged;
//   - "none" (case-insensitive) attaches an empty OpenSSHParser so ~/.ssh/config is skipped;
//   - Any other path loads that file via NewOpenSSHParserFromPath and returns an
//     explicit error if the file does not exist or cannot be read.
func WithOpenSSHConfigOverride(base ConfigProvider, configPath string) (ConfigProvider, error) {
	if configPath == "" {
		return base, nil
	}
	var parser *OpenSSHParser
	if strings.EqualFold(strings.TrimSpace(configPath), "none") {
		parser = &OpenSSHParser{cfg: nil}
	} else {
		info, err := os.Stat(configPath)
		if err != nil {
			return nil, fmt.Errorf("open ssh config %q failed: %w", configPath, err)
		}
		if info.IsDir() {
			return nil, fmt.Errorf("open ssh config %q failed: path is a directory", configPath)
		}
		parser, err = NewOpenSSHParserFromPath(configPath)
		if err != nil {
			return nil, err
		}
	}
	var (
		snap    *Configuration
		origins map[string]OpenSSHOrigin
	)
	if base != nil {
		if src, ok := base.(interface {
			snapshotWithOrigins() (*Configuration, map[string]OpenSSHOrigin)
		}); ok {
			snap, origins = src.snapshotWithOrigins()
		} else {
			snap = base.Snapshot()
		}
	}
	repo, err := NewRepositoryWithOpenSSHParser(snap, readOnlyRejectStore{}, parser)
	if err != nil {
		return nil, fmt.Errorf("create ephemeral ssh config override provider: %w", err)
	}
	if snap != nil && snap.Nodes != nil {
		if origins != nil {
			for nodeID, origin := range origins {
				if _, exists := snap.Nodes.Get(nodeID); exists && !origin.IsZero() {
					repo.provider.setSavedNodeOpenSSHMetadataIfPresent(nodeID, origin.Alias, origin.CanonicalHost)
				}
			}
		} else if base != nil {
			for _, nodeID := range snap.Nodes.Keys() {
				baseNode, ok := base.GetNode(nodeID)
				if !ok {
					continue
				}
				if baseNode.OpenSSHAlias != "" || baseNode.CanonicalHost != "" {
					repo.provider.setSavedNodeOpenSSHMetadataIfPresent(nodeID, baseNode.OpenSSHAlias, baseNode.CanonicalHost)
				}
			}
		}
	}
	return &openSSHOverrideProvider{ConfigProvider: repo, repo: repo}, nil
}

type readOnlyRejectStore struct{}

func (readOnlyRejectStore) Load() (*Configuration, error) {
	return nil, errors.New("read-only OpenSSH override store does not support Load")
}

func (readOnlyRejectStore) Save(*Configuration) error {
	return errors.New("read-only OpenSSH override store does not support Save")
}

type openSSHOverrideProvider struct {
	ConfigProvider
	repo *Repository
}

func (p *openSSHOverrideProvider) PrepareNodeContext(ctx context.Context, opts EnsureNodeOptions) (EnsureNodeResult, error) {
	return p.repo.PrepareNodeContext(ctx, opts)
}

func (p *openSSHOverrideProvider) ResolveConnectionWithOrigin(nodeID, originalHost string) (ConnectionSnapshot, error) {
	return p.repo.ResolveConnectionWithOrigin(nodeID, originalHost)
}

func (p *openSSHOverrideProvider) GetOpenSSHParser() *OpenSSHParser {
	return p.repo.GetOpenSSHParser()
}

func (p *openSSHOverrideProvider) snapshotWithOrigins() (*Configuration, map[string]OpenSSHOrigin) {
	if p == nil || p.repo == nil {
		return cloneConfiguration(nil), nil
	}
	return p.repo.snapshotWithOrigins()
}

func (p *openSSHOverrideProvider) NodeOpenSSHOrigin(nodeID string) OpenSSHOrigin {
	return p.repo.NodeOpenSSHOrigin(nodeID)
}

func (p *openSSHOverrideProvider) SetNodeOpenSSHOrigin(nodeID string, origin OpenSSHOrigin) {
	p.repo.SetNodeOpenSSHOrigin(nodeID, origin)
}

func (p *openSSHOverrideProvider) ClearNodeOpenSSHOrigin(nodeID string) {
	p.repo.ClearNodeOpenSSHOrigin(nodeID)
}

func (p *openSSHOverrideProvider) SetNodeOpenSSHAlias(nodeID, alias string) {
	p.repo.SetNodeOpenSSHAlias(nodeID, alias)
}

func (p *openSSHOverrideProvider) NodeOpenSSHAlias(nodeID string) string {
	return p.repo.NodeOpenSSHAlias(nodeID)
}

func (p *openSSHOverrideProvider) SetNodeCanonicalHost(nodeID, canonicalHost string) {
	p.repo.SetNodeCanonicalHost(nodeID, canonicalHost)
}

func (p *openSSHOverrideProvider) NodeCanonicalHost(nodeID string) string {
	return p.repo.NodeCanonicalHost(nodeID)
}

// ConfirmNodeContext is a no-op on the read-only override provider so ephemeral
// pending nodes prepared under -F are never persisted to disk.
func (*openSSHOverrideProvider) ConfirmNodeContext(context.Context, string) error {
	return nil
}

func (p *openSSHOverrideProvider) PendingNodeExecution(string) (*ssh.ExecutionConfig, bool) {
	return nil, false
}

// ConfirmNodeWithExecutionContext is a no-op on the read-only override provider
// so post-authentication enrollment probing under -F never attempts Save on
// readOnlyRejectStore.
func (*openSSHOverrideProvider) ConfirmNodeWithExecutionContext(context.Context, string, *ssh.ExecutionConfig) error {
	return nil
}

func (*openSSHOverrideProvider) UpdateAuthAtVersionContext(_ context.Context, _, authVersion, _, _, _ string) (string, error) {
	return authVersion, nil
}

func (*openSSHOverrideProvider) UpdateSudoAtVersionContext(_ context.Context, _, sudoVersion string, _ models.SudoMode, _ string) (string, error) {
	return sudoVersion, nil
}

// OpenSSHOriginalHost extracts the effective original host (%n) for an
// "openssh:" virtual node ID by stripping OpenSSHNodePrefix and decomposing
// composite user@host[:port] specs into their host token.
func OpenSSHOriginalHost(nodeID string) (string, bool) {
	if !strings.HasPrefix(nodeID, OpenSSHNodePrefix) {
		return "", false
	}
	clean := strings.TrimSpace(strings.TrimPrefix(nodeID, OpenSSHNodePrefix))
	if clean == "" {
		return "", false
	}
	if parsedHost, _, _, err := parseOpenSSHHostSpec(clean); err == nil && parsedHost != "" {
		return parsedHost, true
	}
	return clean, true
}

// UnwrapOpenSSHSelector extracts the host/alias token from an optional
// "openssh:" virtual selector (including disambiguated "openssh:user@alias:port"),
// or returns the trimmed input unchanged if it does not carry OpenSSHNodePrefix.
func UnwrapOpenSSHSelector(selector string) string {
	trimmed := strings.TrimSpace(selector)
	if orig, ok := OpenSSHOriginalHost(trimmed); ok {
		return orig
	}
	if strings.HasPrefix(trimmed, OpenSSHNodePrefix) {
		return ""
	}
	return trimmed
}

// Find 尝试在 ssh_config 中寻找匹配的主机名
// 如果用户输入了未知主机，我们一律返回带前缀的虚拟 NodeID，
// 在连接时利用 ssh_config 的默认回退属性来尝试连接，
// 这样使得 xops 表现得和原生 ssh 命令的体验完全一致。
func (p *OpenSSHParser) Find(alias string) (string, bool) {
	if alias == "" {
		return "", false
	}
	// xops 内部可能传入全名诸如 "user@host:port" 给 provider 检索，
	// 这些复合物并不是原生的 ssh_config Host (除非极罕见被定义成这样)。
	// 为了不妨碍后续拆分逻辑和别名正确分配，我们过滤掉含有 @ 和 : 的别名。
	if strings.Contains(alias, "@") || strings.Contains(alias, ":") {
		return "", false
	}
	return OpenSSHNodePrefix + alias, true
}

// HasHost 检查 alias 是否在 ssh_config（含 Include 子配置）中显式定义了具体的 Host 模式（排除仅通配符匹配与否定排除）。
func (p *OpenSSHParser) HasHost(alias string) bool {
	if p == nil || p.cfg == nil || alias == "" {
		return false
	}
	cleanAlias := strings.TrimSpace(strings.TrimPrefix(alias, OpenSSHNodePrefix))
	if cleanAlias == "" {
		return false
	}
	lookupAlias, _, _, err := parseOpenSSHHostSpec(cleanAlias)
	if err != nil {
		lookupAlias = cleanAlias
	}
	if lookupAlias == "" {
		return false
	}
	found := false
	walkMatchingSSHConfigBlocks(p.cfg, lookupAlias, func(block *sshConfigBlock) bool {
		if block.matchesConcretePattern(lookupAlias) {
			found = true
			return false
		}
		return true
	})
	return found
}

func hasControlOrLineSepChar(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return true
		}
	}
	return false
}

func unwrapExpandedHostName(rawHostName, expanded string) string {
	clean := StripHostBrackets(expanded)
	rawTrimmed := strings.TrimSpace(rawHostName)
	if len(rawTrimmed) >= 2 && rawTrimmed[0] == '[' && rawTrimmed[len(rawTrimmed)-1] == ']' &&
		strings.Contains(rawTrimmed, "%") &&
		len(clean) >= 2 && clean[0] == '[' && clean[len(clean)-1] == ']' {
		inner := strings.TrimSpace(clean[1 : len(clean)-1])
		if inner != "" {
			if ip, err := netip.ParseAddr(inner); err != nil || ip.Is6() {
				return inner
			}
		}
	}
	return clean
}

func resolveOpenSSHHostName(doc *sshConfigDoc, alias string) (string, error) {
	rawHostName := firstSSHConfigKeyValue(doc, alias, "HostName")
	if rawHostName == "" {
		if hasControlOrLineSepChar(alias) {
			return "", fmt.Errorf("HostName %q contains invalid control characters", alias)
		}
		unwrapped := StripHostBrackets(alias)
		if unwrapped == "" {
			return "", errors.New("HostName cannot be empty")
		}
		return unwrapped, nil
	}
	expanded, err := ssh.ExpandHostName(rawHostName, alias)
	if err != nil {
		return "", err
	}
	return unwrapExpandedHostName(rawHostName, expanded), nil
}

// FindConcreteHostsByAddress returns concrete Host pattern names in ssh_config
// whose resolved HostName matches address and (when port > 0) whose resolved
// Port matches port.
func (p *OpenSSHParser) FindConcreteHostsByAddress(address string, port uint16) []string {
	if p == nil || p.cfg == nil {
		return nil
	}
	cleanAddr := StripHostBrackets(address)
	if cleanAddr == "" {
		return nil
	}
	var matches []string
	walkConcreteSSHHostNames(p.cfg, func(name string) bool {
		cleanHost, expErr := resolveOpenSSHHostName(p.cfg, name)
		if expErr != nil || !SameHostAddress(cleanHost, cleanAddr) {
			return true
		}
		if port > 0 {
			portStr := p.getVal(name, "Port", "22")
			parsedPort, parseErr := strconv.ParseUint(strings.TrimSpace(portStr), 10, 16)
			if parseErr != nil || uint16(parsedPort) != port {
				return true
			}
		}
		matches = append(matches, name)
		return true
	})
	return matches
}

// GetVirtualNode 根据 alias 从 ssh_config 生成运行时的内存 Node / Host / Identity
func (p *OpenSSHParser) GetVirtualNode(alias string) (models.Node, models.Host, models.Identity, error) {
	return p.GetVirtualNodeWithCanonical(alias, "")
}

// GetVirtualNodeWithCanonical evaluates ssh_config across Pass 1 (originalAlias)
// and Pass 2 (canonicalHost) when canonicalHost differs from originalAlias.
func (p *OpenSSHParser) GetVirtualNodeWithCanonical(originalAlias, canonicalHost string) (models.Node, models.Host, models.Identity, error) {
	if p == nil {
		p = &OpenSSHParser{cfg: nil}
	}
	if p.err != nil {
		return models.Node{}, models.Host{}, models.Identity{}, p.err
	}
	lookupAlias, userOverride, portOverride, err := parseOpenSSHHostSpec(originalAlias)
	if err != nil {
		return models.Node{}, models.Host{}, models.Identity{}, fmt.Errorf("parse openssh host %q failed: %w", originalAlias, err)
	}
	return p.getVirtualNodeWithCanonical(lookupAlias, canonicalHost, userOverride, portOverride, originalAlias)
}

func (p *OpenSSHParser) resolveVirtualHostAndPasses(lookupAlias, canonicalHost string) ([]string, string, error) {
	cleanCanon := StripHostBrackets(canonicalHost)
	passes := []string{lookupAlias}
	if cleanCanon == "" || strings.EqualFold(cleanCanon, lookupAlias) {
		hostName, err := resolveOpenSSHHostName(p.cfg, lookupAlias)
		return passes, hostName, err
	}
	passes = append(passes, cleanCanon)
	if firstSSHConfigKeyValue(p.cfg, lookupAlias, "HostName") != "" {
		if hasControlOrLineSepChar(cleanCanon) {
			return nil, "", fmt.Errorf("HostName %q contains invalid control characters", cleanCanon)
		}
		return passes, cleanCanon, nil
	}
	hostName, err := resolveOpenSSHHostName(p.cfg, cleanCanon)
	return passes, hostName, err
}

func (p *OpenSSHParser) getVirtualNodeWithCanonical(
	lookupAlias, canonicalHost, userOverride string,
	portOverride uint16,
	nodeAlias string,
) (models.Node, models.Host, models.Identity, error) {
	if p == nil {
		p = &OpenSSHParser{cfg: nil}
	}
	if p.err != nil {
		return models.Node{}, models.Host{}, models.Identity{}, p.err
	}
	if hasControlOrLineSepChar(lookupAlias) {
		return models.Node{}, models.Host{}, models.Identity{}, fmt.Errorf("HostName %q contains invalid control characters", lookupAlias)
	}
	lookupAlias = strings.TrimSpace(lookupAlias)
	if lookupAlias == "" {
		return models.Node{}, models.Host{}, models.Identity{}, fmt.Errorf("parse openssh host %q failed: host is empty", nodeAlias)
	}
	nodeAlias = strings.TrimSpace(nodeAlias)
	if nodeAlias == "" {
		nodeAlias = lookupAlias
	}
	if hasControlOrLineSepChar(canonicalHost) {
		return models.Node{}, models.Host{}, models.Identity{}, fmt.Errorf("HostName %q contains invalid control characters", canonicalHost)
	}
	passes, hostName, expHostErr := p.resolveVirtualHostAndPasses(lookupAlias, canonicalHost)
	if expHostErr != nil {
		return models.Node{}, models.Host{}, models.Identity{}, expHostErr
	}

	user := firstSSHConfigKeyValuePasses(p.cfg, passes, "User")
	if user == "" {
		defUser, userErr := getCurrentUser()
		if userErr != nil {
			return models.Node{}, models.Host{}, models.Identity{}, userErr
		}
		user = defUser
	}
	portStr := strings.TrimSpace(firstSSHConfigKeyValuePasses(p.cfg, passes, "Port"))
	if portStr == "" {
		portStr = "22"
	}
	parsedPort, parseErr := strconv.ParseUint(portStr, 10, 16)
	if parseErr != nil || parsedPort == 0 {
		return models.Node{}, models.Host{}, models.Identity{}, fmt.Errorf("invalid port %q for %q in ssh config: must be between 1 and 65535", portStr, lookupAlias)
	}
	port := uint16(parsedPort)
	if userOverride != "" {
		user = userOverride
	}
	if portOverride != 0 {
		port = portOverride
	}

	identityFile, expErr := normalizeConfigIdentityKeyPath(firstSSHConfigKeyValuePasses(p.cfg, passes, "IdentityFile"))
	if expErr != nil {
		return models.Node{}, models.Host{}, models.Identity{}, expErr
	}

	_, proxyJump, _ := firstMatchingOpenSSHProxyPasses(p.cfg, passes)

	sshOpts, err := parseOpenSSHOptionsPasses(p.cfg, passes)
	if err != nil {
		return models.Node{}, models.Host{}, models.Identity{}, err
	}

	hostRef := FormatHostPort(hostName, port)
	identityRef := fmt.Sprintf("%s@%s", user, hostName)

	node := models.Node{
		HostRef:     hostRef,
		IdentityRef: identityRef,
		ProxyJump:   proxyJump,
		SudoMode:    models.SudoModeAuto, // 对于导入节点，依然支持 auto
		Tags:        []string{"openssh"}, // 打一个虚拟 tag
		Alias:       []string{nodeAlias},
		SSHOptions:  sshOpts,
	}

	host := models.Host{
		Address: hostName,
		Port:    port,
	}

	identity := models.Identity{
		User:     user,
		AuthType: "auto", // 我们会在 connector 中专门处理 auto 类型的增强 fallback 链
		KeyPath:  identityFile,
	}

	return node, host, identity, nil
}

// GetSSHOptions parses supported OpenSSH client options for a given alias/host in ssh_config.
func (p *OpenSSHParser) GetSSHOptions(alias string) (*ssh.Options, error) {
	return p.GetSSHOptionsWithCanonical(alias, "")
}

// GetSSHOptionsWithCanonical evaluates supported OpenSSH client options across
// Pass 1 (originalAlias) and Pass 2 (canonicalHost) when canonicalHost differs.
func (p *OpenSSHParser) GetSSHOptionsWithCanonical(originalAlias, canonicalHost string) (*ssh.Options, error) {
	if p != nil && p.err != nil {
		return nil, p.err
	}
	if p == nil || p.cfg == nil || originalAlias == "" {
		return nil, nil
	}
	cleanAlias := strings.TrimPrefix(originalAlias, OpenSSHNodePrefix)
	lookupAlias, _, _, err := parseOpenSSHHostSpec(cleanAlias)
	if err != nil {
		lookupAlias = cleanAlias
	}
	passes := []string{lookupAlias}
	cleanCanon := StripHostBrackets(canonicalHost)
	if cleanCanon != "" && !strings.EqualFold(cleanCanon, lookupAlias) {
		passes = append(passes, cleanCanon)
	}
	return parseOpenSSHOptionsPasses(p.cfg, passes)
}

// GetControlConfig parses multiplexing options for a given alias/host in ssh_config.
func (p *OpenSSHParser) GetControlConfig(alias string) (*ssh.ControlConfig, error) {
	opts, err := p.GetSSHOptions(alias)
	if err != nil || opts == nil {
		return nil, err
	}
	return opts.ControlConfig(), nil
}

func parseOpenSSHOptions(doc *sshConfigDoc, host string) (*ssh.Options, error) {
	return parseOpenSSHOptionsPasses(doc, []string{host})
}

func parseOpenSSHOptionsPasses(doc *sshConfigDoc, passes []string) (*ssh.Options, error) {
	if doc == nil || len(passes) == 0 {
		return nil, nil
	}
	opts := &ssh.Options{}
	for _, spec := range ssh.RegisteredOptionSpecs() {
		if err := applyOpenSSHSpecOptionPasses(doc, passes, spec, opts); err != nil {
			return nil, err
		}
	}
	if opts.IsEmpty() {
		return nil, nil
	}
	return opts, nil
}

func applyOpenSSHSpecOptionPasses(doc *sshConfigDoc, passes []string, spec ssh.OptionSpec, opts *ssh.Options) error {
	// Trust-class options (StrictHostKeyChecking, UserKnownHostsFile) are never
	// inherited from ~/.ssh/config so wildcard host blocks cannot implicitly
	// weaken host key verification. Only one-way HashKnownHosts=yes is allowed.
	if spec.Class == ssh.OptionClassTrust && !isAllowedOpenSSHTrustOption(spec.CanonicalKey) {
		return nil
	}
	if spec.MultiValue {
		rawVals := allMatchingOpenSSHOptionsPasses(doc, passes, spec)
		if spec.CanonicalKey == ssh.OptionSetEnv {
			// OpenSSH evaluates only the first matching SetEnv directive
			// in ssh_config (and retains the first occurrence per key inside it).
			// Even if that first directive is invalid, lower blocks must not apply.
			if len(rawVals) > 0 {
				_ = opts.Append(spec.CanonicalKey, rawVals[0])
			}
			return nil
		}
		for _, rawVal := range rawVals {
			if err := opts.Append(spec.CanonicalKey, rawVal); err != nil {
				// Leniently skip invalid or unsupported multi-value entries
				// (e.g. malformed multi-value entries).
				continue
			}
		}
		return nil
	}
	val, skip := resolveOpenSSHSingleOptionPasses(doc, passes, spec)
	if skip || val == "" {
		return nil
	}
	if spec.Class == ssh.OptionClassTrust {
		trimmedTrust := strings.TrimSpace(val)
		if !strings.EqualFold(trimmedTrust, "yes") && !strings.EqualFold(trimmedTrust, "true") {
			return nil
		}
	}
	if spec.AllowList {
		filtered := ssh.FilterSupportedListValue(spec.CanonicalKey, val)
		if filtered == "" {
			return nil
		}
		val = filtered
	}
	if err := opts.Set(spec.CanonicalKey, val); err != nil {
		// Preserve strict error reporting on ControlMaster and ControlPersist,
		// while leniently skipping unsupported ~/.ssh/config values (e.g.
		// ControlPath tokens like %k or PubkeyAuthentication=unbound).
		if spec.CanonicalKey == ssh.OptionControlMaster || spec.CanonicalKey == ssh.OptionControlPersist {
			hostLabel := passes[0]
			return fmt.Errorf("invalid %s %q for %q in ssh config: %w", spec.OpenSSHName, val, hostLabel, err)
		}
	}
	return nil
}

func preservesSSHConfigRawValue(canonicalKey string) bool {
	switch canonicalKey {
	case ssh.OptionProxyCommand,
		ssh.OptionLocalCommand,
		ssh.OptionRemoteCommand,
		ssh.OptionSendEnv,
		ssh.OptionSetEnv,
		ssh.OptionLocalForward,
		ssh.OptionRemoteForward,
		ssh.OptionDynamicForward:
		return true
	default:
		return false
	}
}

func sshConfigOptionValue(d *sshConfigDirective, canonicalKey string) string {
	if d == nil {
		return ""
	}
	if preservesSSHConfigRawValue(canonicalKey) {
		return d.rawValue
	}
	return d.value
}

// allMatchingOpenSSHOptions resolves all entries for a multi-value option strictly
// top-to-bottom across matching ssh_config Host blocks (including Include files),
// matching OpenSSH readconf.c evaluation order for SendEnv, IdentityFile, SetEnv, etc.
func allMatchingOpenSSHOptionsPasses(doc *sshConfigDoc, passes []string, spec ssh.OptionSpec) []string {
	if doc == nil || len(passes) == 0 {
		return nil
	}
	keys := make([]string, 0, 1+len(spec.Aliases))
	keys = append(keys, spec.OpenSSHName)
	keys = append(keys, spec.Aliases...)

	multiPass := len(passes) > 1
	dedupAcrossPasses := multiPass &&
		(spec.CanonicalKey == ssh.OptionIdentityFile || spec.CanonicalKey == ssh.OptionCertificateFile)
	var seen map[string]struct{}
	if dedupAcrossPasses {
		seen = make(map[string]struct{})
	}
	var seenDirectives map[*sshConfigDirective]struct{}
	if multiPass {
		seenDirectives = make(map[*sshConfigDirective]struct{})
	}
	var matches []string
	walkMatchingSSHConfigDirectivesPasses(doc, passes, func(passIndex int, _ string, d *sshConfigDirective) bool {
		if seenDirectives != nil && d != nil {
			if passIndex == 0 {
				seenDirectives[d] = struct{}{}
			} else if _, already := seenDirectives[d]; already {
				return true
			}
		}
		for _, candidate := range keys {
			if strings.EqualFold(d.key, candidate) {
				if v := sshConfigOptionValue(d, spec.CanonicalKey); v != "" {
					if dedupAcrossPasses {
						if _, ok := seen[v]; ok {
							break
						}
						seen[v] = struct{}{}
					}
					matches = append(matches, v)
				}
				break
			}
		}
		return true
	})
	return matches
}

// isAllowedOpenSSHTrustOption reports whether a trust-class option may be inherited
// (one-way security-preserving) from ssh_config.
func isAllowedOpenSSHTrustOption(canonicalKey string) bool {
	return strings.EqualFold(strings.TrimSpace(canonicalKey), "hash_known_hosts")
}

func resolveOpenSSHSingleOptionPasses(doc *sshConfigDoc, passes []string, spec ssh.OptionSpec) (val string, skip bool) {
	if spec.CanonicalKey == ssh.OptionProxyCommand {
		var winner string
		winner, _, val = firstMatchingOpenSSHProxyPasses(doc, passes)
		if winner == "proxyjump" {
			return "", true
		}
		return val, false
	}
	return firstMatchingOpenSSHOptionPasses(doc, passes, spec), false
}

func firstMatchingOpenSSHOptionPasses(doc *sshConfigDoc, passes []string, spec ssh.OptionSpec) string {
	keys := make([]string, 0, 1+len(spec.Aliases))
	keys = append(keys, spec.OpenSSHName)
	keys = append(keys, spec.Aliases...)
	return firstSSHConfigKeyValueRawPasses(doc, passes, preservesSSHConfigRawValue(spec.CanonicalKey), keys...)
}

func parseOpenSSHHostSpec(spec string) (host, userName string, port uint16, err error) {
	host, userName, port, _, err = parseTargetRefPlain(spec)
	return host, userName, port, err
}

// getVal 是封装获取的方法
func (p *OpenSSHParser) getVal(alias, key, defaultVal string) string {
	if p == nil || p.cfg == nil {
		return defaultVal
	}
	val := firstSSHConfigKeyValue(p.cfg, alias, key)
	if val == "" {
		return defaultVal
	}
	return val
}

var currentUserFn = func() (string, error) {
	currUser, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("get current user failed: %w", err)
	}
	return currUser.Username, nil
}

// 辅助函数
func getCurrentUser() (string, error) {
	return currentUserFn()
}

func expandHomeDir(path string) (string, error) {
	if len(path) == 0 || path[0] != '~' {
		return path, nil
	}
	sep := strings.IndexAny(path[1:], `/\`)
	var userPart, rest string
	if sep < 0 {
		userPart = path[1:]
	} else {
		userPart = path[1 : 1+sep]
		rest = path[1+sep+1:]
	}
	var home string
	if userPart == "" {
		var err error
		home, err = os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("expand home dir failed: %w", err)
		}
	} else {
		u, err := user.Lookup(userPart)
		if err != nil || u == nil || u.HomeDir == "" {
			return path, nil
		}
		home = u.HomeDir
	}
	if rest == "" {
		return home, nil
	}
	return filepath.Join(home, rest), nil
}

func normalizeConfigIdentityKeyPath(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || strings.EqualFold(trimmed, "none") {
		return "", nil
	}
	if strings.Contains(trimmed, "%") || strings.Contains(trimmed, "${") {
		return "", nil
	}
	expanded, err := expandHomeDir(trimmed)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(expanded, "~") {
		return "", nil
	}
	return expanded, nil
}

func parseOpenSSHProxyJump(raw string) string {
	if raw == "" || strings.EqualFold(strings.TrimSpace(raw), "none") {
		return ""
	}
	hops := strings.Split(raw, ",")
	var parsedHops []string
	for _, rawHop := range hops {
		hop := strings.TrimSpace(rawHop)
		if hop == "" || strings.EqualFold(hop, "none") {
			continue
		}
		parsedHops = append(parsedHops, OpenSSHNodePrefix+hop)
	}
	return strings.Join(parsedHops, ",")
}

// firstMatchingOpenSSHProxy resolves ProxyJump and ProxyCommand in OpenSSH
// first-match-wins order across matching Host blocks (including Include files),
// including "none" stopping further search for that directive.
func firstMatchingOpenSSHProxy(doc *sshConfigDoc, host string) (winner, proxyJump, proxyCommand string) {
	return firstMatchingOpenSSHProxyPasses(doc, []string{host})
}

func firstMatchingOpenSSHProxyPasses(doc *sshConfigDoc, passes []string) (winner, proxyJump, proxyCommand string) {
	if doc == nil || len(passes) == 0 {
		return "", "", ""
	}
	var sawJump, sawCmd bool
	var jumpVal, cmdVal string
	walkMatchingSSHConfigDirectivesPasses(doc, passes, func(_ int, _ string, d *sshConfigDirective) bool {
		switch d.lowerKey {
		case "proxyjump":
			v := d.value
			if v == "" {
				return true
			}
			if !sawJump {
				sawJump = true
				jumpVal = v
				if winner == "" && ssh.HasActiveProxyJump(v) {
					winner = "proxyjump"
				}
			}
		case "proxycommand":
			v := d.rawValue
			if v == "" {
				return true
			}
			if !sawCmd {
				sawCmd = true
				cmdVal = v
				if winner == "" {
					if strings.EqualFold(v, "none") {
						winner = "none"
					} else {
						winner = "proxycommand"
					}
				}
			}
		}
		return !sawJump || !sawCmd
	})
	switch winner {
	case "proxyjump":
		return winner, parseOpenSSHProxyJump(jumpVal), ""
	case "proxycommand":
		return winner, "", cmdVal
	default:
		if sawCmd {
			return winner, "", cmdVal
		}
		return "", "", ""
	}
}
