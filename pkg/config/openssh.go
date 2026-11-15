package config

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/kevinburke/ssh_config"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/models"
)

const (
	OpenSSHNodePrefix            = "openssh:"
	maxIncludeDepth              = 16
	openSSHIncludePlaceholderKey = "__xops_include__"
)

// OpenSSHParser 提供针对 ~/.ssh/config 的解析和模型映射功能
type OpenSSHParser struct {
	cfg *ssh_config.Config
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
	var snap *Configuration
	if base != nil {
		snap = base.Snapshot()
	}
	repo, err := NewRepositoryWithOpenSSHParser(snap, readOnlyRejectStore{}, parser)
	if err != nil {
		return nil, fmt.Errorf("create ephemeral ssh config override provider: %w", err)
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

func (p *openSSHOverrideProvider) GetOpenSSHParser() *OpenSSHParser {
	return p.repo.GetOpenSSHParser()
}

func (p *openSSHOverrideProvider) SetNodeOpenSSHAlias(nodeID, alias string) {
	p.repo.SetNodeOpenSSHAlias(nodeID, alias)
}

func (p *openSSHOverrideProvider) NodeOpenSSHAlias(nodeID string) string {
	return p.repo.NodeOpenSSHAlias(nodeID)
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
	walkMatchingSSHConfigHostBlocks(p.cfg, lookupAlias, func(block *ssh_config.Host) bool {
		if hostBlockMatchesConcretePattern(block, lookupAlias) {
			found = true
			return false
		}
		return true
	})
	return found
}

func hostBlockMatchesConcretePattern(block *ssh_config.Host, lookupAlias string) bool {
	if block == nil || lookupAlias == "" || !block.Matches(lookupAlias) {
		return false
	}
	for _, pattern := range block.Patterns {
		if pattern == nil {
			continue
		}
		pat := pattern.String()
		if isConcreteSSHHost(pat) && pat == lookupAlias {
			return true
		}
	}
	return false
}

// FindConcreteHostsByAddress returns concrete Host pattern names in ssh_config
// whose resolved HostName matches address and (when port > 0) whose resolved
// Port matches port.
func (p *OpenSSHParser) FindConcreteHostsByAddress(address string, port uint16) []string {
	if p == nil || p.cfg == nil {
		return nil
	}
	cleanAddr := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(address), "]"), "[")
	if cleanAddr == "" {
		return nil
	}
	var matches []string
	walkConcreteSSHHostNames(p.cfg, func(name string) bool {
		hostName := p.getVal(name, "HostName", name)
		if expanded, expErr := ssh.ExpandHostName(hostName, name); expErr == nil {
			hostName = expanded
		}
		cleanHost := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(hostName), "]"), "[")
		if !strings.EqualFold(cleanHost, cleanAddr) {
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
	if p == nil {
		p = &OpenSSHParser{cfg: nil}
	}
	lookupAlias, userOverride, portOverride, err := parseOpenSSHHostSpec(alias)
	if err != nil {
		return models.Node{}, models.Host{}, models.Identity{}, fmt.Errorf("parse openssh host %q failed: %w", alias, err)
	}
	// 从配置中提取各种字段
	rawHostName := p.getVal(lookupAlias, "HostName", lookupAlias)
	expandedHostName, expHostErr := ssh.ExpandHostName(rawHostName, lookupAlias)
	if expHostErr != nil {
		return models.Node{}, models.Host{}, models.Identity{}, expHostErr
	}
	hostName := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(expandedHostName), "]"), "[")
	user := p.getVal(lookupAlias, "User", "")
	if user == "" {
		defUser, userErr := getCurrentUser()
		if userErr != nil {
			return models.Node{}, models.Host{}, models.Identity{}, userErr
		}
		user = defUser
	}
	portStr := strings.TrimSpace(p.getVal(lookupAlias, "Port", "22"))
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

	identityFile := p.getVal(lookupAlias, "IdentityFile", "")
	if identityFile != "" {
		var expErr error
		identityFile, expErr = expandHomeDir(identityFile)
		if expErr != nil {
			return models.Node{}, models.Host{}, models.Identity{}, expErr
		}
	}

	_, proxyJump, _ := firstMatchingOpenSSHProxy(p.cfg, lookupAlias)

	sshOpts, err := parseOpenSSHOptions(p.cfg, lookupAlias)
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
		Alias:       []string{alias},
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
	if p == nil || p.cfg == nil || alias == "" {
		return nil, nil
	}
	cleanAlias := strings.TrimPrefix(alias, OpenSSHNodePrefix)
	lookupAlias, _, _, err := parseOpenSSHHostSpec(cleanAlias)
	if err != nil {
		lookupAlias = cleanAlias
	}
	return parseOpenSSHOptions(p.cfg, lookupAlias)
}

// GetControlConfig parses multiplexing options for a given alias/host in ssh_config.
func (p *OpenSSHParser) GetControlConfig(alias string) (*ssh.ControlConfig, error) {
	opts, err := p.GetSSHOptions(alias)
	if err != nil || opts == nil {
		return nil, err
	}
	return opts.ControlConfig(), nil
}

func parseOpenSSHOptions(cfg *ssh_config.Config, host string) (*ssh.Options, error) {
	if cfg == nil || host == "" {
		return nil, nil
	}
	opts := &ssh.Options{}
	for _, spec := range ssh.RegisteredOptionSpecs() {
		// Trust-class options (StrictHostKeyChecking, UserKnownHostsFile) are never
		// inherited from ~/.ssh/config so wildcard host blocks cannot implicitly
		// weaken host key verification. Only one-way HashKnownHosts=yes is allowed.
		if spec.Class == ssh.OptionClassTrust && !isAllowedOpenSSHTrustOption(spec.CanonicalKey) {
			continue
		}
		if spec.MultiValue {
			for _, rawVal := range allMatchingOpenSSHOptions(cfg, host, spec) {
				if err := opts.Append(spec.CanonicalKey, rawVal); err != nil {
					// Leniently skip invalid or unsupported multi-value entries
					// (e.g. malformed multi-value entries).
					continue
				}
			}
			continue
		}
		val, skip := resolveOpenSSHSingleOption(cfg, host, spec)
		if skip || val == "" {
			continue
		}
		if spec.Class == ssh.OptionClassTrust && !strings.EqualFold(strings.TrimSpace(val), "yes") {
			continue
		}
		if spec.AllowList {
			filtered := ssh.FilterSupportedListValue(spec.CanonicalKey, val)
			if filtered == "" {
				continue
			}
			val = filtered
		}
		if err := opts.Set(spec.CanonicalKey, val); err != nil {
			// Preserve strict error reporting on ControlMaster and ControlPersist,
			// while leniently skipping unsupported ~/.ssh/config values (e.g.
			// ControlPath tokens like %k or PubkeyAuthentication=unbound).
			if spec.CanonicalKey == ssh.OptionControlMaster || spec.CanonicalKey == ssh.OptionControlPersist {
				return nil, fmt.Errorf("invalid %s %q for %q in ssh config: %w", spec.OpenSSHName, val, host, err)
			}
			continue
		}
	}
	if opts.IsEmpty() {
		return nil, nil
	}
	return opts, nil
}

// allMatchingOpenSSHOptions resolves all entries for a multi-value option across matching
// ssh_config Host blocks (including Include files). For SendEnv/SetEnv (which
// MergeOptionLayers/ResolveSessionEnv evaluate low-to-high so later entries override/exclude
// earlier ones), matching stanzas are traversed from lowest specificity (bottom) to highest
// specificity (top) while keeping top-to-bottom order within each stanza segment.
func allMatchingOpenSSHOptions(cfg *ssh_config.Config, host string, spec ssh.OptionSpec) []string {
	if cfg == nil || host == "" {
		return nil
	}
	keys := make([]string, 0, 1+len(spec.Aliases))
	keys = append(keys, spec.OpenSSHName)
	keys = append(keys, spec.Aliases...)

	var matches []string
	collectKV := func(kv *ssh_config.KV) {
		k := strings.TrimSpace(kv.Key)
		for _, candidate := range keys {
			if strings.EqualFold(k, candidate) {
				if v := strings.TrimSpace(kv.Value); v != "" {
					matches = append(matches, v)
				}
				break
			}
		}
	}

	reverseHosts := spec.CanonicalKey == ssh.OptionSendEnv || spec.CanonicalKey == ssh.OptionSetEnv
	if reverseHosts {
		walkMatchingSSHConfigKVsReverseHosts(cfg, host, collectKV)
		return matches
	}
	walkMatchingSSHConfigKVs(cfg, host, func(kv *ssh_config.KV) bool {
		collectKV(kv)
		return true
	})
	return matches
}

// isAllowedOpenSSHTrustOption reports whether a trust-class option may be inherited
// (one-way security-preserving) from ssh_config.
func isAllowedOpenSSHTrustOption(canonicalKey string) bool {
	return strings.EqualFold(strings.TrimSpace(canonicalKey), "hash_known_hosts")
}

func resolveOpenSSHSingleOption(cfg *ssh_config.Config, host string, spec ssh.OptionSpec) (val string, skip bool) {
	if spec.CanonicalKey == ssh.OptionProxyCommand {
		var winner string
		winner, _, val = firstMatchingOpenSSHProxy(cfg, host)
		if winner == "proxyjump" {
			return "", true
		}
		return val, false
	}
	return firstMatchingOpenSSHOption(cfg, host, spec), false
}

func firstMatchingOpenSSHOption(cfg *ssh_config.Config, host string, spec ssh.OptionSpec) string {
	keys := make([]string, 0, 1+len(spec.Aliases))
	keys = append(keys, spec.OpenSSHName)
	keys = append(keys, spec.Aliases...)
	return firstSSHConfigKeyValue(cfg, host, keys...)
}

func parseOpenSSHHostSpec(spec string) (host, userName string, port uint16, err error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", "", 0, fmt.Errorf("host is empty")
	}
	if at := strings.LastIndex(spec, "@"); at >= 0 {
		userName = strings.TrimSpace(spec[:at])
		spec = strings.TrimSpace(spec[at+1:])
		if userName == "" || spec == "" {
			return "", "", 0, fmt.Errorf("invalid user or host")
		}
	}

	portText := ""
	portSpecified := false
	switch {
	case strings.HasPrefix(spec, "["):
		end := strings.Index(spec, "]")
		if end < 0 {
			return "", "", 0, fmt.Errorf("invalid bracketed host")
		}
		host = spec[1:end]
		if suffix := spec[end+1:]; suffix != "" {
			if !strings.HasPrefix(suffix, ":") {
				return "", "", 0, fmt.Errorf("invalid host suffix %q", suffix)
			}
			portSpecified = true
			portText = strings.TrimPrefix(suffix, ":")
		}
	case strings.Count(spec, ":") == 1:
		portSpecified = true
		var splitErr error
		host, portText, splitErr = net.SplitHostPort(spec)
		if splitErr != nil {
			return "", "", 0, fmt.Errorf("parse host and port failed: %w", splitErr)
		}
	default:
		host = spec
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", "", 0, fmt.Errorf("host is empty")
	}
	if !portSpecified {
		return host, userName, 0, nil
	}
	parsedPort, parseErr := strconv.ParseUint(portText, 10, 16)
	if parseErr != nil || parsedPort == 0 {
		return "", "", 0, fmt.Errorf("invalid port %q", portText)
	}
	return host, userName, uint16(parsedPort), nil
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
	if len(path) == 0 {
		return path, nil
	}
	if path[0] == '~' {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("expand home dir failed: %w", err)
		}
		return filepath.Join(home, path[1:]), nil
	}
	return path, nil
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
func firstMatchingOpenSSHProxy(cfg *ssh_config.Config, host string) (winner, proxyJump, proxyCommand string) {
	if cfg == nil || host == "" {
		return "", "", ""
	}
	var sawJump, sawCmd bool
	var jumpVal, cmdVal string
	walkMatchingSSHConfigKVs(cfg, host, func(kv *ssh_config.KV) bool {
		v := strings.TrimSpace(kv.Value)
		if v == "" {
			return true
		}
		switch strings.ToLower(strings.TrimSpace(kv.Key)) {
		case "proxyjump":
			if !sawJump {
				sawJump = true
				jumpVal = v
				if winner == "" && !strings.EqualFold(v, "none") {
					winner = "proxyjump"
				}
			}
		case "proxycommand":
			if !sawCmd {
				sawCmd = true
				cmdVal = v
				if winner == "" && !strings.EqualFold(v, "none") {
					winner = "proxycommand"
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
			return "", "", cmdVal
		}
		return "", "", ""
	}
}

// ---------------------------------------------------------------------------
// Canonical Include-Aware ssh_config Decoding & AST Walkers
// ---------------------------------------------------------------------------

type openSSHIncludeSpec struct {
	patterns     []string
	hasEquals    bool
	leadingSpace int
	comment      string
}

type openSSHIncludeNode struct {
	pos   ssh_config.Position
	spec  openSSHIncludeSpec
	files map[string]*ssh_config.Config
}

func (n *openSSHIncludeNode) Pos() ssh_config.Position {
	if n == nil {
		return ssh_config.Position{}
	}
	return n.pos
}

func (n *openSSHIncludeNode) String() string {
	if n == nil {
		return ""
	}
	sep := " "
	if n.spec.hasEquals {
		sep = " = "
	}
	var b strings.Builder
	if n.spec.leadingSpace > 0 {
		b.WriteString(strings.Repeat(" ", n.spec.leadingSpace))
	}
	b.WriteString("Include")
	b.WriteString(sep)
	for i, pat := range n.spec.patterns {
		if i > 0 {
			b.WriteByte(' ')
		}
		if strings.ContainsAny(pat, " \t#") {
			b.WriteByte('"')
			b.WriteString(pat)
			b.WriteByte('"')
		} else {
			b.WriteString(pat)
		}
	}
	if n.spec.comment != "" {
		b.WriteString(" #")
		b.WriteString(n.spec.comment)
	}
	return b.String()
}

func decodeOpenSSHReader(r io.Reader) (*ssh_config.Config, error) {
	var sourcePath string
	if named, ok := r.(interface{ Name() string }); ok && named != nil {
		sourcePath = named.Name()
	}
	return decodeOpenSSHConfig(r, sourcePath)
}

func decodeOpenSSHConfig(r io.Reader, sourcePath string) (*ssh_config.Config, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	active := make(map[string]struct{}, 4)
	if sourcePath != "" {
		active[canonicalIncludePath(sourcePath)] = struct{}{}
	}
	return decodeOpenSSHBytes(b, isSystemSSHConfigPath(sourcePath), 0, active)
}

func decodeOpenSSHFile(path string, system bool, depth int, active map[string]struct{}) (*ssh_config.Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return decodeOpenSSHBytes(b, system || isSystemSSHConfigPath(path), depth, active)
}

func decodeOpenSSHBytes(b []byte, system bool, depth int, active map[string]struct{}) (*ssh_config.Config, error) {
	rewritten, specs, err := rewriteOpenSSHIncludes(b)
	if err != nil {
		return nil, err
	}
	cfg, err := ssh_config.DecodeBytes(rewritten)
	if err != nil {
		return nil, err
	}
	if len(specs) == 0 {
		return cfg, nil
	}
	if err := resolveOpenSSHIncludePlaceholders(cfg, specs, system, depth, active); err != nil {
		return nil, err
	}
	return cfg, nil
}

func rewriteOpenSSHIncludes(b []byte) ([]byte, []openSSHIncludeSpec, error) {
	if len(b) == 0 {
		return b, nil, nil
	}
	lines := strings.Split(string(b), "\n")
	var specs []openSSHIncludeSpec
	var out bytes.Buffer
	rewrittenAny := false

	for idx, rawLine := range lines {
		hasCR := strings.HasSuffix(rawLine, "\r")
		line := strings.TrimSuffix(rawLine, "\r")
		spec, matched, err := parseOpenSSHIncludeLine(line)
		if err != nil {
			return nil, nil, fmt.Errorf("line %d: %w", idx+1, err)
		}
		if matched {
			if !rewrittenAny {
				rewrittenAny = true
				out.Grow(len(b) + 32)
				for prev := 0; prev < idx; prev++ {
					out.WriteString(lines[prev])
					out.WriteByte('\n')
				}
			}
			specIdx := len(specs)
			specs = append(specs, spec)
			out.WriteString(line[:spec.leadingSpace])
			out.WriteString(openSSHIncludePlaceholderKey)
			out.WriteByte(' ')
			out.WriteString(strconv.Itoa(specIdx))
			if hasCR {
				out.WriteByte('\r')
			}
		} else if rewrittenAny {
			out.WriteString(rawLine)
		}
		if rewrittenAny && idx < len(lines)-1 {
			out.WriteByte('\n')
		}
	}
	if !rewrittenAny {
		return b, nil, nil
	}
	return out.Bytes(), specs, nil
}

func parseOpenSSHIncludeLine(line string) (openSSHIncludeSpec, bool, error) {
	trimmed := strings.TrimLeft(line, " \t")
	leadingSpace := len(line) - len(trimmed)
	if trimmed == "" || trimmed[0] == '#' {
		return openSSHIncludeSpec{}, false, nil
	}
	kEnd := strings.IndexAny(trimmed, " \t=#")
	if kEnd < 0 {
		kEnd = len(trimmed)
	}
	if kEnd == 0 || !strings.EqualFold(trimmed[:kEnd], "include") {
		return openSSHIncludeSpec{}, false, nil
	}
	rest := strings.TrimLeft(trimmed[kEnd:], " \t")
	hasEquals := false
	if strings.HasPrefix(rest, "=") {
		hasEquals = true
		rest = strings.TrimLeft(rest[1:], " \t")
	}
	patterns, comment, err := parseOpenSSHIncludeArgs(rest)
	if err != nil {
		return openSSHIncludeSpec{}, true, err
	}
	return openSSHIncludeSpec{
		patterns:     patterns,
		hasEquals:    hasEquals,
		leadingSpace: leadingSpace,
		comment:      comment,
	}, true, nil
}

func parseOpenSSHIncludeArgs(rest string) (patterns []string, comment string, err error) {
	var cur strings.Builder
	inToken := false
	inQuotes := false
	flushToken := func() error {
		if !inToken {
			return nil
		}
		if cur.Len() == 0 {
			return errors.New("empty pattern in Include directive")
		}
		patterns = append(patterns, cur.String())
		cur.Reset()
		inToken = false
		return nil
	}

	for i := 0; i < len(rest); i++ {
		ch := rest[i]
		if inQuotes {
			if ch == '"' {
				inQuotes = false
			} else {
				cur.WriteByte(ch)
			}
			continue
		}
		switch ch {
		case '"':
			inQuotes = true
			inToken = true
		case ' ', '\t':
			if err := flushToken(); err != nil {
				return nil, "", err
			}
		case '#':
			comment = rest[i+1:]
			i = len(rest)
		default:
			inToken = true
			cur.WriteByte(ch)
		}
	}
	if inQuotes {
		return nil, "", errors.New("unterminated quote in Include directive")
	}
	if err := flushToken(); err != nil {
		return nil, "", err
	}
	if len(patterns) == 0 {
		return nil, "", errors.New("include directive requires at least one pattern")
	}
	return patterns, comment, nil
}

func resolveOpenSSHIncludePlaceholders(
	cfg *ssh_config.Config,
	specs []openSSHIncludeSpec,
	system bool,
	depth int,
	active map[string]struct{},
) error {
	if cfg == nil {
		return nil
	}
	for _, block := range cfg.Hosts {
		if block == nil {
			continue
		}
		for i, node := range block.Nodes {
			kv, ok := node.(*ssh_config.KV)
			if !ok || kv == nil || kv.Key != openSSHIncludePlaceholderKey {
				continue
			}
			specIdx, err := strconv.Atoi(strings.TrimSpace(kv.Value))
			if err != nil || specIdx < 0 || specIdx >= len(specs) {
				return fmt.Errorf("invalid internal Include placeholder index %q", kv.Value)
			}
			spec := specs[specIdx]
			files, err := loadOpenSSHIncludeFiles(spec.patterns, system, depth, active)
			if err != nil {
				return err
			}
			block.Nodes[i] = &openSSHIncludeNode{
				pos:   kv.Pos(),
				spec:  spec,
				files: files,
			}
		}
	}
	return nil
}

func loadOpenSSHIncludeFiles(
	patterns []string,
	system bool,
	depth int,
	active map[string]struct{},
) (map[string]*ssh_config.Config, error) {
	if depth >= maxIncludeDepth || len(patterns) == 0 {
		return nil, nil
	}
	files := make(map[string]*ssh_config.Config)
	for _, pat := range patterns {
		globPat, err := expandOpenSSHIncludePattern(pat, system)
		if err != nil {
			return nil, err
		}
		matches, err := filepath.Glob(globPat)
		if err != nil {
			return nil, fmt.Errorf("expand Include pattern %q: %w", pat, err)
		}
		slices.Sort(matches)
		for _, match := range matches {
			if _, exists := files[match]; exists {
				continue
			}
			info, statErr := os.Stat(match)
			if statErr != nil {
				if errors.Is(statErr, os.ErrNotExist) {
					continue
				}
				return nil, fmt.Errorf("stat included ssh config %q: %w", match, statErr)
			}
			if info.IsDir() {
				continue
			}
			canonPath := canonicalIncludePath(match)
			if _, inCycle := active[canonPath]; inCycle {
				continue
			}
			active[canonPath] = struct{}{}
			subCfg, decErr := decodeOpenSSHFile(match, system, depth+1, active)
			delete(active, canonPath)
			if decErr != nil {
				return nil, fmt.Errorf("decode included ssh config %q: %w", match, decErr)
			}
			files[match] = subCfg
		}
	}
	return files, nil
}

func expandOpenSSHIncludePattern(pat string, system bool) (string, error) {
	if pat == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("expand home dir for Include %q: %w", pat, err)
		}
		return home, nil
	}
	if strings.HasPrefix(pat, "~/") || strings.HasPrefix(pat, `~\`) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("expand home dir for Include %q: %w", pat, err)
		}
		return filepath.Join(home, pat[2:]), nil
	}
	if filepath.IsAbs(pat) {
		return pat, nil
	}
	if system {
		return filepath.Join("/etc/ssh", pat), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("expand user ssh dir for Include %q: %w", pat, err)
	}
	return filepath.Join(home, ".ssh", pat), nil
}

func isSystemSSHConfigPath(path string) bool {
	if path == "" {
		return false
	}
	clean := filepath.ToSlash(filepath.Clean(path))
	return clean == "/etc/ssh" || strings.HasPrefix(clean, "/etc/ssh/")
}

func canonicalIncludePath(path string) string {
	if resolved, err := filepath.EvalSymlinks(path); err == nil && resolved != "" {
		return filepath.Clean(resolved)
	}
	if abs, err := filepath.Abs(path); err == nil && abs != "" {
		return filepath.Clean(abs)
	}
	return filepath.Clean(path)
}

func includedConfigsFromNode(node ssh_config.Node, depth int) map[string]*ssh_config.Config {
	switch inc := node.(type) {
	case *openSSHIncludeNode:
		if inc == nil {
			return nil
		}
		return inc.files
	case *ssh_config.Include:
		if inc == nil || depth >= maxIncludeDepth {
			return nil
		}
		spec, matched, err := parseOpenSSHIncludeLine(inc.String())
		if err != nil || !matched {
			return nil
		}
		files, err := loadOpenSSHIncludeFiles(spec.patterns, false, depth, make(map[string]struct{}))
		if err != nil {
			return nil
		}
		return files
	default:
		return nil
	}
}

func firstSSHConfigKeyValue(cfg *ssh_config.Config, host string, keys ...string) string {
	if cfg == nil || host == "" || len(keys) == 0 {
		return ""
	}
	var found string
	walkMatchingSSHConfigKVs(cfg, host, func(kv *ssh_config.KV) bool {
		k := strings.TrimSpace(kv.Key)
		for _, candidate := range keys {
			if strings.EqualFold(k, candidate) {
				if v := strings.TrimSpace(kv.Value); v != "" {
					found = v
					return false
				}
				break
			}
		}
		return true
	})
	return found
}

func walkMatchingSSHConfigKVs(cfg *ssh_config.Config, alias string, visit func(kv *ssh_config.KV) bool) {
	if cfg == nil || alias == "" || visit == nil {
		return
	}
	walkMatchingSSHConfigAST(cfg, alias, nil, visit, nil)
}

func walkMatchingSSHConfigKVsReverseHosts(cfg *ssh_config.Config, alias string, visit func(kv *ssh_config.KV)) {
	if cfg == nil || alias == "" || visit == nil {
		return
	}
	var segments [][]*ssh_config.KV
	var current []*ssh_config.KV
	flush := func() {
		if len(current) > 0 {
			segments = append(segments, current)
			current = nil
		}
	}
	walkMatchingSSHConfigAST(
		cfg,
		alias,
		func(*ssh_config.Host) bool {
			flush()
			return true
		},
		func(kv *ssh_config.KV) bool {
			current = append(current, kv)
			return true
		},
		flush,
	)
	flush()
	for i := len(segments) - 1; i >= 0; i-- {
		for _, kv := range segments[i] {
			visit(kv)
		}
	}
}

func walkMatchingSSHConfigHostBlocks(
	cfg *ssh_config.Config,
	alias string,
	visit func(block *ssh_config.Host) bool,
) {
	if cfg == nil || alias == "" || visit == nil {
		return
	}
	walkMatchingSSHConfigAST(cfg, alias, visit, nil, nil)
}

func walkMatchingSSHConfigAST(
	cfg *ssh_config.Config,
	alias string,
	onBlock func(block *ssh_config.Host) bool,
	onKV func(kv *ssh_config.KV) bool,
	onIncludeBoundary func(),
) {
	active := make(map[*ssh_config.Config]struct{}, 4)
	_ = walkMatchingSSHConfigASTRec(cfg, alias, 0, active, onBlock, onKV, onIncludeBoundary)
}

func walkMatchingSSHConfigASTRec(
	cfg *ssh_config.Config,
	alias string,
	depth int,
	active map[*ssh_config.Config]struct{},
	onBlock func(block *ssh_config.Host) bool,
	onKV func(kv *ssh_config.KV) bool,
	onIncludeBoundary func(),
) bool {
	if cfg == nil || depth > maxIncludeDepth {
		return true
	}
	if _, seen := active[cfg]; seen {
		return true
	}
	active[cfg] = struct{}{}
	defer delete(active, cfg)

	for _, block := range cfg.Hosts {
		if block == nil || !block.Matches(alias) {
			continue
		}
		if onBlock != nil && !onBlock(block) {
			return false
		}
		for _, node := range block.Nodes {
			if kv, ok := node.(*ssh_config.KV); ok {
				if kv != nil && onKV != nil && !onKV(kv) {
					return false
				}
				continue
			}
			incFiles := includedConfigsFromNode(node, depth)
			if len(incFiles) == 0 || depth >= maxIncludeDepth {
				continue
			}
			if onIncludeBoundary != nil {
				onIncludeBoundary()
			}
			for _, path := range slices.Sorted(maps.Keys(incFiles)) {
				if !walkMatchingSSHConfigASTRec(incFiles[path], alias, depth+1, active, onBlock, onKV, onIncludeBoundary) {
					return false
				}
			}
			if onIncludeBoundary != nil {
				onIncludeBoundary()
			}
		}
	}
	return true
}

func walkConcreteSSHHostNames(cfg *ssh_config.Config, visit func(name string) bool) {
	if cfg == nil || visit == nil {
		return
	}
	seen := make(map[string]struct{})
	active := make(map[*ssh_config.Config]struct{}, 4)
	_ = walkConcreteSSHHostNamesRec(cfg, nil, 0, active, seen, visit)
}

func walkConcreteSSHHostNamesRec(
	cfg *ssh_config.Config,
	enclosing []*ssh_config.Host,
	depth int,
	active map[*ssh_config.Config]struct{},
	seen map[string]struct{},
	visit func(name string) bool,
) bool {
	if cfg == nil || depth > maxIncludeDepth {
		return true
	}
	if _, ok := active[cfg]; ok {
		return true
	}
	active[cfg] = struct{}{}
	defer delete(active, cfg)

	for _, block := range cfg.Hosts {
		if block == nil {
			continue
		}
		for _, pattern := range block.Patterns {
			if pattern == nil {
				continue
			}
			name := pattern.String()
			if !isConcreteSSHHost(name) {
				continue
			}
			if _, dup := seen[name]; dup {
				continue
			}
			if !hostBlockMatchesConcretePattern(block, name) || !allHostBlocksMatch(enclosing, name) {
				continue
			}
			seen[name] = struct{}{}
			if !visit(name) {
				return false
			}
		}
		nextEnclosing := append(slices.Clip(enclosing), block)
		for _, node := range block.Nodes {
			incFiles := includedConfigsFromNode(node, depth)
			if len(incFiles) == 0 || depth >= maxIncludeDepth {
				continue
			}
			for _, path := range slices.Sorted(maps.Keys(incFiles)) {
				if !walkConcreteSSHHostNamesRec(incFiles[path], nextEnclosing, depth+1, active, seen, visit) {
					return false
				}
			}
		}
	}
	return true
}

func allHostBlocksMatch(blocks []*ssh_config.Host, alias string) bool {
	for _, b := range blocks {
		if b == nil || !b.Matches(alias) {
			return false
		}
	}
	return true
}
