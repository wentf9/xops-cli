package config

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
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
	openSSHHostPlaceholder       = "__xops_host__"
	openSSHKVPlaceholder         = "__xops_kv__"
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

func hasASCIIControlChar(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

func resolveOpenSSHHostName(cfg *ssh_config.Config, alias string) (string, error) {
	rawHostName := firstSSHConfigKeyValue(cfg, alias, "HostName")
	if rawHostName == "" {
		unwrapped := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(alias), "]"), "[")
		if unwrapped == "" {
			return "", errors.New("HostName cannot be empty")
		}
		if hasASCIIControlChar(unwrapped) {
			return "", fmt.Errorf("HostName %q contains invalid ASCII control characters", unwrapped)
		}
		return unwrapped, nil
	}
	expanded, err := ssh.ExpandHostName(rawHostName, alias)
	if err != nil {
		return "", err
	}
	return strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(expanded), "]"), "["), nil
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
		cleanHost, expErr := resolveOpenSSHHostName(p.cfg, name)
		if expErr != nil || !strings.EqualFold(cleanHost, cleanAddr) {
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
	hostName, expHostErr := resolveOpenSSHHostName(p.cfg, lookupAlias)
	if expHostErr != nil {
		return models.Node{}, models.Host{}, models.Identity{}, expHostErr
	}
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

	identityFile, expErr := normalizeConfigIdentityKeyPath(p.getVal(lookupAlias, "IdentityFile", ""))
	if expErr != nil {
		return models.Node{}, models.Host{}, models.Identity{}, expErr
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
		if err := applyOpenSSHSpecOption(cfg, host, spec, opts); err != nil {
			return nil, err
		}
	}
	if opts.IsEmpty() {
		return nil, nil
	}
	return opts, nil
}

func applyOpenSSHSpecOption(cfg *ssh_config.Config, host string, spec ssh.OptionSpec, opts *ssh.Options) error {
	// Trust-class options (StrictHostKeyChecking, UserKnownHostsFile) are never
	// inherited from ~/.ssh/config so wildcard host blocks cannot implicitly
	// weaken host key verification. Only one-way HashKnownHosts=yes is allowed.
	if spec.Class == ssh.OptionClassTrust && !isAllowedOpenSSHTrustOption(spec.CanonicalKey) {
		return nil
	}
	if spec.MultiValue {
		rawVals := allMatchingOpenSSHOptions(cfg, host, spec)
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
	val, skip := resolveOpenSSHSingleOption(cfg, host, spec)
	if skip || val == "" {
		return nil
	}
	if spec.Class == ssh.OptionClassTrust && !strings.EqualFold(strings.TrimSpace(val), "yes") {
		return nil
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
			return fmt.Errorf("invalid %s %q for %q in ssh config: %w", spec.OpenSSHName, val, host, err)
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

func rawSSHConfigKVValue(kv *ssh_config.KV) string {
	if kv == nil {
		return ""
	}
	cp := *kv
	cp.Comment = ""
	s := strings.TrimSpace(cp.String())
	if len(s) >= len(kv.Key) && strings.EqualFold(s[:len(kv.Key)], kv.Key) {
		rest := strings.TrimLeft(s[len(kv.Key):], " \t")
		if strings.HasPrefix(rest, "=") {
			rest = strings.TrimLeft(rest[1:], " \t")
		}
		if trimmed := strings.TrimSpace(rest); trimmed != "" {
			return trimmed
		}
	}
	return strings.TrimSpace(kv.Value)
}

func sshConfigOptionValue(kv *ssh_config.KV, canonicalKey string) string {
	if kv == nil {
		return ""
	}
	if preservesSSHConfigRawValue(canonicalKey) {
		return rawSSHConfigKVValue(kv)
	}
	return strings.TrimSpace(kv.Value)
}

// allMatchingOpenSSHOptions resolves all entries for a multi-value option strictly
// top-to-bottom across matching ssh_config Host blocks (including Include files),
// matching OpenSSH readconf.c evaluation order for SendEnv, IdentityFile, SetEnv, etc.
func allMatchingOpenSSHOptions(cfg *ssh_config.Config, host string, spec ssh.OptionSpec) []string {
	if cfg == nil || host == "" {
		return nil
	}
	keys := make([]string, 0, 1+len(spec.Aliases))
	keys = append(keys, spec.OpenSSHName)
	keys = append(keys, spec.Aliases...)

	var matches []string
	walkMatchingSSHConfigKVs(cfg, host, func(kv *ssh_config.KV) bool {
		k := strings.TrimSpace(kv.Key)
		for _, candidate := range keys {
			if strings.EqualFold(k, candidate) {
				if v := sshConfigOptionValue(kv, spec.CanonicalKey); v != "" {
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
	return firstSSHConfigKeyValueRaw(cfg, host, preservesSSHConfigRawValue(spec.CanonicalKey), keys...)
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
func firstMatchingOpenSSHProxy(cfg *ssh_config.Config, host string) (winner, proxyJump, proxyCommand string) {
	if cfg == nil || host == "" {
		return "", "", ""
	}
	var sawJump, sawCmd bool
	var jumpVal, cmdVal string
	walkMatchingSSHConfigKVs(cfg, host, func(kv *ssh_config.KV) bool {
		switch strings.ToLower(strings.TrimSpace(kv.Key)) {
		case "proxyjump":
			v := strings.TrimSpace(kv.Value)
			if v == "" {
				return true
			}
			if !sawJump {
				sawJump = true
				jumpVal = v
				if winner == "" && !strings.EqualFold(v, "none") {
					winner = "proxyjump"
				}
			}
		case "proxycommand":
			v := rawSSHConfigKVValue(kv)
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

// ---------------------------------------------------------------------------
// Canonical Include-Aware ssh_config Decoding & AST Walkers
// ---------------------------------------------------------------------------

type openSSHIncludeSpec struct {
	patterns     []string
	hasEquals    bool
	leadingSpace int
	comment      string
}

type includedSSHConfigFile struct {
	path string
	cfg  *ssh_config.Config
}

type openSSHIncludeNode struct {
	pos    ssh_config.Position
	spec   openSSHIncludeSpec
	files  []includedSSHConfigFile
	system bool
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

type openSSHKVOverride struct {
	value   string
	comment string
}

type openSSHPreprocessResult struct {
	rewritten     []byte
	includes      []openSSHIncludeSpec
	hostOverrides map[int][]string
	kvOverrides   map[int]openSSHKVOverride
}

func decodeOpenSSHBytes(b []byte, system bool, depth int, active map[string]struct{}) (*ssh_config.Config, error) {
	prep, err := preprocessOpenSSHBytes(b)
	if err != nil {
		return nil, err
	}
	cfg, err := ssh_config.DecodeBytes(prep.rewritten)
	if err != nil {
		return nil, err
	}
	if err := applyOpenSSHOverrides(cfg, prep); err != nil {
		return nil, err
	}
	if len(prep.includes) == 0 {
		return cfg, nil
	}
	if err := resolveOpenSSHIncludePlaceholders(cfg, prep.includes, system, depth, active); err != nil {
		return nil, err
	}
	return cfg, nil
}

func preprocessOpenSSHBytes(b []byte) (openSSHPreprocessResult, error) {
	res := openSSHPreprocessResult{rewritten: b}
	if len(b) == 0 {
		return res, nil
	}
	lines := strings.Split(string(b), "\n")
	var out bytes.Buffer
	rewrittenAny := false
	blockIdx := 0

	for idx, rawLine := range lines {
		hasCR := strings.HasSuffix(rawLine, "\r")
		line := strings.TrimSuffix(rawLine, "\r")
		replacement, matched, err := preprocessOpenSSHLine(idx+1, line, &blockIdx, &res)
		if err != nil {
			return res, fmt.Errorf("line %d: %w", idx+1, err)
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
			out.WriteString(replacement)
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
	if rewrittenAny {
		res.rewritten = out.Bytes()
	}
	return res, nil
}

func preprocessOpenSSHLine(lineNum int, line string, blockIdx *int, res *openSSHPreprocessResult) (string, bool, error) {
	if spec, matched, err := parseOpenSSHIncludeLine(line); err != nil {
		return "", false, err
	} else if matched {
		specIdx := len(res.includes)
		res.includes = append(res.includes, spec)
		return line[:spec.leadingSpace] + openSSHIncludePlaceholderKey + " " + strconv.Itoa(specIdx), true, nil
	}
	indent, key, sep, rest, ok := splitOpenSSHDirectiveLine(line)
	if !ok {
		return "", false, nil
	}
	lowerKey := strings.ToLower(key)
	switch lowerKey {
	case "host":
		*blockIdx++
		return preprocessOpenSSHHostLine(*blockIdx, indent, key, sep, rest, res)
	case "match":
		*blockIdx++
		return preprocessOpenSSHMatchLine(*blockIdx, indent, key, sep, rest, res)
	default:
		return preprocessOpenSSHKVLine(lineNum, indent, key, lowerKey, sep, rest, res)
	}
}

func splitOpenSSHDirectiveLine(line string) (indent, key, sep, rest string, ok bool) {
	trimmed := strings.TrimLeft(line, " \t")
	if trimmed == "" || trimmed[0] == '#' {
		return "", "", "", "", false
	}
	leadingSpace := len(line) - len(trimmed)
	indent = line[:leadingSpace]
	kEnd := strings.IndexAny(trimmed, " \t=")
	if kEnd < 0 {
		kEnd = len(trimmed)
	}
	key = trimmed[:kEnd]
	if key == "" || strings.ContainsRune(key, '#') {
		return "", "", "", "", false
	}
	afterKey := strings.TrimLeft(trimmed[kEnd:], " \t")
	sep = " "
	if strings.HasPrefix(afterKey, "=") {
		sep = " = "
		afterKey = strings.TrimLeft(afterKey[1:], " \t")
	}
	return indent, key, sep, afterKey, true
}

func preprocessOpenSSHHostLine(blockIdx int, indent, key, sep, rest string, res *openSSHPreprocessResult) (string, bool, error) {
	if !strings.ContainsAny(rest, "#\t\"'\\") {
		return "", false, nil
	}
	argsPart, comment, unclosed := splitOpenSSHArgvComment(rest)
	if unclosed {
		return "", false, errors.New("unterminated quote in Host directive")
	}
	patterns, err := splitOpenSSHArgvTokens(argsPart)
	if err != nil {
		return "", false, fmt.Errorf("invalid Host directive: %w", err)
	}
	if res.hostOverrides == nil {
		res.hostOverrides = make(map[int][]string)
	}
	if patterns == nil {
		patterns = []string{}
	}
	res.hostOverrides[blockIdx] = patterns
	repl := indent + key + sep + openSSHHostPlaceholder
	if comment != "" {
		repl += " #" + comment
	}
	return repl, true, nil
}

func preprocessOpenSSHMatchLine(blockIdx int, indent, key, sep, rest string, res *openSSHPreprocessResult) (string, bool, error) {
	if !strings.ContainsAny(rest, "#\t\"'\\") {
		return "", false, nil
	}
	argsPart, comment, unclosed := splitOpenSSHArgvComment(rest)
	if unclosed {
		trimmedRest := strings.TrimLeft(rest, " \t")
		if len(trimmedRest) >= 4 && strings.EqualFold(trimmedRest[:4], "host") && (len(trimmedRest) == 4 || trimmedRest[4] == ' ' || trimmedRest[4] == '\t') {
			return "", false, errors.New("unterminated quote in Match Host directive")
		}
		return "", false, nil
	}
	toks, err := splitOpenSSHArgvTokens(argsPart)
	if err != nil || len(toks) < 2 || !strings.EqualFold(toks[0], "host") {
		return "", false, nil
	}
	if res.hostOverrides == nil {
		res.hostOverrides = make(map[int][]string)
	}
	res.hostOverrides[blockIdx] = toks[1:]
	repl := indent + key + sep + toks[0] + " " + openSSHHostPlaceholder
	if comment != "" {
		repl += " #" + comment
	}
	return repl, true, nil
}

func preprocessOpenSSHKVLine(lineNum int, indent, key, lowerKey, sep, rest string, res *openSSHPreprocessResult) (string, bool, error) {
	if isOpenSSHIgnoredQuoteHashDirective(lowerKey) {
		return "", false, nil
	}
	if isOpenSSHWholeLineCommandDirective(lowerKey) {
		trimmedRest := strings.TrimSpace(rest)
		if trimmedRest == "" || !strings.ContainsAny(trimmedRest, "#\t\"'") {
			return "", false, nil
		}
		return recordOpenSSHKVOverride(lineNum, indent, key, sep, openSSHKVOverride{value: trimmedRest}, res), true, nil
	}
	if !strings.ContainsAny(rest, "#\t\"'\\") {
		return "", false, nil
	}
	argsPart, comment, unclosed := splitOpenSSHArgvComment(rest)
	if isOpenSSHRawTokenListDirective(lowerKey) {
		return recordOpenSSHKVOverride(lineNum, indent, key, sep, openSSHKVOverride{value: argsPart, comment: comment}, res), true, nil
	}
	val := argsPart
	if !unclosed {
		if toks, err := splitOpenSSHArgvTokens(argsPart); err == nil && len(toks) == 1 {
			val = toks[0]
		}
	}
	return recordOpenSSHKVOverride(lineNum, indent, key, sep, openSSHKVOverride{value: val, comment: comment}, res), true, nil
}

func recordOpenSSHKVOverride(lineNum int, indent, key, sep string, ov openSSHKVOverride, res *openSSHPreprocessResult) string {
	if res.kvOverrides == nil {
		res.kvOverrides = make(map[int]openSSHKVOverride)
	}
	res.kvOverrides[lineNum] = ov
	return indent + key + sep + openSSHKVPlaceholder
}

func isOpenSSHWholeLineCommandDirective(lowerKey string) bool {
	switch lowerKey {
	case "proxycommand", "proxy_command",
		"localcommand", "local_command",
		"remotecommand", "remote_command":
		return true
	default:
		return false
	}
}

func isOpenSSHRawTokenListDirective(lowerKey string) bool {
	switch lowerKey {
	case "setenv", "set_env",
		"sendenv", "send_env",
		"localforward", "local_forward",
		"remoteforward", "remote_forward",
		"dynamicforward", "dynamic_forward":
		return true
	default:
		return false
	}
}

func isOpenSSHIgnoredQuoteHashDirective(lowerKey string) bool {
	return lowerKey == "proxyjump" || lowerKey == "proxy_jump"
}

func isOpenSSHArgvEscapable(ch byte) bool {
	return ch == ' ' || ch == '\t' || ch == '"' || ch == '\'' || ch == '\\'
}

func splitOpenSSHArgvComment(rest string) (argsPart, comment string, unclosedQuote bool) {
	var quote byte
	atWordStart := true
	for i := 0; i < len(rest); {
		ch := rest[i]
		if quote != 0 {
			if quote == '"' && ch == '\\' && i+1 < len(rest) && (rest[i+1] == '"' || rest[i+1] == '\\') {
				i += 2
				atWordStart = false
				continue
			}
			if ch == quote {
				quote = 0
			}
			i++
			atWordStart = false
			continue
		}
		if ch == ' ' || ch == '\t' {
			atWordStart = true
			i++
			continue
		}
		if ch == '#' && atWordStart {
			return strings.TrimRight(rest[:i], " \t"), rest[i+1:], false
		}
		if ch == '\'' || ch == '"' {
			quote = ch
			atWordStart = false
			i++
			continue
		}
		if ch == '\\' && i+1 < len(rest) && isOpenSSHArgvEscapable(rest[i+1]) {
			atWordStart = false
			i += 2
			continue
		}
		atWordStart = false
		i++
	}
	return strings.TrimRight(rest, " \t"), "", quote != 0
}

func splitOpenSSHArgvTokens(s string) ([]string, error) {
	var tokens []string
	i := 0
	for i < len(s) {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= len(s) {
			break
		}
		var sb strings.Builder
		nextIdx, err := consumeOpenSSHArgvToken(s, i, &sb)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, sb.String())
		i = nextIdx
	}
	return tokens, nil
}

func consumeOpenSSHArgvToken(s string, i int, sb *strings.Builder) (int, error) {
	var quote byte
	for i < len(s) {
		ch := s[i]
		if quote != 0 {
			if quote == '"' && ch == '\\' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\\') {
				sb.WriteByte(s[i+1])
				i += 2
				continue
			}
			if ch == quote {
				quote = 0
				i++
				continue
			}
			sb.WriteByte(ch)
			i++
			continue
		}
		if ch == ' ' || ch == '\t' {
			break
		}
		if ch == '\'' || ch == '"' {
			quote = ch
			i++
			continue
		}
		if ch == '\\' && i+1 < len(s) && isOpenSSHArgvEscapable(s[i+1]) {
			sb.WriteByte(s[i+1])
			i += 2
			continue
		}
		sb.WriteByte(ch)
		i++
	}
	if quote != 0 {
		return i, fmt.Errorf("unterminated %c quote", quote)
	}
	return i, nil
}

func applyOpenSSHOverrides(cfg *ssh_config.Config, res openSSHPreprocessResult) error {
	if cfg == nil || (len(res.hostOverrides) == 0 && len(res.kvOverrides) == 0) {
		return nil
	}
	for idx, block := range cfg.Hosts {
		if block == nil {
			continue
		}
		if rawPatterns, ok := res.hostOverrides[idx]; ok {
			compiled := make([]*ssh_config.Pattern, 0, len(rawPatterns))
			for _, pat := range rawPatterns {
				p, err := ssh_config.NewPattern(pat)
				if err != nil {
					return fmt.Errorf("invalid host pattern %q: %w", pat, err)
				}
				compiled = append(compiled, p)
			}
			block.Patterns = compiled
		}
		if len(res.kvOverrides) == 0 {
			continue
		}
		for i, node := range block.Nodes {
			kv, ok := node.(*ssh_config.KV)
			if !ok || kv == nil {
				continue
			}
			if ov, has := res.kvOverrides[kv.Pos().Line]; has {
				block.Nodes[i] = &ssh_config.KV{
					Key:     kv.Key,
					Value:   ov.value,
					Comment: ov.comment,
				}
			}
		}
	}
	return nil
}

func parseOpenSSHIncludeLine(line string) (openSSHIncludeSpec, bool, error) {
	trimmed := strings.TrimLeft(line, " \t")
	leadingSpace := len(line) - len(trimmed)
	if trimmed == "" || trimmed[0] == '#' {
		return openSSHIncludeSpec{}, false, nil
	}
	kEnd := strings.IndexAny(trimmed, " \t=")
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
	for i := 0; i < len(rest); {
		if rest[i] == ' ' || rest[i] == '\t' {
			i++
			continue
		}
		if rest[i] == '#' {
			comment = rest[i+1:]
			break
		}
		tok, nextIdx, tokErr := readNextOpenSSHIncludeToken(rest, i)
		if tokErr != nil {
			return nil, "", tokErr
		}
		patterns = append(patterns, tok)
		i = nextIdx
	}
	if len(patterns) == 0 {
		return nil, "", errors.New("include directive requires at least one pattern")
	}
	return patterns, comment, nil
}

func readNextOpenSSHIncludeToken(rest string, start int) (string, int, error) {
	var cur strings.Builder
	var quoteChar byte
	i := start
	for i < len(rest) {
		ch := rest[i]
		if quoteChar != 0 {
			if next, adv, closed := consumeOpenSSHIncludeQuotedChar(rest, i, quoteChar); closed {
				quoteChar = 0
				i += adv
			} else {
				cur.WriteByte(next)
				i += adv
			}
			continue
		}
		if ch == ' ' || ch == '\t' {
			break
		}
		if ch == '"' || ch == '\'' {
			quoteChar = ch
			i++
			continue
		}
		b, adv := consumeOpenSSHIncludeUnquotedChar(rest, i)
		cur.WriteByte(b)
		i += adv
	}
	if quoteChar != 0 {
		return "", 0, errors.New("unterminated quote in Include directive")
	}
	if cur.Len() == 0 {
		return "", 0, errors.New("empty pattern in Include directive")
	}
	return cur.String(), i, nil
}

func consumeOpenSSHIncludeQuotedChar(rest string, i int, quoteChar byte) (ch byte, advance int, closed bool) {
	if quoteChar == '"' && rest[i] == '\\' && i+1 < len(rest) {
		if next := rest[i+1]; next == '"' || next == '\\' {
			return next, 2, false
		}
	}
	if rest[i] == quoteChar {
		return 0, 1, true
	}
	return rest[i], 1, false
}

func consumeOpenSSHIncludeUnquotedChar(rest string, i int) (ch byte, advance int) {
	if rest[i] == '\\' && i+1 < len(rest) {
		next := rest[i+1]
		if next == ' ' || next == '\t' || next == '"' || next == '\'' || next == '#' {
			return next, 2
		}
	}
	return rest[i], 1
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
				pos:    kv.Pos(),
				spec:   spec,
				files:  files,
				system: system,
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
) ([]includedSSHConfigFile, error) {
	if depth >= maxIncludeDepth || len(patterns) == 0 {
		return nil, nil
	}
	var files []includedSSHConfigFile
	seenPaths := make(map[string]struct{})
	for _, pat := range patterns {
		globPat, skip, err := expandOpenSSHIncludePattern(pat, system)
		if err != nil {
			return nil, err
		}
		if skip || globPat == "" {
			continue
		}
		matches, err := filepath.Glob(globPat)
		if err != nil {
			return nil, fmt.Errorf("expand Include pattern %q: %w", pat, err)
		}
		slices.Sort(matches)
		for _, match := range matches {
			if _, exists := seenPaths[match]; exists {
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
			seenPaths[match] = struct{}{}
			files = append(files, includedSSHConfigFile{
				path: match,
				cfg:  subCfg,
			})
		}
	}
	return files, nil
}

func expandOpenSSHIncludePattern(pat string, system bool) (string, bool, error) {
	expanded, skip, err := expandIncludeTokens(pat, pat, system)
	if err != nil || skip {
		return "", skip, err
	}
	combined := expanded
	if strings.HasPrefix(expanded, "~") {
		if system {
			return "", true, nil
		}
		sep := strings.IndexAny(expanded[1:], `/\`)
		var userPart, rest string
		if sep < 0 {
			userPart = expanded[1:]
		} else {
			userPart = expanded[1 : 1+sep]
			rest = expanded[1+sep+1:]
		}
		var prefix string
		if userPart == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", false, fmt.Errorf("expand home dir for Include %q: %w", pat, err)
			}
			prefix = home
		} else {
			u, err := user.Lookup(userPart)
			if err != nil || u == nil || u.HomeDir == "" {
				return "", true, nil
			}
			prefix = u.HomeDir
		}
		if rest != "" {
			combined = filepath.Join(prefix, rest)
		} else {
			combined = prefix
		}
	}
	if combined == "" {
		return "", true, nil
	}
	if filepath.IsAbs(combined) {
		return combined, false, nil
	}
	if system {
		return filepath.Join("/etc/ssh", combined), false, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", false, fmt.Errorf("expand user ssh dir for Include %q: %w", pat, err)
	}
	return filepath.Join(home, ".ssh", combined), false, nil
}

func expandIncludeTokens(s, rawPat string, system bool) (string, bool, error) {
	if !strings.ContainsAny(s, "$%") {
		return s, false, nil
	}
	var out strings.Builder
	out.Grow(len(s))
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '$' && i+1 < len(s) && s[i+1] == '{' {
			closeIdx := strings.IndexByte(s[i+2:], '}')
			if closeIdx < 0 {
				return "", false, fmt.Errorf("unterminated environment variable in Include %q", rawPat)
			}
			name := s[i+2 : i+2+closeIdx]
			if name == "" {
				return "", false, fmt.Errorf("empty environment variable name in Include %q", rawPat)
			}
			val, ok := os.LookupEnv(name)
			if !ok || val == "" {
				return "", true, nil
			}
			out.WriteString(val)
			i += 2 + closeIdx
			continue
		}
		if ch == '%' {
			if i+1 >= len(s) {
				return "", false, fmt.Errorf("trailing '%%' token in Include %q", rawPat)
			}
			tok := s[i+1]
			i++
			rep, skip, err := resolveIncludePercentToken(tok, rawPat, system)
			if err != nil || skip {
				return "", skip, err
			}
			out.WriteString(rep)
			continue
		}
		out.WriteByte(ch)
	}
	return out.String(), false, nil
}

func resolveIncludePercentToken(tok byte, rawPat string, system bool) (string, bool, error) {
	switch tok {
	case '%':
		return "%", false, nil
	case 'd':
		if system {
			return "", true, nil
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", false, fmt.Errorf("expand %%d for Include %q: %w", rawPat, err)
		}
		return home, false, nil
	case 'u':
		u, err := getCurrentUser()
		if err != nil || u == "" {
			return "", false, fmt.Errorf("expand %%u for Include %q: %w", rawPat, err)
		}
		return u, false, nil
	case 'i':
		uid := os.Getuid()
		if uid < 0 {
			return "", true, nil
		}
		return strconv.Itoa(uid), false, nil
	case 'l':
		hn, err := os.Hostname()
		if err != nil || hn == "" {
			return "", true, nil
		}
		return hn, false, nil
	case 'L':
		hn, err := os.Hostname()
		if err != nil || hn == "" {
			return "", true, nil
		}
		short, _, _ := strings.Cut(hn, ".")
		return short, false, nil
	case 'h', 'n', 'r', 'p', 'C', 'k':
		// Target-dependent OpenSSH tokens are unavailable at config-load time;
		// OpenSSH skips expanding them quietly during Include loading.
		return "", true, nil
	default:
		return "", false, fmt.Errorf("unsupported Include token %%%c in %q", tok, rawPat)
	}
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

func includedConfigsFromNode(node ssh_config.Node, system bool, depth int) ([]includedSSHConfigFile, bool) {
	switch inc := node.(type) {
	case *openSSHIncludeNode:
		if inc == nil {
			return nil, system
		}
		return inc.files, inc.system
	case *ssh_config.Include:
		if inc == nil || depth >= maxIncludeDepth {
			return nil, system
		}
		spec, matched, err := parseOpenSSHIncludeLine(inc.String())
		if err != nil || !matched {
			return nil, system
		}
		files, err := loadOpenSSHIncludeFiles(spec.patterns, system, depth, make(map[string]struct{}))
		if err != nil {
			return nil, system
		}
		return files, system
	default:
		return nil, system
	}
}

func firstSSHConfigKeyValue(cfg *ssh_config.Config, host string, keys ...string) string {
	return firstSSHConfigKeyValueRaw(cfg, host, false, keys...)
}

func firstSSHConfigKeyValueRaw(cfg *ssh_config.Config, host string, preserveRaw bool, keys ...string) string {
	if cfg == nil || host == "" || len(keys) == 0 {
		return ""
	}
	var found string
	walkMatchingSSHConfigKVs(cfg, host, func(kv *ssh_config.KV) bool {
		k := strings.TrimSpace(kv.Key)
		for _, candidate := range keys {
			if strings.EqualFold(k, candidate) {
				var v string
				if preserveRaw {
					v = rawSSHConfigKVValue(kv)
				} else {
					v = strings.TrimSpace(kv.Value)
				}
				if v != "" {
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
	walkMatchingSSHConfigAST(cfg, alias, nil, visit)
}

func walkMatchingSSHConfigHostBlocks(
	cfg *ssh_config.Config,
	alias string,
	visit func(block *ssh_config.Host) bool,
) {
	if cfg == nil || alias == "" || visit == nil {
		return
	}
	walkMatchingSSHConfigAST(cfg, alias, visit, nil)
}

func walkMatchingSSHConfigAST(
	cfg *ssh_config.Config,
	alias string,
	onBlock func(block *ssh_config.Host) bool,
	onKV func(kv *ssh_config.KV) bool,
) {
	active := make(map[*ssh_config.Config]struct{}, 4)
	_ = walkMatchingSSHConfigASTRec(cfg, alias, false, 0, active, onBlock, onKV)
}

func walkMatchingSSHConfigASTRec(
	cfg *ssh_config.Config,
	alias string,
	system bool,
	depth int,
	active map[*ssh_config.Config]struct{},
	onBlock func(block *ssh_config.Host) bool,
	onKV func(kv *ssh_config.KV) bool,
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
			incFiles, incSystem := includedConfigsFromNode(node, system, depth)
			if len(incFiles) == 0 || depth >= maxIncludeDepth {
				continue
			}
			for _, inc := range incFiles {
				if !walkMatchingSSHConfigASTRec(inc.cfg, alias, system || incSystem, depth+1, active, onBlock, onKV) {
					return false
				}
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
	_ = walkConcreteSSHHostNamesRec(cfg, nil, false, 0, active, seen, visit)
}

func walkConcreteSSHHostNamesRec(
	cfg *ssh_config.Config,
	enclosing []*ssh_config.Host,
	system bool,
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
			incFiles, incSystem := includedConfigsFromNode(node, system, depth)
			if len(incFiles) == 0 || depth >= maxIncludeDepth {
				continue
			}
			for _, inc := range incFiles {
				if !walkConcreteSSHHostNamesRec(inc.cfg, nextEnclosing, system || incSystem, depth+1, active, seen, visit) {
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
