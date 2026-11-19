package config

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

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
	walkMatchingSSHConfigBlocks(p.cfg, lookupAlias, func(block *sshConfigBlock) bool {
		if block.matchesConcretePattern(lookupAlias) {
			found = true
			return false
		}
		return true
	})
	return found
}

func hasASCIIControlChar(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

func resolveOpenSSHHostName(doc *sshConfigDoc, alias string) (string, error) {
	rawHostName := firstSSHConfigKeyValue(doc, alias, "HostName")
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

func parseOpenSSHOptions(doc *sshConfigDoc, host string) (*ssh.Options, error) {
	if doc == nil || host == "" {
		return nil, nil
	}
	opts := &ssh.Options{}
	for _, spec := range ssh.RegisteredOptionSpecs() {
		if err := applyOpenSSHSpecOption(doc, host, spec, opts); err != nil {
			return nil, err
		}
	}
	if opts.IsEmpty() {
		return nil, nil
	}
	return opts, nil
}

func applyOpenSSHSpecOption(doc *sshConfigDoc, host string, spec ssh.OptionSpec, opts *ssh.Options) error {
	// Trust-class options (StrictHostKeyChecking, UserKnownHostsFile) are never
	// inherited from ~/.ssh/config so wildcard host blocks cannot implicitly
	// weaken host key verification. Only one-way HashKnownHosts=yes is allowed.
	if spec.Class == ssh.OptionClassTrust && !isAllowedOpenSSHTrustOption(spec.CanonicalKey) {
		return nil
	}
	if spec.MultiValue {
		rawVals := allMatchingOpenSSHOptions(doc, host, spec)
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
	val, skip := resolveOpenSSHSingleOption(doc, host, spec)
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
func allMatchingOpenSSHOptions(doc *sshConfigDoc, host string, spec ssh.OptionSpec) []string {
	if doc == nil || host == "" {
		return nil
	}
	keys := make([]string, 0, 1+len(spec.Aliases))
	keys = append(keys, spec.OpenSSHName)
	keys = append(keys, spec.Aliases...)

	var matches []string
	walkMatchingSSHConfigDirectives(doc, host, func(d *sshConfigDirective) bool {
		for _, candidate := range keys {
			if strings.EqualFold(d.key, candidate) {
				if v := sshConfigOptionValue(d, spec.CanonicalKey); v != "" {
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

func resolveOpenSSHSingleOption(doc *sshConfigDoc, host string, spec ssh.OptionSpec) (val string, skip bool) {
	if spec.CanonicalKey == ssh.OptionProxyCommand {
		var winner string
		winner, _, val = firstMatchingOpenSSHProxy(doc, host)
		if winner == "proxyjump" {
			return "", true
		}
		return val, false
	}
	return firstMatchingOpenSSHOption(doc, host, spec), false
}

func firstMatchingOpenSSHOption(doc *sshConfigDoc, host string, spec ssh.OptionSpec) string {
	keys := make([]string, 0, 1+len(spec.Aliases))
	keys = append(keys, spec.OpenSSHName)
	keys = append(keys, spec.Aliases...)
	return firstSSHConfigKeyValueRaw(doc, host, preservesSSHConfigRawValue(spec.CanonicalKey), keys...)
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
	if doc == nil || host == "" {
		return "", "", ""
	}
	var sawJump, sawCmd bool
	var jumpVal, cmdVal string
	walkMatchingSSHConfigDirectives(doc, host, func(d *sshConfigDirective) bool {
		switch d.lowerKey {
		case "proxyjump":
			v := d.value
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
