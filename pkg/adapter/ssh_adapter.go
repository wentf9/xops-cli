package adapter

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	coreauth "github.com/wentf9/xops-cli/core/auth"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/internal/credentialhelper"
	"github.com/wentf9/xops-cli/internal/sshenv"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
)

// SessionAuth 描述单个连接会话的临时认证机密与跳板覆盖
type SessionAuth struct {
	Password   string
	Passphrase string
	KeyPath    string
	SuPwd      string
	OTP        string
	ProxyJump  string
	Remember   bool
}

// SessionControlOptions specifies session-level OpenSSH option overrides (Tier 1).
// Pointers indicate whether a multiplexing flag was explicitly specified on the CLI.
type SessionControlOptions struct {
	Master  *ssh.ControlMasterMode
	Path    *string
	Persist *string
	Options *ssh.Options
}

// IsEmpty returns true if no session control or SSH option flags were provided.
func (s SessionControlOptions) IsEmpty() bool {
	return s.Master == nil && s.Path == nil && s.Persist == nil && s.Options.IsEmpty()
}

func (s *SessionControlOptions) ensureOptions() *ssh.Options {
	if s.Options == nil {
		s.Options = &ssh.Options{}
	}
	return s.Options
}

// SetMaster sets the ControlMaster override.
func (s *SessionControlOptions) SetMaster(m ssh.ControlMasterMode) {
	if m == "" {
		s.Master = nil
		if s.Options != nil {
			s.Options.Delete(ssh.OptionControlMaster)
		}
		return
	}
	s.Master = &m
	s.ensureOptions().SetControlMaster(m)
}

// SetPath sets the ControlPath override.
func (s *SessionControlOptions) SetPath(p string) {
	if p == "" {
		s.Path = nil
		if s.Options != nil {
			s.Options.Delete(ssh.OptionControlPath)
		}
		return
	}
	s.Path = &p
	s.ensureOptions().SetControlPath(p)
}

// SetPersist sets the ControlPersist override.
func (s *SessionControlOptions) SetPersist(p string) {
	if p == "" {
		s.Persist = nil
		if s.Options != nil {
			s.Options.Delete(ssh.OptionControlPersist)
		}
		return
	}
	s.Persist = &p
	s.ensureOptions().SetControlPersist(p)
}

// ToSSHOptions returns the session-level ssh.Options representation (including Master/Path/Persist fields).
func (s SessionControlOptions) ToSSHOptions() *ssh.Options {
	opts := s.Options.Clone()
	if s.Master != nil && *s.Master != "" {
		if opts == nil {
			opts = &ssh.Options{}
		}
		opts.SetControlMaster(*s.Master)
	}
	if s.Path != nil && *s.Path != "" {
		if opts == nil {
			opts = &ssh.Options{}
		}
		opts.SetControlPath(*s.Path)
	}
	if s.Persist != nil && *s.Persist != "" {
		if opts == nil {
			opts = &ssh.Options{}
		}
		opts.SetControlPersist(*s.Persist)
	}
	if opts.IsEmpty() {
		return nil
	}
	return opts
}

// ParseOptionStrings parses OpenSSH -o Key=Value strings into SessionControlOptions.
// Unknown keys are rejected instead of ignored so a typo cannot silently disable
// the requested behavior.
func ParseOptionStrings(options []string) (SessionControlOptions, error) {
	var opts SessionControlOptions
	for _, opt := range options {
		opt = strings.TrimSpace(opt)
		if opt == "" {
			continue
		}
		key, val, ok := strings.Cut(opt, "=")
		if !ok {
			return opts, fmt.Errorf("invalid -o option format (expected Key=Value): %q", opt)
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		if key == "" {
			return opts, fmt.Errorf("invalid -o option format (expected Key=Value): %q", opt)
		}
		if err := applyParsedOption(&opts, key, val); err != nil {
			return opts, err
		}
	}
	return opts, nil
}

func applyParsedOption(opts *SessionControlOptions, key, val string) error {
	switch strings.ToLower(key) {
	case "controlmaster", "control_master":
		m, err := ssh.ParseControlMasterMode(val)
		if err != nil {
			return fmt.Errorf("invalid ControlMaster in -o option: %w", err)
		}
		opts.SetMaster(m)
	case "controlpath", "control_path":
		if val == "" {
			return fmt.Errorf("invalid ControlPath in -o option: value cannot be empty")
		}
		if strings.EqualFold(val, "none") {
			val = "none"
		} else if err := ssh.ValidateControlPathSyntax(val); err != nil {
			return fmt.Errorf("invalid ControlPath in -o option: %w", err)
		}
		opts.SetPath(val)
	case "controlpersist", "control_persist":
		if _, _, _, err := ssh.ParseControlPersist(val); err != nil {
			return fmt.Errorf("invalid ControlPersist in -o option: %w", err)
		}
		opts.SetPersist(strings.ToLower(val))
	case "port":
		p, err := strconv.ParseUint(val, 10, 16)
		if err != nil || p == 0 {
			return fmt.Errorf("invalid Port in -o option: %q", val)
		}
	case "user", "identityfile", "proxyjump":
		if val == "" {
			return fmt.Errorf("invalid %s in -o option: value cannot be empty", key)
		}
		// Applied to the connection target by the CLI, see ApplyGeneralOptions.
	default:
		spec, supported := ssh.LookupOptionSpec(key)
		if !supported {
			return fmt.Errorf("unsupported -o option %q", key)
		}
		if val == "" {
			return fmt.Errorf("invalid %s in -o option: value cannot be empty", spec.OpenSSHName)
		}
		if err := opts.ensureOptions().Set(spec.CanonicalKey, val); err != nil {
			return fmt.Errorf("invalid %s in -o option: %w", spec.OpenSSHName, err)
		}
	}
	return nil
}

// CredentialResolver 描述能够根据 Ref 解析 Secret 的契约（如 *credential.Registry）
type CredentialResolver interface {
	Resolve(ctx context.Context, ref credential.Ref) (credential.Secret, error)
}

// Option 定义 SSHAdapter 的配置选项
type Option func(*SSHAdapter)

// WithCredentialSource 注入凭据解析器（如 credential.Registry），用于解析 Ref 引用
func WithCredentialSource(source CredentialResolver) Option {
	return func(a *SSHAdapter) {
		a.credentialResolver = source
	}
}

// WithSessionAuthOverride 注入特定节点的会话级临时机密覆盖
func WithSessionAuthOverride(nodeID string, auth SessionAuth) Option {
	return func(a *SSHAdapter) {
		if a.sessionOverrides == nil {
			a.sessionOverrides = make(map[string]SessionAuth)
		}
		a.sessionOverrides[nodeID] = auth
	}
}

// WithGlobalSessionAuth 注入会话级全局默认机密覆盖（当特定节点未显式指定 override 时生效）
func WithGlobalSessionAuth(auth SessionAuth) Option {
	return func(a *SSHAdapter) {
		a.globalSessionAuth = &auth
	}
}

// WithSessionControlOverride registers session multiplexing overrides for a specific node.
func WithSessionControlOverride(nodeID string, opts SessionControlOptions) Option {
	return func(a *SSHAdapter) {
		if a.sessionControlOverrides == nil {
			a.sessionControlOverrides = make(map[string]SessionControlOptions)
		}
		a.sessionControlOverrides[nodeID] = opts
	}
}

// WithGlobalSessionControl registers session multiplexing overrides for all nodes in the session.
func WithGlobalSessionControl(opts SessionControlOptions) Option {
	return func(a *SSHAdapter) {
		a.globalSessionControl = &opts
	}
}

// DisableSessionControlSharing forces ControlPath=none for the session (both
// globally and on nodeID) while preserving any non-multiplexing session SSH
// options already registered for nodeID or globally.
func (a *SSHAdapter) DisableSessionControlSharing(nodeID string) {
	disable := func(s SessionControlOptions) SessionControlOptions {
		var out SessionControlOptions
		if s.Options != nil {
			out.Options = s.Options.Clone()
			out.Options.StripClasses(ssh.OptionClassMux)
		}
		out.SetPath("none")
		return out
	}
	if a.globalSessionControl != nil {
		updated := disable(*a.globalSessionControl)
		a.globalSessionControl = &updated
	} else {
		updated := disable(SessionControlOptions{})
		a.globalSessionControl = &updated
	}
	if a.sessionControlOverrides == nil {
		a.sessionControlOverrides = make(map[string]SessionControlOptions)
	}
	a.sessionControlOverrides[nodeID] = disable(a.sessionControlOverrides[nodeID])
}

// WithOpenSSHParser injects an explicit OpenSSHParser for Tier 4 resolution (e.g. in tests).
func WithOpenSSHParser(parser *config.OpenSSHParser) Option {
	return func(a *SSHAdapter) {
		a.openSSHParser = parser
	}
}

// WithNonInteractive 标记该适配器为非交互式环境（如批处理、MCP、Playbook）
func WithNonInteractive(nonInteractive bool) Option {
	return func(a *SSHAdapter) {
		a.nonInteractive = nonInteractive
	}
}

// WithCredentialRecording controls persistence of secrets discovered during a
// connection. Composition roots apply remember policy and terminal ownership;
// explicit credential form actions use the service independently.
func WithCredentialRecording(enabled bool) Option {
	return func(a *SSHAdapter) {
		a.credentialRecording = enabled
	}
}

// WithRememberConfirmation injects a presentation-owned decision made only
// after authentication succeeds and before a newly discovered secret is saved.
func WithRememberConfirmation(confirm func(context.Context, string) (bool, error)) Option {
	return func(a *SSHAdapter) { a.rememberConfirmation = confirm }
}

// WithControlMultiplexing controls whether this adapter exposes a
// ControlProvider to the underlying ssh.Connector. Credential verification and
// MCP hosts disable it so they never attach to or create external control
// sockets on disk.
func WithControlMultiplexing(enabled bool) Option {
	return func(a *SSHAdapter) {
		a.disableControl = !enabled
	}
}

// WithHostTrustOverrides controls whether this adapter forwards trust-class
// SSH options (StrictHostKeyChecking, UserKnownHostsFile) from configuration
// or session overrides to the underlying ssh.Connector. MCP and verification
// paths disable it to enforce fail-closed host key verification.
func WithHostTrustOverrides(enabled bool) Option {
	return func(a *SSHAdapter) {
		a.disableHostTrust = !enabled
	}
}

// SSHAdapter 实现 ssh.ConnectionProvider, ssh.SecretResolver, ssh.CredentialRecorder 接口，作为业务模型与底层 SSH 的防腐层
type SSHAdapter struct {
	cfgProvider             config.ConfigProvider
	credentialResolver      CredentialResolver
	credentialService       *credential.Service
	sessionOverrides        map[string]SessionAuth
	globalSessionAuth       *SessionAuth
	sessionControlOverrides map[string]SessionControlOptions
	globalSessionControl    *SessionControlOptions
	openSSHParser           *config.OpenSSHParser
	nonInteractive          bool
	disableControl          bool
	disableHostTrust        bool
	credentialRecording     bool
	rememberConfirmation    func(context.Context, string) (bool, error)
	enrollmentProbe         bool
	enrollmentProbeWarning  func(string, error)
	enrollmentProbeExcluded map[string]struct{}
}

// WithCredentialService injects the transactional writer used when an
// interactive connection is explicitly allowed to remember a discovered
// secret.  Secrets must never be written through the legacy configuration
// fields.
func WithCredentialService(service *credential.Service) Option {
	return func(a *SSHAdapter) {
		a.credentialService = service
	}
}

var (
	_ ssh.ConnectionProvider = (*SSHAdapter)(nil)
	_ ssh.SecretResolver     = (*SSHAdapter)(nil)
	_ ssh.CredentialRecorder = (*SSHAdapter)(nil)
	_ ssh.ConfigStore        = (*SSHAdapter)(nil)
	_ ssh.ControlProvider    = (*SSHAdapter)(nil)
)

// NewSSHAdapter 创建 SSH 适配器
func NewSSHAdapter(cfgProvider config.ConfigProvider, opts ...Option) *SSHAdapter {
	adp := &SSHAdapter{
		cfgProvider:         cfgProvider,
		sessionOverrides:    make(map[string]SessionAuth),
		credentialRecording: true,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(adp)
		}
	}
	return adp
}

// NewNonInteractiveSSHAdapter 创建非交互式的 SSH 适配器
func NewNonInteractiveSSHAdapter(cfgProvider config.ConfigProvider, opts ...Option) *SSHAdapter {
	opts = append([]Option{WithNonInteractive(true)}, opts...)
	return NewSSHAdapter(cfgProvider, opts...)
}

// NewConnector 是一个辅助方法，快速创建组装好 Adapter 的 ssh.Connector，支持传入 Option 进行显式注入配置。
func NewConnector(cfgProvider config.ConfigProvider, opts ...ssh.Option) *ssh.Connector {
	adp := NewSSHAdapter(cfgProvider)
	return newConnector(adp, opts...)
}

// NewConnectorWithAdapterOptions 创建组装好 Adapter 选项和 SSH 选项的 Connector
func NewConnectorWithAdapterOptions(cfgProvider config.ConfigProvider, adpOpts []Option, sshOpts ...ssh.Option) *ssh.Connector {
	adp := NewSSHAdapter(cfgProvider, adpOpts...)
	return newConnector(adp, sshOpts...)
}

// NewConnectorWithInteraction creates a connector with a presentation-layer
// interaction handler supplied by the composition root.
func NewConnectorWithInteraction(cfgProvider config.ConfigProvider, interaction ssh.InteractionHandler, opts ...ssh.Option) *ssh.Connector {
	var finalOpts []ssh.Option
	if interaction != nil {
		finalOpts = append(finalOpts, ssh.WithInteractionHandler(interaction))
	}
	finalOpts = append(finalOpts, opts...)
	return NewConnector(cfgProvider, finalOpts...)
}

func newConnector(adp *SSHAdapter, opts ...ssh.Option) *ssh.Connector {
	finalOpts := []ssh.Option{ssh.WithEnvironment(sshenv.Discover())}
	if cfg := adp.cfgProvider.Snapshot(); cfg != nil && cfg.PasswordPromptPattern != "" {
		finalOpts = append(finalOpts, ssh.WithPasswordPromptPattern(cfg.PasswordPromptPattern))
	}
	if !adp.disableControl {
		finalOpts = append(finalOpts, ssh.WithControlProvider(adp))
	}
	finalOpts = append(finalOpts, opts...)
	return ssh.NewConnector(adp, finalOpts...)
}

// NewNonInteractiveConnector 创建一个非交互式的 Connector，避免在批量操作中阻塞等待输入，支持传入 Option。
func NewNonInteractiveConnector(cfgProvider config.ConfigProvider, opts ...ssh.Option) *ssh.Connector {
	adp := NewNonInteractiveSSHAdapter(cfgProvider)
	return newConnector(adp, opts...)
}

func (a *SSHAdapter) getSessionOverride(nodeID string) (SessionAuth, bool) {
	if a.sessionOverrides != nil {
		if override, ok := a.sessionOverrides[nodeID]; ok {
			return override, true
		}
	}
	if a.globalSessionAuth != nil {
		return *a.globalSessionAuth, true
	}
	return SessionAuth{}, false
}

func (a *SSHAdapter) getSessionControlOverride(nodeID string) (SessionControlOptions, bool) {
	if a.sessionControlOverrides != nil {
		if override, ok := a.sessionControlOverrides[nodeID]; ok {
			return override, true
		}
	}
	if a.globalSessionControl != nil {
		return *a.globalSessionControl, true
	}
	return SessionControlOptions{}, false
}

// GetControlConfig implements ssh.ControlProvider.
func (a *SSHAdapter) GetControlConfig(nodeID string) (*ssh.ControlConfig, error) {
	if a.disableControl {
		return nil, nil
	}
	sessionOpts, _ := a.getSessionControlOverride(nodeID)
	return a.ResolveControl(nodeID, sessionOpts)
}

// ResolveSSHOptions resolves the effective ssh.Options for nodeName given session options,
// enforcing the 4-tier precedence hierarchy (Tier 1 CLI > Tier 2 Node > Tier 3 Global > Tier 4 ~/.ssh/config).
func (a *SSHAdapter) ResolveSSHOptions(nodeName string, sessionOpts SessionControlOptions) (*ssh.Options, error) {
	if a.cfgProvider == nil {
		return nil, fmt.Errorf("configuration provider is nil")
	}

	t2Opts, t3Opts, t4Opts := a.resolveOptionTiers(nodeName)
	merged, err := ssh.EffectiveOptions(sessionOpts.ToSSHOptions(), t2Opts, t3Opts, t4Opts)
	if err != nil {
		return nil, err
	}
	if merged.IsEmpty() {
		return nil, nil
	}
	// Multiplexing options are governed and validated by ResolveControl / GetControlConfig;
	// strip control fields when control multiplexing is disabled on this adapter.
	if a.disableControl {
		merged.StripClasses(ssh.OptionClassMux)
	}
	if a.disableHostTrust {
		merged.StripClasses(ssh.OptionClassTrust)
	}
	if merged.IsEmpty() {
		return nil, nil
	}
	return merged, nil
}

func (a *SSHAdapter) resolveOptionTiers(nodeName string) (tier2Node, tier3Global, tier4OpenSSH *ssh.Options) {
	snapshot, snapErr := a.cfgProvider.ResolveConnection(nodeName)
	virtualOpenSSHNode := strings.HasPrefix(nodeName, config.OpenSSHNodePrefix)
	if snapErr == nil {
		if !virtualOpenSSHNode {
			tier2Node = snapshot.Node.SSHOptions
		}
	}

	if globalCfg := a.cfgProvider.Snapshot(); globalCfg != nil {
		tier3Global = globalCfg.SSHOptions
	}

	if virtualOpenSSHNode {
		if snapErr == nil {
			tier4OpenSSH = snapshot.Node.SSHOptions.Clone()
		}
	} else {
		tier4OpenSSH = a.resolveTier4OpenSSHOptions(nodeName, snapErr, snapshot).FilterByClasses(
			ssh.OptionClassMux,
			ssh.OptionClassTransport,
		)
	}
	if tier4OpenSSH != nil && tier4OpenSSH.ControlConfig() != nil {
		tier4OpenSSH.ImplicitTier4 = true
	}
	return tier2Node, tier3Global, tier4OpenSSH
}

// ResolveControl resolves the effective ControlConfig for nodeID given session options,
// strictly enforcing the 4-tier precedence hierarchy and field-by-field merging semantics.
func (a *SSHAdapter) ResolveControl(nodeName string, sessionOpts SessionControlOptions) (*ssh.ControlConfig, error) {
	if a.disableControl {
		return nil, nil
	}
	if a.cfgProvider == nil {
		return nil, fmt.Errorf("configuration provider is nil")
	}

	t2Opts, t3Opts, t4Opts := a.resolveOptionTiers(nodeName)
	tier2NodeCtrl := t2Opts.ControlConfig()
	tier3GlobalCtrl := t3Opts.ControlConfig()
	tier4OpenSSHCtrl := t4Opts.ControlConfig()

	// 4. Field-by-field merging: Tier 1 > Tier 2 > Tier 3 > Tier 4
	merged := mergeControlFields(sessionOpts, tier2NodeCtrl, tier3GlobalCtrl, tier4OpenSSHCtrl)
	if merged == nil {
		return nil, nil // No multiplexing configured
	}

	// 5. Validation
	if err := validateMergedControl(merged); err != nil {
		return nil, err
	}

	return merged, nil
}

func (a *SSHAdapter) resolveTier4OpenSSHOptions(nodeName string, snapErr error, snapshot config.ConnectionSnapshot) *ssh.Options {
	if strings.HasPrefix(nodeName, config.OpenSSHNodePrefix) {
		return nil
	}
	parser := a.getOpenSSHParser()
	if parser == nil {
		return nil
	}
	lookupKeys := a.buildTier4OpenSSHLookupKeys(parser, nodeName, snapErr, snapshot)

	// 1. First pass: prioritize concrete host matches (defined without wildcards like Host *)
	// across OpenSSHAlias, nodeName, Host.Address, and Alias so specific definitions take precedence.
	var layers []*ssh.Options
	for _, key := range lookupKeys {
		if parser.HasHost(key) {
			if opts, err := parser.GetSSHOptions(key); err == nil && !opts.IsEmpty() {
				layers = append(layers, opts)
			}
		}
	}
	if len(layers) == 0 {
		// 2. Second pass: fallback to generic wildcard / pattern matches (e.g. Host *).
		for _, key := range lookupKeys {
			if opts, err := parser.GetSSHOptions(key); err == nil && !opts.IsEmpty() {
				layers = append(layers, opts)
			}
		}
	}
	return ssh.MergeOptionLayers(layers...)
}

func (a *SSHAdapter) buildTier4OpenSSHLookupKeys(parser *config.OpenSSHParser, nodeName string, snapErr error, snapshot config.ConnectionSnapshot) []string {
	var lookupKeys []string
	appendUnique := func(keys ...string) {
		for _, k := range keys {
			k = strings.TrimSpace(k)
			if k != "" && !slicesContain(lookupKeys, k) {
				lookupKeys = append(lookupKeys, k)
			}
		}
	}

	openSSHAlias := snapshot.Node.OpenSSHAlias
	if openSSHAlias == "" {
		openSSHAlias = a.lookupNodeOpenSSHAlias(nodeName)
	}
	if openSSHAlias != "" {
		appendUnique(openSSHAlias)
	}
	if snapErr != nil {
		if !strings.Contains(nodeName, "@") && !strings.Contains(nodeName, ":") {
			appendUnique(nodeName)
		}
		if addr, port, ok := parseFallbackNodeIDAddressPort(nodeName); ok {
			appendUnique(parser.FindConcreteHostsByAddress(addr, port)...)
			if addr != nodeName {
				appendUnique(addr)
			}
		} else {
			appendUnique(nodeName)
		}
		return lookupKeys
	}

	appendUnique(snapshot.Node.Alias...)
	appendUnique(snapshot.Host.Alias...)
	if !strings.Contains(nodeName, "@") && !strings.Contains(nodeName, ":") {
		appendUnique(nodeName)
	}
	if snapshot.Host.Address != "" {
		appendUnique(parser.FindConcreteHostsByAddress(snapshot.Host.Address, uint16(effectiveSnapshotPort(snapshot.Host.Port)))...)
		if snapshot.Host.Address != nodeName {
			appendUnique(snapshot.Host.Address)
		}
	}
	appendUnique(nodeName)
	return lookupKeys
}

func (a *SSHAdapter) lookupNodeOpenSSHAlias(nodeName string) string {
	if a == nil || a.cfgProvider == nil || nodeName == "" {
		return ""
	}
	if p, ok := a.cfgProvider.(interface{ NodeOpenSSHAlias(string) string }); ok {
		return p.NodeOpenSSHAlias(nodeName)
	}
	return ""
}

func parseFallbackNodeIDAddressPort(nodeName string) (string, uint16, bool) {
	spec := strings.TrimSpace(nodeName)
	if at := strings.LastIndex(spec, "@"); at >= 0 {
		spec = strings.TrimSpace(spec[at+1:])
	}
	host, portText, err := net.SplitHostPort(spec)
	if err != nil {
		return "", 0, false
	}
	host = strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(host), "]"), "[")
	parsedPort, parseErr := strconv.ParseUint(strings.TrimSpace(portText), 10, 16)
	if host == "" || parseErr != nil || parsedPort == 0 {
		return "", 0, false
	}
	return host, uint16(parsedPort), true
}

func slicesContain(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func validateMergedControl(merged *ssh.ControlConfig) error {
	if merged.Master != "" {
		m, err := ssh.ParseControlMasterMode(string(merged.Master))
		if err != nil {
			return err
		}
		merged.Master = m
	}
	if merged.Persist != "" {
		if _, _, _, err := ssh.ParseControlPersist(merged.Persist); err != nil {
			return err
		}
	}
	// Path == "none" disables multiplexing: normalize Master to "no" and clear Persist
	if merged.Path == "none" {
		merged.Master = ssh.ControlMasterNo
		merged.Persist = ""
		return nil
	}
	if merged.Master != ssh.ControlMasterNo && merged.Master != "" {
		if merged.Path == "" {
			return fmt.Errorf("ControlPath is required when ControlMaster is %s", merged.Master)
		}
	}
	if merged.Persist != "" && merged.Path == "" {
		return fmt.Errorf("ControlPath is required when ControlPersist is configured")
	}
	return nil
}

func resolveMergedMaster(t1 SessionControlOptions, t2, t3, t4 *ssh.ControlConfig) ssh.ControlMasterMode {
	if t1.Master != nil && *t1.Master != "" {
		return *t1.Master
	}
	if t1.Options != nil && t1.Options.ControlMaster() != "" {
		return t1.Options.ControlMaster()
	}
	if t2 != nil && t2.Master != "" {
		return t2.Master
	}
	if t3 != nil && t3.Master != "" {
		return t3.Master
	}
	if t4 != nil && t4.Master != "" {
		return t4.Master
	}
	return ssh.ControlMasterNo
}

func resolveMergedPath(t1 SessionControlOptions, t2, t3, t4 *ssh.ControlConfig) string {
	if t1.Path != nil {
		return *t1.Path
	}
	if t1.Options != nil && t1.Options.ControlPath() != "" {
		return t1.Options.ControlPath()
	}
	if t2 != nil && t2.Path != "" {
		return t2.Path
	}
	if t3 != nil && t3.Path != "" {
		return t3.Path
	}
	if t4 != nil && t4.Path != "" {
		return t4.Path
	}
	return ""
}

func resolveMergedPersist(t1 SessionControlOptions, t2, t3, t4 *ssh.ControlConfig) string {
	if t1.Persist != nil {
		return *t1.Persist
	}
	if t1.Options != nil && t1.Options.ControlPersist() != "" {
		return t1.Options.ControlPersist()
	}
	if t2 != nil && t2.Persist != "" {
		return t2.Persist
	}
	if t3 != nil && t3.Persist != "" {
		return t3.Persist
	}
	if t4 != nil && t4.Persist != "" {
		return t4.Persist
	}
	return ""
}

func mergeControlFields(
	t1 SessionControlOptions,
	t2 *ssh.ControlConfig,
	t3 *ssh.ControlConfig,
	t4 *ssh.ControlConfig,
) *ssh.ControlConfig {
	master := resolveMergedMaster(t1, t2, t3, t4)
	path := resolveMergedPath(t1, t2, t3, t4)
	persist := resolveMergedPersist(t1, t2, t3, t4)

	// Handle "-S none" or Path == "none": disables connection sharing
	if path == "none" {
		master = ssh.ControlMasterNo
		persist = ""
	}

	// Unconfigured check: if nothing was configured across all 4 tiers, return nil
	if master == ssh.ControlMasterNo && path == "" && persist == "" {
		return nil
	}

	hasExplicitPersist := (t1.Persist != nil && *t1.Persist != "") ||
		(t1.Options != nil && t1.Options.ControlPersist() != "") ||
		(t2 != nil && t2.Persist != "") ||
		(t3 != nil && t3.Persist != "")

	return &ssh.ControlConfig{
		Master:        master,
		Path:          path,
		Persist:       persist,
		ImplicitTier4: !hasExplicitPersist && t4 != nil,
	}
}

func (a *SSHAdapter) getOpenSSHParser() *config.OpenSSHParser {
	if a.openSSHParser != nil {
		return a.openSSHParser
	}
	if p, ok := a.cfgProvider.(interface{ GetOpenSSHParser() *config.OpenSSHParser }); ok {
		return p.GetOpenSSHParser()
	}
	return nil
}

func effectiveSnapshotPort(port uint16) int {
	if port == 0 {
		return 22
	}
	return int(port)
}

func effectiveSnapshotUser(user string) string {
	if u := strings.TrimSpace(user); u != "" {
		return u
	}
	return sshenv.Discover().LocalUser
}

// ExpandControlPath expands tokens in rawPath for nodeID using node snapshot context.
// Useful for CLI control commands (-O check/exit/stop) that directly connect to sockets.
func (a *SSHAdapter) ExpandControlPath(nodeID string, rawPath string) (string, error) {
	if rawPath == "" || rawPath == "none" {
		return rawPath, nil
	}
	snapshot, err := a.cfgProvider.ResolveConnection(nodeID)
	if err != nil {
		return "", fmt.Errorf("resolve node %q for control path expansion: %w", nodeID, err)
	}
	target := ssh.TargetContext{
		Host:         snapshot.Host.Address,
		Port:         effectiveSnapshotPort(snapshot.Host.Port),
		User:         effectiveSnapshotUser(snapshot.Identity.User),
		OriginalHost: nodeID,
		JumpHost:     snapshot.Node.ProxyJump,
	}
	return ssh.ExpandControlPath(rawPath, sshenv.Discover(), target)
}

// ConfirmConnection publishes a prepared node before credentials are recorded.
// Providers without pending connections require no additional mutation.
func (a *SSHAdapter) ConfirmConnection(ctx context.Context, nodeID string) error {
	if provider, ok := a.cfgProvider.(interface {
		ConfirmNodeContext(context.Context, string) error
	}); ok {
		return provider.ConfirmNodeContext(ctx, nodeID)
	}
	return nil
}

// GetConfig 获取底层 SSH 客户端需要的配置
func (a *SSHAdapter) GetConfig(nodeID string) (*ssh.ClientConfig, error) {
	if a.cfgProvider == nil {
		return nil, fmt.Errorf("configuration provider is nil")
	}
	snapshot, err := a.cfgProvider.ResolveConnection(nodeID)
	if err != nil {
		return nil, fmt.Errorf("resolve node %q failed: %w", nodeID, err)
	}
	var authUpdateToken, sudoUpdateToken string
	if snapshot.UpdateRef != nil {
		authUpdateToken = string(snapshot.UpdateRef.AuthVersion[:])
		sudoUpdateToken = string(snapshot.UpdateRef.SudoVersion[:])
	}

	var globalExec *ssh.ExecutionConfig
	if globalCfg := a.cfgProvider.Snapshot(); globalCfg != nil {
		globalExec = globalCfg.Execution
	}
	execCfg, err := ssh.ResolveExecution(snapshot.Node.Execution, globalExec)
	if err != nil {
		return nil, fmt.Errorf("resolve execution for node %q failed: %w", nodeID, err)
	}

	sessionCtrlOpts, _ := a.getSessionControlOverride(nodeID)
	sshOpts, err := a.ResolveSSHOptions(nodeID, sessionCtrlOpts)
	if err != nil {
		return nil, fmt.Errorf("resolve ssh options for node %q failed: %w", nodeID, err)
	}

	cfg := &ssh.ClientConfig{
		NodeID:                nodeID,
		Address:               snapshot.Host.Address,
		Port:                  effectiveSnapshotPort(snapshot.Host.Port),
		User:                  effectiveSnapshotUser(snapshot.Identity.User),
		AuthType:              snapshot.Identity.AuthType,
		Password:              snapshot.Identity.Password,
		KeyPath:               snapshot.Identity.KeyPath,
		Passphrase:            snapshot.Identity.Passphrase,
		AuthUpdateToken:       authUpdateToken,
		SudoMode:              ssh.SudoMode(snapshot.Node.SudoMode),
		SuPwd:                 snapshot.Node.SuPwd,
		SudoUpdateToken:       sudoUpdateToken,
		ProxyJump:             snapshot.Node.ProxyJump,
		OriginalProxyJump:     snapshot.Node.ProxyJump,
		HasOriginalProxyJump:  true,
		PasswordPromptPattern: snapshot.Node.PasswordPromptPattern,
		Execution:             execCfg,
		Options:               sshOpts,
	}

	if override, ok := a.getSessionOverride(nodeID); ok {
		if err := a.applySessionOverrideToConfig(nodeID, cfg, override); err != nil {
			return nil, err
		}
	}

	return cfg, nil
}

func (a *SSHAdapter) applySessionOverrideToConfig(nodeID string, cfg *ssh.ClientConfig, override SessionAuth) error {
	if override.Password != "" {
		cfg.Password = override.Password
	}
	if override.Passphrase != "" {
		cfg.Passphrase = override.Passphrase
	}
	if override.KeyPath != "" {
		cfg.KeyPath = override.KeyPath
	}
	// Route explicit session material through auto authentication unless the
	// identity already uses keyboard-interactive or otp. This lets the
	// connector record discovered credentials after a successful handshake
	// and enables stage-0 keyboard-interactive when --otp is supplied on a
	// default password node.
	if cfg.AuthType != "keyboard-interactive" && cfg.AuthType != "otp" {
		if override.Password != "" || override.Passphrase != "" || override.KeyPath != "" {
			cfg.AuthType = "auto"
		} else if override.OTP != "" && (cfg.AuthType == "" || cfg.AuthType == "password") {
			cfg.AuthType = "auto"
		}
	}
	if override.SuPwd != "" {
		cfg.SuPwd = override.SuPwd
	}
	if override.ProxyJump != "" {
		resolvedJump, err := a.cfgProvider.ResolveProxyJumpChain(override.ProxyJump)
		if err != nil {
			return fmt.Errorf("resolve proxy jump %q for node %q failed: %w", override.ProxyJump, nodeID, err)
		}
		cfg.ProxyJump = resolvedJump
		cfg.OriginalProxyJump = resolvedJump
		cfg.HasOriginalProxyJump = true
	}
	return nil
}

func (a *SSHAdapter) isNonInteractiveForNode(nodeID string) bool {
	if a.nonInteractive {
		return true
	}
	if a.cfgProvider == nil {
		return false
	}
	sessionCtrlOpts, _ := a.getSessionControlOverride(nodeID)
	opts, err := a.ResolveSSHOptions(nodeID, sessionCtrlOpts)
	return err == nil && opts != nil && opts.BatchMode()
}

// UpdateAuth 处理密码或私钥密码的回写并返回本次提交后的新认证令牌
func (a *SSHAdapter) UpdateAuth(ctx context.Context, nodeID, authUpdateToken, password, keyPath, passphrase string) (string, error) {
	if a.isNonInteractiveForNode(nodeID) {
		// 非交互模式或 BatchMode=yes 禁止写回自动发现的秘密
		return authUpdateToken, nil
	}
	if !a.credentialRecording {
		return authUpdateToken, nil
	}
	if override, ok := a.getSessionOverride(nodeID); ok && !override.Remember {
		// 显式指定 session-only 覆盖，不写回持久化配置
		return authUpdateToken, nil
	}
	if password != "" || passphrase != "" {
		var err error
		password, passphrase, err = a.newAuthenticationMaterial(ctx, nodeID, password, keyPath, passphrase)
		if err != nil {
			return "", err
		}
		if password == "" && passphrase == "" {
			return authUpdateToken, nil
		}
	}
	if a.rememberConfirmation != nil && (password != "" || passphrase != "") {
		ok, err := a.rememberConfirmation(ctx, nodeID)
		if err != nil {
			return "", fmt.Errorf("confirm credential persistence: %w", err)
		}
		if !ok {
			return authUpdateToken, nil
		}
	}
	if a.credentialService == nil {
		// Backward compatibility for embedders that intentionally use the
		// legacy ConfigStore API. All xops CLI composition roots inject a
		// credential service, so they never take this plaintext path.
		provider, ok := a.cfgProvider.(interface {
			UpdateAuthAtVersionContext(context.Context, string, string, string, string, string) (string, error)
		})
		if !ok {
			return "", fmt.Errorf("configuration provider does not support versioned authentication updates")
		}
		return provider.UpdateAuthAtVersionContext(ctx, nodeID, authUpdateToken, password, keyPath, passphrase)
	}
	return a.persistAuthentication(ctx, nodeID, authUpdateToken, password, keyPath, passphrase)
}

func (a *SSHAdapter) persistAuthentication(ctx context.Context, nodeID, authUpdateToken, password, keyPath, passphrase string) (string, error) {
	snapshot, err := a.cfgProvider.ResolveConnection(nodeID)
	if err != nil {
		return "", fmt.Errorf("resolve node %q for remembered authentication: %w", nodeID, err)
	}
	version := authUpdateToken
	if password != "" {
		ref, nextVersion, rotateErr := a.credentialService.Rotate(ctx,
			credential.Target{NodeID: nodeID, Kind: credential.KindLoginPassword},
			version, snapshot.Identity.LoginPasswordRef, a.defaultStoreID(), credential.Secret{Value: []byte(password)})
		if rotateErr != nil {
			return "", fmt.Errorf("persist remembered login password: %w", rotateErr)
		}
		_ = ref
		version = nextVersion
	}
	if passphrase != "" {
		// The first rotation may have advanced the auth version; resolve the
		// latest snapshot before rotating the independent passphrase ref.
		snapshot, err = a.cfgProvider.ResolveConnection(nodeID)
		if err != nil {
			return "", fmt.Errorf("refresh node %q before persisting passphrase: %w", nodeID, err)
		}
		target, err := config.BindPrivateKeyFingerprint(a.cfgProvider.Snapshot(), credential.Target{NodeID: nodeID, Kind: credential.KindPassphrase, KeyPath: keyPath}, []byte(passphrase))
		if err != nil {
			return "", err
		}
		_, nextVersion, rotateErr := a.credentialService.Rotate(ctx,
			target,
			version, snapshot.Identity.PassphraseRef, a.defaultStoreID(), credential.Secret{Value: []byte(passphrase)})
		if rotateErr != nil {
			return "", fmt.Errorf("persist remembered private-key passphrase: %w", rotateErr)
		}
		version = nextVersion
	}
	return version, nil
}

func (a *SSHAdapter) defaultStoreID() string {
	if cfg := a.cfgProvider.Snapshot(); cfg != nil && cfg.Credential != nil {
		return cfg.Credential.DefaultStore
	}
	return "none"
}

// UpdateSudo 处理提权密码和模式的回写并返回本次提交后的新提权令牌
func (a *SSHAdapter) UpdateSudo(ctx context.Context, nodeID, sudoUpdateToken string, mode ssh.SudoMode, suPwd string) (string, error) {
	if a.isNonInteractiveForNode(nodeID) {
		// 非交互模式或 BatchMode=yes 禁止写回自动发现的秘密
		return sudoUpdateToken, nil
	}
	if !a.credentialRecording {
		return sudoUpdateToken, nil
	}
	if override, ok := a.getSessionOverride(nodeID); ok && !override.Remember {
		// 显式指定 session-only 覆盖，不写回持久化配置
		return sudoUpdateToken, nil
	}
	return a.updateRecordedSudo(ctx, nodeID, sudoUpdateToken, mode, suPwd)
}

func (a *SSHAdapter) updateRecordedSudo(ctx context.Context, nodeID, sudoUpdateToken string, mode ssh.SudoMode, suPwd string) (string, error) {
	if mode == ssh.SudoModeSudo {
		snapshot, err := a.cfgProvider.ResolveConnection(nodeID)
		if err != nil {
			return "", fmt.Errorf("resolve privilege binding: %w", err)
		}
		if snapshot.Node.SudoMode != models.SudoModeSudo && snapshot.Node.PrivilegePasswordRef != nil {
			// Auto detection must not reinterpret an existing su reference as
			// a sudo password or overwrite it with a different credential kind.
			if suPwd == "" {
				return sudoUpdateToken, nil
			}
			return "", fmt.Errorf("existing privilege reference is not bound to sudo")
		}
	}
	if a.credentialService != nil && suPwd != "" {
		snapshot, err := a.cfgProvider.ResolveConnection(nodeID)
		if err != nil {
			return "", fmt.Errorf("resolve privilege before recording: %w", err)
		}
		same, err := a.unchangedSecret(ctx, snapshot.Node.PrivilegePasswordRef, suPwd)
		if err != nil {
			return "", err
		}
		if same {
			suPwd = ""
		}
	}
	if a.rememberConfirmation != nil && suPwd != "" {
		ok, err := a.rememberConfirmation(ctx, nodeID)
		if err != nil {
			return "", fmt.Errorf("confirm privilege credential persistence: %w", err)
		}
		if !ok {
			return sudoUpdateToken, nil
		}
	}
	if a.credentialService != nil && suPwd != "" {
		snapshot, err := a.cfgProvider.ResolveConnection(nodeID)
		if err != nil {
			return "", fmt.Errorf("resolve node %q for remembered privilege password: %w", nodeID, err)
		}
		_, version, rotateErr := a.credentialService.Rotate(ctx,
			credential.Target{NodeID: nodeID, Kind: credential.KindPrivilegePassword},
			sudoUpdateToken, snapshot.Node.PrivilegePasswordRef, a.defaultStoreID(), credential.Secret{Value: []byte(suPwd)})
		if rotateErr != nil {
			return "", fmt.Errorf("persist remembered privilege password: %w", rotateErr)
		}
		return version, nil
	}
	provider, ok := a.cfgProvider.(interface {
		UpdateSudoAtVersionContext(context.Context, string, string, models.SudoMode, string) (string, error)
	})
	if !ok {
		return "", fmt.Errorf("configuration provider does not support versioned sudo updates")
	}
	return provider.UpdateSudoAtVersionContext(ctx, nodeID, sudoUpdateToken, models.SudoMode(mode), suPwd)
}

// ResolveSecret 从当前配置模型解析认证或提权所需机密，并严格校验与连接快照的一致性
func (a *SSHAdapter) ResolveSecret(ctx context.Context, req ssh.SecretRequest) ([]byte, error) {
	if ctx == nil {
		return nil, fmt.Errorf("secret resolution context is nil")
	}
	if a.isNonInteractiveForNode(req.NodeID) {
		ctx = credential.WithoutInteraction(ctx)
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	if a.cfgProvider == nil {
		return nil, fmt.Errorf("configuration provider is nil")
	}
	snapshot, err := a.cfgProvider.ResolveConnection(req.NodeID)
	if err != nil {
		return nil, fmt.Errorf("resolve node %q failed: %w", req.NodeID, err)
	}

	if err := validateSecretRequestSnapshot(snapshot, req); err != nil {
		return nil, err
	}

	override, hasOverride := a.getSessionOverride(req.NodeID)

	switch req.Kind {
	case ssh.SecretKindLoginPassword:
		return a.resolveLoginPassword(ctx, snapshot, hasOverride, override)
	case ssh.SecretKindPrivateKeyPassphrase:
		return a.resolvePassphrase(ctx, snapshot, hasOverride, override)
	case ssh.SecretKindSudoPassword:
		// Legacy SuPwd belongs to su and must never be tried as a sudo login
		// password. Only an explicit override or a sudo-bound v2 ref qualifies.
		if (hasOverride && override.SuPwd != "") || (snapshot.Node.SudoMode == models.SudoModeSudo && snapshot.Node.PrivilegePasswordRef != nil) {
			return a.resolveSuPassword(ctx, snapshot, hasOverride, override)
		}
		return nil, ssh.ErrInteractionRequired
	case ssh.SecretKindSuPassword:
		return a.resolveSuPassword(ctx, snapshot, hasOverride, override)
	case ssh.SecretKindOTP:
		return a.resolveOTP(ctx, snapshot, req, hasOverride, override)
	case ssh.SecretKindKeyboardInteractive:
		return a.resolveKeyboardInteractive(ctx, snapshot, req, hasOverride, override)
	default:
		return nil, fmt.Errorf("unsupported secret kind: %v", req.Kind)
	}
}

func (a *SSHAdapter) resolveOTP(
	ctx context.Context,
	snapshot config.ConnectionSnapshot,
	req ssh.SecretRequest,
	hasOverride bool,
	override SessionAuth,
) ([]byte, error) {
	if req.Attempt > 1 {
		return nil, ssh.ErrInteractionRequired
	}
	if hasOverride && override.OTP != "" {
		return []byte(override.OTP), nil
	}
	otpCfg := snapshot.Identity.OTP
	if otpCfg == nil {
		return nil, ssh.ErrInteractionRequired
	}
	if ref := otpCfg.TOTPSecretRef; ref != nil && !ref.IsEmpty() {
		if a.credentialResolver == nil {
			return nil, fmt.Errorf("totp secret ref %q/%q is configured but no credential resolver is available: %w",
				ref.StoreID, ref.ItemID, coreauth.ErrCredentialStoreUnavailable)
		}
		sec, err := a.credentialResolver.Resolve(ctx, *ref)
		if err != nil {
			return nil, fmt.Errorf("get totp secret from store: %w", err)
		}
		defer sec.Zero()
		code, err := coreauth.GenerateTOTP(string(sec.Value), time.Now())
		if err != nil {
			return nil, fmt.Errorf("generate totp: %w", err)
		}
		return []byte(code), nil
	}
	if strings.TrimSpace(otpCfg.Command) != "" {
		timeout := otpCfg.Timeout
		if timeout <= 0 {
			timeout = credentialhelper.DefaultAnswerCommandTimeout
		}
		promptText := req.Prompt
		if promptText == "" {
			promptText = "OTP"
		}
		effectiveUser := effectiveSnapshotUser(snapshot.Identity.User)
		identityName := snapshot.Node.IdentityRef
		if identityName == "" {
			identityName = effectiveUser
		}
		opts := credentialhelper.AnswerCommandOptions{
			Command:        otpCfg.Command,
			Args:           otpCfg.Args,
			Timeout:        timeout,
			Node:           req.NodeID,
			Host:           snapshot.Host.Address,
			User:           effectiveUser,
			Identity:       identityName,
			Prompt:         promptText,
			Instruction:    req.Instruction,
			Echo:           req.Echo,
			NonInteractive: a.isNonInteractiveForNode(req.NodeID) || credential.InteractionDisabled(ctx),
		}
		ans, err := credentialhelper.RunAnswerCommand(ctx, opts)
		if err != nil {
			return nil, fmt.Errorf("execute otp command: %w", err)
		}
		return ans, nil
	}
	return nil, ssh.ErrInteractionRequired
}

func (a *SSHAdapter) resolveKeyboardInteractive(
	ctx context.Context,
	snapshot config.ConnectionSnapshot,
	req ssh.SecretRequest,
	hasOverride bool,
	override SessionAuth,
) ([]byte, error) {
	// Anti-loop protection: if server rejected previous answer, fall back immediately to interaction
	if req.Attempt > 1 {
		return nil, ssh.ErrInteractionRequired
	}

	// 1. Inspect user-configured keyboard-interactive rules
	if ki := snapshot.Identity.KeyboardInteractive; ki != nil && len(ki.Rules) > 0 {
		for _, rule := range ki.Rules {
			promptRe, err := regexp.Compile(rule.PromptPattern)
			if err != nil {
				return nil, fmt.Errorf("invalid prompt pattern %q in rule %q: %w", rule.PromptPattern, rule.Name, err)
			}
			if !promptRe.MatchString(req.Prompt) {
				continue
			}
			if rule.InstructionPattern != "" {
				instRe, err := regexp.Compile(rule.InstructionPattern)
				if err != nil {
					return nil, fmt.Errorf("invalid instruction pattern %q in rule %q: %w", rule.InstructionPattern, rule.Name, err)
				}
				if !instRe.MatchString(req.Instruction) {
					continue
				}
			}

			// Matched rule! Resolve answer by source
			return a.resolveChallengeRuleAnswer(ctx, snapshot, req, rule, hasOverride, override)
		}
	}

	// 2. Fallback to explicit OTP matching
	if snapshot.Identity.OTP != nil && snapshot.Identity.OTP.PromptPattern != "" {
		otpPromptRe, err := regexp.Compile(snapshot.Identity.OTP.PromptPattern)
		if err != nil {
			return nil, fmt.Errorf("invalid otp prompt pattern %q: %w", snapshot.Identity.OTP.PromptPattern, err)
		}
		if otpPromptRe.MatchString(req.Prompt) {
			return a.resolveOTP(ctx, snapshot, req, hasOverride, override)
		}
	} else if req.NumPrompts <= 1 && ((hasOverride && override.OTP != "") || snapshot.Identity.AuthType == "otp" || hasConfiguredOTP(snapshot.Identity.OTP)) {
		return a.resolveOTP(ctx, snapshot, req, hasOverride, override)
	}

	// 3. No rule matched: fallback to interactive prompt
	return nil, ssh.ErrInteractionRequired
}

func hasConfiguredOTP(otp *models.OTPConfig) bool {
	if otp == nil {
		return false
	}
	return (otp.TOTPSecretRef != nil && !otp.TOTPSecretRef.IsEmpty()) || strings.TrimSpace(otp.Command) != ""
}

func (a *SSHAdapter) resolveChallengeRuleAnswer(
	ctx context.Context,
	snapshot config.ConnectionSnapshot,
	req ssh.SecretRequest,
	rule models.ChallengeRule,
	hasOverride bool,
	override SessionAuth,
) ([]byte, error) {
	switch rule.Source {
	case models.ChallengeSourceOTP:
		return a.resolveOTP(ctx, snapshot, req, hasOverride, override)
	case models.ChallengeSourceLoginPassword:
		return a.resolveLoginPassword(ctx, snapshot, hasOverride, override)
	case models.ChallengeSourceSecret:
		if rule.SecretRef == nil || rule.SecretRef.IsEmpty() {
			return nil, fmt.Errorf("rule %q has source secret but secret_ref is empty", rule.Name)
		}
		if a.credentialResolver == nil {
			return nil, fmt.Errorf("rule %q secret ref %q/%q is configured but no credential resolver is available: %w",
				rule.Name, rule.SecretRef.StoreID, rule.SecretRef.ItemID, coreauth.ErrCredentialStoreUnavailable)
		}
		sec, err := a.credentialResolver.Resolve(ctx, *rule.SecretRef)
		if err != nil {
			return nil, fmt.Errorf("get challenge answer for rule %q from store: %w", rule.Name, err)
		}
		defer sec.Zero()
		ans := make([]byte, len(sec.Value))
		copy(ans, sec.Value)
		return ans, nil
	case models.ChallengeSourceCommand:
		if strings.TrimSpace(rule.Command) == "" {
			return nil, fmt.Errorf("rule %q has source command but command is empty", rule.Name)
		}
		timeout := rule.Timeout
		if timeout <= 0 {
			timeout = credentialhelper.DefaultAnswerCommandTimeout
		}
		effectiveUser := effectiveSnapshotUser(snapshot.Identity.User)
		identityName := snapshot.Node.IdentityRef
		if identityName == "" {
			identityName = effectiveUser
		}
		opts := credentialhelper.AnswerCommandOptions{
			Command:        rule.Command,
			Args:           rule.Args,
			Timeout:        timeout,
			Node:           req.NodeID,
			Host:           snapshot.Host.Address,
			User:           effectiveUser,
			Identity:       identityName,
			Prompt:         req.Prompt,
			Instruction:    req.Instruction,
			Echo:           req.Echo,
			NonInteractive: a.isNonInteractiveForNode(req.NodeID) || credential.InteractionDisabled(ctx),
		}
		ans, err := credentialhelper.RunAnswerCommand(ctx, opts)
		if err != nil {
			return nil, fmt.Errorf("execute challenge rule %q command: %w", rule.Name, err)
		}
		return ans, nil
	default:
		return nil, fmt.Errorf("unsupported challenge answer source %q in rule %q", rule.Source, rule.Name)
	}
}

func (a *SSHAdapter) resolveLoginPassword(
	ctx context.Context,
	snapshot config.ConnectionSnapshot,
	hasOverride bool,
	override SessionAuth,
) ([]byte, error) {
	if hasOverride && override.Password != "" {
		return []byte(override.Password), nil
	}
	if ref := snapshot.Identity.LoginPasswordRef; ref != nil && !ref.IsEmpty() {
		if a.credentialResolver == nil {
			return nil, fmt.Errorf("login password ref %q/%q is configured but no credential resolver is available: %w",
				ref.StoreID, ref.ItemID, coreauth.ErrCredentialStoreUnavailable)
		}
		sec, err := a.credentialResolver.Resolve(ctx, *ref)
		if err != nil {
			return nil, fmt.Errorf("get login password from store: %w", err)
		}
		return sec.Value, nil
	}
	if snapshot.Identity.Password != "" {
		return []byte(snapshot.Identity.Password), nil
	}
	return nil, ssh.ErrInteractionRequired
}

func (a *SSHAdapter) resolvePassphrase(
	ctx context.Context,
	snapshot config.ConnectionSnapshot,
	hasOverride bool,
	override SessionAuth,
) ([]byte, error) {
	if hasOverride && override.Passphrase != "" {
		return []byte(override.Passphrase), nil
	}
	if ref := snapshot.Identity.PassphraseRef; ref != nil && !ref.IsEmpty() {
		if a.credentialResolver == nil {
			return nil, fmt.Errorf("passphrase ref %q/%q is configured but no credential resolver is available: %w",
				ref.StoreID, ref.ItemID, coreauth.ErrCredentialStoreUnavailable)
		}
		sec, err := a.credentialResolver.Resolve(ctx, *ref)
		if err != nil {
			return nil, fmt.Errorf("get passphrase from store: %w", err)
		}
		return sec.Value, nil
	}
	if snapshot.Identity.Passphrase != "" {
		return []byte(snapshot.Identity.Passphrase), nil
	}
	return nil, ssh.ErrInteractionRequired
}

func (a *SSHAdapter) resolveSuPassword(
	ctx context.Context,
	snapshot config.ConnectionSnapshot,
	hasOverride bool,
	override SessionAuth,
) ([]byte, error) {
	if hasOverride && override.SuPwd != "" {
		return []byte(override.SuPwd), nil
	}
	if ref := snapshot.Node.PrivilegePasswordRef; ref != nil && !ref.IsEmpty() {
		if a.credentialResolver == nil {
			return nil, fmt.Errorf("privilege password ref %q/%q is configured but no credential resolver is available: %w",
				ref.StoreID, ref.ItemID, coreauth.ErrCredentialStoreUnavailable)
		}
		sec, err := a.credentialResolver.Resolve(ctx, *ref)
		if err != nil {
			return nil, fmt.Errorf("get su password from store: %w", err)
		}
		return sec.Value, nil
	}
	if snapshot.Node.SuPwd != "" {
		return []byte(snapshot.Node.SuPwd), nil
	}
	return nil, ssh.ErrInteractionRequired
}

func validateSecretRequestSnapshot(snapshot config.ConnectionSnapshot, req ssh.SecretRequest) error {
	// 1. 版本一致性校验：若请求携带了 VersionToken，必须与当前快照的版本严格匹配
	if req.VersionToken != "" {
		var currentVersion string
		if snapshot.UpdateRef != nil {
			switch req.Kind {
			case ssh.SecretKindLoginPassword, ssh.SecretKindPrivateKeyPassphrase, ssh.SecretKindOTP, ssh.SecretKindKeyboardInteractive:
				currentVersion = string(snapshot.UpdateRef.AuthVersion[:])
			case ssh.SecretKindSuPassword, ssh.SecretKindSudoPassword:
				currentVersion = string(snapshot.UpdateRef.SudoVersion[:])
			}
		}
		if currentVersion != req.VersionToken {
			return fmt.Errorf("%w: version mismatch for node %q: expected %q, got %q",
				ssh.ErrSnapshotMismatch, req.NodeID, req.VersionToken, currentVersion)
		}
	}

	// 2. 目标主机与用户一致性校验：防止节点目标地址、端口或用户名发生变动时将新机密用于旧目标
	if req.Host != "" && snapshot.Host.Address != req.Host {
		return fmt.Errorf("%w: host address changed for node %q: expected %q, got %q",
			ssh.ErrSnapshotMismatch, req.NodeID, req.Host, snapshot.Host.Address)
	}
	effectivePort := effectiveSnapshotPort(snapshot.Host.Port)
	if req.Port != 0 && effectivePort != req.Port {
		return fmt.Errorf("%w: host port changed for node %q: expected %d, got %d",
			ssh.ErrSnapshotMismatch, req.NodeID, req.Port, effectivePort)
	}
	effectiveUser := effectiveSnapshotUser(snapshot.Identity.User)
	if req.User != "" && effectiveUser != req.User {
		return fmt.Errorf("%w: user changed for node %q: expected %q, got %q",
			ssh.ErrSnapshotMismatch, req.NodeID, req.User, effectiveUser)
	}
	return nil
}
