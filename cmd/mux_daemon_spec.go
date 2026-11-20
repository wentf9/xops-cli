package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
)

const (
	muxDaemonSpecVersion  = 1
	maxMuxDaemonSpecBytes = 256 * 1024
	muxDaemonSpecFDFlag   = "mux-daemon-spec-fd"
)

// MuxDaemonSpec carries typed startup parameters from a foreground handoff
// session to the detached ControlPersist daemon over an inherited pipe FD,
// avoiding lossy CLI argv reconstruction and secret exposure in process lists.
type MuxDaemonSpec struct {
	Version          int                   `json:"version"`
	TargetHost       string                `json:"target_host"`
	OpenSSHNamespace bool                  `json:"openssh_namespace,omitempty"`
	DialHost         string                `json:"dial_host,omitempty"`
	OriginalHost     string                `json:"original_host,omitempty"`
	Port             uint16                `json:"port,omitempty"`
	User             string                `json:"user,omitempty"`
	ControlPath      string                `json:"control_path"`
	ControlMaster    ssh.ControlMasterMode `json:"control_master"`
	ControlPersist   string                `json:"control_persist,omitempty"`
	JumpHost         string                `json:"jump_host,omitempty"`
	ConfigFile       string                `json:"config_file,omitempty"`
	CipherSpec       string                `json:"cipher_spec,omitempty"`
	AddressFamily    string                `json:"address_family,omitempty"`
	GatewayPorts     bool                  `json:"gateway_ports,omitempty"`
	IdentityFiles    []string              `json:"identity_files,omitempty"`
	Options          []string              `json:"options,omitempty"`
	PreserveSelector bool                  `json:"preserve_selector,omitempty"`
	Canonicalized    bool                  `json:"canonicalized,omitempty"`
}

// Validate checks that s contains well-formed detached daemon parameters.
func (s MuxDaemonSpec) Validate() error {
	if s.Version != muxDaemonSpecVersion {
		return fmt.Errorf("unsupported mux daemon spec version %d", s.Version)
	}
	if strings.TrimSpace(s.TargetHost) == "" {
		return fmt.Errorf("mux daemon spec requires non-empty target host")
	}
	cp := strings.TrimSpace(s.ControlPath)
	if cp == "" || strings.EqualFold(cp, "none") {
		return fmt.Errorf("mux daemon spec requires active control path")
	}
	if s.ControlMaster != ssh.ControlMasterYes && s.ControlMaster != ssh.ControlMasterAsk {
		return fmt.Errorf("mux daemon spec requires ControlMaster yes or ask, got %q", s.ControlMaster)
	}
	return nil
}

func readMuxDaemonSpec(r io.Reader) (MuxDaemonSpec, error) {
	if r == nil {
		return MuxDaemonSpec{}, fmt.Errorf("mux daemon spec reader is nil")
	}
	data, err := io.ReadAll(io.LimitReader(r, maxMuxDaemonSpecBytes+1))
	if err != nil {
		return MuxDaemonSpec{}, fmt.Errorf("read mux daemon spec failed: %w", err)
	}
	if len(data) > maxMuxDaemonSpecBytes {
		return MuxDaemonSpec{}, fmt.Errorf("mux daemon spec exceeds %d byte limit", maxMuxDaemonSpecBytes)
	}
	if len(data) == 0 {
		return MuxDaemonSpec{}, fmt.Errorf("mux daemon spec is empty")
	}
	var spec MuxDaemonSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		return MuxDaemonSpec{}, fmt.Errorf("decode mux daemon spec failed: %w", err)
	}
	if err := spec.Validate(); err != nil {
		return MuxDaemonSpec{}, err
	}
	return spec, nil
}

func (o *SshOptions) buildMuxDaemonSpec(nodeID, expandedPath string, master *ssh.MuxServer) MuxDaemonSpec {
	return o.buildMuxDaemonSpecWithProvider(nil, nodeID, expandedPath, master)
}

func (o *SshOptions) buildMuxDaemonSpecWithProvider(provider config.ConfigProvider, nodeID, expandedPath string, master *ssh.MuxServer) MuxDaemonSpec {
	return o.buildMuxDaemonSpecWithRawNode(provider, nodeID, nodeID, expandedPath, master)
}

func (o *SshOptions) buildMuxDaemonSpecWithRawNode(provider config.ConfigProvider, nodeID, rawNodeID, expandedPath string, master *ssh.MuxServer) MuxDaemonSpec {
	targetHost, port, user, preserveSelector := o.resolveMuxDaemonTargetWithProvider(provider, nodeID, master)
	forTarget := o.shouldPassIdentityFile(nodeID, master)
	masterMode, persist := o.resolveMuxDaemonControl(master)

	spec := MuxDaemonSpec{
		Version:          muxDaemonSpecVersion,
		TargetHost:       targetHost,
		OpenSSHNamespace: config.IsOpenSSHNodeID(strings.TrimSpace(nodeID)),
		Port:             uint16(port),
		User:             user,
		ControlPath:      expandedPath,
		ControlMaster:    masterMode,
		ControlPersist:   persist,
		JumpHost:         o.resolveMuxDaemonJumpHost(master),
		ConfigFile:       o.control.ConfigFile,
		AddressFamily:    o.control.AddressFamily,
		IdentityFiles:    o.resolveMuxDaemonIdentityFiles(nodeID, master, forTarget),
		PreserveSelector: preserveSelector,
	}
	canonHost := ""
	if master != nil {
		spec.OriginalHost = strings.TrimSpace(master.Target().OriginalHost)
		canonHost = strings.TrimSpace(master.Target().CanonicalHost)
		if dh := cleanMuxHost(master.Target().Host); dh != "" && dh != cleanMuxHost(targetHost) {
			spec.DialHost = dh
		}
	}
	if canonHost == "" {
		canonHost = resolveNodeCanonicalHost(provider, nodeID)
	}
	if canonHost == "" && rawNodeID != "" && rawNodeID != nodeID {
		canonHost = resolveNodeCanonicalHost(provider, rawNodeID)
	}
	spec.Canonicalized = (forTarget && o.canonicalized) || canonHost != ""
	if spec.OriginalHost == "" {
		if forTarget && o.canonicalized {
			spec.OriginalHost = o.originalHostForExpansion()
		} else if spec.Canonicalized {
			spec.OriginalHost = resolveNodeOpenSSHAlias(provider, nodeID)
			if spec.OriginalHost == "" && rawNodeID != "" && rawNodeID != nodeID {
				spec.OriginalHost = resolveNodeOpenSSHAlias(provider, rawNodeID)
			}
		}
	}
	if forTarget {
		spec.CipherSpec = o.CipherSpec
		spec.GatewayPorts = o.GatewayPorts
		spec.Options = o.collectMuxDaemonTargetOptions(master, len(spec.IdentityFiles) > 0)
	} else {
		spec.Options = o.collectMuxDaemonJumpOptions()
	}
	return spec
}

func (o *SshOptions) resolveMuxDaemonJumpHost(master *ssh.MuxServer) string {
	jumpHost := o.JumpHost
	if master != nil {
		jumpHost = master.Target().JumpHost
		if jumpHost == "" && ssh.IsDisabledProxyJump(o.JumpHost) {
			return "none"
		}
	}
	return jumpHost
}

func (o *SshOptions) resolveMuxDaemonIdentityFiles(nodeID string, master *ssh.MuxServer, forTarget bool) []string {
	keys := o.effectiveIdentityFiles()
	firstCLIKey := o.firstCLIIdentityFile(keys)
	if forTarget {
		if len(keys) > 0 {
			return slices.Clone(keys)
		}
		if master != nil && master.Target().KeyPath != "" {
			return []string{master.Target().KeyPath}
		}
		return nil
	}
	if master != nil && master.Target().KeyPath != "" {
		if firstCLIKey == "" || len(o.targetNodeIDs) > 0 || master.Target().KeyPath != normalizeCLIIdentityPath(firstCLIKey) {
			return []string{master.Target().KeyPath}
		}
	}
	return nil
}

func (o *SshOptions) collectMuxDaemonJumpOptions() []string {
	var opts []string
	for _, opt := range o.control.Options {
		if isConnectionWideMuxDaemonOption(opt) {
			opts = append(opts, opt)
		}
	}
	return opts
}

func (o *SshOptions) collectMuxDaemonTargetOptions(master *ssh.MuxServer, hasIdentities bool) []string {
	var opts []string
	preserveProxyNone := isEffectiveCLIProxyCommandNone(o.control.Options)
	emittedProxyNone := false
	for _, opt := range o.control.Options {
		if isMuxDaemonAuthoritativeOption(opt) {
			continue
		}
		if hasIdentities && isIdentityFileOption(opt) {
			continue
		}
		if o.GatewayPorts && isGatewayPortsOption(opt) {
			continue
		}
		if isSessionOrForwardOption(opt) && !isMuxDaemonPreservedOption(opt) {
			continue
		}
		if master != nil && isTargetOnlyMuxDaemonOption(opt) {
			if preserveProxyNone && !emittedProxyNone && isProxyCommandNoneOption(opt) {
				emittedProxyNone = true
				opts = append(opts, opt)
			}
			continue
		}
		opts = append(opts, opt)
	}
	return opts
}

func (o *SshOptions) applyMuxDaemonSpec(spec MuxDaemonSpec) error {
	if err := spec.Validate(); err != nil {
		return err
	}
	targetHost := strings.TrimSpace(spec.TargetHost)
	if spec.OpenSSHNamespace && !config.IsOpenSSHNodeID(targetHost) {
		targetHost = config.OpenSSHNodePrefix + targetHost
	}
	o.muxDaemonMode = true
	o.preserveDaemonSelector = spec.PreserveSelector
	o.Host = targetHost
	o.Port = spec.Port
	o.User = spec.User
	o.JumpHost = spec.JumpHost
	o.HostName = spec.DialHost
	o.cliHostName = ""
	o.canonicalized = spec.Canonicalized
	o.originalHost = strings.TrimSpace(spec.OriginalHost)
	o.control.ConfigFile = spec.ConfigFile
	o.control.AddressFamily = spec.AddressFamily
	o.control.ControlPath = spec.ControlPath
	o.control.MasterCount = 0
	o.CipherSpec = spec.CipherSpec
	o.GatewayPorts = spec.GatewayPorts
	o.Remember = "never"

	o.IdentityFiles = slices.Clone(spec.IdentityFiles)
	o.IdentityFile = ""
	o.identityFromCLIOptions = len(spec.IdentityFiles) > 0
	o.syncIdentityFiles()

	daemonOpts := make([]string, 0, len(spec.Options)+3)
	daemonOpts = append(daemonOpts, spec.Options...)
	if spec.ControlPersist != "" {
		daemonOpts = append(daemonOpts, "ControlPersist="+spec.ControlPersist)
	}
	daemonOpts = append(daemonOpts, "ClearAllForwardings=yes", "ControlMaster="+string(spec.ControlMaster))
	o.control.Options = daemonOpts

	o.PasswordStdin = false
	o.PassphraseStdin = false
	o.OTPStdin = false
	o.StdinRedirect = true
	o.args = nil
	o.appliedGeneralOpts = true
	o.normalizeForMuxDaemon()
	return nil
}

func (o *SshOptions) resolveMuxDaemonControl(master *ssh.MuxServer) (ssh.ControlMasterMode, string) {
	masterMode := ssh.ControlMasterYes
	if master != nil {
		if ctrl := master.Target().Control; ctrl != nil {
			if ctrl.Master == ssh.ControlMasterAsk || ctrl.Master == ssh.ControlMasterAutoAsk {
				masterMode = ssh.ControlMasterAsk
			}
			return masterMode, ctrl.Persist
		}
		return masterMode, ""
	}
	if o == nil {
		return masterMode, ""
	}
	if ctrlOpts, err := o.control.ToSessionControlOptions(); err == nil {
		var persist string
		if ctrlOpts.Persist != nil {
			persist = *ctrlOpts.Persist
		}
		if ctrlOpts.Master != nil && (*ctrlOpts.Master == ssh.ControlMasterAsk || *ctrlOpts.Master == ssh.ControlMasterAutoAsk) {
			masterMode = ssh.ControlMasterAsk
		}
		return masterMode, persist
	}
	return masterMode, firstCLIControlPersistOption(o.control.Options)
}

func firstCLIControlPersistOption(opts []string) string {
	for _, opt := range opts {
		key, val, err := adapter.SplitOptionKeyValue(opt)
		if err != nil || key == "" {
			continue
		}
		if spec, ok := ssh.LookupOptionSpec(key); ok && spec.CanonicalKey == ssh.OptionControlPersist {
			return val
		}
	}
	return ""
}

func isMuxDaemonAuthoritativeOption(opt string) bool {
	key, _, err := adapter.SplitOptionKeyValue(opt)
	if err != nil || key == "" {
		return false
	}
	spec, ok := ssh.LookupOptionSpec(key)
	if !ok {
		return false
	}
	switch spec.CanonicalKey {
	case ssh.OptionControlMaster, ssh.OptionControlPath, ssh.OptionControlPersist, ssh.OptionClearAllForwardings:
		return true
	default:
		return false
	}
}

func isIdentityFileOption(opt string) bool {
	key, _, err := adapter.SplitOptionKeyValue(opt)
	if err != nil || key == "" {
		return false
	}
	spec, ok := ssh.LookupOptionSpec(key)
	return ok && spec.CanonicalKey == ssh.OptionIdentityFile
}

func isConnectionWideMuxDaemonOption(opt string) bool {
	key, _, err := adapter.SplitOptionKeyValue(opt)
	if err != nil || key == "" {
		return false
	}
	spec, ok := ssh.LookupOptionSpec(key)
	if !ok {
		return false
	}
	if spec.Class == ssh.OptionClassTrust {
		return true
	}
	switch spec.CanonicalKey {
	case ssh.OptionAddressFamily, ssh.OptionBatchMode, ssh.OptionConnectTimeout, ssh.OptionIdentityAgent:
		return true
	default:
		return false
	}
}

func (o *SshOptions) firstCLIIdentityFile(keys []string) string {
	if o == nil {
		return ""
	}
	if len(keys) > 0 {
		return keys[0]
	}
	if o.IdentityFile != "" {
		return o.IdentityFile
	}
	return ""
}

func isProxyCommandOptionKey(key string) bool {
	return ssh.CanonicalOptionKey(key) == ssh.OptionProxyCommand
}

func isProxyCommandNoneOption(opt string) bool {
	key, val, err := adapter.SplitOptionKeyValue(opt)
	return err == nil && isProxyCommandOptionKey(key) && strings.EqualFold(strings.TrimSpace(val), "none")
}

func isEffectiveCLIProxyCommandNone(opts []string) bool {
	for _, opt := range opts {
		key, val, err := adapter.SplitOptionKeyValue(opt)
		if err != nil || !isProxyCommandOptionKey(key) {
			continue
		}
		return strings.EqualFold(strings.TrimSpace(val), "none")
	}
	return false
}

func (o *SshOptions) shouldPassIdentityFile(nodeID string, master *ssh.MuxServer) bool {
	if master == nil {
		return true
	}
	hasActiveCLIJump := ssh.HasActiveProxyJump(o.JumpHost)
	if hasActiveCLIJump && master.Target().JumpHost == "" {
		return false
	}
	if len(o.targetNodeIDs) > 0 {
		return matchesAnyTargetNodeID(nodeID, master, o.targetNodeIDs)
	}
	if o.Port > 0 && master.Target().Port > 0 && int(o.Port) != master.Target().Port {
		return false
	}
	if o.User != "" && master.Target().User != "" && o.User != master.Target().User {
		return false
	}
	if hasActiveCLIJump && isMasterInJumpSpec(nodeID, master, o.JumpHost) {
		return false
	}
	if o.Host != "" || o.Target.Selector != "" {
		return matchesTargetSelector(nodeID, master, o.Host, o.Target.Selector)
	}
	return true
}

func isMasterInJumpSpec(nodeID string, master *ssh.MuxServer, jumpSpec string) bool {
	for hop := range strings.SplitSeq(jumpSpec, ",") {
		hop = strings.TrimSpace(hop)
		if hop == "" || ssh.IsDisabledProxyJump(hop) {
			continue
		}
		if matchesTargetSelector(nodeID, master, hop, hop) {
			return true
		}
	}
	return false
}

func matchesAnyTargetNodeID(nodeID string, master *ssh.MuxServer, targetIDs []string) bool {
	candidates := []string{
		strings.TrimSpace(nodeID),
		config.UnwrapOpenSSHSelector(nodeID),
	}
	if master != nil {
		orig := strings.TrimSpace(master.Target().OriginalHost)
		candidates = append(candidates,
			orig,
			config.UnwrapOpenSSHSelector(orig),
		)
		if master.Target().Host != "" && master.Target().User != "" && master.Target().Port > 0 {
			candidates = append(candidates, config.FormatNodeID(master.Target().User, master.Target().Host, uint16(master.Target().Port)))
		}
	}
	for _, tid := range targetIDs {
		want := strings.TrimSpace(tid)
		if want == "" {
			continue
		}
		cleanWant := config.UnwrapOpenSSHSelector(want)
		for _, c := range candidates {
			if c != "" && (c == want || c == cleanWant) {
				return true
			}
		}
	}
	return false
}

func matchesTargetSelector(nodeID string, master *ssh.MuxServer, host, selector string) bool {
	candidates := []string{
		strings.TrimSpace(nodeID),
		config.UnwrapOpenSSHSelector(nodeID),
	}
	if master != nil {
		orig := strings.TrimSpace(master.Target().OriginalHost)
		candidates = append(candidates,
			orig,
			config.UnwrapOpenSSHSelector(orig),
			strings.TrimSpace(master.Target().Host),
		)
		if master.Target().Host != "" && master.Target().User != "" && master.Target().Port > 0 {
			candidates = append(candidates, config.FormatNodeID(master.Target().User, master.Target().Host, uint16(master.Target().Port)))
		}
	}
	for _, want := range []string{strings.TrimSpace(host), strings.TrimSpace(selector)} {
		if want == "" {
			continue
		}
		cleanWant := config.UnwrapOpenSSHSelector(want)
		for _, c := range candidates {
			if c != "" && (c == want || c == cleanWant) {
				return true
			}
		}
	}
	return false
}

func isTargetOnlyMuxDaemonOption(opt string) bool {
	key, _, err := adapter.SplitOptionKeyValue(opt)
	if err != nil || key == "" {
		return false
	}
	switch ssh.CanonicalOptionKey(key) {
	case ssh.OptionPort, ssh.OptionUser, ssh.OptionProxyJump, ssh.OptionIdentityFile, ssh.OptionHostName,
		ssh.OptionProxyCommand, ssh.OptionLocalCommand, ssh.OptionPermitLocalCommand:
		return true
	default:
		return false
	}
}

func (o *SshOptions) resolveMuxDaemonTarget(nodeID string, master *ssh.MuxServer) (host string, port int, user string) {
	host, port, user, _ = o.resolveMuxDaemonTargetWithProvider(nil, nodeID, master)
	return host, port, user
}

func (o *SshOptions) resolveMuxDaemonTargetWithProvider(provider config.ConfigProvider, nodeID string, master *ssh.MuxServer) (host string, port int, user string, preserveSelector bool) {
	rawSelector := strings.TrimSpace(nodeID)
	if rawSelector == "" && master != nil {
		rawSelector = strings.TrimSpace(master.Target().OriginalHost)
	}
	if rawSelector == "" {
		rawSelector = strings.TrimSpace(o.Host)
	}
	host, parsedUser, parsedPort, preserveSelector := extractMuxDaemonTargetComponents(provider, rawSelector)
	if host == "" && master != nil {
		host = master.Target().Host
	}
	if master != nil && master.Target().Port > 0 {
		port = master.Target().Port
	} else if o.Port > 0 {
		port = int(o.Port)
	} else {
		port = parsedPort
	}
	if master != nil && master.Target().User != "" {
		user = master.Target().User
	} else if o.User != "" {
		user = o.User
	} else {
		user = parsedUser
	}
	return host, port, user, preserveSelector
}

func extractMuxDaemonTargetComponents(provider config.ConfigProvider, rawSelector string) (host, parsedUser string, parsedPort int, preserveSelector bool) {
	if provider != nil && rawSelector != "" {
		if _, ok := provider.GetNode(rawSelector); ok {
			return rawSelector, "", 0, true
		}
	}
	if strings.HasPrefix(rawSelector, config.OpenSSHNodePrefix) {
		host = config.UnwrapOpenSSHSelector(rawSelector)
		if u, _, p, err := utils.ParseAddr(strings.TrimPrefix(rawSelector, config.OpenSSHNodePrefix)); err == nil {
			parsedUser = u
			parsedPort = int(p)
		}
		return host, parsedUser, parsedPort, false
	}
	if u, h, p, err := utils.ParseAddr(rawSelector); err == nil && u != "" && p != 0 && h != "" {
		return h, u, int(p), false
	}
	return rawSelector, "", 0, false
}
