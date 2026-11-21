package cmd

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
)

const (
	muxDaemonSpecVersion  = 1
	maxMuxDaemonSpecBytes = 256 * 1024
	muxDaemonSpecFDFlag   = "mux-daemon-spec-fd"

	bgChildSpecVersion  = 1
	maxBgChildSpecBytes = 1024
	bgChildSpecFDFlag   = "bg-child-spec-fd"
)

// bgChildSpec is the bounded JSON token delivered over an anonymous pipe FD
// from a -f parent process to its detached background child.
type bgChildSpec struct {
	Version int  `json:"version"`
	BgChild bool `json:"bg_child"`
}

func (s bgChildSpec) Validate() error {
	if s.Version != bgChildSpecVersion {
		return fmt.Errorf("unsupported background child spec version %d", s.Version)
	}
	if !s.BgChild {
		return fmt.Errorf("background child spec requires bg_child=true")
	}
	return nil
}

func readBgChildSpec(r io.Reader) (bgChildSpec, error) {
	if r == nil {
		return bgChildSpec{}, fmt.Errorf("background child spec reader is nil")
	}
	data, err := io.ReadAll(io.LimitReader(r, maxBgChildSpecBytes+1))
	if err != nil {
		return bgChildSpec{}, fmt.Errorf("read background child spec failed: %w", err)
	}
	if len(data) > maxBgChildSpecBytes {
		return bgChildSpec{}, fmt.Errorf("background child spec exceeds %d byte limit", maxBgChildSpecBytes)
	}
	if len(data) == 0 {
		return bgChildSpec{}, fmt.Errorf("background child spec is empty")
	}
	var spec bgChildSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		return bgChildSpec{}, fmt.Errorf("decode background child spec failed: %w", err)
	}
	if err := spec.Validate(); err != nil {
		return bgChildSpec{}, err
	}
	return spec, nil
}

// injectBackgroundChildSpecFDFlag inserts "--bg-child-spec-fd <fd>" right after
// the "ssh" subcommand (preserving root flags and "--" separators), or after
// "--" for test-binary subprocesses that omit the "ssh" subcommand.
func injectBackgroundChildSpecFDFlag(args []string, fd int) []string {
	fdStr := strconv.Itoa(fd)
	root := newRootCmd()
	initRootFlags(root)
	insertAt := -1
	for i := 0; i < len(args); {
		if args[i] == "--" {
			insertAt = i + 1
			break
		}
		if strings.HasPrefix(args[i], "-") {
			n, _, ok := routingFlag(root, args[i])
			if !ok {
				if sepIdx := slices.Index(args, "--"); sepIdx >= 0 {
					insertAt = sepIdx + 1
				}
				break
			}
			i += n
			continue
		}
		if args[i] == "ssh" {
			insertAt = i + 1
		} else if sepIdx := slices.Index(args, "--"); sepIdx >= 0 {
			insertAt = sepIdx + 1
		}
		break
	}
	if insertAt < 0 || insertAt > len(args) {
		insertAt = len(args)
	}
	out := make([]string, 0, len(args)+2)
	out = append(out, args[:insertAt]...)
	out = append(out, "--"+bgChildSpecFDFlag, fdStr)
	out = append(out, args[insertAt:]...)
	return out
}

// MuxDaemonSpec carries typed startup parameters from a foreground handoff
// session to the detached ControlPersist daemon over an inherited pipe FD,
// avoiding lossy CLI argv reconstruction and secret exposure in process lists.
type MuxDaemonSpec struct {
	Version            int                   `json:"version"`
	TargetHost         string                `json:"target_host"`
	OpenSSHNamespace   bool                  `json:"openssh_namespace,omitempty"`
	DialHost           string                `json:"dial_host,omitempty"`
	OriginalHost       string                `json:"original_host,omitempty"`
	Port               uint16                `json:"port,omitempty"`
	User               string                `json:"user,omitempty"`
	ControlPath        string                `json:"control_path"`
	ControlPathLiteral bool                  `json:"control_path_literal,omitempty"`
	ControlMaster      ssh.ControlMasterMode `json:"control_master"`
	ControlPersist     string                `json:"control_persist,omitempty"`
	JumpHost           string                `json:"jump_host,omitempty"`
	ConfigFile         string                `json:"config_file,omitempty"`
	CipherSpec         string                `json:"cipher_spec,omitempty"`
	AddressFamily      string                `json:"address_family,omitempty"`
	GatewayPorts       bool                  `json:"gateway_ports,omitempty"`
	IdentityFiles      []string              `json:"identity_files,omitempty"`
	Options            []string              `json:"options,omitempty"`
	PreserveSelector   bool                  `json:"preserve_selector,omitempty"`
	Canonicalized      bool                  `json:"canonicalized,omitempty"`
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
	if cp == "" || ssh.IsNoneValue(cp) {
		return fmt.Errorf("mux daemon spec requires active control path")
	}
	if s.ControlPathLiteral {
		if err := ssh.ValidateControlPath(s.ControlPath); err != nil {
			return fmt.Errorf("mux daemon spec invalid literal control path: %w", err)
		}
	}
	if s.ControlMaster != ssh.ControlMasterYes && s.ControlMaster != ssh.ControlMasterAsk {
		return fmt.Errorf("mux daemon spec requires ControlMaster yes or ask, got %q", s.ControlMaster)
	}
	if strings.TrimSpace(s.ControlPersist) != "" {
		if _, err := ssh.ParsePersistSetting(s.ControlPersist); err != nil {
			return fmt.Errorf("mux daemon spec invalid control persist %q: %w", s.ControlPersist, err)
		}
	}
	for _, opt := range s.Options {
		if err := validateMuxDaemonSpecOption(opt); err != nil {
			return err
		}
	}
	return nil
}

func validateMuxDaemonSpecOption(opt string) error {
	if strings.ContainsAny(opt, "\r\n\x00") {
		return fmt.Errorf("mux daemon spec option %q contains invalid control character", opt)
	}
	key, val, err := ssh.SplitOptionKeyValue(opt)
	if err != nil {
		return fmt.Errorf("mux daemon spec invalid option %q: %w", opt, err)
	}
	if key == "" || strings.TrimSpace(val) == "" {
		return fmt.Errorf("mux daemon spec option %q requires non-empty key and value", opt)
	}
	optSpec, ok := ssh.LookupOptionSpec(key)
	if !ok {
		return fmt.Errorf("mux daemon spec rejects unsupported option %q", opt)
	}
	switch optSpec.MuxPolicy {
	case ssh.OptionMuxAllow:
		var check ssh.Options
		if err := check.Append(optSpec.CanonicalKey, val); err != nil {
			return fmt.Errorf("mux daemon spec invalid option %q: %w", opt, err)
		}
		return nil
	case ssh.OptionMuxAllowNoneOnly:
		if !ssh.IsNoneValue(val) {
			return fmt.Errorf("mux daemon spec rejects option %q: only %s=none is allowed", opt, optSpec.OpenSSHName)
		}
		var check ssh.Options
		if err := check.Set(optSpec.CanonicalKey, val); err != nil {
			return fmt.Errorf("mux daemon spec invalid option %q: %w", opt, err)
		}
		return nil
	case ssh.OptionMuxAuthoritative:
		return fmt.Errorf("mux daemon spec rejects authoritative option %q", opt)
	case ssh.OptionMuxReject:
		return fmt.Errorf("mux daemon spec rejects option %q", opt)
	default:
		return fmt.Errorf("mux daemon spec rejects option %q", opt)
	}
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
		Version:            muxDaemonSpecVersion,
		TargetHost:         targetHost,
		OpenSSHNamespace:   config.IsOpenSSHNodeID(strings.TrimSpace(nodeID)),
		Port:               uint16(port),
		User:               user,
		ControlPath:        expandedPath,
		ControlPathLiteral: true,
		ControlMaster:      masterMode,
		ControlPersist:     persist,
		JumpHost:           o.resolveMuxDaemonJumpHost(master),
		ConfigFile:         o.control.ConfigFile,
		AddressFamily:      o.control.AddressFamily,
		IdentityFiles:      o.resolveMuxDaemonIdentityFiles(nodeID, master, forTarget),
		PreserveSelector:   preserveSelector,
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
		spec.Options = o.collectMuxDaemonTargetOptions()
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
	keys := canonicalIdentityFileSlice(o.effectiveIdentityFiles())
	firstCLIKey := o.firstCLIIdentityFile(keys)
	if forTarget {
		if len(keys) > 0 {
			return keys
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
	return projectMuxDaemonCLIOptions(o.control.Options, false, false)
}

func (o *SshOptions) collectMuxDaemonTargetOptions() []string {
	return projectMuxDaemonCLIOptions(o.control.Options, true, o.GatewayPorts)
}

func isTargetLevelDirectiveKey(key string) bool {
	switch ssh.CanonicalOptionKey(key) {
	case ssh.OptionPort, ssh.OptionUser, ssh.OptionHostName, ssh.OptionProxyJump:
		return true
	default:
		return false
	}
}

func muxDaemonCandidateAllowed(spec ssh.OptionSpec, forTarget, suppressGatewayPorts bool) bool {
	if !forTarget {
		return spec.IsConnectionWide() && spec.MuxPolicy == ssh.OptionMuxAllow
	}
	switch spec.MuxPolicy {
	case ssh.OptionMuxAllow:
		return !suppressGatewayPorts || spec.CanonicalKey != ssh.OptionGatewayPorts
	case ssh.OptionMuxAllowNoneOnly:
		return true
	default:
		return false
	}
}

func projectMuxDaemonCLIOptions(rawOpts []string, forTarget, suppressGatewayPorts bool) []string {
	if len(rawOpts) == 0 {
		return nil
	}
	candidates := make([]string, 0, len(rawOpts))
	firstOrder := make(map[string]int, len(rawOpts))
	for _, opt := range rawOpts {
		key, _, err := ssh.SplitOptionKeyValue(opt)
		if err != nil || key == "" || isTargetLevelDirectiveKey(key) {
			continue
		}
		spec, ok := ssh.LookupOptionSpec(key)
		if !ok || !muxDaemonCandidateAllowed(spec, forTarget, suppressGatewayPorts) {
			continue
		}
		if _, seen := firstOrder[spec.CanonicalKey]; !seen {
			firstOrder[spec.CanonicalKey] = len(firstOrder)
		}
		candidates = append(candidates, opt)
	}
	if len(candidates) == 0 {
		return nil
	}
	parsed, err := ssh.ParseCLIOptions(candidates)
	if err != nil {
		return fallbackMuxDaemonCLIOptions(candidates)
	}
	if parsed.IsEmpty() {
		return nil
	}
	if forTarget {
		stripNonNoneAllowNoneOnlyOptions(parsed)
	}
	projected := ssh.ProjectCLIOptions(parsed)
	if len(projected) <= 1 {
		return projected
	}
	slices.SortStableFunc(projected, func(a, b string) int {
		return compareProjectedOptionOrder(a, b, firstOrder)
	})
	return projected
}

func stripNonNoneAllowNoneOnlyOptions(opts *ssh.Options) {
	if opts.IsEmpty() {
		return
	}
	for _, spec := range ssh.RegisteredOptionSpecs() {
		if spec.MuxPolicy != ssh.OptionMuxAllowNoneOnly {
			continue
		}
		if opts.Has(spec.CanonicalKey) && !ssh.IsNoneValue(opts.Get(spec.CanonicalKey)) {
			opts.Delete(spec.CanonicalKey)
		}
	}
}

func compareProjectedOptionOrder(a, b string, firstOrder map[string]int) int {
	ka, _, _ := strings.Cut(a, "=")
	kb, _, _ := strings.Cut(b, "=")
	oa, oka := firstOrder[ssh.CanonicalOptionKey(ka)]
	ob, okb := firstOrder[ssh.CanonicalOptionKey(kb)]
	if !oka {
		oa = len(firstOrder)
	}
	if !okb {
		ob = len(firstOrder)
	}
	return cmp.Compare(oa, ob)
}

func fallbackMuxDaemonCLIOptions(candidates []string) []string {
	seenNoneOnly := make(map[string]bool)
	out := make([]string, 0, len(candidates))
	for _, opt := range candidates {
		key, val, err := ssh.SplitOptionKeyValue(opt)
		if err != nil || key == "" {
			continue
		}
		spec, ok := ssh.LookupOptionSpec(key)
		if !ok {
			continue
		}
		if spec.MuxPolicy == ssh.OptionMuxAllowNoneOnly {
			if !seenNoneOnly[spec.CanonicalKey] {
				seenNoneOnly[spec.CanonicalKey] = true
				if ssh.IsNoneValue(val) {
					out = append(out, opt)
				}
			}
			continue
		}
		out = append(out, opt)
	}
	if len(out) == 0 {
		return nil
	}
	return out
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
	o.control.controlPathLiteral = spec.ControlPathLiteral
	o.control.MasterCount = 0
	o.control.CtlCmd = ""
	o.control.ctlCmdSet = false
	o.CipherSpec = spec.CipherSpec
	o.GatewayPorts = spec.GatewayPorts
	o.Remember = "never"
	o.Sudo = false
	o.OTP = ""
	o.DisableTTY = false
	o.ForceTTYCount = 0
	o.cliTTYMode = ""

	o.IdentityFiles = canonicalIdentityFileSlice(spec.IdentityFiles)
	o.IdentityFile = ""
	o.identityFromCLIOptions = len(o.IdentityFiles) > 0
	o.syncIdentityFiles()

	daemonOpts := make([]string, 0, len(spec.Options)+3)
	daemonOpts = append(daemonOpts, "ControlMaster="+string(spec.ControlMaster), "ClearAllForwardings=yes")
	if spec.ControlPersist != "" {
		daemonOpts = append(daemonOpts, "ControlPersist="+spec.ControlPersist)
	}
	daemonOpts = append(daemonOpts, spec.Options...)
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
		key, val, err := ssh.SplitOptionKeyValue(opt)
		if err != nil || key == "" {
			continue
		}
		if spec, ok := ssh.LookupOptionSpec(key); ok && spec.CanonicalKey == ssh.OptionControlPersist {
			return val
		}
	}
	return ""
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
	key, val, err := ssh.SplitOptionKeyValue(opt)
	if err != nil || key == "" || strings.TrimSpace(val) == "" {
		return true
	}
	if spec, ok := ssh.LookupOptionSpec(key); ok {
		return !spec.IsConnectionWide()
	}
	return true
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
