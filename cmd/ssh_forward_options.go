package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/internal/sshenv"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"golang.org/x/term"
)

type optionArrayFlagValue struct {
	values  *[]string
	changed bool
	onAdded func(string)
}

var (
	_ pflag.Value      = (*optionArrayFlagValue)(nil)
	_ pflag.SliceValue = (*optionArrayFlagValue)(nil)
)

func newOptionArrayFlagValue(target *[]string, onAdded func(string)) *optionArrayFlagValue {
	return &optionArrayFlagValue{
		values:  target,
		onAdded: onAdded,
	}
}

func (v *optionArrayFlagValue) Set(val string) error {
	if !v.changed {
		*v.values = []string{val}
		v.changed = true
	} else {
		*v.values = append(*v.values, val)
	}
	if v.onAdded != nil {
		v.onAdded(val)
	}
	return nil
}

func (v *optionArrayFlagValue) Append(val string) error {
	*v.values = append(*v.values, val)
	if v.onAdded != nil {
		v.onAdded(val)
	}
	return nil
}

func (v *optionArrayFlagValue) Replace(vals []string) error {
	out := make([]string, len(vals))
	copy(out, vals)
	*v.values = out
	for _, val := range vals {
		if v.onAdded != nil {
			v.onAdded(val)
		}
	}
	return nil
}

func (v *optionArrayFlagValue) GetSlice() []string {
	if v.values == nil {
		return nil
	}
	out := make([]string, len(*v.values))
	copy(out, *v.values)
	return out
}

func (v *optionArrayFlagValue) Type() string {
	return "stringArray"
}

func (v *optionArrayFlagValue) String() string {
	if v.values == nil || len(*v.values) == 0 {
		return "[]"
	}
	return "[" + strings.Join(*v.values, ",") + "]"
}

type stdioForwardFlagValue struct {
	opts *SshOptions
	set  bool
}

func (v *stdioForwardFlagValue) Set(val string) error {
	if v.set {
		return errors.New("stdio forward (-W) cannot be specified multiple times")
	}
	v.set = true
	v.opts.StdioForward = val
	v.opts.stdioForwardSet = true
	return nil
}

func (v *stdioForwardFlagValue) Type() string {
	return "string"
}

func (v *stdioForwardFlagValue) String() string {
	if v.opts == nil {
		return ""
	}
	return v.opts.StdioForward
}

type tunnelDeviceFlagValue struct {
	opts *SshOptions
}

func (v *tunnelDeviceFlagValue) Set(val string) error {
	v.opts.TunnelDevice = val
	v.opts.tunnelDeviceSet = true
	if strings.TrimSpace(val) != "" {
		v.opts.recordTunnelDeviceFlag()
	}
	return nil
}

func (v *tunnelDeviceFlagValue) Type() string {
	return "string"
}

func (v *tunnelDeviceFlagValue) String() string {
	if v.opts == nil {
		return ""
	}
	return v.opts.TunnelDevice
}

type disableTTYFlagValue struct {
	opts *SshOptions
}

func (v *disableTTYFlagValue) Set(val string) error {
	parsed, err := strconv.ParseBool(val)
	if err != nil {
		return err
	}
	v.opts.DisableTTY = parsed
	if parsed {
		v.opts.ForceTTYCount = 0
		v.opts.cliTTYMode = ssh.RequestTTYNo
	} else if v.opts.cliTTYMode == ssh.RequestTTYNo {
		v.opts.cliTTYMode = ""
	}
	return nil
}

func (v *disableTTYFlagValue) Type() string {
	return "bool"
}

func (v *disableTTYFlagValue) String() string {
	if v.opts == nil {
		return "false"
	}
	return strconv.FormatBool(v.opts.DisableTTY)
}

type forceTTYFlagValue struct {
	opts *SshOptions
}

func (v *forceTTYFlagValue) Set(val string) error {
	if val == "+1" {
		v.opts.ForceTTYCount++
	} else {
		n, err := strconv.Atoi(val)
		if err != nil {
			return err
		}
		v.opts.ForceTTYCount = n
	}
	if v.opts.ForceTTYCount <= 0 {
		if !v.opts.DisableTTY {
			v.opts.cliTTYMode = ""
		}
		return nil
	}
	v.opts.DisableTTY = false
	if v.opts.ForceTTYCount >= 2 {
		v.opts.cliTTYMode = ssh.RequestTTYForce
	} else {
		v.opts.cliTTYMode = ssh.RequestTTYYes
	}
	return nil
}

func (v *forceTTYFlagValue) Type() string {
	return "count"
}

func (v *forceTTYFlagValue) String() string {
	if v.opts == nil {
		return "0"
	}
	return strconv.Itoa(v.opts.ForceTTYCount)
}

type dynamicForwardFlagValue struct {
	opts *SshOptions
}

func (v *dynamicForwardFlagValue) Set(val string) error {
	v.opts.DynamicForward = val
	v.opts.DynamicForwards = append(v.opts.DynamicForwards, val)
	return nil
}

func (v *dynamicForwardFlagValue) Type() string {
	return "string"
}

func (v *dynamicForwardFlagValue) String() string {
	if v.opts == nil {
		return ""
	}
	return v.opts.DynamicForward
}

func (o *SshOptions) registerForwardAndSessionFlags(cmd *cobra.Command) {
	o.control.onOptionAdded = o.recordOptionFlag

	cmd.Flags().BoolVarP(&o.GatewayPorts, "gateway-ports", "g", false, i18n.T("ssh_flag_gateway_ports"))
	cmd.Flags().VarP(&dynamicForwardFlagValue{opts: o}, "dynamic-forward", "D", i18n.T("flag_dynamic_forward"))
	cmd.Flags().VarP(&stdioForwardFlagValue{opts: o}, "stdio-forward", "W", i18n.T("ssh_flag_stdio_forward"))
	cmd.Flags().VarP(&tunnelDeviceFlagValue{opts: o}, "tunnel-device", "w", i18n.T("ssh_flag_tunnel_device"))

	disableFlag := cmd.Flags().VarPF(&disableTTYFlagValue{opts: o}, "disable-tty", "T", i18n.T("ssh_flag_disable_tty"))
	disableFlag.NoOptDefVal = "true"

	forceFlag := cmd.Flags().VarPF(&forceTTYFlagValue{opts: o}, "force-tty", "t", i18n.T("ssh_flag_force_tty"))
	forceFlag.NoOptDefVal = "+1"
}

func (o *SshOptions) recordOptionFlag(raw string) {
	if o == nil || o.cliTunnelLockedByW || o.cliTunnelMode != "" {
		return
	}
	key, val, err := ssh.SplitOptionKeyValue(raw)
	if err != nil {
		return
	}
	if ssh.CanonicalOptionKey(key) == ssh.OptionTunnel {
		if mode, parseErr := ssh.ParseTunnelOption(val); parseErr == nil {
			o.cliTunnelMode = mode
		}
	}
}

func (o *SshOptions) recordTunnelDeviceFlag() {
	if o == nil {
		return
	}
	if o.cliTunnelMode == "" {
		o.cliTunnelMode = string(ssh.TunnelModePointToPoint)
	}
	o.cliTunnelLockedByW = true
}

func (o *SshOptions) explicitCLITTYMode() ssh.RequestTTYMode {
	if o == nil {
		return ""
	}
	if o.cliTTYMode != "" {
		return o.cliTTYMode
	}
	if o.DisableTTY {
		return ssh.RequestTTYNo
	}
	if o.ForceTTYCount >= 2 {
		return ssh.RequestTTYForce
	}
	if o.ForceTTYCount == 1 {
		return ssh.RequestTTYYes
	}
	return ""
}

func (o *SshOptions) cliDynamicForwards() []string {
	if o == nil {
		return nil
	}
	if len(o.DynamicForwards) > 0 {
		return o.DynamicForwards
	}
	if o.DynamicForward != "" {
		return []string{o.DynamicForward}
	}
	return nil
}

func (o *SshOptions) toSessionControlOptions() (adapter.SessionControlOptions, error) {
	if o == nil {
		return adapter.SessionControlOptions{}, nil
	}
	sessionOpts, err := o.controlSessionOptions()
	if err != nil {
		return sessionOpts, err
	}
	if err := o.applyCLISessionFlags(&sessionOpts.Options); err != nil {
		return sessionOpts, err
	}
	return sessionOpts, nil
}

func (o *SshOptions) applyCLISessionFlags(opts **ssh.Options) error {
	ensureOpts := func() *ssh.Options {
		if *opts == nil {
			*opts = &ssh.Options{}
		}
		return *opts
	}
	for _, kv := range []struct {
		set bool
		key string
		val string
	}{
		{o.GatewayPorts, ssh.OptionGatewayPorts, "yes"},
		{o.BgRun, ssh.OptionForkAfterAuthentication, "yes"},
		{o.NoCmd, ssh.OptionSessionType, string(ssh.SessionTypeNone)},
		{o.StdinRedirect, ssh.OptionStdinNull, "yes"},
		{o.CipherSpec != "", ssh.OptionCiphers, o.CipherSpec},
		{o.EscapeCharSpec != "", ssh.OptionEscapeChar, o.EscapeCharSpec},
		{o.ForwardAgentSpec != "", ssh.OptionForwardAgent, o.ForwardAgentSpec},
	} {
		if kv.set {
			if setErr := ensureOpts().Set(kv.key, kv.val); setErr != nil {
				return setErr
			}
		}
	}
	if o.TunnelDevice != "" {
		if setErr := o.applyCLITunnelDevice(ensureOpts); setErr != nil {
			return setErr
		}
	}
	if ttyMode := o.explicitCLITTYMode(); ttyMode != "" {
		if setErr := ensureOpts().Set(ssh.OptionRequestTTY, string(ttyMode)); setErr != nil {
			return setErr
		}
	}
	return o.applyCLIIdentityNoneTruncation(ensureOpts)
}

func (o *SshOptions) applyCLIIdentityNoneTruncation(ensureOpts func() *ssh.Options) error {
	o.syncIdentityFiles()
	if !slices.ContainsFunc(o.IdentityFiles, ssh.IsNoneValue) {
		return nil
	}
	opts := ensureOpts()
	opts.Delete(ssh.OptionIdentityFile)
	for _, keyPath := range o.absIdentityFiles() {
		if appendErr := opts.Append(ssh.OptionIdentityFile, keyPath); appendErr != nil {
			return appendErr
		}
	}
	return nil
}

func (o *SshOptions) applyCLITunnelDevice(ensureOpts func() *ssh.Options) error {
	devSpec, parseErr := ssh.ParseTunnelDevice(o.TunnelDevice)
	if parseErr != nil {
		return fmt.Errorf("invalid tunnel device (-w): %w", parseErr)
	}
	opts := ensureOpts()
	if setErr := opts.Set(ssh.OptionTunnelDevice, devSpec.String()); setErr != nil {
		return setErr
	}
	if o.cliTunnelMode != "" {
		if setErr := opts.Set(ssh.OptionTunnel, o.cliTunnelMode); setErr != nil {
			return setErr
		}
	} else if opts.Tunnel() == "" {
		if setErr := opts.Set(ssh.OptionTunnel, string(ssh.TunnelModePointToPoint)); setErr != nil {
			return setErr
		}
	}
	return nil
}

func (o *SshOptions) normalizeForMuxDaemon() {
	o.NoCmd = true
	o.Subsystem = false
	o.EscapeCharSpec = ""
	o.ForwardAgentSpec = ""
	o.Command = ""
	o.stdinScript = false
	o.StdioForward = ""
	o.stdioForwardSet = false
	o.TunnelDevice = ""
	o.tunnelDeviceSet = false
	o.cliTunnelMode = ""
	o.cliTunnelLockedByW = false
	o.LocalForwards = nil
	o.RemoteForwards = nil
	o.DynamicForward = ""
	o.DynamicForwards = nil
	o.BgRun = false
}

func (o *SshOptions) validateSubsystemFlags() error {
	if !o.Subsystem {
		return nil
	}
	if strings.TrimSpace(o.Command) == "" {
		return errors.New(i18n.T("ssh_err_subsystem_requires_name"))
	}
	if o.effectiveNoCmd() {
		return errors.New(i18n.T("ssh_err_subsystem_with_nocmd"))
	}
	if o.effectiveBgRun() {
		return errors.New("subsystem (-s) cannot be combined with background mode (-f)")
	}
	if o.StdioForward != "" {
		return errors.New(i18n.T("ssh_err_subsystem_with_stdio_forward"))
	}
	if o.Sudo {
		return errors.New(i18n.T("ssh_err_subsystem_with_sudo"))
	}
	if o.stdinScript {
		return errors.New(i18n.T("ssh_err_subsystem_with_stdin_script"))
	}
	if o.execution.enabled() || o.execution.noLoginSet || o.NoLoginShell || o.execution.interpreter != "" || o.execution.login {
		return errors.New(i18n.T("ssh_err_subsystem_with_exec_flags"))
	}
	return nil
}

func (o *SshOptions) validateForwardAndSessionFlags() error {
	if o.stdioForwardSet || o.StdioForward != "" {
		if _, _, err := ssh.ParseStdioForward(o.StdioForward); err != nil {
			return err
		}
		if o.Command != "" || o.stdinScript {
			return errors.New(i18n.T("ssh_err_stdio_forward_with_cmd"))
		}
		if o.effectiveBgRun() {
			return errors.New(i18n.T("ssh_err_stdio_forward_with_bg"))
		}
		if o.Sudo {
			return errors.New(i18n.T("ssh_err_stdio_forward_with_sudo"))
		}
		ctlCmd := strings.ToLower(strings.TrimSpace(o.control.CtlCmd))
		if ctlCmd != "" && ctlCmd != "proxy" {
			return errors.New(i18n.T("ssh_err_stdio_forward_with_mux_cmd"))
		}
	}
	if (o.NoCmd || (!o.NoCmd && o.cliSessionTypeNone())) && o.Command != "" {
		return errors.New(i18n.T("ssh_err_nocmd_with_command"))
	}
	if err := o.validateSubsystemFlags(); err != nil {
		return err
	}
	if o.tunnelDeviceSet || o.TunnelDevice != "" {
		if _, err := ssh.ParseTunnelDevice(o.TunnelDevice); err != nil {
			return fmt.Errorf("invalid tunnel device (-w): %w", err)
		}
	}
	if err := o.validateCLIForwardArgs(); err != nil {
		return err
	}
	if _, err := o.toSessionControlOptions(); err != nil {
		return err
	}
	return nil
}

func (o *SshOptions) resolveAndCacheSessionOptions(provider config.ConfigProvider, nodeID string) (*ssh.Options, error) {
	if err := o.ensureGeneralOptionsApplied(); err != nil {
		return nil, err
	}
	sessionOpts, err := o.toSessionControlOptions()
	if err != nil {
		return nil, err
	}
	isChild := o.isBackgroundChild()
	if provider == nil {
		eff := ssh.MergeOptions(sessionOpts.ToSSHOptions())
		if o.isMuxDaemon() && eff != nil {
			eff.StripClasses(ssh.OptionClassSession, ssh.OptionClassLocalExec)
			eff.Delete(ssh.OptionForwardAgent)
		} else if isChild && eff != nil {
			eff.StripClasses(ssh.OptionClassLocalExec)
		}
		o.effectiveSSHOptions = eff
		return eff, nil
	}
	connTarget := effectiveConnectionTarget(o, nodeID)
	target := controlTarget(o, provider, nodeID)
	o.resolvedTarget = &target
	lookupKey, sessionAuth := resolveControlSessionLookup(o, provider, nodeID, connTarget, target)
	adpOpts := []adapter.Option{adapter.WithLocalExecution(!o.isMuxDaemon() && !isChild)}
	if lookupKey != "" && (sessionAuth.ProxyJump != "" || sessionAuth.OriginalHost != "" || sessionAuth.CanonicalHost != "") {
		adpOpts = append(adpOpts, adapter.WithSessionAuthOverride(lookupKey, sessionAuth))
	}
	pol, err := adapter.NewSSHAdapter(provider, adpOpts...).Resolve(context.Background(), adapter.ResolveRequest{
		NodeID:         lookupKey,
		SessionControl: &sessionOpts,
	})
	if err != nil {
		return nil, err
	}
	eff := pol.Options()
	if o.isMuxDaemon() && eff != nil {
		eff.StripClasses(ssh.OptionClassSession, ssh.OptionClassLocalExec)
		eff.Delete(ssh.OptionForwardAgent)
	} else if isChild && eff != nil {
		eff.StripClasses(ssh.OptionClassLocalExec)
	}
	o.effectiveSSHOptions = eff
	return eff, nil
}

func (o *SshOptions) effectiveSessionOptions() (*ssh.Options, error) {
	if o == nil {
		return nil, nil
	}
	if o.effectiveSSHOptions != nil {
		return o.effectiveSSHOptions, nil
	}
	sessionOpts, err := o.toSessionControlOptions()
	if err != nil {
		return nil, err
	}
	return ssh.MergeOptions(sessionOpts.ToSSHOptions()), nil
}

func (o *SshOptions) effectiveNoCmd() bool {
	if o == nil {
		return false
	}
	if o.NoCmd || o.StdioForward != "" {
		return true
	}
	eff, err := o.effectiveSessionOptions()
	if err == nil && eff != nil && eff.SessionType() == ssh.SessionTypeNone {
		return true
	}
	return false
}

func (o *SshOptions) effectiveBgRunChecked() (bool, error) {
	if o == nil {
		return false, nil
	}
	if o.BgRun {
		return true, nil
	}
	eff, err := o.effectiveSessionOptions()
	if err != nil {
		return false, err
	}
	if eff != nil {
		if fork, ok := eff.ForkAfterAuthentication(); ok && fork {
			return true, nil
		}
	}
	return false, nil
}

func (o *SshOptions) effectiveBgRun() bool {
	bg, _ := o.effectiveBgRunChecked()
	return bg
}

func (o *SshOptions) effectiveStdinNull() bool {
	if o == nil {
		return false
	}
	if o.StdinRedirect || o.effectiveBgRun() {
		return true
	}
	eff, err := o.effectiveSessionOptions()
	if err == nil && eff != nil {
		if sn, ok := eff.StdinNull(); ok && sn {
			return true
		}
	}
	return false
}

func (o *SshOptions) cliSessionTypeNone() bool {
	if o == nil {
		return false
	}
	eff, err := o.effectiveSessionOptions()
	if err == nil && eff != nil {
		return eff.SessionType() == ssh.SessionTypeNone
	}
	return false
}

func (o *SshOptions) effectiveRequestTTY() ssh.RequestTTYMode {
	if o == nil {
		return ssh.RequestTTYAuto
	}
	if ttyMode := o.explicitCLITTYMode(); ttyMode != "" {
		return ttyMode
	}
	if eff, err := o.effectiveSessionOptions(); err == nil && eff != nil {
		if mode := eff.RequestTTY(); mode != "" {
			return mode
		}
	}
	if o.StdioForward != "" || o.effectiveNoCmd() {
		return ssh.RequestTTYNo
	}
	return ssh.RequestTTYAuto
}

// subsystemAllocatePTY reports whether `-s <subsystem>` should request a PTY.
// Subsystems default to raw non-PTY streams unless -t / RequestTTY=yes|force is explicitly set.
func (o *SshOptions) subsystemAllocatePTY(stdin io.Reader) bool {
	if o == nil {
		return false
	}
	switch o.effectiveRequestTTY() {
	case ssh.RequestTTYForce:
		return true
	case ssh.RequestTTYYes:
		if stdin == nil {
			return false
		}
		_, isTerm := isLocalTerminal(stdin)
		return isTerm
	default:
		return false
	}
}

// hasNonEmptyRemoteCommand reports whether an effective RemoteCommand (not "none") is configured.
func (o *SshOptions) hasNonEmptyRemoteCommand() (bool, error) {
	if o == nil || o.NoCmd || o.StdioForward != "" || o.Subsystem || o.isMuxDaemon() {
		return false, nil
	}
	eff, err := o.effectiveSessionOptions()
	if err != nil {
		return false, err
	}
	if eff == nil {
		return false, nil
	}
	rc := strings.TrimSpace(eff.RemoteCommand())
	return rc != "" && !strings.EqualFold(rc, "none"), nil
}

// resolveEffectiveRemoteCommand returns the expanded RemoteCommand option when no explicit CLI command,
// stdin script, -N, -W, -s, or mux-daemon child mode is active.
func (o *SshOptions) resolveEffectiveRemoteCommand(target ssh.TargetContext) (string, error) {
	if o == nil || o.Command != "" || o.stdinScript || o.effectiveNoCmd() || o.StdioForward != "" || o.Subsystem || o.isMuxDaemon() {
		return "", nil
	}
	eff, err := o.effectiveSessionOptions()
	if err != nil || eff == nil {
		return "", err
	}
	rc := strings.TrimSpace(eff.RemoteCommand())
	if rc == "" || strings.EqualFold(rc, "none") {
		return "", nil
	}
	return ssh.ExpandRemoteCommand(rc, sshenv.Discover(), target)
}

type sessionForwardConfig struct {
	localForwards         []ssh.ForwardSpec
	remoteForwards        []ssh.ForwardSpec
	dynamicForwards       []ssh.ForwardEndpoint
	gatewayPorts          bool
	streamLocalBindUnlink bool
	streamLocalBindMask   uint32
	hasTunnelDevice       bool
	tunnelMode            ssh.TunnelMode
	tunnelDevice          ssh.TunnelDeviceSpec
	exitOnForwardFailure  bool
	clearAllForwardings   bool
}

func collectUniqueForwardSpecs(primary, secondary []string) ([]ssh.ForwardSpec, error) {
	seen := make(map[string]struct{})
	var out []ssh.ForwardSpec
	appendSpec := func(raw string) error {
		spec, err := ssh.ParseForwardSpec(raw)
		if err != nil {
			return err
		}
		if spec.Bind.IsUnix() {
			if err := ssh.ValidateStreamLocalPathSyntax(spec.Bind.SocketPath); err != nil {
				return err
			}
		}
		if spec.Dest.IsUnix() {
			if err := ssh.ValidateStreamLocalPathSyntax(spec.Dest.SocketPath); err != nil {
				return err
			}
		}
		key := spec.String()
		if _, exists := seen[key]; !exists {
			seen[key] = struct{}{}
			out = append(out, spec)
		}
		return nil
	}
	for _, raw := range primary {
		if err := appendSpec(raw); err != nil {
			return nil, err
		}
	}
	for _, raw := range secondary {
		if err := appendSpec(raw); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func collectUniqueRemoteForwardSpecs(primary, secondary []string) ([]ssh.ForwardSpec, error) {
	seen := make(map[string]struct{})
	var out []ssh.ForwardSpec
	appendSpec := func(raw string) error {
		spec, err := ssh.ParseRemoteForwardSpec(raw)
		if err != nil {
			return err
		}
		if spec.Bind.IsUnix() {
			if err := ssh.ValidateStreamLocalPathSyntax(spec.Bind.SocketPath); err != nil {
				return err
			}
		}
		if !spec.IsDynamic && spec.Dest.IsUnix() {
			if err := ssh.ValidateStreamLocalPathSyntax(spec.Dest.SocketPath); err != nil {
				return err
			}
		}
		key := spec.String()
		if _, exists := seen[key]; !exists {
			seen[key] = struct{}{}
			out = append(out, spec)
		}
		return nil
	}
	for _, raw := range primary {
		if err := appendSpec(raw); err != nil {
			return nil, err
		}
	}
	for _, raw := range secondary {
		if err := appendSpec(raw); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func collectUniqueDynamicEndpoints(primary, secondary []string) ([]ssh.ForwardEndpoint, error) {
	seen := make(map[string]struct{})
	var out []ssh.ForwardEndpoint
	appendEp := func(raw string) error {
		ep, err := ssh.ParseDynamicForwardEndpoint(raw)
		if err != nil {
			return err
		}
		if ep.IsUnix() {
			if err := ssh.ValidateStreamLocalPathSyntax(ep.SocketPath); err != nil {
				return err
			}
		}
		key := ep.String()
		if _, exists := seen[key]; !exists {
			seen[key] = struct{}{}
			out = append(out, ep)
		}
		return nil
	}
	for _, raw := range primary {
		if err := appendEp(raw); err != nil {
			return nil, err
		}
	}
	for _, raw := range secondary {
		if err := appendEp(raw); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (o *SshOptions) validateCLIForwardArgs() error {
	if _, err := collectUniqueForwardSpecs(o.LocalForwards, nil); err != nil {
		return err
	}
	if _, err := collectUniqueRemoteForwardSpecs(o.RemoteForwards, nil); err != nil {
		return err
	}
	if _, err := collectUniqueDynamicEndpoints(o.cliDynamicForwards(), nil); err != nil {
		return err
	}
	return nil
}

func expandForwardSpecs(cfg *sessionForwardConfig, env ssh.Environment, target ssh.TargetContext) error {
	for i := range cfg.localForwards {
		if cfg.localForwards[i].Bind.IsUnix() {
			expanded, err := ssh.ExpandStreamLocalPath(cfg.localForwards[i].Bind.SocketPath, env, target, true)
			if err != nil {
				return err
			}
			cfg.localForwards[i].Bind.SocketPath = expanded
			cfg.localForwards[i].BindAddr = expanded
		}
		if cfg.localForwards[i].Dest.IsUnix() {
			expanded, err := ssh.ExpandStreamLocalPath(cfg.localForwards[i].Dest.SocketPath, env, target, false)
			if err != nil {
				return err
			}
			cfg.localForwards[i].Dest.SocketPath = expanded
			cfg.localForwards[i].DestAddr = expanded
		}
	}
	for i := range cfg.remoteForwards {
		if cfg.remoteForwards[i].Bind.IsUnix() {
			expanded, err := ssh.ExpandStreamLocalPath(cfg.remoteForwards[i].Bind.SocketPath, env, target, false)
			if err != nil {
				return err
			}
			cfg.remoteForwards[i].Bind.SocketPath = expanded
			cfg.remoteForwards[i].BindAddr = expanded
		}
		if !cfg.remoteForwards[i].IsDynamic && cfg.remoteForwards[i].Dest.IsUnix() {
			expanded, err := ssh.ExpandStreamLocalPath(cfg.remoteForwards[i].Dest.SocketPath, env, target, true)
			if err != nil {
				return err
			}
			cfg.remoteForwards[i].Dest.SocketPath = expanded
			cfg.remoteForwards[i].DestAddr = expanded
		}
	}
	for i := range cfg.dynamicForwards {
		if cfg.dynamicForwards[i].IsUnix() {
			expanded, err := ssh.ExpandStreamLocalPath(cfg.dynamicForwards[i].SocketPath, env, target, true)
			if err != nil {
				return err
			}
			cfg.dynamicForwards[i].SocketPath = expanded
		}
	}
	deduplicateExpandedForwards(cfg)
	return nil
}

func deduplicateExpandedForwards(cfg *sessionForwardConfig) {
	if len(cfg.localForwards) > 1 {
		seen := make(map[string]struct{}, len(cfg.localForwards))
		dedup := cfg.localForwards[:0]
		for _, spec := range cfg.localForwards {
			key := spec.String()
			if _, exists := seen[key]; !exists {
				seen[key] = struct{}{}
				dedup = append(dedup, spec)
			}
		}
		cfg.localForwards = dedup
	}
	if len(cfg.remoteForwards) > 1 {
		seen := make(map[string]struct{}, len(cfg.remoteForwards))
		dedup := cfg.remoteForwards[:0]
		for _, spec := range cfg.remoteForwards {
			key := spec.String()
			if _, exists := seen[key]; !exists {
				seen[key] = struct{}{}
				dedup = append(dedup, spec)
			}
		}
		cfg.remoteForwards = dedup
	}
	if len(cfg.dynamicForwards) > 1 {
		seen := make(map[string]struct{}, len(cfg.dynamicForwards))
		dedup := cfg.dynamicForwards[:0]
		for _, ep := range cfg.dynamicForwards {
			key := ep.String()
			if _, exists := seen[key]; !exists {
				seen[key] = struct{}{}
				dedup = append(dedup, ep)
			}
		}
		cfg.dynamicForwards = dedup
	}
}

func (o *SshOptions) resolveSessionForwardConfig() (sessionForwardConfig, error) {
	var target ssh.TargetContext
	if o != nil && o.resolvedTarget != nil {
		target = *o.resolvedTarget
	} else {
		target = controlTarget(o, nil, "")
	}
	return o.resolveSessionForwardConfigWithTarget(nil, "", target)
}

func (o *SshOptions) resolveSessionForwardConfigWithTarget(provider config.ConfigProvider, nodeID string, target ssh.TargetContext) (sessionForwardConfig, error) {
	var out sessionForwardConfig
	out.exitOnForwardFailure = true

	// Always validate explicit CLI forwarding syntax even if ClearAllForwardings=yes.
	if err := o.validateCLIForwardArgs(); err != nil {
		return out, err
	}

	var eff *ssh.Options
	var err error
	if provider != nil {
		eff, err = o.resolveAndCacheSessionOptions(provider, nodeID)
		if err != nil {
			return out, err
		}
		target = controlTarget(o, provider, nodeID)
	} else {
		eff, err = o.effectiveSessionOptions()
		if err != nil {
			return out, err
		}
	}

	if clearVal, ok := eff.ClearAllForwardings(); ok {
		out.clearAllForwardings = clearVal
	} else {
		out.clearAllForwardings = o.StdioForward != ""
	}

	if exitVal, ok := eff.ExitOnForwardFailure(); ok {
		out.exitOnForwardFailure = exitVal
	}

	if out.clearAllForwardings || o.isMuxDaemon() {
		return out, nil
	}

	if out.localForwards, err = collectUniqueForwardSpecs(o.LocalForwards, eff.LocalForwards()); err != nil {
		return out, err
	}
	if out.remoteForwards, err = collectUniqueRemoteForwardSpecs(o.RemoteForwards, eff.RemoteForwards()); err != nil {
		return out, err
	}
	if out.dynamicForwards, err = collectUniqueDynamicEndpoints(o.cliDynamicForwards(), eff.DynamicForwards()); err != nil {
		return out, err
	}

	if tunnelMode := eff.EffectiveTunnelMode(); tunnelMode != ssh.TunnelModeNo {
		devSpec, ok := eff.TunnelDevice()
		if !ok {
			devSpec = ssh.TunnelDeviceSpec{
				LocalUnit:  ssh.TunnelIDAny,
				RemoteUnit: ssh.TunnelIDAny,
			}
		}
		out.hasTunnelDevice = true
		out.tunnelMode = tunnelMode
		out.tunnelDevice = devSpec
	}

	out.gatewayPorts = o.GatewayPorts || eff.EffectiveGatewayPorts()
	out.streamLocalBindUnlink = eff.EffectiveStreamLocalBindUnlink()
	out.streamLocalBindMask = eff.EffectiveStreamLocalBindMask()

	if err := expandForwardSpecs(&out, sshenv.Discover(), target); err != nil {
		return out, err
	}

	return out, nil
}

func isLocalTerminal(r io.Reader) (*os.File, bool) {
	f, ok := r.(*os.File)
	if !ok || f == nil {
		return nil, false
	}
	return f, term.IsTerminal(int(f.Fd()))
}
