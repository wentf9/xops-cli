package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/wentf9/xops-cli/core/ssh"
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
	v.opts.recordTunnelDeviceFlag()
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

	cmd.Flags().VarP(&dynamicForwardFlagValue{opts: o}, "dynamic-forward", "D", i18n.T("flag_dynamic_forward"))
	cmd.Flags().VarP(&stdioForwardFlagValue{opts: o}, "stdio-forward", "W", i18n.T("ssh_flag_stdio_forward"))
	cmd.Flags().VarP(&tunnelDeviceFlagValue{opts: o}, "tunnel-device", "w", i18n.T("ssh_flag_tunnel_device"))

	disableFlag := cmd.Flags().VarPF(&disableTTYFlagValue{opts: o}, "disable-tty", "T", i18n.T("ssh_flag_disable_tty"))
	disableFlag.NoOptDefVal = "true"

	forceFlag := cmd.Flags().VarPF(&forceTTYFlagValue{opts: o}, "force-tty", "t", i18n.T("ssh_flag_force_tty"))
	forceFlag.NoOptDefVal = "+1"
}

func (o *SshOptions) recordOptionFlag(raw string) {
	if o == nil || o.cliTunnelLockedByW {
		return
	}
	key, val, err := adapter.SplitOptionKeyValue(raw)
	if err != nil {
		return
	}
	if strings.EqualFold(key, "tunnel") {
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
	sessionOpts, err := o.control.ToSessionControlOptions()
	if err != nil {
		return sessionOpts, err
	}
	if o.TunnelDevice != "" {
		devSpec, parseErr := ssh.ParseTunnelDevice(o.TunnelDevice)
		if parseErr != nil {
			return sessionOpts, fmt.Errorf("invalid tunnel device (-w): %w", parseErr)
		}
		if sessionOpts.Options == nil {
			sessionOpts.Options = &ssh.Options{}
		}
		if setErr := sessionOpts.Options.Set(ssh.OptionTunnelDevice, devSpec.String()); setErr != nil {
			return sessionOpts, setErr
		}
		if o.cliTunnelMode != "" {
			if setErr := sessionOpts.Options.Set(ssh.OptionTunnel, o.cliTunnelMode); setErr != nil {
				return sessionOpts, setErr
			}
		} else if sessionOpts.Options.Tunnel() == "" {
			if setErr := sessionOpts.Options.Set(ssh.OptionTunnel, string(ssh.TunnelModePointToPoint)); setErr != nil {
				return sessionOpts, setErr
			}
		}
	}
	if ttyMode := o.explicitCLITTYMode(); ttyMode != "" {
		if sessionOpts.Options == nil {
			sessionOpts.Options = &ssh.Options{}
		}
		if setErr := sessionOpts.Options.Set(ssh.OptionRequestTTY, string(ttyMode)); setErr != nil {
			return sessionOpts, setErr
		}
	}
	return sessionOpts, nil
}

func (o *SshOptions) normalizeForMuxDaemon() {
	o.NoCmd = true
	o.Command = ""
	o.stdinScript = false
	o.StdioForward = ""
	o.TunnelDevice = ""
	o.LocalForwards = nil
	o.RemoteForwards = nil
	o.DynamicForward = ""
	o.DynamicForwards = nil
}

func (o *SshOptions) validateForwardAndSessionFlags() error {
	if o.StdioForward != "" {
		if _, _, err := ssh.ParseStdioForward(o.StdioForward); err != nil {
			return err
		}
		if o.Command != "" || o.stdinScript {
			return errors.New(i18n.T("ssh_err_stdio_forward_with_cmd"))
		}
		if o.BgRun {
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
	if o.TunnelDevice != "" {
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
	sessionOpts, err := o.toSessionControlOptions()
	if err != nil {
		return nil, err
	}
	if provider == nil {
		eff, effErr := ssh.EffectiveOptions(sessionOpts.ToSSHOptions())
		if effErr != nil {
			return nil, effErr
		}
		o.effectiveSSHOptions = eff
		return eff, nil
	}
	connTarget := effectiveConnectionTarget(o, nodeID)
	target := controlTarget(o, provider, nodeID)
	lookupKey := resolveEffectiveControlNodeID(provider, nodeID, target.OriginalHost)
	if lookupKey == "" {
		lookupKey = connTarget.Selector
	}
	eff, err := adapter.NewSSHAdapter(provider).ResolveSSHOptions(lookupKey, sessionOpts)
	if err != nil {
		return nil, err
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
	return ssh.EffectiveOptions(sessionOpts.ToSSHOptions())
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
	if o.StdioForward != "" || o.NoCmd {
		return ssh.RequestTTYNo
	}
	return ssh.RequestTTYAuto
}

type sessionForwardConfig struct {
	localForwards        []ssh.ForwardSpec
	remoteForwards       []ssh.ForwardSpec
	dynamicForwards      []string
	hasTunnelDevice      bool
	tunnelMode           ssh.TunnelMode
	tunnelDevice         ssh.TunnelDeviceSpec
	exitOnForwardFailure bool
	clearAllForwardings  bool
}

func collectUniqueForwardSpecs(primary, secondary []string) ([]ssh.ForwardSpec, error) {
	seen := make(map[string]struct{})
	var out []ssh.ForwardSpec
	appendSpec := func(raw string) error {
		spec, err := ssh.ParseForwardSpec(raw)
		if err != nil {
			return err
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

func collectUniqueDynamicSpecs(primary, secondary []string) ([]string, error) {
	seen := make(map[string]struct{})
	var out []string
	appendAddr := func(raw string) error {
		addr, err := ssh.ParseDynamicForwardSpec(raw)
		if err != nil {
			return err
		}
		if _, exists := seen[addr]; !exists {
			seen[addr] = struct{}{}
			out = append(out, addr)
		}
		return nil
	}
	for _, raw := range primary {
		if err := appendAddr(raw); err != nil {
			return nil, err
		}
	}
	for _, raw := range secondary {
		if err := appendAddr(raw); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (o *SshOptions) validateCLIForwardArgs() error {
	if _, err := collectUniqueForwardSpecs(o.LocalForwards, nil); err != nil {
		return err
	}
	if _, err := collectUniqueForwardSpecs(o.RemoteForwards, nil); err != nil {
		return err
	}
	if _, err := collectUniqueDynamicSpecs(o.cliDynamicForwards(), nil); err != nil {
		return err
	}
	return nil
}

func (o *SshOptions) resolveSessionForwardConfig() (sessionForwardConfig, error) {
	var out sessionForwardConfig
	out.exitOnForwardFailure = true

	// Always validate explicit CLI forwarding syntax even if ClearAllForwardings=yes.
	if err := o.validateCLIForwardArgs(); err != nil {
		return out, err
	}

	eff, err := o.effectiveSessionOptions()
	if err != nil {
		return out, err
	}

	if clearVal, ok := eff.ClearAllForwardings(); ok {
		out.clearAllForwardings = clearVal
	} else {
		out.clearAllForwardings = o.StdioForward != ""
	}

	if exitVal, ok := eff.ExitOnForwardFailure(); ok {
		out.exitOnForwardFailure = exitVal
	}

	if out.clearAllForwardings || isMuxDaemonChild() {
		return out, nil
	}

	if out.localForwards, err = collectUniqueForwardSpecs(o.LocalForwards, eff.LocalForwards()); err != nil {
		return out, err
	}
	if out.remoteForwards, err = collectUniqueForwardSpecs(o.RemoteForwards, eff.RemoteForwards()); err != nil {
		return out, err
	}
	if out.dynamicForwards, err = collectUniqueDynamicSpecs(o.cliDynamicForwards(), eff.DynamicForwards()); err != nil {
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

	return out, nil
}

func isLocalTerminal(r io.Reader) (*os.File, bool) {
	f, ok := r.(*os.File)
	if !ok || f == nil {
		return nil, false
	}
	return f, term.IsTerminal(int(f.Fd()))
}

func isSessionOrForwardOption(opt string) bool {
	key, _, err := adapter.SplitOptionKeyValue(opt)
	if err != nil || key == "" {
		return false
	}
	spec, ok := ssh.LookupOptionSpec(key)
	if !ok {
		return false
	}
	return spec.Class == ssh.OptionClassForward || spec.Class == ssh.OptionClassSession
}
