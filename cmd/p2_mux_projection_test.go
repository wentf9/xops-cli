package cmd

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
)

type p2OptionSample struct {
	primary   string
	secondary string
	invalid   string
}

func p2AllOptionSpecSamples() map[string]p2OptionSample {
	return map[string]p2OptionSample{
		ssh.OptionControlMaster:                {primary: "yes"},
		ssh.OptionControlPath:                  {primary: "/tmp/p2-cm-%C.sock"},
		ssh.OptionControlPersist:               {primary: "10m"},
		ssh.OptionAddressFamily:                {primary: "inet", secondary: "inet6", invalid: "ipx"},
		ssh.OptionConnectTimeout:               {primary: "15", secondary: "30", invalid: "not-a-duration"},
		ssh.OptionServerAliveInterval:          {primary: "20", secondary: "45", invalid: "not-a-duration"},
		ssh.OptionServerAliveCountMax:          {primary: "5", secondary: "9", invalid: "-1"},
		ssh.OptionTCPKeepAlive:                 {primary: "yes", secondary: "no", invalid: "maybe"},
		ssh.OptionStrictHostKeyChecking:        {primary: "accept-new", secondary: "yes", invalid: "bogus"},
		ssh.OptionUserKnownHostsFile:           {primary: "/tmp/p2-kh1", secondary: "/tmp/p2-kh2", invalid: "/tmp/kh\x00bad"},
		ssh.OptionGlobalKnownHostsFile:         {primary: "/tmp/p2-gkh1", secondary: "/tmp/p2-gkh2", invalid: "/tmp/gkh\x00bad"},
		ssh.OptionHashKnownHosts:               {primary: "yes", secondary: "no", invalid: "maybe"},
		ssh.OptionVerifyHostKeyDNS:             {primary: "ask", secondary: "no", invalid: "bogus"},
		ssh.OptionCanonicalizeHostname:         {primary: "yes", secondary: "no", invalid: "bogus"},
		ssh.OptionCanonicalDomains:             {primary: "corp.example.com", secondary: "alt.example.com", invalid: "bad\x00domain"},
		ssh.OptionCanonicalizeMaxDots:          {primary: "2", secondary: "3", invalid: "-5"},
		ssh.OptionCanonicalizeFallbackLocal:    {primary: "no", secondary: "yes", invalid: "maybe"},
		ssh.OptionCanonicalizePermittedCNAMEs:  {primary: "*.a.example:*.b.example", secondary: "*.c.example:*.d.example", invalid: "missingcolon"},
		ssh.OptionIdentityFile:                 {primary: "/tmp/p2-id_ed25519"},
		ssh.OptionCertificateFile:              {primary: "/tmp/p2-cert1.pub", secondary: "/tmp/p2-cert2.pub", invalid: "/tmp/cert\x00bad"},
		ssh.OptionIdentityAgent:                {primary: "/tmp/p2-agent.sock", secondary: "none", invalid: "/tmp/agent\x00bad"},
		ssh.OptionPubkeyAuthentication:         {primary: "yes", secondary: "no", invalid: "maybe"},
		ssh.OptionPasswordAuthentication:       {primary: "no", secondary: "yes", invalid: "maybe"},
		ssh.OptionKbdInteractiveAuthentication: {primary: "no", secondary: "yes", invalid: "maybe"},
		ssh.OptionIdentitiesOnly:               {primary: "yes", secondary: "no", invalid: "maybe"},
		ssh.OptionPreferredAuthentications:     {primary: "publickey,password", secondary: "password", invalid: "bogus-method"},
		ssh.OptionBatchMode:                    {primary: "yes", secondary: "no", invalid: "maybe"},
		ssh.OptionHostKeyAlgorithms:            {primary: "ssh-ed25519", secondary: "rsa-sha2-256", invalid: "no-such-hostkey-algo"},
		ssh.OptionCiphers:                      {primary: "aes256-gcm@openssh.com", secondary: "aes128-gcm@openssh.com", invalid: "no-such-cipher"},
		ssh.OptionMACs:                         {primary: "hmac-sha2-256", secondary: "hmac-sha2-512", invalid: "no-such-mac"},
		ssh.OptionKexAlgorithms:                {primary: "curve25519-sha256", secondary: "ecdh-sha2-nistp256", invalid: "no-such-kex"},
		ssh.OptionExitOnForwardFailure:         {primary: "yes"},
		ssh.OptionClearAllForwardings:          {primary: "no"},
		ssh.OptionForwardAgent:                 {primary: "yes"},
		ssh.OptionGatewayPorts:                 {primary: "clientspecified", secondary: "no", invalid: "bogus"},
		ssh.OptionStreamLocalBindUnlink:        {primary: "yes", secondary: "no", invalid: "maybe"},
		ssh.OptionStreamLocalBindMask:          {primary: "177", secondary: "0077", invalid: "9999"},
		ssh.OptionForkAfterAuthentication:      {primary: "yes"},
		ssh.OptionStdinNull:                    {primary: "yes"},
		ssh.OptionSessionType:                  {primary: "none"},
		ssh.OptionTunnel:                       {primary: "point-to-point"},
		ssh.OptionTunnelDevice:                 {primary: "0:1"},
		ssh.OptionRequestTTY:                   {primary: "force"},
		ssh.OptionLocalForward:                 {primary: "8080 127.0.0.1:80"},
		ssh.OptionRemoteForward:                {primary: "9090 127.0.0.1:90"},
		ssh.OptionDynamicForward:               {primary: "1080"},
		ssh.OptionSendEnv:                      {primary: "LANG"},
		ssh.OptionSetEnv:                       {primary: "FOO=bar"},
		ssh.OptionRemoteCommand:                {primary: "uptime"},
		ssh.OptionEscapeChar:                   {primary: "^"},
		ssh.OptionProxyCommand:                 {primary: "nc %h %p"},
		ssh.OptionLocalCommand:                 {primary: "echo hi"},
		ssh.OptionPermitLocalCommand:           {primary: "yes"},
	}
}

func makeP2TestMuxSpec(opts ...string) MuxDaemonSpec {
	return MuxDaemonSpec{
		Version:       muxDaemonSpecVersion,
		TargetHost:    "app",
		ControlPath:   "/tmp/p2-matrix.sock",
		ControlMaster: ssh.ControlMasterYes,
		Options:       opts,
	}
}

func TestP2_MuxDaemonSpec_ExhaustiveOptionSpecMatrix(t *testing.T) {
	specs := ssh.RegisteredOptionSpecs()
	samples := p2AllOptionSpecSamples()

	if len(specs) != len(samples) {
		t.Fatalf("RegisteredOptionSpecs() has %d entries, sample matrix has %d entries; keep exhaustive matrix in sync", len(specs), len(samples))
	}

	for _, spec := range specs {
		sample, ok := samples[spec.CanonicalKey]
		if !ok {
			t.Fatalf("missing sample for registered option %s (%s)", spec.OpenSSHName, spec.CanonicalKey)
		}
		if spec.MuxPolicy == ssh.OptionMuxUnset {
			t.Fatalf("registered option %s has unset MuxPolicy", spec.OpenSSHName)
		}

		t.Run(spec.OpenSSHName, func(t *testing.T) {
			verifyP2SpecValidateMatrix(t, spec, sample)
			verifyP2SpecTargetProjectionMatrix(t, spec, sample)
			verifyP2SpecJumpProjectionMatrix(t, spec, sample)

			gotTargetOnly, err := isTargetOnlyMuxDaemonOption(spec.CanonicalKey + "=" + sample.primary)
			if err != nil || gotTargetOnly != !spec.IsConnectionWide() {
				t.Errorf("isTargetOnlyMuxDaemonOption(%s) = (%v, %v), want (%v, nil) (!IsConnectionWide)", spec.CanonicalKey, gotTargetOnly, err, !spec.IsConnectionWide())
			}
		})
	}

	t.Run("target_level_non_registry_directives", func(t *testing.T) {
		for _, raw := range []string{
			"Port=2222",
			"User=ops",
			"HostName=10.0.0.1",
			"ProxyJump=bastion",
			"proxy_jump=bastion",
		} {
			if err := makeP2TestMuxSpec(raw).Validate(); err == nil {
				t.Errorf("Validate() accepted target-level directive %q", raw)
			}
			opts := NewSshOptions()
			opts.control.Options = []string{raw}
			if got := opts.collectMuxDaemonTargetOptions(); len(got) != 0 {
				t.Errorf("collectMuxDaemonTargetOptions(%q) = %v, want empty", raw, got)
			}
			if got := opts.collectMuxDaemonJumpOptions(); len(got) != 0 {
				t.Errorf("collectMuxDaemonJumpOptions(%q) = %v, want empty", raw, got)
			}
			if targetOnly, err := isTargetOnlyMuxDaemonOption(raw); err != nil || !targetOnly {
				t.Errorf("isTargetOnlyMuxDaemonOption(%q) = (%v, %v), want (true, nil)", raw, targetOnly, err)
			}
		}
	})
}

func verifyP2SpecValidateMatrix(t *testing.T, spec ssh.OptionSpec, sample p2OptionSample) {
	t.Helper()
	opt := spec.OpenSSHName + "=" + sample.primary

	switch spec.MuxPolicy {
	case ssh.OptionMuxAllow:
		if err := makeP2TestMuxSpec(opt).Validate(); err != nil {
			t.Errorf("Validate(%q) unexpected error for OptionMuxAllow: %v", opt, err)
		}
		if sample.invalid != "" {
			if err := makeP2TestMuxSpec(spec.OpenSSHName + "=" + sample.invalid).Validate(); err == nil {
				t.Errorf("Validate accepted invalid value %q for %s", sample.invalid, spec.OpenSSHName)
			}
		}
		if spec.MultiValue {
			multi := makeP2TestMuxSpec(
				spec.OpenSSHName+"="+sample.primary,
				spec.OpenSSHName+"="+sample.secondary,
				spec.OpenSSHName+"=none",
			)
			if err := multi.Validate(); err != nil {
				t.Errorf("Validate(multi-value %s) unexpected error: %v", spec.OpenSSHName, err)
			}
			smuggled := makeP2TestMuxSpec(spec.OpenSSHName + "=" + sample.primary + "\n" + sample.secondary)
			if err := smuggled.Validate(); err == nil {
				t.Errorf("Validate accepted newline-smuggled multi-value %s", spec.OpenSSHName)
			}
		}
	case ssh.OptionMuxAllowNoneOnly:
		if err := makeP2TestMuxSpec(opt).Validate(); err == nil {
			t.Errorf("Validate(%q) accepted non-none value for OptionMuxAllowNoneOnly", opt)
		}
		for _, allowedNone := range []string{spec.OpenSSHName + "=none", spec.CanonicalKey + "=NONE"} {
			if err := makeP2TestMuxSpec(allowedNone).Validate(); err != nil {
				t.Errorf("Validate(%q) rejected none for OptionMuxAllowNoneOnly: %v", allowedNone, err)
			}
		}
		if err := makeP2TestMuxSpec(spec.OpenSSHName + "=none\n").Validate(); err == nil {
			t.Errorf("Validate accepted control-char suffix on %s=none", spec.OpenSSHName)
		}
		if err := makeP2TestMuxSpec(spec.OpenSSHName + "=none\x00").Validate(); err == nil {
			t.Errorf("Validate accepted NUL suffix on %s=none", spec.OpenSSHName)
		}
	case ssh.OptionMuxAuthoritative, ssh.OptionMuxReject:
		if err := makeP2TestMuxSpec(opt).Validate(); err == nil {
			t.Errorf("Validate(%q) accepted option with MuxPolicy=%v", opt, spec.MuxPolicy)
		}
	default:
		t.Fatalf("unhandled MuxPolicy %v for %s", spec.MuxPolicy, spec.OpenSSHName)
	}
}

func verifyP2SpecTargetProjectionMatrix(t *testing.T, spec ssh.OptionSpec, sample p2OptionSample) {
	t.Helper()
	opts := NewSshOptions()
	opts.control.Options = []string{spec.CanonicalKey + " " + sample.primary}
	got := opts.collectMuxDaemonTargetOptions()

	switch spec.MuxPolicy {
	case ssh.OptionMuxAllow:
		wantNorm, err := spec.Normalize(sample.primary)
		if err != nil {
			t.Fatalf("spec.Normalize(%s, %q): %v", spec.OpenSSHName, sample.primary, err)
		}
		want := []string{spec.OpenSSHName + "=" + wantNorm}
		if !slices.Equal(got, want) {
			t.Errorf("collectMuxDaemonTargetOptions(%s) = %v, want %v", spec.OpenSSHName, got, want)
		}
		if err := makeP2TestMuxSpec(got...).Validate(); err != nil {
			t.Errorf("projected target option %v failed Validate: %v", got, err)
		}
		verifyP2SpecTargetAllowExtras(t, spec, sample, wantNorm)
	case ssh.OptionMuxAllowNoneOnly:
		if len(got) != 0 {
			t.Errorf("collectMuxDaemonTargetOptions(non-none %s) = %v, want empty", spec.OpenSSHName, got)
		}
		optsNonNoneFirst := NewSshOptions()
		optsNonNoneFirst.control.Options = []string{spec.OpenSSHName + "=" + sample.primary, spec.OpenSSHName + "=none"}
		if out := optsNonNoneFirst.collectMuxDaemonTargetOptions(); len(out) != 0 {
			t.Errorf("collectMuxDaemonTargetOptions(non-none before none %s) = %v, want empty", spec.OpenSSHName, out)
		}
		optsNoneFirst := NewSshOptions()
		optsNoneFirst.control.Options = []string{spec.CanonicalKey + "=NONE", spec.OpenSSHName + "=" + sample.primary}
		wantNone := []string{spec.OpenSSHName + "=none"}
		if out := optsNoneFirst.collectMuxDaemonTargetOptions(); !slices.Equal(out, wantNone) {
			t.Errorf("collectMuxDaemonTargetOptions(none before non-none %s) = %v, want %v", spec.OpenSSHName, out, wantNone)
		}
	case ssh.OptionMuxAuthoritative, ssh.OptionMuxReject:
		if len(got) != 0 {
			t.Errorf("collectMuxDaemonTargetOptions(%s, MuxPolicy=%v) = %v, want empty", spec.OpenSSHName, spec.MuxPolicy, got)
		}
	default:
		t.Fatalf("unhandled MuxPolicy %v for %s", spec.MuxPolicy, spec.OpenSSHName)
	}
}

func verifyP2SpecTargetAllowExtras(t *testing.T, spec ssh.OptionSpec, sample p2OptionSample, wantNorm string) {
	t.Helper()
	if spec.MultiValue {
		multiOpts := NewSshOptions()
		multiOpts.control.Options = []string{
			spec.CanonicalKey + "=" + sample.primary,
			spec.OpenSSHName + "=" + sample.secondary,
			spec.OpenSSHName + "=" + sample.primary,
			spec.OpenSSHName + "=none",
		}
		wantMulti := []string{
			spec.OpenSSHName + "=" + sample.primary,
			spec.OpenSSHName + "=" + sample.secondary,
			spec.OpenSSHName + "=none",
		}
		gotMulti := multiOpts.collectMuxDaemonTargetOptions()
		if !slices.Equal(gotMulti, wantMulti) {
			t.Errorf("collectMuxDaemonTargetOptions(multi %s) = %v, want %v", spec.OpenSSHName, gotMulti, wantMulti)
		}
		if err := makeP2TestMuxSpec(gotMulti...).Validate(); err != nil {
			t.Errorf("projected multi-value %v failed Validate: %v", gotMulti, err)
		}
		return
	}
	if sample.secondary != "" {
		dupOpts := NewSshOptions()
		dupOpts.control.Options = []string{
			spec.CanonicalKey + "=" + sample.primary,
			spec.OpenSSHName + "=" + sample.secondary,
		}
		wantDedup := []string{spec.OpenSSHName + "=" + wantNorm}
		if gotDedup := dupOpts.collectMuxDaemonTargetOptions(); !slices.Equal(gotDedup, wantDedup) {
			t.Errorf("collectMuxDaemonTargetOptions(scalar dedup %s) = %v, want %v", spec.OpenSSHName, gotDedup, wantDedup)
		}
	}
	if spec.CanonicalKey == ssh.OptionGatewayPorts {
		gwOpts := NewSshOptions()
		gwOpts.GatewayPorts = true
		gwOpts.control.Options = []string{spec.OpenSSHName + "=" + sample.primary}
		if gotGW := gwOpts.collectMuxDaemonTargetOptions(); len(gotGW) != 0 {
			t.Errorf("collectMuxDaemonTargetOptions(GatewayPorts suppressed by -g) = %v, want empty", gotGW)
		}
	}
}

func verifyP2SpecJumpProjectionMatrix(t *testing.T, spec ssh.OptionSpec, sample p2OptionSample) {
	t.Helper()
	opts := NewSshOptions()
	opts.control.Options = []string{spec.CanonicalKey + " " + sample.primary}
	if spec.MuxPolicy == ssh.OptionMuxAllowNoneOnly {
		opts.control.Options = []string{spec.OpenSSHName + "=none"}
	}
	got := opts.collectMuxDaemonJumpOptions()

	if spec.IsConnectionWide() && spec.MuxPolicy == ssh.OptionMuxAllow {
		wantNorm, err := spec.Normalize(sample.primary)
		if err != nil {
			t.Fatalf("spec.Normalize(%s, %q): %v", spec.OpenSSHName, sample.primary, err)
		}
		want := []string{spec.OpenSSHName + "=" + wantNorm}
		if !slices.Equal(got, want) {
			t.Errorf("collectMuxDaemonJumpOptions(%s) = %v, want %v", spec.OpenSSHName, got, want)
		}
		if err := makeP2TestMuxSpec(got...).Validate(); err != nil {
			t.Errorf("projected jump option %v failed Validate: %v", got, err)
		}
		return
	}
	if len(got) != 0 {
		t.Errorf("collectMuxDaemonJumpOptions(%s, scope=%v, policy=%v) = %v, want empty",
			spec.OpenSSHName, spec.Scope, spec.MuxPolicy, got)
	}
}

func resolveP2ParentAndDaemonChild(
	t *testing.T,
	sshConfigText string,
	cliArgs []string,
) (parentCfg, childCfg *ssh.ClientConfig, parentEff, childEff *ssh.Options, childOpts *SshOptions, decoded MuxDaemonSpec) {
	t.Helper()
	ctx := context.Background()

	parentRepo := buildPass6Repo(t, sshConfigText)
	parentOpts := NewSshOptions()
	parentCmd := newCmdSshWithOptions(parentOpts)
	if err := parentCmd.ParseFlags(cliArgs); err != nil {
		t.Fatalf("parent ParseFlags(%v): %v", cliArgs, err)
	}
	if err := parentOpts.Complete(parentCmd, parentCmd.Flags().Args()); err != nil {
		t.Fatalf("parent Complete(%v): %v", cliArgs, err)
	}
	if err := parentOpts.Validate(); err != nil {
		t.Fatalf("parent Validate(%v): %v", cliArgs, err)
	}
	var spec MuxDaemonSpec
	if err := parentOpts.withTestPendingNode(ctx, parentRepo, func(lease config.PendingLease) error {
		parentNodeID := lease.NodeID()
		parentAdpOpts, err := parentOpts.buildAdapterOptions(parentNodeID, parentRepo.Snapshot(), parentRepo)
		if err != nil {
			t.Fatalf("parent buildAdapterOptions: %v", err)
		}
		parentAdp := adapter.NewSSHAdapter(parentRepo, parentAdpOpts...)
		parentCfg, err = parentAdp.GetConfig(parentNodeID)
		if err != nil {
			t.Fatalf("parent GetConfig(%q): %v", parentNodeID, err)
		}
		parentCtrl, err := parentOpts.toSessionControlOptions()
		if err != nil {
			t.Fatalf("parent toSessionControlOptions: %v", err)
		}
		parentPol, err := parentAdp.Resolve(ctx, adapter.ResolveRequest{NodeID: parentNodeID, SessionControl: &parentCtrl})
		if err != nil {
			t.Fatalf("parent Resolve(%q): %v", parentNodeID, err)
		}
		parentEff = parentPol.Options()
		sockPath := filepath.Join(t.TempDir(), "p2-rt.sock")
		spec = parentOpts.buildMuxDaemonSpecWithProvider(parentRepo, parentNodeID, sockPath, nil)
		return nil
	}); err != nil {
		t.Fatalf("parent withTestPendingNode: %v", err)
	}
	decoded = roundTripMuxDaemonSpecThroughPipe(t, spec)

	childRepo := buildPass6Repo(t, sshConfigText)
	childOpts = NewSshOptions()
	if err := childOpts.applyMuxDaemonSpec(decoded); err != nil {
		t.Fatalf("child applyMuxDaemonSpec: %v", err)
	}
	if err := childOpts.Validate(); err != nil {
		t.Fatalf("child Validate: %v", err)
	}
	if err := childOpts.withTestPendingNode(ctx, childRepo, func(lease config.PendingLease) error {
		childNodeID := lease.NodeID()
		childAdpOpts, err := childOpts.buildAdapterOptions(childNodeID, childRepo.Snapshot(), childRepo)
		if err != nil {
			t.Fatalf("child buildAdapterOptions: %v", err)
		}
		childAdp := adapter.NewSSHAdapter(childRepo, childAdpOpts...)
		childCfg, err = childAdp.GetConfig(childNodeID)
		if err != nil {
			t.Fatalf("child GetConfig(%q): %v", childNodeID, err)
		}
		childCtrl, err := childOpts.toSessionControlOptions()
		if err != nil {
			t.Fatalf("child toSessionControlOptions: %v", err)
		}
		childPol, err := childAdp.Resolve(ctx, adapter.ResolveRequest{NodeID: childNodeID, SessionControl: &childCtrl})
		if err != nil {
			t.Fatalf("child Resolve(%q): %v", childNodeID, err)
		}
		childEff = childPol.Options()
		return nil
	}); err != nil {
		t.Fatalf("child withTestPendingNode: %v", err)
	}
	return parentCfg, childCfg, parentEff, childEff, childOpts, decoded
}

type p2RoundTripPaths struct {
	tmpDir       string
	cfgKey1      string
	cfgKey2      string
	cliKey       string
	afterNoneKey string
	cert1        string
	cert2        string
	khFile       string
	agentSock    string
}

func newP2RoundTripFixture(t *testing.T) (p2RoundTripPaths, string) {
	t.Helper()
	tmpDir := t.TempDir()
	p := p2RoundTripPaths{
		tmpDir:       tmpDir,
		cfgKey1:      filepath.Join(tmpDir, "id_from_config_1"),
		cfgKey2:      filepath.Join(tmpDir, "id_from_config_2"),
		cliKey:       filepath.Join(tmpDir, "id_from_cli"),
		afterNoneKey: filepath.Join(tmpDir, "id_after_none"),
		cert1:        filepath.Join(tmpDir, "id_cert_1.pub"),
		cert2:        filepath.Join(tmpDir, "id_cert_2.pub"),
		khFile:       filepath.Join(tmpDir, "known_hosts"),
		agentSock:    filepath.Join(tmpDir, "agent.sock"),
	}
	sshCfg := strings.Join([]string{
		"Host app-edge",
		"  HostName 10.42.0.10",
		"  User ops",
		"  Port 2222",
		"  ServerAliveCountMax 7",
		"  ConnectTimeout 30",
		"  IdentityFile " + p.cfgKey1,
		"  IdentityFile " + p.cfgKey2,
		"  CertificateFile " + filepath.Join(tmpDir, "cfg_cert.pub"),
		"  ProxyCommand sh -c 'exit 1'",
		"  GatewayPorts no",
		"  StreamLocalBindMask 0077",
		"  LocalForward 8080 127.0.0.1:80",
		"  SendEnv LANG",
		"  RemoteCommand uname -a",
	}, "\n") + "\n"
	return p, sshCfg
}

func TestP2_MuxDaemonSpec_RoundTripEquivalenceAndIdentityNone(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	paths, sshCfg := newP2RoundTripFixture(t)

	t.Run("round_trip_equivalence_across_transport_auth_trust_server_forward", func(t *testing.T) {
		assertP2RoundTripEquivalence(t, paths, sshCfg)
	})
	t.Run("identity_file_none_truncates_ssh_config_in_detached_mux_daemon", func(t *testing.T) {
		assertP2IdentityFileNoneOnlyTruncation(t, paths, sshCfg)
	})
	t.Run("cli_key_before_identity_file_none_keeps_cli_key_and_truncates_config", func(t *testing.T) {
		assertP2CLIKeyBeforeIdentityNoneTruncation(t, paths, sshCfg)
	})
	t.Run("cli_key_without_none_still_inherits_ssh_config_keys", func(t *testing.T) {
		assertP2CLIKeyWithoutNoneInheritsConfig(t, paths, sshCfg)
	})
}

func assertP2RoundTripEquivalence(t *testing.T, p p2RoundTripPaths, sshCfg string) {
	t.Helper()
	cliArgs := []string{
		"-M",
		"-o", "ControlPersist=10m",
		"-o", "ControlPath=" + filepath.Join(p.tmpDir, "parent.sock"),
		"-o", "ProxyCommand=none",
		"-o", "ProxyCommand=nc %h %p",
		"-o", "address_family=inet",
		"-o", "ConnectTimeout=5",
		"-o", "ConnectTimeout=99",
		"-o", "server_alive_interval=15",
		"-o", "TCPKeepAlive=yes",
		"-o", "strict_host_key_checking=accept-new",
		"-o", "UserKnownHostsFile=" + p.khFile,
		"-o", "HashKnownHosts=yes",
		"-o", "VerifyHostKeyDNS=ask",
		"-o", "CertificateFile=" + p.cert1,
		"-o", "CertificateFile=" + p.cert2,
		"-o", "CertificateFile=none",
		"-o", "IdentityAgent=" + p.agentSock,
		"-o", "PubkeyAuthentication=yes",
		"-o", "PasswordAuthentication=no",
		"-o", "ChallengeResponseAuthentication=no",
		"-o", "IdentitiesOnly=yes",
		"-o", "PreferredAuthentications=publickey,password",
		"-o", "BatchMode=yes",
		"-o", "Ciphers=aes256-gcm@openssh.com",
		"-o", "MACs=hmac-sha2-256",
		"-o", "KexAlgorithms=curve25519-sha256",
		"-o", "HostKeyAlgorithms=ssh-ed25519",
		"-o", "GatewayPorts=clientspecified",
		"-o", "StreamLocalBindUnlink=yes",
		"-o", "StreamLocalBindMask=177",
		"-o", "LocalForward=9090 127.0.0.1:90",
		"-o", "ForwardAgent=yes",
		"-o", "RemoteCommand=uptime",
		"-o", "SendEnv=FOO",
		"-o", "SetEnv=BAR=1",
		"app-edge",
	}

	parentCfg, childCfg, parentEff, childEff, childOpts, decoded := resolveP2ParentAndDaemonChild(t, sshCfg, cliArgs)

	if slices.Contains(decoded.Options, "ConnectTimeout=99") {
		t.Fatalf("overridden duplicate scalar ConnectTimeout=99 leaked into decoded.Options: %v", decoded.Options)
	}
	for _, wantCanon := range []string{"ProxyCommand=none", "StreamLocalBindMask=0177", "KbdInteractiveAuthentication=no"} {
		if !slices.Contains(decoded.Options, wantCanon) {
			t.Fatalf("expected canonicalized option %q in decoded.Options, got %v", wantCanon, decoded.Options)
		}
	}
	for _, opt := range decoded.Options {
		if strings.HasPrefix(opt, "LocalForward=") {
			t.Fatalf("CLI LocalForward leaked into decoded.Options: %v", decoded.Options)
		}
	}

	for _, spec := range ssh.RegisteredOptionSpecs() {
		if spec.MuxPolicy != ssh.OptionMuxAllow {
			continue
		}
		if gotVal, wantVal := childEff.Get(spec.CanonicalKey), parentEff.Get(spec.CanonicalKey); gotVal != wantVal {
			t.Errorf("effective %s mismatch after round-trip: child=%q, parent=%q", spec.OpenSSHName, gotVal, wantVal)
		}
	}

	assertP2ChildServerForwardAndStripping(t, p, parentCfg, childCfg, parentEff, childEff, childOpts)
}

func assertP2ChildServerForwardAndStripping(
	t *testing.T,
	p p2RoundTripPaths,
	parentCfg, childCfg *ssh.ClientConfig,
	parentEff, childEff *ssh.Options,
	childOpts *SshOptions,
) {
	t.Helper()
	wantCerts := []string{p.cert1, p.cert2}
	if !slices.Equal(childEff.CertificateFiles(), wantCerts) || !slices.Equal(parentEff.CertificateFiles(), wantCerts) {
		t.Errorf("CertificateFiles mismatch: parent=%v child=%v want=%v", parentEff.CertificateFiles(), childEff.CertificateFiles(), wantCerts)
	}
	if childEff.GatewayPortsMode() != ssh.GatewayPortsClientSpecified ||
		!childEff.EffectiveStreamLocalBindUnlink() ||
		childEff.EffectiveStreamLocalBindMask() != 0o177 {
		t.Errorf("server-forward options mismatch in child: gw=%q unlink=%v mask=%04o",
			childEff.GatewayPortsMode(), childEff.EffectiveStreamLocalBindUnlink(), childEff.EffectiveStreamLocalBindMask())
	}
	if childEff.Get(ssh.OptionProxyCommand) != "none" {
		t.Errorf("child effective ProxyCommand = %q, want none", childEff.Get(ssh.OptionProxyCommand))
	}
	assertP2ChildStrippedForwardAndSession(t, parentCfg, childCfg, childEff, childOpts)
}

func assertP2ChildStrippedForwardAndSession(
	t *testing.T,
	parentCfg, childCfg *ssh.ClientConfig,
	childEff *ssh.Options,
	childOpts *SshOptions,
) {
	t.Helper()
	if clearVal, ok := childEff.ClearAllForwardings(); !ok || !clearVal {
		t.Errorf("child ClearAllForwardings = (%v, %v), want (true, true)", clearVal, ok)
	}
	fwdCfg, err := childOpts.resolveSessionForwardConfig()
	if err != nil {
		t.Fatalf("child resolveSessionForwardConfig: %v", err)
	}
	if !fwdCfg.clearAllForwardings || len(fwdCfg.localForwards) != 0 || len(fwdCfg.remoteForwards) != 0 || len(fwdCfg.dynamicForwards) != 0 {
		t.Errorf("child daemon kept active forwardings despite ClearAllForwardings=yes: %+v", fwdCfg)
	}
	if slices.Contains(childEff.LocalForwards(), "9090 127.0.0.1:90") || childEff.ForwardAgent() != "" || childEff.RemoteCommand() != "" ||
		len(childEff.SendEnvPatterns()) != 0 || len(childEff.SetEnvDirectives()) != 0 {
		t.Errorf("session/forward options leaked into child: lf=%v fa=%q rc=%q send=%v set=%v",
			childEff.LocalForwards(), childEff.ForwardAgent(), childEff.RemoteCommand(), childEff.SendEnvPatterns(), childEff.SetEnvDirectives())
	}
	if childCfg.Address != parentCfg.Address || childCfg.Port != parentCfg.Port || childCfg.User != parentCfg.User {
		t.Errorf("GetConfig target mismatch: child=(%s:%d %s) parent=(%s:%d %s)",
			childCfg.Address, childCfg.Port, childCfg.User, parentCfg.Address, parentCfg.Port, parentCfg.User)
	}
}

func assertP2IdentityFileNoneOnlyTruncation(t *testing.T, p p2RoundTripPaths, sshCfg string) {
	t.Helper()
	cliArgs := []string{
		"-M",
		"-o", "ControlPersist=10m",
		"-o", "ControlPath=" + filepath.Join(p.tmpDir, "idnone.sock"),
		"-o", "ProxyCommand=none",
		"-o", "IdentityFile=none",
		"app-edge",
	}
	parentCfg, childCfg, parentEff, childEff, _, decoded := resolveP2ParentAndDaemonChild(t, sshCfg, cliArgs)

	if !slices.Equal(decoded.IdentityFiles, []string{"none"}) {
		t.Fatalf("decoded.IdentityFiles = %v, want [none]", decoded.IdentityFiles)
	}
	for _, opt := range decoded.Options {
		if strings.HasPrefix(strings.ToLower(opt), "identityfile=") {
			t.Fatalf("IdentityFile leaked into decoded.Options: %v", decoded.Options)
		}
	}
	for _, pair := range []struct {
		name string
		cfg  *ssh.ClientConfig
		eff  *ssh.Options
	}{
		{"parent", parentCfg, parentEff},
		{"child", childCfg, childEff},
	} {
		if !slices.Equal(pair.eff.IdentityFiles(), []string{"none"}) {
			t.Errorf("%s Resolve IdentityFiles = %v, want [none] (must truncate ~/.ssh/config)", pair.name, pair.eff.IdentityFiles())
		}
		if slices.Contains(pair.cfg.KeyPaths, p.cfgKey1) || slices.Contains(pair.cfg.KeyPaths, p.cfgKey2) {
			t.Errorf("%s GetConfig KeyPaths leaked ~/.ssh/config keys despite IdentityFile=none: %v", pair.name, pair.cfg.KeyPaths)
		}
		if !slices.Equal(pair.cfg.KeyPaths, []string{"none"}) {
			t.Errorf("%s GetConfig KeyPaths = %v, want [none]", pair.name, pair.cfg.KeyPaths)
		}
	}
	if childCfg.KeyPath != parentCfg.KeyPath {
		t.Errorf("GetConfig KeyPath mismatch: child=%q parent=%q", childCfg.KeyPath, parentCfg.KeyPath)
	}
}

func assertP2CLIKeyBeforeIdentityNoneTruncation(t *testing.T, p p2RoundTripPaths, sshCfg string) {
	t.Helper()
	cliArgs := []string{
		"-M",
		"-o", "ControlPersist=10m",
		"-o", "ControlPath=" + filepath.Join(p.tmpDir, "idmixed.sock"),
		"-o", "ProxyCommand=none",
		"-i", p.cliKey,
		"-o", "IdentityFile=none",
		"-o", "IdentityFile=" + p.afterNoneKey,
		"app-edge",
	}
	parentCfg, childCfg, parentEff, childEff, _, _ := resolveP2ParentAndDaemonChild(t, sshCfg, cliArgs)

	for _, pair := range []struct {
		name string
		cfg  *ssh.ClientConfig
		eff  *ssh.Options
	}{
		{"parent", parentCfg, parentEff},
		{"child", childCfg, childEff},
	} {
		if !slices.Equal(pair.eff.IdentityFiles(), []string{p.cliKey}) {
			t.Errorf("%s Resolve IdentityFiles = %v, want [%s]", pair.name, pair.eff.IdentityFiles(), p.cliKey)
		}
		if slices.Contains(pair.cfg.KeyPaths, p.cfgKey1) || slices.Contains(pair.cfg.KeyPaths, p.cfgKey2) {
			t.Errorf("%s GetConfig KeyPaths leaked ~/.ssh/config keys after IdentityFile=none: %v", pair.name, pair.cfg.KeyPaths)
		}
		if pair.cfg.KeyPath != p.cliKey {
			t.Errorf("%s GetConfig KeyPath = %q, want %q", pair.name, pair.cfg.KeyPath, p.cliKey)
		}
	}
}

func assertP2CLIKeyWithoutNoneInheritsConfig(t *testing.T, p p2RoundTripPaths, sshCfg string) {
	t.Helper()
	cliArgs := []string{
		"-M",
		"-o", "ControlPersist=10m",
		"-o", "ControlPath=" + filepath.Join(p.tmpDir, "idinherit.sock"),
		"-o", "ProxyCommand=none",
		"-i", p.cliKey,
		"app-edge",
	}
	parentCfg, childCfg, parentEff, childEff, _, _ := resolveP2ParentAndDaemonChild(t, sshCfg, cliArgs)

	wantConfigKeys := []string{p.cfgKey1, p.cfgKey2}
	wantKeyPaths := []string{p.cliKey, p.cfgKey1, p.cfgKey2}
	for _, pair := range []struct {
		name string
		cfg  *ssh.ClientConfig
		eff  *ssh.Options
	}{
		{"parent", parentCfg, parentEff},
		{"child", childCfg, childEff},
	} {
		if !slices.Equal(pair.eff.IdentityFiles(), wantConfigKeys) {
			t.Errorf("%s Resolve IdentityFiles = %v, want %v", pair.name, pair.eff.IdentityFiles(), wantConfigKeys)
		}
		if !slices.Equal(pair.cfg.KeyPaths, wantKeyPaths) {
			t.Errorf("%s GetConfig KeyPaths = %v, want %v", pair.name, pair.cfg.KeyPaths, wantKeyPaths)
		}
	}
}
