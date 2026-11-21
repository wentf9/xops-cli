package adapter

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/concurrent"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

type p2AdapterOptionSample struct {
	val1    string
	val2    string
	invalid string
}

func p2AdapterOptionSamples() map[string]p2AdapterOptionSample {
	return map[string]p2AdapterOptionSample{
		ssh.OptionControlMaster:                {val1: "auto", val2: "yes", invalid: "bogus-master"},
		ssh.OptionControlPath:                  {val1: "~/.ssh/cm-%C", val2: "/tmp/alt-%h.sock", invalid: "/tmp/bad-%k.sock"},
		ssh.OptionControlPersist:               {val1: "10m", val2: "30s", invalid: "not-a-duration"},
		ssh.OptionAddressFamily:                {val1: "inet", val2: "inet6", invalid: "ipx"},
		ssh.OptionConnectTimeout:               {val1: "15", val2: "30", invalid: "forever"},
		ssh.OptionServerAliveInterval:          {val1: "30", val2: "60", invalid: "never"},
		ssh.OptionServerAliveCountMax:          {val1: "3", val2: "5", invalid: "-2"},
		ssh.OptionTCPKeepAlive:                 {val1: "yes", val2: "no", invalid: "maybe"},
		ssh.OptionStrictHostKeyChecking:        {val1: "accept-new", val2: "no", invalid: "sometimes"},
		ssh.OptionUserKnownHostsFile:           {val1: "~/.ssh/known_hosts /etc/ssh/extra", val2: "/tmp/kh", invalid: "/tmp/bad-%k"},
		ssh.OptionGlobalKnownHostsFile:         {val1: "/etc/ssh/ssh_known_hosts", val2: "/etc/ssh/kh2", invalid: "/tmp/bad-%k"},
		ssh.OptionHashKnownHosts:               {val1: "yes", val2: "no", invalid: "maybe"},
		ssh.OptionVerifyHostKeyDNS:             {val1: "ask", val2: "yes", invalid: "bogus"},
		ssh.OptionCanonicalizeHostname:         {val1: "yes", val2: "always", invalid: "never"},
		ssh.OptionCanonicalDomains:             {val1: "dev.example.com corp.example.com", val2: "lab.example.com", invalid: "bad..domain!"},
		ssh.OptionCanonicalizeMaxDots:          {val1: "2", val2: "4", invalid: "-1"},
		ssh.OptionCanonicalizeFallbackLocal:    {val1: "yes", val2: "no", invalid: "maybe"},
		ssh.OptionCanonicalizePermittedCNAMEs:  {val1: "*.internal:*.prod.example.com", val2: "*.a:*.b", invalid: "missingcolon"},
		ssh.OptionIdentityFile:                 {val1: "~/.ssh/id_ed25519", val2: "~/.ssh/id_rsa", invalid: "~/.ssh/bad-%k"},
		ssh.OptionCertificateFile:              {val1: "~/.ssh/id_ed25519-cert.pub", val2: "~/.ssh/id_rsa-cert.pub", invalid: "~/.ssh/bad-%k"},
		ssh.OptionIdentityAgent:                {val1: "SSH_AUTH_SOCK", val2: "none", invalid: "/tmp/bad-%k"},
		ssh.OptionPubkeyAuthentication:         {val1: "yes", val2: "no", invalid: "unbound"},
		ssh.OptionPasswordAuthentication:       {val1: "no", val2: "yes", invalid: "maybe"},
		ssh.OptionKbdInteractiveAuthentication: {val1: "no", val2: "yes", invalid: "maybe"},
		ssh.OptionIdentitiesOnly:               {val1: "yes", val2: "no", invalid: "maybe"},
		ssh.OptionPreferredAuthentications:     {val1: "publickey,password", val2: "password", invalid: "unsupported-auth-method"},
		ssh.OptionBatchMode:                    {val1: "yes", val2: "no", invalid: "maybe"},
		ssh.OptionHostKeyAlgorithms:            {val1: "ssh-ed25519", val2: "ecdsa-sha2-nistp256", invalid: "bogus-hostkey-algo"},
		ssh.OptionCiphers:                      {val1: "aes256-gcm@openssh.com", val2: "chacha20-poly1305@openssh.com", invalid: "bogus-cipher-algo"},
		ssh.OptionMACs:                         {val1: "hmac-sha2-256-etm@openssh.com", val2: "hmac-sha2-512-etm@openssh.com", invalid: "bogus-mac-algo"},
		ssh.OptionKexAlgorithms:                {val1: "curve25519-sha256", val2: "diffie-hellman-group14-sha256", invalid: "bogus-kex-algo"},
		ssh.OptionExitOnForwardFailure:         {val1: "yes", val2: "no", invalid: "maybe"},
		ssh.OptionClearAllForwardings:          {val1: "no", val2: "yes", invalid: "maybe"},
		ssh.OptionForwardAgent:                 {val1: "yes", val2: "no", invalid: "/tmp/bad-%k"},
		ssh.OptionGatewayPorts:                 {val1: "clientspecified", val2: "yes", invalid: "always"},
		ssh.OptionStreamLocalBindUnlink:        {val1: "yes", val2: "no", invalid: "maybe"},
		ssh.OptionStreamLocalBindMask:          {val1: "0177", val2: "0117", invalid: "9999"},
		ssh.OptionForkAfterAuthentication:      {val1: "no", val2: "yes", invalid: "maybe"},
		ssh.OptionStdinNull:                    {val1: "yes", val2: "no", invalid: "maybe"},
		ssh.OptionSessionType:                  {val1: "default", val2: "none", invalid: "bogus"},
		ssh.OptionTunnel:                       {val1: "point-to-point", val2: "ethernet", invalid: "bridge"},
		ssh.OptionTunnelDevice:                 {val1: "0:any", val2: "1:2", invalid: "bad:dev:spec"},
		ssh.OptionRequestTTY:                   {val1: "force", val2: "no", invalid: "sometimes"},
		ssh.OptionLocalForward:                 {val1: "127.0.0.1:8080 10.0.0.2:80", val2: "127.0.0.1:8081 10.0.0.3:81", invalid: "not-a-forward"},
		ssh.OptionRemoteForward:                {val1: "*:9090 127.0.0.1:9000", val2: "*:9091 127.0.0.1:9001", invalid: "not-a-forward"},
		ssh.OptionDynamicForward:               {val1: "127.0.0.1:1080", val2: "127.0.0.1:1081", invalid: "not-a-port:abc:def"},
		ssh.OptionSendEnv:                      {val1: "LANG LC_*", val2: "COLORTERM", invalid: "BAD=NAME"},
		ssh.OptionSetEnv:                       {val1: `FOO="hello world" BAR=baz`, val2: "BAZ=qux", invalid: "MISSING_EQUALS"},
		ssh.OptionRemoteCommand:                {val1: "tmux attach || tmux new", val2: "uname -a", invalid: "bad\x00cmd"},
		ssh.OptionEscapeChar:                   {val1: "^A", val2: "none", invalid: "toolong"},
		ssh.OptionProxyCommand:                 {val1: "nc %h %p", val2: "ssh -W %h:%p bastion", invalid: "bad\x00cmd"},
		ssh.OptionLocalCommand:                 {val1: "echo connected %h", val2: "echo done", invalid: "bad\x00cmd"},
		ssh.OptionPermitLocalCommand:           {val1: "yes", val2: "no", invalid: "maybe"},
	}
}

func TestP2_SplitOptionKeyValueDelegation(t *testing.T) {
	t.Parallel()

	inputs := []string{
		"",
		"   ",
		"BatchMode=yes",
		"BatchMode yes",
		"BatchMode = yes",
		"SetEnv=FOO=bar BAZ=1",
		"ControlMaster",
		"=Value",
		"=",
	}
	for _, in := range inputs {
		gotK, gotV, gotErr := SplitOptionKeyValue(in)
		wantK, wantV, wantErr := ssh.SplitOptionKeyValue(in)
		if gotK != wantK || gotV != wantV || (gotErr != nil) != (wantErr != nil) {
			t.Errorf("SplitOptionKeyValue(%q) = (%q, %q, %v), want (%q, %q, %v)",
				in, gotK, gotV, gotErr, wantK, wantV, wantErr)
		}
		if gotErr != nil && !errors.Is(gotErr, ssh.ErrSSHOptionsValidation) {
			t.Errorf("SplitOptionKeyValue(%q) err %v does not wrap ErrSSHOptionsValidation", in, gotErr)
		}
	}
}

func TestP2_ParseOptionStringsDeclarativeMergeMode(t *testing.T) {
	t.Parallel()

	specs := ssh.RegisteredOptionSpecs()
	samples := p2AdapterOptionSamples()
	if len(specs) != len(samples) {
		t.Fatalf("RegisteredOptionSpecs count = %d, sample table count = %d", len(specs), len(samples))
	}

	for _, spec := range specs {
		sample, ok := samples[spec.CanonicalKey]
		if !ok {
			t.Fatalf("missing sample for %q", spec.CanonicalKey)
		}
		assertParseOptionStringsSpec(t, spec, sample)
	}
}

func assertParseOptionStringsSpec(t *testing.T, spec ssh.OptionSpec, sample p2AdapterOptionSample) {
	t.Helper()

	first := spec.OpenSSHName + "=" + sample.val1
	second := spec.OpenSSHName + "=" + sample.val2
	badSecond := spec.OpenSSHName + "=" + sample.invalid

	parsed, err := ParseOptionStrings([]string{first, second})
	if err != nil {
		t.Fatalf("ParseOptionStrings(%s) failed: %v", spec.OpenSSHName, err)
	}
	opts := parsed.ToSSHOptions()
	if opts == nil {
		t.Fatalf("ParseOptionStrings(%s) produced nil Options", spec.OpenSSHName)
	}

	if spec.MergeMode.SingleDirectivePerLayer() {
		want, err := spec.Normalize(sample.val1)
		if err != nil {
			t.Fatalf("normalize %s: %v", spec.CanonicalKey, err)
		}
		if got := opts.Get(spec.CanonicalKey); got != want {
			t.Errorf("%s SingleDirectivePerLayer got %q, want %q", spec.CanonicalKey, got, want)
		}
	} else {
		gotAll := opts.GetAll(spec.CanonicalKey)
		if len(gotAll) < 2 {
			t.Errorf("%s multi-directive (%v) got %v, want >=2 entries", spec.CanonicalKey, spec.MergeMode, gotAll)
		}
	}

	// Second directive must still be validated even when SingleDirectivePerLayer ignores its value.
	if _, err := ParseOptionStrings([]string{first, badSecond}); err == nil {
		t.Errorf("%s accepted invalid second directive %q", spec.CanonicalKey, badSecond)
	}
}

func TestP2_ResolveControlUsesMergeEffectiveOptions(t *testing.T) {
	t.Parallel()

	t.Run("MasterWithoutPathWrapsValidationErr", func(t *testing.T) {
		t.Parallel()
		var sc SessionControlOptions
		sc.SetMaster(ssh.ControlMasterYes)
		_, err := sc.ResolveControl()
		if !errors.Is(err, ssh.ErrSSHOptionsValidation) || !strings.Contains(err.Error(), `ControlMaster "yes" requires non-empty ControlPath`) {
			t.Fatalf("ResolveControl(master=yes) err = %v, want ErrSSHOptionsValidation + requires non-empty ControlPath", err)
		}
	})

	t.Run("PersistWithoutPathWrapsValidationErr", func(t *testing.T) {
		t.Parallel()
		var sc SessionControlOptions
		sc.SetPersist("10m")
		_, err := sc.ResolveControl()
		if !errors.Is(err, ssh.ErrSSHOptionsValidation) || !strings.Contains(err.Error(), "ControlPath is required when ControlPersist is configured") {
			t.Fatalf("ResolveControl(persist=10m) err = %v, want ErrSSHOptionsValidation + ControlPath is required", err)
		}
	})

	t.Run("CrossLayerMasterNoWithPersistFailsClosed", func(t *testing.T) {
		t.Parallel()
		var sc SessionControlOptions
		sc.SetMaster(ssh.ControlMasterNo)
		lower := ssh.MustOptions(
			ssh.OptionControlMaster, "auto",
			ssh.OptionControlPath, "/tmp/cm-%C",
			ssh.OptionControlPersist, "10m",
		)
		_, err := sc.ResolveControl(lower)
		if !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Fatalf("ResolveControl(cross-layer master=no + persist=10m) err = %v, want ErrSSHOptionsValidation", err)
		}
	})

	t.Run("MasterNoAloneReturnsNil", func(t *testing.T) {
		t.Parallel()
		var sc SessionControlOptions
		sc.SetMaster(ssh.ControlMasterNo)
		ctrl, err := sc.ResolveControl()
		if err != nil || ctrl != nil {
			t.Fatalf("ResolveControl(master=no alone) = (%+v, %v), want (nil, nil)", ctrl, err)
		}
	})

	t.Run("PathNoneOverridesActiveLowerLayersAndClearsAllowReuse", func(t *testing.T) {
		t.Parallel()
		sc := SessionControlOptions{AllowReuse: true}
		sc.SetPath("NONE")
		lower := ssh.MustOptions(
			ssh.OptionControlMaster, "auto",
			ssh.OptionControlPath, "/tmp/cm-%C",
			ssh.OptionControlPersist, "10m",
		)
		ctrl, err := sc.ResolveControl(lower)
		if err != nil {
			t.Fatalf("ResolveControl(path=NONE) unexpected err: %v", err)
		}
		if ctrl == nil || ctrl.Path != "none" || ctrl.Master != ssh.ControlMasterNo || ctrl.Persist != "" || ctrl.AllowReuse {
			t.Fatalf("ResolveControl(path=NONE) = %+v, want disabled none with AllowReuse=false", ctrl)
		}
	})

	t.Run("AllowReusePreservedWithoutExplicitMaster", func(t *testing.T) {
		t.Parallel()
		sc := SessionControlOptions{AllowReuse: true}
		sc.SetPath("/tmp/cli.sock")
		lower := ssh.MustOptions(ssh.OptionControlMaster, "yes")
		ctrl, err := sc.ResolveControl(lower)
		if err != nil {
			t.Fatalf("ResolveControl(-S + lower Master=yes) err: %v", err)
		}
		if ctrl == nil || !ctrl.AllowReuse || ctrl.Master != ssh.ControlMasterYes || ctrl.Path != "/tmp/cli.sock" {
			t.Fatalf("ResolveControl(-S + lower Master=yes) = %+v, want AllowReuse=true Master=yes Path=/tmp/cli.sock", ctrl)
		}
	})
}

func TestP2_FilterNonVirtualTier4OptionsDeclarative(t *testing.T) {
	t.Parallel()

	if got := filterNonVirtualTier4Options(nil); got != nil {
		t.Fatalf("filterNonVirtualTier4Options(nil) = %v, want nil", got)
	}

	samples := p2AdapterOptionSamples()
	for _, spec := range ssh.RegisteredOptionSpecs() {
		sample := samples[spec.CanonicalKey]
		raw := ssh.MustOptions(spec.CanonicalKey, sample.val1)
		filtered := filterNonVirtualTier4Options(raw)

		wantKept := spec.Class == ssh.OptionClassMux ||
			spec.Class == ssh.OptionClassTransport ||
			spec.Tier4Policy == ssh.OptionTier4OneWayYes

		if wantKept {
			if filtered == nil || !filtered.Has(spec.CanonicalKey) {
				t.Errorf("filterNonVirtualTier4Options dropped expected option %s (class=%s, tier4=%v)",
					spec.CanonicalKey, spec.Class, spec.Tier4Policy)
			}
		} else if filtered != nil && filtered.Has(spec.CanonicalKey) {
			t.Errorf("filterNonVirtualTier4Options kept disallowed non-virtual Tier4 option %s (class=%s, tier4=%v)",
				spec.CanonicalKey, spec.Class, spec.Tier4Policy)
		}

		if spec.Tier4Policy == ssh.OptionTier4OneWayYes {
			rawNo := ssh.MustOptions(spec.CanonicalKey, "no")
			if filteredNo := filterNonVirtualTier4Options(rawNo); filteredNo != nil && filteredNo.Has(spec.CanonicalKey) {
				t.Errorf("filterNonVirtualTier4Options kept %s=no", spec.CanonicalKey)
			}
			rawTrue := ssh.MustOptions(spec.CanonicalKey, "true")
			if filteredTrue := filterNonVirtualTier4Options(rawTrue); filteredTrue == nil || filteredTrue.Get(spec.CanonicalKey) != "yes" {
				t.Errorf("filterNonVirtualTier4Options(%s=true) = %v, want yes", spec.CanonicalKey, filteredTrue)
			}
		}
	}
}

func TestP2_GetConfigIntraCLIIdentityFileNoneTruncation(t *testing.T) {
	t.Parallel()

	setupManaged := func(nodeKey string, nodeOpts *ssh.Options) config.ConfigProvider {
		cfg := &config.Configuration{
			Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
			Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
			Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		}
		cfg.Hosts.Set("h1", models.Host{Address: "10.90.0.1", Port: 22})
		cfg.Identities.Set("id1", models.Identity{User: "ops", AuthType: "auto", KeyPath: nodeKey})
		cfg.Nodes.Set("srv", models.Node{
			HostRef:     "h1",
			IdentityRef: "id1",
			SSHOptions:  nodeOpts,
		})
		return config.NewProviderWithoutOpenSSH(cfg)
	}

	t.Run("NoneBeforeExtraTruncatesExtraOnManagedNode", func(t *testing.T) {
		t.Parallel()
		prov := setupManaged("", ssh.MustOptions(ssh.OptionIdentityFile, "/tmp/node_tier2_key"))
		sc, err := ParseOptionStrings([]string{
			"IdentityFile=none",
			"IdentityFile=/tmp/extra",
		})
		if err != nil {
			t.Fatalf("ParseOptionStrings: %v", err)
		}
		adp := NewSSHAdapter(prov, WithSessionControlOverride("srv", sc))
		clientCfg, err := adp.GetConfig("srv")
		if err != nil {
			t.Fatalf("GetConfig: %v", err)
		}
		if slices.Contains(clientCfg.KeyPaths, "/tmp/extra") {
			t.Fatalf("GetConfig leaked /tmp/extra after -o IdentityFile=none: KeyPaths=%v", clientCfg.KeyPaths)
		}
		if slices.Contains(clientCfg.KeyPaths, "/tmp/node_tier2_key") {
			t.Fatalf("GetConfig leaked lower-tier key after -o IdentityFile=none: KeyPaths=%v", clientCfg.KeyPaths)
		}
		if !slices.Equal(clientCfg.KeyPaths, []string{"none"}) || clientCfg.KeyPath != "" {
			t.Fatalf("GetConfig = (KeyPaths=%v, KeyPath=%q), want ([none], \"\")", clientCfg.KeyPaths, clientCfg.KeyPath)
		}
	})

	t.Run("ConcreteThenNoneThenExtraTruncatesExtraAndLowerTier", func(t *testing.T) {
		t.Parallel()
		prov := setupManaged("", ssh.MustOptions(ssh.OptionIdentityFile, "/tmp/node_tier2_key"))
		sc, err := ParseOptionStrings([]string{
			"IdentityFile=/tmp/first",
			"IdentityFile=NONE",
			"IdentityFile=/tmp/extra",
		})
		if err != nil {
			t.Fatalf("ParseOptionStrings: %v", err)
		}
		adp := NewSSHAdapter(prov, WithSessionControlOverride("srv", sc))
		clientCfg, err := adp.GetConfig("srv")
		if err != nil {
			t.Fatalf("GetConfig: %v", err)
		}
		if !slices.Equal(clientCfg.KeyPaths, []string{"/tmp/first"}) || clientCfg.KeyPath != "/tmp/first" {
			t.Fatalf("GetConfig = (KeyPaths=%v, KeyPath=%q), want ([/tmp/first], /tmp/first)",
				clientCfg.KeyPaths, clientCfg.KeyPath)
		}
	})

	t.Run("NoneBeforeExtraTruncatesExtraOnOpenSSHVirtualNode", func(t *testing.T) {
		t.Parallel()
		parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(`
Host vapp
    HostName 10.90.0.2
    User deploy
    IdentityFile /tmp/ssh_config_key
`))
		if err != nil {
			t.Fatalf("NewOpenSSHParserFromReader: %v", err)
		}
		prov := config.NewProviderWithOpenSSHParser(&config.Configuration{}, parser)
		sc, err := ParseOptionStrings([]string{
			"IdentityFile=none",
			"IdentityFile=/tmp/extra",
		})
		if err != nil {
			t.Fatalf("ParseOptionStrings: %v", err)
		}
		nodeID := config.OpenSSHNodePrefix + "vapp"
		adp := NewSSHAdapter(prov, WithSessionControlOverride(nodeID, sc))
		clientCfg, err := adp.GetConfig(nodeID)
		if err != nil {
			t.Fatalf("GetConfig(%s): %v", nodeID, err)
		}
		if slices.Contains(clientCfg.KeyPaths, "/tmp/extra") || slices.Contains(clientCfg.KeyPaths, "/tmp/ssh_config_key") {
			t.Fatalf("GetConfig(%s) leaked key after IdentityFile=none: KeyPaths=%v", nodeID, clientCfg.KeyPaths)
		}
		if !slices.Equal(clientCfg.KeyPaths, []string{"none"}) {
			t.Fatalf("GetConfig(%s) KeyPaths = %v, want [none]", nodeID, clientCfg.KeyPaths)
		}
	})

	t.Run("MultipleConcreteCLIIdentityFilesPreservedInOrder", func(t *testing.T) {
		t.Parallel()
		prov := setupManaged("", nil)
		sc, err := ParseOptionStrings([]string{
			"IdentityFile=/tmp/a",
			"IdentityFile=/tmp/b",
		})
		if err != nil {
			t.Fatalf("ParseOptionStrings: %v", err)
		}
		adp := NewSSHAdapter(prov, WithSessionControlOverride("srv", sc))
		clientCfg, err := adp.GetConfig("srv")
		if err != nil {
			t.Fatalf("GetConfig: %v", err)
		}
		if !slices.Equal(clientCfg.KeyPaths, []string{"/tmp/a", "/tmp/b"}) {
			t.Fatalf("GetConfig KeyPaths = %v, want [/tmp/a /tmp/b]", clientCfg.KeyPaths)
		}
	})
}
