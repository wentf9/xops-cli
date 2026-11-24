package option

import (
	"bytes"
	"encoding"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
)

func mustEndpoint(t *testing.T, raw string) netaddr.Endpoint {
	t.Helper()
	ep, err := netaddr.ParseEndpoint(raw)
	if err != nil {
		t.Fatalf("ParseEndpoint(%q) 失败: %v", raw, err)
	}
	return ep
}

func mustCanonicalHost(t *testing.T, raw string) netaddr.CanonicalHost {
	t.Helper()
	ch, err := netaddr.ParseCanonicalHost(raw)
	if err != nil {
		t.Fatalf("ParseCanonicalHost(%q) 失败: %v", raw, err)
	}
	return ch
}

func TestParseOptionValidDirectives(t *testing.T) {
	validDirectives := []struct {
		raw string
		key OptionKey
	}{
		{"HostName=10.0.0.1", KeyHostName},
		{"hostname = %h.corp.example.com", KeyHostName},
		{"HostName fe80::1%%eth0", KeyHostName},
		{"PORT 2222", KeyPort},
		{"user=\"alice\"", KeyUser},
		{"proxy_jump='bob@jump.example.com:2200'", KeyProxyJump},
		{"ProxyCommand ssh -W \"%h:%p\" bastion", KeyProxyCommand},
		{"ProxyCommand=\"ssh -W \\\"%h:%p\\\" bastion\"", KeyProxyCommand},
		{`ProxyCommand "C:\Program Files\OpenSSH\ssh.exe" -W %h:%p gw`, KeyProxyCommand},
		{"ControlMaster autoask", KeyControlMaster},
		{"ControlPath \"~/.ssh/cm %C\"", KeyControlPath},
		{"ControlPersist=10m", KeyControlPersist},
		{"ConnectTimeout=15", KeyConnectTimeout},
		{"ConnectTimeout=1m30s", KeyConnectTimeout},
		{"ConnectTimeout=0", KeyConnectTimeout},
		{"ConnectTimeout=none", KeyConnectTimeout},
		{"ServerAliveInterval 0", KeyServerAliveInterval},
		{"ServerAliveInterval 2m", KeyServerAliveInterval},
		{"cIpHeRs +aes128-ctr", KeyCiphers},
		{"Ciphers -*-cbc,aes???-ctr", KeyCiphers},
		{"MACs -hmac-sha2-256", KeyMACs},
		{"kex_algorithms ^curve25519-sha256", KeyKexAlgorithms},
		{"HostKeyAlgorithms ssh-ed25519", KeyHostKeyAlgorithms},
		{"IdentityFile \"~/.ssh/my key\"", KeyIdentityFile},
		{"CertificateFile ~/.ssh/id-cert.pub", KeyCertificateFile},
		{"IdentitiesOnly yes", KeyIdentitiesOnly},
		{"BatchMode false", KeyBatchMode},
		{"strict_host_key_checking=accept-new", KeyStrictHostKeyChecking},
		{"UserKnownHostsFile \"~/.ssh/known hosts\" ~/.ssh/kh2", KeyUserKnownHostsFile},
		{"UserKnownHostsFile none", KeyUserKnownHostsFile},
		{"ForwardAgent no", KeyForwardAgent},
		{"SendEnv LANG \"LC_*\" -LC_ALL", KeySendEnv},
		{"PermitLocalCommand true", KeyPermitLocalCommand},
		{"LocalCommand echo hello %h %C", KeyLocalCommand},
		{`LocalCommand "/Users/alice/My Scripts/notify.sh" %h`, KeyLocalCommand},
	}
	for _, tc := range validDirectives {
		opt, err := ParseOption(tc.raw)
		if err != nil || !opt.IsValid() || opt.Key() != tc.key || opt.Layer().Validate() != nil {
			t.Fatalf("ParseOption(%q) 失败或异常: err=%v key=%q", tc.raw, err, opt.Key())
		}
	}
	assertParseOptionKVParity(t)
}

func assertParseOptionKVParity(t *testing.T) {
	t.Helper()
	kvKH, err := ParseOptionKV("UserKnownHostsFile", `"~/.ssh/known hosts" ~/.ssh/kh2`)
	if err != nil || !slices.Equal(kvKH.Layer().UserKnownHostsFiles().RawItems(), []string{"~/.ssh/known hosts", "~/.ssh/kh2"}) {
		t.Fatalf("ParseOptionKV(UserKnownHostsFile) 引号路径切分错误: err=%v items=%v", err, kvKH.Layer().UserKnownHostsFiles().RawItems())
	}
	kvEnv, err := ParseOptionKV("SendEnv", `LANG "LC_*" -LC_ALL`)
	if err != nil || !slices.Equal(kvEnv.Layer().SendEnv().Patterns(), []string{"LANG", "LC_*"}) {
		t.Fatalf("ParseOptionKV(SendEnv) 引号切分错误: err=%v pats=%v", err, kvEnv.Layer().SendEnv().Patterns())
	}
	winCmd := `"C:\Program Files\OpenSSH\ssh.exe" -W %h:%p gw`
	kvCmd, err := ParseOptionKV("ProxyCommand", winCmd)
	if err != nil || kvCmd.RawValue() != winCmd {
		t.Fatalf("ParseOptionKV(ProxyCommand) 带引号 arg0 被破坏: err=%v got=%q", err, kvCmd.RawValue())
	}
	kvTimeout, err := ParseOptionKV("ConnectTimeout", "1m30s")
	if err != nil || kvTimeout.Layer().ConnectTimeout().OrElse(algebraic.ZeroDuration()).Std() != 90*time.Second {
		t.Fatalf("ParseOptionKV(ConnectTimeout, 1m30s) 解析错误: err=%v", err)
	}
}

func TestParseOptionLayerAndFailClosed(t *testing.T) {
	layer := mustOptionLayer(t, "User alice", "User bob", "SendEnv LANG LC_ALL", "SendEnv -LC_*",
		"IdentityFile ~/.ssh/a", "IdentityFile none", "IdentityFile ~/.ssh/b",
		"UserKnownHostsFile ~/.ssh/kh1", "UserKnownHostsFile ~/.ssh/kh2",
		"Ciphers +aes256-ctr", "Ciphers -aes128-ctr")
	if layer.User().OrElse(Username{}).String() != "alice" ||
		!slices.Equal(layer.SendEnv().Patterns(), []string{"LANG"}) ||
		!slices.Equal(layer.IdentityFiles().RawItems(), []string{"~/.ssh/a"}) || !layer.IdentityFiles().Terminated() ||
		!slices.Equal(layer.UserKnownHostsFiles().RawItems(), []string{"~/.ssh/kh1"}) ||
		layer.Ciphers().String() != "+aes256-ctr" {
		t.Fatalf("ParseOptionLayer 同层折叠语义异常")
	}

	badInputs := []struct {
		raw  string
		want error
	}{
		{"", ErrInvalidOption}, {"   ", ErrInvalidOption}, {"# Port 22", ErrInvalidOption}, {"-oPort=22", ErrInvalidOption},
		{"UnknownOption yes", ErrUnknownOption}, {"Port=", ErrInvalidOption}, {"Port 0", ErrInvalidOption},
		{"Port 022", ErrInvalidOption}, {"Port 65536", ErrInvalidOption}, {"User \"unclosed", ErrInvalidOption},
		{"User bad\"quote", ErrInvalidOption}, {"User -inject", ErrInvalidOption}, {"HostName -inject", ErrInvalidOption},
		{"ConnectTimeout +5", ErrInvalidOption}, {"ConnectTimeout -5", ErrInvalidOption}, {"ConnectTimeout 10x", ErrInvalidOption},
		{"ServerAliveInterval -1", ErrInvalidOption}, {"ServerAliveInterval none", ErrInvalidOption},
		{"BatchMode maybe", ErrInvalidOption}, {"User alice\nPort 22", ErrInvalidOption}, {"User alice\u202ebob", ErrInvalidOption},
		{"IdentityFile /a /b", ErrInvalidOption}, {"CertificateFile /c1 /c2", ErrInvalidOption}, {"IdentityFile \"/a b\" /c", ErrInvalidOption},
		{"UserKnownHostsFile none ~/.ssh/kh2", ErrInvalidPathList}, {"UserKnownHostsFile ~/.ssh/kh1 none", ErrInvalidPathList},
		{"UserKnownHostsFile none none", ErrInvalidPathList},
		{`ProxyCommand "echo"trailing`, ErrInvalidOption}, {`ProxyCommand "echo hi" "unclosed`, ErrInvalidOption},
		{`ProxyCommand "" -W %h:%p`, ErrInvalidOption}, {"ProxyCommand nc %h %p %u", ErrInvalidProxyRoute},
		{"ProxyCommand nc %h %p %j", ErrInvalidProxyRoute}, {"LocalCommand echo %z", ErrInvalidOption},
	}
	for _, tc := range badInputs {
		if _, err := ParseOption(tc.raw); !errors.Is(err, tc.want) {
			t.Fatalf("ParseOption(%q) 期望 %v，实际 %v", tc.raw, tc.want, err)
		}
	}
	if _, err := ParseStrictHostKeyChecking("yes\n"); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("ParseStrictHostKeyChecking 应拒绝控制字符，实际 %v", err)
	}
	if _, err := ParseOriginKind("managed\r\n"); !errors.Is(err, ErrInvalidOrigin) {
		t.Fatalf("ParseOriginKind 应拒绝控制字符，实际 %v", err)
	}
}

func TestHostNameSpecCanonicalAndZonedIPv6(t *testing.T) {
	for _, bad := range []string{"fe80::1%eth0", "fe80::1%hom0", "a;id%h", "..%h", "bad%z"} {
		if _, err := ParseHostNameSpec(bad); !errors.Is(err, ErrInvalidOption) {
			t.Fatalf("ParseHostNameSpec(%q) 应失败关闭，实际 %v", bad, err)
		}
	}
	origWeb := mustCanonicalHost(t, "web01")
	specEsc, err := ParseHostNameSpec("FE80::0001%%hom0")
	if err != nil || specEsc.String() != "fe80::1%%hom0" {
		t.Fatalf("ParseHostNameSpec(%% 转义带区 IPv6) 异常: err=%v str=%q", err, specEsc.String())
	}
	if resolved, err := specEsc.ResolveHost(origWeb); err != nil || resolved.String() != "fe80::1%hom0" {
		t.Fatalf("HostNameSpec.ResolveHost 不得将 %%%%hom0 误判为 %%h: err=%v got=%s", err, resolved)
	}

	zonedHost := mustCanonicalHost(t, "fe80::1%hom0")
	fromHost, err := HostNameSpecFromHost(zonedHost)
	if err != nil || !fromHost.Equal(specEsc) {
		t.Fatalf("HostNameSpecFromHost 规范表示不匹配: err=%v got=%q", err, fromHost.String())
	}
	if resolved, err := fromHost.ResolveHost(origWeb); err != nil || !resolved.Equal(zonedHost) {
		t.Fatalf("HostNameSpecFromHost.ResolveHost 失真: err=%v got=%s", err, resolved)
	}
	rawText, err := fromHost.MarshalText()
	var rt HostNameSpec
	if err != nil || rt.UnmarshalText(rawText) != nil || !rt.Equal(fromHost) {
		t.Fatalf("HostNameSpecFromHost 文本往返非双射: raw=%q", rawText)
	}
	var zeroHost netaddr.CanonicalHost
	if _, err := HostNameSpecFromHost(zeroHost); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("零值 CanonicalHost 应失败关闭，实际 %v", err)
	}
}

func TestPercentCAndTokenExpansion(t *testing.T) {
	// 经本地 OpenSSH 10.6p2 ssh -G 与 sha1sum 双重核验的协议级黄金向量。
	gotNoJump, err := ComputePercentC("cachyos-x8664", "example.com", 2222, "alice")
	if err != nil || gotNoJump != "65dd530a34eac12d242e8410cd2a1fcd4a31c687" {
		t.Fatalf("%%C(无跳板) 不匹配: err=%v got=%s", err, gotNoJump)
	}
	gotWithJump, err := ComputeConnectionHash("cachyos-x8664", "example.com", 2222, "alice", "bastion.example.com")
	if err != nil || gotWithJump != "6a3261cba819f18724aab66d963731d4b9514c77" {
		t.Fatalf("%%C(含跳板) 不匹配: err=%v got=%s", err, gotWithJump)
	}

	ctx := TokenContext{
		LocalHost: "workstation.local.lan", TargetHost: "example.com", Port: 2222,
		OriginalHost: "prod-web", LocalUser: "dev", LocalUID: "1000", HomeDir: "/home/dev", JumpHost: "bastion.example.com",
	}
	expanded, err := ExpandPathTokens("%d/.ssh/cm-%L-%l-%n-%h-%p-%r-%u-%i-%j-%%-%C", ctx)
	wantHash, _ := ComputeConnectionHash("workstation.local.lan", "example.com", 2222, "dev", "bastion.example.com")
	wantExpanded := "/home/dev/.ssh/cm-workstation-workstation.local.lan-prod-web-example.com-2222-dev-dev-1000-bastion.example.com-%-" + wantHash
	if err != nil || expanded != wantExpanded {
		t.Fatalf("ExpandPathTokens 展开不符: err=%v\ngot:  %s\nwant: %s", err, expanded, wantExpanded)
	}
	// 无跳板时 %j 允许展开为空串。
	noJumpCtx := ctx
	noJumpCtx.JumpHost = ""
	if s, err := ExpandPathTokens("j=%j", noJumpCtx); err != nil || s != "j=" {
		t.Fatalf("空 %%j 应合法展开为空串: err=%v got=%q", err, s)
	}
	assertPercentFailClosed(t, ctx)
}

func assertPercentFailClosed(t *testing.T, base TokenContext) {
	t.Helper()
	badPathCtx := base
	badPathCtx.RemoteUser = "../root"
	if _, err := ExpandPathTokens("%d/.ssh/%r.sock", badPathCtx); !errors.Is(err, ErrInvalidPercentInput) {
		t.Fatalf("ExpandPathTokens 应阻断目录穿越，实际 %v", err)
	}
	for _, badTpl := range []string{"%z", "trailing%", "bad\nline"} {
		if _, err := ExpandTokens(badTpl, base); !errors.Is(err, ErrInvalidPercentInput) {
			t.Fatalf("ExpandTokens(%q) 应返回 ErrInvalidPercentInput，实际 %v", badTpl, err)
		}
	}
	// 空字段严格失败关闭（%d/%u/%r/%i/%l/%L 绝不静默坍缩）。
	emptyCases := []struct {
		tpl    string
		mutate func(*TokenContext)
	}{
		{"%d/.ssh/cm", func(c *TokenContext) { c.HomeDir = "" }},
		{"%u", func(c *TokenContext) { c.LocalUser = "" }},
		{"%r", func(c *TokenContext) { c.RemoteUser, c.LocalUser = "", "" }},
		{"%i", func(c *TokenContext) { c.LocalUID = "" }},
		{"%l", func(c *TokenContext) { c.LocalHost = "" }},
		{"%L", func(c *TokenContext) { c.LocalHost = ".onlydot" }},
	}
	for _, tc := range emptyCases {
		c := base
		tc.mutate(&c)
		if _, err := ExpandPathTokens(tc.tpl, c); !errors.Is(err, ErrInvalidPercentInput) {
			t.Fatalf("空字段模板 %q 应失败关闭，实际 %v", tc.tpl, err)
		}
	}
	for _, args := range [][4]string{{"", "example.com", "22", "u"}, {"local", "", "22", "u"}, {"local", "example.com", "22", ""}} {
		if _, err := ComputePercentC(args[0], args[1], 22, args[3]); !errors.Is(err, ErrInvalidPercentInput) {
			t.Fatalf("ComputePercentC(%v) 应失败关闭，实际 %v", args, err)
		}
	}
	if _, err := ComputePercentC("local", "example.com", 0, "u"); !errors.Is(err, ErrInvalidPercentInput) {
		t.Fatalf("端口 0 %%C 应失败关闭")
	}
}

func buildTestRichOpenSSHT4(t *testing.T) OptionLayer {
	t.Helper()
	return mustOptionLayer(t,
		"HostName %h.corp.example.com", "Port 2299", "User attacker",
		"ProxyCommand ssh -W %h:%p evil-gw",
		"ControlMaster auto", "ControlPath ~/.ssh/cm-%C", "ControlPersist 5m",
		"ConnectTimeout 30s", "ServerAliveInterval 1m", "Ciphers -aes128-ctr",
		"IdentityFile ~/.ssh/id_openssh", "IdentitiesOnly yes", "BatchMode yes",
		"StrictHostKeyChecking no", "UserKnownHostsFile ~/.ssh/openssh_kh",
		"ForwardAgent yes", "SendEnv SECRET_*",
		"PermitLocalCommand yes", "LocalCommand id",
	)
}

func TestResolveEffectivePolicyFourTierAndSecurityTrim(t *testing.T) {
	baseEP := mustEndpoint(t, "app.internal:22")
	t1 := mustOptionLayer(t, "ConnectTimeout 0", "Ciphers ^aes256-gcm@openssh.com")
	t2 := mustOptionLayer(t, "Port 2222", "User deploy", "ConnectTimeout 15s")
	t3Global := mustOptionLayer(t, "StrictHostKeyChecking yes", "UserKnownHostsFile ~/.ssh/xops_kh",
		"IdentityFile ~/.ssh/id_global", "ControlPersist 10m")
	t4OpenSSH := buildTestRichOpenSSHT4(t)

	for _, origin := range []OriginKind{OriginManaged, OriginAdHoc} {
		pol, err := ResolveEffectivePolicy(origin, baseEP, t1, t2, t3Global, t4OpenSSH)
		if err != nil {
			t.Fatalf("ResolveEffectivePolicy(%s) 失败: %v", origin, err)
		}
		assertNonOpenSSHPolicyTrimmed(t, origin, pol)
	}
}

func assertNonOpenSSHPolicyTrimmed(t *testing.T, origin OriginKind, pol EffectivePolicy) {
	t.Helper()
	if !pol.IsValid() || pol.Endpoint().String() != "app.internal:2222" || pol.OriginalHost().String() != "app.internal" {
		t.Fatalf("%s 端点求解错误: ep=%s orig=%s", origin, pol.Endpoint(), pol.OriginalHost())
	}
	if pol.User().OrElse(Username{}).String() != "deploy" || !EqualProxyRoute(pol.Proxy(), NewProxyUnset()) {
		t.Fatalf("%s User 或 Proxy 裁剪错误", origin)
	}
	// INV-D2：t4 的 Auth（含 BatchMode/IdentitiesOnly）、Trust、Forward、Session、LocalExec 全部剥离；t3 全局配置完整保留。
	if pol.ForwardAgent() || pol.PermitLocalCommand() || pol.LocalCommand().IsSome() || !pol.SendEnv().IsUnset() ||
		pol.BatchMode() || pol.IdentitiesOnly() {
		t.Fatalf("%s 泄露了被裁剪的 t4 高危或认证选项: batch=%v idOnly=%v", origin, pol.BatchMode(), pol.IdentitiesOnly())
	}
	if !slices.Equal(pol.IdentityFiles().RawItems(), []string{"~/.ssh/id_global"}) ||
		!slices.Equal(pol.UserKnownHostsFiles().RawItems(), []string{"~/.ssh/xops_kh"}) ||
		pol.StrictHostKeyChecking() != StrictHostKeyCheckingYes {
		t.Fatalf("%s 受信任 t3（XOps 全局配置）不得被裁剪", origin)
	}
	perDur, ok := pol.Control().EffectivePersist().Timeout()
	if !pol.Control().IsEnabled() || pol.Control().EffectiveMaster() != ControlMasterAuto ||
		!ok || perDur.Std() != 10*time.Minute || pol.ServerAliveInterval().Std() != 60*time.Second {
		t.Fatalf("%s t3>t4 优先级或 t4 Mux/Transport 保留异常", origin)
	}
	ct, hasCT := pol.ConnectTimeout().Get()
	if !hasCT || ct.Std() != 0 {
		t.Fatalf("%s t1 ConnectTimeout=0 应保留，实际 has=%v dur=%v", origin, hasCT, ct)
	}
	// AlgoPolicy FirstWins：t1 遮蔽 t4 的 -aes128-ctr，故 aes128-ctr 保持存在。
	if pol.Ciphers()[0] != "aes256-gcm@openssh.com" || !slices.Contains(pol.Ciphers(), "aes128-ctr") {
		t.Fatalf("%s AlgoPolicy FirstWins 求解异常: %v", origin, pol.Ciphers())
	}
}

func TestResolveEffectivePolicyOpenSSHAndFailClosed(t *testing.T) {
	baseEP := mustEndpoint(t, "app.internal:22")
	t3Global := mustOptionLayer(t, "User globalops")
	t4OpenSSH := buildTestRichOpenSSHT4(t)

	polSSH, err := ResolveEffectivePolicy(OriginOpenSSHVirtual, baseEP, UnsetOptionLayer(), UnsetOptionLayer(), t3Global, t4OpenSSH)
	if err != nil || polSSH.Endpoint().String() != "app.internal.corp.example.com:2299" ||
		polSSH.User().OrElse(Username{}).String() != "globalops" ||
		polSSH.OriginalHost().String() != "app.internal" || !polSSH.PermitLocalCommand() ||
		polSSH.LocalCommand().OrElse(SanitizedCmd{}).String() != "id" {
		t.Fatalf("OpenSSHVirtual t3>t4 继承与 HostName %%h 展开错误: err=%v ep=%s", err, polSSH.Endpoint())
	}

	polGated, err := ResolveEffectivePolicy(OriginOpenSSHDerived, baseEP, mustOptionLayer(t, "PermitLocalCommand no"), UnsetOptionLayer(), UnsetOptionLayer(), t4OpenSSH)
	if err != nil || polGated.LocalCommand().IsSome() {
		t.Fatalf("PermitLocalCommand=no 必须阻断 LocalCommand，实际 err=%v", err)
	}

	// 验证多跳 ProxyJump 的 %C 严格仅使用末跳无方括号规范主机名（%j = "2001:db8::1"）。
	polMultiJump, err := ResolveEffectivePolicy(OriginOpenSSHVirtual, mustEndpoint(t, "example.com:22"),
		mustOptionLayer(t, "User alice", "Port 2222", "ProxyJump u1@hop1.example.com:2201,u2@[2001:db8::1]:2202"),
		UnsetOptionLayer(), UnsetOptionLayer(), UnsetOptionLayer())
	if err != nil {
		t.Fatalf("ResolveEffectivePolicy(polMultiJump) 失败: %v", err)
	}
	wantMulti, err := ComputeConnectionHash("cachyos-x8664", "example.com", 2222, "alice", "2001:db8::1")
	if gotMulti, err2 := polMultiJump.PercentC("cachyos-x8664", "ignored"); err != nil || err2 != nil || gotMulti != wantMulti {
		t.Fatalf("多跳 %%C 应取末跳无方括号主机名: err=%v got=%s want=%s", err2, gotMulti, wantMulti)
	}
	// 验证大小写敏感 ProxyJump Host 别名在 %C 中保持原样（ProdBastion != prodbastion）。
	polCaseJump, err := ResolveEffectivePolicy(OriginOpenSSHVirtual, mustEndpoint(t, "example.com:22"),
		mustOptionLayer(t, "User alice", "Port 2222", "ProxyJump ProdBastion"),
		UnsetOptionLayer(), UnsetOptionLayer(), UnsetOptionLayer())
	wantCase, _ := ComputeConnectionHash("cachyos-x8664", "example.com", 2222, "alice", "ProdBastion")
	wantLower, _ := ComputeConnectionHash("cachyos-x8664", "example.com", 2222, "alice", "prodbastion")
	if gotCase, err2 := polCaseJump.PercentC("cachyos-x8664", "ignored"); err != nil || err2 != nil || gotCase != wantCase || gotCase == wantLower {
		t.Fatalf("大小写敏感 ProxyJump 别名 %%C 错误: err=%v/%v got=%s want=%s", err, err2, gotCase, wantCase)
	}
	assertResolveFailClosed(t, baseEP)
}

func assertResolveFailClosed(t *testing.T, baseEP netaddr.Endpoint) {
	t.Helper()
	u := UnsetOptionLayer()
	if _, err := ResolveEffectivePolicy(OriginInvalid, baseEP, u, u, u, u); !errors.Is(err, ErrInvalidOrigin) {
		t.Fatalf("OriginInvalid 应失败关闭，实际 %v", err)
	}
	var zeroEP netaddr.Endpoint
	if _, err := ResolveEffectivePolicy(OriginManaged, zeroEP, u, u, u, u); !errors.Is(err, ErrInvalidEndpoint) {
		t.Fatalf("零值 Endpoint 应失败关闭，实际 %v", err)
	}
	if _, err := ResolveEffectivePolicy(OriginManaged, baseEP, u.WithProxyRoute((*ProxyCommandSpec)(nil)), u, u, u); !errors.Is(err, ErrInvalidProxyRoute) {
		t.Fatalf("非法层应失败关闭，实际 %v", err)
	}
	wipeAll := u.WithCiphers(mustAlgoPolicy(t, "-*"))
	if _, err := ResolveEffectivePolicy(OriginManaged, baseEP, wipeAll, u, u, u); !errors.Is(err, ErrEmptyAlgorithmList) {
		t.Fatalf("算法清空应返回 ErrEmptyAlgorithmList，实际 %v", err)
	}
	var zeroPol EffectivePolicy
	if zeroPol.IsValid() || zeroPol.Equal(zeroPol) {
		t.Fatalf("零值 EffectivePolicy 必须失败关闭")
	}
	if _, err := zeroPol.PercentC("local", "user"); !errors.Is(err, ErrInvalidEndpoint) {
		t.Fatalf("零值 EffectivePolicy.PercentC 应失败关闭，实际 %v", err)
	}
}

func TestJSONv2DeterministicRoundTrip(t *testing.T) {
	fullLayer := mustOptionLayer(t,
		"HostName %h.prod.example.com", "Port 2222", "User ops",
		"ControlMaster auto", "ControlPath ~/.ssh/cm-%C", "ControlPersist 15m",
		"ConnectTimeout 10s", "ServerAliveInterval 30s",
		"Ciphers +aes128-ctr", "MACs -hmac-sha2-256,*sha1*", "KexAlgorithms ^curve25519-sha256", "HostKeyAlgorithms ssh-ed25519",
		"IdentityFile ~/.ssh/id_a", "IdentityFile none", "CertificateFile ~/.ssh/id_a-cert.pub",
		"IdentitiesOnly yes", "BatchMode yes", "StrictHostKeyChecking accept-new",
		"UserKnownHostsFile ~/.ssh/kh1 ~/.ssh/kh2", "ForwardAgent yes",
		"SendEnv LANG LC_* -LC_ALL", "PermitLocalCommand yes", "LocalCommand echo connected %h",
	).WithProxyRoute(ComposeProxyRoute(mustProxyJump(t, "alice@jump1.example.com:2222,[2001:db8::1]"), mustProxyCmd(t, "ssh -W %h:%p gw")))

	pol, err := ResolveEffectivePolicy(OriginOpenSSHVirtual, mustEndpoint(t, "web01.internal:22"), fullLayer, UnsetOptionLayer(), UnsetOptionLayer(), UnsetOptionLayer())
	if err != nil {
		t.Fatalf("ResolveEffectivePolicy 失败: %v", err)
	}
	b1, err := jsonv2.Marshal(pol, jsonv2.Deterministic(true))
	b2, err2 := jsonv2.Marshal(pol, jsonv2.Deterministic(true))
	if err != nil || err2 != nil || !bytes.Equal(b1, b2) {
		t.Fatalf("Deterministic(true) 编码失败或非确定性: %v / %v", err, err2)
	}
	var decoded EffectivePolicy
	if err := jsonv2.Unmarshal(b1, &decoded); err != nil || !pol.Equal(decoded) {
		t.Fatalf("EffectivePolicy JSON/v2 往返失败: %v", err)
	}

	lb, err := jsonv2.Marshal(fullLayer, jsonv2.Deterministic(true))
	var decodedLayer OptionLayer
	if err != nil || jsonv2.Unmarshal(lb, &decodedLayer) != nil || !fullLayer.Equal(decodedLayer) {
		t.Fatalf("OptionLayer JSON/v2 往返失败")
	}
	if err := jsonv2.Unmarshal([]byte("null"), &decodedLayer); err != nil || !decodedLayer.IsUnset() {
		t.Fatalf("OptionLayer null 解码应返回 Unset")
	}
	if _, err := jsonv2.Marshal(EffectivePolicy{}); !errors.Is(err, ErrInvalidOrigin) {
		t.Fatalf("零值 EffectivePolicy 编码应失败关闭，实际 %v", err)
	}
	assertInvalidEffectivePolicyJSON(t, pol)
	assertInvalidWireJSON(t)
	assertPolymorphicProxyRouteJSON(t)
}

func assertInvalidEffectivePolicyJSON(t *testing.T, validPol EffectivePolicy) {
	t.Helper()
	badPol := validPol
	if err := jsonv2.Unmarshal([]byte(`null`), &badPol); !errors.Is(err, ErrInvalidOrigin) || badPol.IsValid() {
		t.Fatalf("顶层 null 解码 EffectivePolicy 应失败关闭并重置为零值，实际 %v", err)
	}
	if err := jsonv2.Unmarshal([]byte(`nul`), &badPol); err == nil || errors.Is(err, ErrInvalidOrigin) {
		t.Fatalf("畸形 JSON 前缀 nul 应保留语法错误而非伪装 ErrInvalidOrigin，实际 %v", err)
	}
	if err := jsonv2.Unmarshal([]byte(`{"origin":"invalid"}`), &badPol); err == nil || badPol.IsValid() {
		t.Fatalf("非法 EffectivePolicy JSON 解码应失败关闭")
	}
}

func assertPolymorphicProxyRouteJSON(t *testing.T) {
	t.Helper()
	var (
		_ jsonv2.MarshalerTo = ProxyUnset{}
		_ jsonv2.MarshalerTo = ProxyDisabled{}
		_ jsonv2.MarshalerTo = ProxyJumpChain{}
		_ jsonv2.MarshalerTo = ProxyCommandSpec{}
	)
	if err := MarshalProxyRouteTo(nil, NewProxyUnset()); !errors.Is(err, ErrNilReceiver) {
		t.Fatalf("MarshalProxyRouteTo(nil) 应返回 ErrNilReceiver，实际 %v", err)
	}
	if r, err := UnmarshalProxyRouteFrom(nil); r != nil || !errors.Is(err, ErrNilReceiver) {
		t.Fatalf("UnmarshalProxyRouteFrom(nil) 应返回 (nil, ErrNilReceiver)，实际 (%#v, %v)", r, err)
	}
	if r, err := UnmarshalProxyRouteFrom(jsontext.NewDecoder(bytes.NewReader([]byte(`{"kind":"bogus"}`)))); r != nil || !errors.Is(err, ErrInvalidProxyRoute) {
		t.Fatalf("UnmarshalProxyRouteFrom 失败必须返回 (nil, ErrInvalidProxyRoute)，实际 (%#v, %v)", r, err)
	}
	if _, err := jsonv2.Marshal(ProxyJumpChain{}); !errors.Is(err, ErrInvalidProxyRoute) {
		t.Fatalf("零值 ProxyJumpChain 编码应失败关闭，实际 %v", err)
	}
	if _, err := jsonv2.Marshal(ProxyCommandSpec{}); !errors.Is(err, ErrInvalidProxyRoute) {
		t.Fatalf("零值 ProxyCommandSpec 编码应失败关闭，实际 %v", err)
	}
	bDis, err := jsonv2.Marshal(ProxyDisabled{}, jsonv2.Deterministic(true))
	if err != nil {
		t.Fatalf("ProxyDisabled 编码失败: %v", err)
	}
	rDis, err := UnmarshalProxyRouteFrom(jsontext.NewDecoder(bytes.NewReader(bDis)))
	if err != nil || !EqualProxyRoute(rDis, NewProxyDisabled()) {
		t.Fatalf("UnmarshalProxyRouteFrom(ProxyDisabled) 往返失败: err=%v r=%T", err, rDis)
	}
	shadowed := ComposeProxyRoute(mustProxyJump(t, "bastion.example.com"), mustProxyCmd(t, "ssh -W %h:%p gw"))
	var buf bytes.Buffer
	if err := MarshalProxyRouteTo(jsontext.NewEncoder(&buf), shadowed); err != nil {
		t.Fatalf("MarshalProxyRouteTo 失败: %v", err)
	}
	rShadow, err := UnmarshalProxyRouteFrom(jsontext.NewDecoder(bytes.NewReader(buf.Bytes())))
	if err != nil || !EqualProxyRoute(rShadow, shadowed) {
		t.Fatalf("多态 ProxyRoute JSON 往返不等: err=%v", err)
	}
}

func assertInvalidWireJSON(t *testing.T) {
	t.Helper()
	var pl PathList
	if err := jsonv2.Unmarshal([]byte(`{"state":"bad"}`), &pl); !errors.Is(err, ErrInvalidPathList) {
		t.Fatalf("非法 PathList JSON 应失败关闭，实际 %v", err)
	}
	var kh KnownHostsList
	for _, raw := range []string{`{"state":"bad"}`, `{"state":"set"}`, `{"state":"disabled","items":["~/.ssh/a"]}`, `{"state":"set","items":["~/.ssh/a"],"terminated":true}`} {
		if err := jsonv2.Unmarshal([]byte(raw), &kh); !errors.Is(err, ErrInvalidPathList) {
			t.Fatalf("非法 KnownHostsList JSON %s 应失败关闭，实际 %v", raw, err)
		}
	}
	var ap AlgoPolicy
	for _, raw := range []string{`{"op":"bad"}`, `{"op":"exact"}`, `{"op":"exact","tokens":["aes*"]}`, `{"op":"unset","tokens":["a"]}`} {
		if err := jsonv2.Unmarshal([]byte(raw), &ap); !errors.Is(err, ErrInvalidAlgoPolicy) {
			t.Fatalf("非法 AlgoPolicy JSON %s 应失败关闭，实际 %v", raw, err)
		}
	}
	var ef EnvFilter
	if err := jsonv2.Unmarshal([]byte(`{"added":["BAD=NAME"]}`), &ef); !errors.Is(err, ErrInvalidEnvFilter) {
		t.Fatalf("非法 EnvFilter JSON 应失败关闭，实际 %v", err)
	}
	assertInvalidControlAndLayerWireJSON(t)
}

func assertInvalidControlAndLayerWireJSON(t *testing.T) {
	t.Helper()
	var cp ControlPolicy
	if err := jsonv2.Unmarshal([]byte(`{"master":"bogus"}`), &cp); !errors.Is(err, ErrInvalidControlPolicy) {
		t.Fatalf("非法 ControlPolicy JSON 应失败关闭，实际 %v", err)
	}
	if err := jsonv2.Unmarshal([]byte(`{"literal_path":true}`), &cp); !errors.Is(err, ErrInvalidControlPolicy) {
		t.Fatalf("无路径的 literal_path=true 应失败关闭，实际 %v", err)
	}
	var l OptionLayer
	for _, raw := range []string{`{"proxy":{"kind":"unknown"}}`, `{"proxy":{"kind":"disabled","hops":["a"]}}`, `{"proxy":{"kind":"command","command":"nc %h %p","scope":"all"}}`} {
		if err := jsonv2.Unmarshal([]byte(raw), &l); !errors.Is(err, ErrInvalidProxyRoute) {
			t.Fatalf("非法 ProxyRoute JSON %s 应失败关闭，实际 %v", raw, err)
		}
	}
	if err := jsonv2.Unmarshal([]byte(`{"local_command":"echo %z"}`), &l); !errors.Is(err, ErrInvalidPercentInput) {
		t.Fatalf("非法 LocalCommand 占位符 JSON 应失败关闭，实际 %v", err)
	}
	for _, cfRaw := range []string{"User alice\u200bbob", "User alice\U000e0041"} {
		if _, err := ParseOption(cfRaw); !errors.Is(err, ErrInvalidOption) {
			t.Fatalf("Unicode Cf 载荷 %q 应失败关闭，实际 %v", cfRaw, err)
		}
	}
}

func TestTextCodecsRoundTripAndNilReceiver(t *testing.T) {
	cmd, err := NewSanitizedCmd("echo hi")
	if err != nil {
		t.Fatalf("NewSanitizedCmd 失败: %v", err)
	}
	per, err := ParseControlPersist("300s")
	if err != nil {
		t.Fatalf("ParseControlPersist 失败: %v", err)
	}
	u, err := ParseUsername("alice")
	if err != nil {
		t.Fatalf("ParseUsername 失败: %v", err)
	}
	hn, err := ParseHostNameSpec("%h.example.com")
	if err != nil {
		t.Fatalf("ParseHostNameSpec 失败: %v", err)
	}

	assertTextRoundTrip(t, mustPathEntry(t, "~/.ssh/id_%r"), new(PathEntry))
	assertTextRoundTrip(t, mustHop(t, "alice@[2001:db8::1]:2222"), new(HopTarget))
	assertTextRoundTrip(t, cmd, new(SanitizedCmd))
	assertTextRoundTrip(t, ControlMasterAutoAsk, new(ControlMasterMode))
	assertTextRoundTrip(t, per, new(ControlPersistSpec))
	assertTextRoundTrip(t, KeyStrictHostKeyChecking, new(OptionKey))
	assertTextRoundTrip(t, StrictHostKeyCheckingAcceptNew, new(StrictHostKeyCheckingMode))
	assertTextRoundTrip(t, u, new(Username))
	assertTextRoundTrip(t, hn, new(HostNameSpec))
	assertTextRoundTrip(t, OriginOpenSSHDerived, new(OriginKind))

	if err := (*PathEntry)(nil).UnmarshalText([]byte("~/.ssh/a")); !errors.Is(err, ErrNilReceiver) {
		t.Fatalf("nil PathEntry.UnmarshalText 应返回 ErrNilReceiver，实际 %v", err)
	}
	if err := (*EffectivePolicy)(nil).UnmarshalJSONFrom(nil); !errors.Is(err, ErrNilReceiver) {
		t.Fatalf("nil EffectivePolicy.UnmarshalJSONFrom 应返回 ErrNilReceiver，实际 %v", err)
	}
}

type textValCodec interface {
	encoding.TextAppender
	encoding.TextMarshaler
}

type textRoundTripTarget interface {
	encoding.TextMarshaler
	encoding.TextUnmarshaler
}

func assertTextRoundTrip(t *testing.T, val textValCodec, dst textRoundTripTarget) {
	t.Helper()
	raw, err := val.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText(%T) 失败: %v", val, err)
	}
	appended, err := val.AppendText([]byte("prefix:"))
	if err != nil || string(appended) != "prefix:"+string(raw) {
		t.Fatalf("AppendText(%T) 不一致: got=%q want=%q err=%v", val, appended, "prefix:"+string(raw), err)
	}
	if err := dst.UnmarshalText(raw); err != nil {
		t.Fatalf("UnmarshalText(%T, %q) 失败: %v", val, raw, err)
	}
	reEncoded, err := dst.MarshalText()
	if err != nil || !bytes.Equal(raw, reEncoded) {
		t.Fatalf("文本往返(%T) 不一致: %q != %q", val, raw, reEncoded)
	}
}
