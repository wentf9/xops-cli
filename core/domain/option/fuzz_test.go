package option

import (
	"bytes"
	jsonv2 "encoding/json/v2"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/netaddr"
)

func FuzzParseOption(f *testing.F) {
	for _, s := range []string{
		"Port=2222", "HostName %h.corp.example.com", "HostName fe80::1%%eth0", "User \"alice\"",
		"ProxyJump alice@jump1:2222,[2001:db8::1]", "ProxyCommand ssh -W \"%h:%p\" bastion",
		`ProxyCommand "C:\Program Files\OpenSSH\ssh.exe" -W %h:%p gw`,
		"ControlMaster auto", "ControlPath ~/.ssh/cm-%C", "ControlPersist 1h30m",
		"ConnectTimeout none", "ConnectTimeout 1m30s", "ServerAliveInterval 2m",
		"Ciphers +aes128-ctr", "Ciphers -*-cbc,aes???-ctr", "IdentityFile none",
		"IdentityFile /a /b", "UserKnownHostsFile \"~/.ssh/known hosts\" ~/.ssh/kh2",
		"UserKnownHostsFile none ~/.ssh/kh2", "SendEnv LANG LC_* -LC_ALL",
		"LocalCommand echo hi %h", "UnknownKey=val", "", "-oPort=22", "User alice\nPort 22",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, directive string) {
		verifyFuzzParsedOption(t, directive)
	})
}

func verifyFuzzParsedOption(t *testing.T, directive string) {
	t.Helper()
	opt, err := ParseOption(directive)
	if err != nil {
		if opt.IsValid() {
			t.Fatalf("失败返回了有效 ParsedOption: %q", directive)
		}
		return
	}
	if !opt.IsValid() || !opt.Key().IsValid() {
		t.Fatalf("成功解析但键无效: %q", directive)
	}
	layer := opt.Layer()
	if err := layer.Validate(); err != nil {
		t.Fatalf("已解析选项层未通过 Validate: %q -> %v", directive, err)
	}
	b1, err := jsonv2.Marshal(layer, jsonv2.Deterministic(true))
	if err != nil {
		t.Fatalf("OptionLayer 编码失败: %q -> %v", directive, err)
	}
	var roundTrip OptionLayer
	if err := jsonv2.Unmarshal(b1, &roundTrip); err != nil || !layer.Equal(roundTrip) {
		t.Fatalf("OptionLayer JSON/v2 往返不一致: %q err=%v", directive, err)
	}
}

func FuzzAlgoPolicy(f *testing.F) {
	f.Add("aes128-ctr,aes256-ctr", "+chacha20-poly1305@openssh.com", "-aes128-ctr")
	f.Add("^aes256-gcm@openssh.com", "-*-cbc,aes???-ctr", "+aes128-ctr")
	f.Add("-a,b", "+a", "^b")
	f.Add("-*", "a,b", "+c")
	f.Add("", "+", "-")
	f.Fuzz(func(t *testing.T, s1, s2, s3 string) {
		verifyFuzzAlgoTriple(t, s1, s2, s3)
	})
}

func verifyFuzzAlgoTriple(t *testing.T, s1, s2, s3 string) {
	t.Helper()
	p1, p2, p3 := parseFuzzAlgo(s1), parseFuzzAlgo(s2), parseFuzzAlgo(s3)
	if !p1.Compose(p2).Compose(p3).Equal(p1.Compose(p2.Compose(p3))) {
		t.Fatalf("AlgoPolicy 结合律违例: (%q, %q, %q)", s1, s2, s3)
	}
	if !UnsetAlgoPolicy().Compose(p1).Equal(p1) || !p1.Compose(UnsetAlgoPolicy()).Equal(p1) || !p1.Compose(p1).Equal(p1) {
		t.Fatalf("AlgoPolicy 单位元或幂等律违例: %q", s1)
	}
	want := p1
	if p1.IsUnset() {
		want = p2
	}
	if !p1.Compose(p2).Equal(want) {
		t.Fatalf("AlgoPolicy FirstWins 违例: (%q, %q)", s1, s2)
	}
	raw, err := jsonv2.Marshal(p1, jsonv2.Deterministic(true))
	var rt AlgoPolicy
	if err != nil || jsonv2.Unmarshal(raw, &rt) != nil || !p1.Equal(rt) {
		t.Fatalf("AlgoPolicy JSON/v2 往返违例: %q err=%v", s1, err)
	}
}

func parseFuzzAlgo(s string) AlgoPolicy {
	p, err := ParseAlgoPolicy(s)
	if err != nil {
		return UnsetAlgoPolicy()
	}
	return p
}

func FuzzResolveEffectivePolicy(f *testing.F) {
	f.Add(uint8(OriginManaged), "web.example.com:22", "Port 2222", "User deploy", "StrictHostKeyChecking yes", "ProxyCommand ssh -W %h:%p gw")
	f.Add(uint8(OriginOpenSSHVirtual), "app.internal:22", "Ciphers +aes128-ctr", "SendEnv LANG", "User globalops", "HostName %h.corp.example.com")
	f.Add(uint8(OriginAdHoc), "[2001:db8::1]:2200", "ForwardAgent no", "IdentityFile none", "ControlMaster auto", "BatchMode yes")
	f.Fuzz(func(t *testing.T, originRaw uint8, rawEP, d1, d2, d3, d4 string) {
		verifyFuzzResolve(t, OriginKind(originRaw%5), rawEP, d1, d2, d3, d4)
	})
}

func verifyFuzzResolve(t *testing.T, origin OriginKind, rawEP, d1, d2, d3, d4 string) {
	t.Helper()
	ep, epErr := netaddr.ParseEndpoint(rawEP)
	pol, err := ResolveEffectivePolicy(origin, ep, parseFuzzLayer(d1), parseFuzzLayer(d2), parseFuzzLayer(d3), parseFuzzLayer(d4))
	if err != nil {
		if pol.IsValid() {
			t.Fatalf("失败返回了有效 EffectivePolicy")
		}
		return
	}
	if !origin.IsValid() || epErr != nil || !pol.IsValid() {
		t.Fatalf("非法输入不应求解成功: origin=%v epErr=%v", origin, epErr)
	}
	if !pol.PermitLocalCommand() && pol.LocalCommand().IsSome() {
		t.Fatalf("LocalCommand 门控违例")
	}
	if !pol.Control().IsEnabled() && (pol.Control().EffectiveMaster() != ControlMasterNo || pol.Control().EffectivePersist().IsEnabled()) {
		t.Fatalf("ControlPolicy 运行期投影归零违例")
	}
	if len(pol.Ciphers()) == 0 || len(pol.MACs()) == 0 || len(pol.KexAlgorithms()) == 0 || len(pol.HostKeyAlgorithms()) == 0 {
		t.Fatalf("求解结果含空算法列表")
	}
	verifyFuzzPolicyRoundTrip(t, pol)
}

func verifyFuzzPolicyRoundTrip(t *testing.T, pol EffectivePolicy) {
	t.Helper()
	b1, err1 := jsonv2.Marshal(pol, jsonv2.Deterministic(true))
	b2, err2 := jsonv2.Marshal(pol, jsonv2.Deterministic(true))
	if err1 != nil || err2 != nil || !bytes.Equal(b1, b2) {
		t.Fatalf("EffectivePolicy 确定性编码失败: %v / %v", err1, err2)
	}
	var roundTrip EffectivePolicy
	if err := jsonv2.Unmarshal(b1, &roundTrip); err != nil || !pol.Equal(roundTrip) {
		t.Fatalf("EffectivePolicy JSON/v2 往返不一致: %v", err)
	}
}

func parseFuzzLayer(directive string) OptionLayer {
	opt, err := ParseOption(directive)
	if err != nil {
		return UnsetOptionLayer()
	}
	return opt.Layer()
}
