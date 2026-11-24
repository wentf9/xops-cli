package inventory

import (
	"bytes"
	"crypto/sha256"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/secret"
)

func mustSecretRef(t *testing.T, store, item string) secret.Ref {
	t.Helper()
	r, err := secret.NewRef(store, item)
	if err != nil {
		t.Fatalf("NewRef(%s, %s) 失败: %v", store, item, err)
	}
	return r
}

func mustKeyFP(t *testing.T, seed byte) KeyFingerprint {
	t.Helper()
	var sum [sha256.Size]byte
	for i := range sum {
		sum[i] = seed + byte(i)
	}
	return KeyFingerprintFromSHA256(sum)
}

func TestIDsAndKeyPassphraseBinding(t *testing.T) {
	assertForbiddenIDsAndKeyPaths(t)
	assertPassphraseBindingContract(t)
}

func assertForbiddenIDsAndKeyPaths(t *testing.T) {
	t.Helper()
	for _, bad := range []string{"", "a@b", "host:22", "openssh:prod", "OpenSSH:x", "bad\u202ename", "-flag", "a b", ".."} {
		if _, err := ParseNodeID(bad); err == nil {
			t.Fatalf("ParseNodeID(%q) 期望拒绝", bad)
		}
		if _, err := ParseAlias(bad); err == nil {
			t.Fatalf("ParseAlias(%q) 期望拒绝", bad)
		}
	}
	for _, bad := range []string{"", "none", "NONE", "~/.ssh/%h", "${HOME}/id_ed25519", "~alice/.ssh/id_ed25519", "a\u202eb"} {
		if _, err := ParseKeyPathSpec(bad); err == nil {
			t.Fatalf("ParseKeyPathSpec(%q) 期望拒绝", bad)
		}
	}
	if kp, err := ParseKeyPathSpec("~/.ssh/id_ed25519"); err != nil || kp.String() != "~/.ssh/id_ed25519" {
		t.Fatalf("有效 KeyPathSpec 解析失败: err=%v", err)
	}
}

func assertPassphraseBindingContract(t *testing.T) {
	t.Helper()
	ref := mustSecretRef(t, "local", "pass1")
	fp := mustKeyFP(t, 7)
	if _, err := NewKeyPassphraseBinding(ref, KeyFingerprint{}); err == nil {
		t.Fatal("缺少指纹的 KeyPassphraseBinding 必须拒绝")
	}
	var zeroRef secret.Ref
	if _, err := NewKeyPassphraseBinding(zeroRef, fp); err == nil {
		t.Fatal("缺少凭据引用的 KeyPassphraseBinding 必须拒绝")
	}
	pb, err := NewKeyPassphraseBinding(ref, fp)
	if err != nil || !pb.IsValid() {
		t.Fatalf("NewKeyPassphraseBinding 失败: %v", err)
	}
	raw, err := jsonv2.Marshal(pb, jsonv2.Deterministic(true))
	if err != nil {
		t.Fatalf("Marshal KeyPassphraseBinding 失败: %v", err)
	}
	var dec KeyPassphraseBinding
	if err := jsonv2.Unmarshal(raw, &dec); err != nil || !dec.Equal(pb) {
		t.Fatalf("KeyPassphraseBinding JSON 往返失败: err=%v", err)
	}
	if err := jsonv2.Unmarshal([]byte(`{"passphrase_ref":"local/pass1"}`), &dec); err == nil || dec.IsValid() {
		t.Fatal("缺失 key_fingerprint 的 JSON 必须失败关闭")
	}
}

func TestAuthMethodADTsDepthAndCanonical(t *testing.T) {
	authPW, comp := buildFullCompositeAuth(t)
	assertAuthRoundTripAndCanonical(t, comp)
	assertAuthCompositeDepthLimit(t, authPW)
}

func buildFullCompositeAuth(t *testing.T) (*AuthPassword, *AuthComposite) {
	t.Helper()
	authPW, err := NewAuthPassword(mustSecretRef(t, "vault1", "login_pw"))
	if err != nil {
		t.Fatalf("NewAuthPassword 失败: %v", err)
	}
	kp, _ := ParseKeyPathSpec("~/.ssh/id_ed25519")
	cert, _ := ParseCertPathSpec("~/.ssh/id_ed25519-cert.pub")
	pb, _ := NewKeyPassphraseBinding(mustSecretRef(t, "vault1", "key_pass"), mustKeyFP(t, 1))
	authKey, err := NewAuthPrivateKey(algebraic.NewNonEmpty(kp), algebraic.Some(pb), []CertPathSpec{cert})
	if err != nil {
		t.Fatalf("NewAuthPrivateKey 失败: %v", err)
	}
	agSpec, _ := ParseAgentSpec("default")
	authAgent, _ := NewAuthAgent(algebraic.Some(agSpec))
	authKBI := buildTestKBIAuth(t)
	comp, err := NewAuthComposite(algebraic.NewNonEmpty[AuthMethod](authKey, authKBI, authAgent, authPW))
	if err != nil {
		t.Fatalf("NewAuthComposite 失败: %v", err)
	}
	return authPW, comp
}

func buildTestKBIAuth(t *testing.T) *AuthKeyboardInteractive {
	t.Helper()
	rTOTP, err := NewRuleTOTP(ChallengeRuleMeta{Name: "otp", PromptPattern: `(?i)verification code`}, mustSecretRef(t, "vault1", "totp_seed"))
	if err != nil || !rTOTP.Matches("", "Verification Code:") {
		t.Fatalf("RuleTOTP 失败: err=%v", err)
	}
	rSec, _ := NewRuleSecretRef(ChallengeRuleMeta{Name: "pin", PromptPattern: `^PIN:`}, mustSecretRef(t, "vault1", "pin_ans"))
	rCmd, _ := NewRuleCommand(ChallengeRuleMeta{Name: "op", PromptPattern: `^Token:`}, "/usr/local/bin/op", []string{"item", "get"}, algebraic.Some(algebraic.FromStdDuration(5*time.Second)))
	rLP, _ := NewRuleLoginPassword(ChallengeRuleMeta{Name: "pwd", PromptPattern: `^Password:`})
	if _, err := NewAuthKeyboardInteractive(algebraic.NewNonEmpty[ChallengeRule](rTOTP, rTOTP)); err == nil {
		t.Fatal("重复规则名必须拒绝")
	}
	if _, err := NewRuleCommand(ChallengeRuleMeta{PromptPattern: `.*`}, "sh -c; rm -rf /", nil, algebraic.None[algebraic.Duration]()); err == nil {
		t.Fatal("含 Shell 元字符的 RuleCommand 必须拒绝")
	}
	if EqualChallengeRule(rCmd, rTOTP) || EqualChallengeRule(rTOTP, rCmd) {
		t.Fatal("跨变体 EqualChallengeRule 必须安全返回 false")
	}
	assertNilVariantAccessorsSafe(t)
	authKBI, err := NewAuthKeyboardInteractive(algebraic.NewNonEmpty[ChallengeRule](rTOTP, rSec, rCmd, rLP))
	if err != nil {
		t.Fatalf("NewAuthKeyboardInteractive 失败: %v", err)
	}
	return authKBI
}

func assertNilVariantAccessorsSafe(t *testing.T) {
	t.Helper()
	var (
		nTOTP *RuleTOTP
		nCmd  *RuleCommand
		nPW   *AuthPassword
		nKey  *AuthPrivateKey
		nComp *AuthComposite
		nVirt *OriginOpenSSHVirtual
		nDer  *OriginOpenSSHDerived
		nAdH  *OriginAdHoc
	)
	if nTOTP.Name() != "" || nTOTP.TOTPSecretRef().IsValid() || nCmd.Command() != "" || len(nCmd.Args()) != 0 ||
		nPW.PasswordRef().IsValid() || nKey.KeyPaths().IsValid() || nKey.Passphrase().IsSome() || len(nKey.CertPaths()) != 0 ||
		len(nComp.Methods()) != 0 || nVirt.HostPattern() != "" || nDer.BaseAlias() != "" || nAdH.ParentNode().IsSome() {
		t.Fatal("nil 具体变体指针访问器必须零 panic 且返回失败关闭零值")
	}
}

func assertAuthRoundTripAndCanonical(t *testing.T, comp AuthMethod) {
	t.Helper()
	var buf bytes.Buffer
	if err := MarshalAuthMethodTo(jsontext.NewEncoder(&buf), comp); err != nil {
		t.Fatalf("MarshalAuthMethodTo 失败: %v", err)
	}
	dec, err := UnmarshalAuthMethodFrom(jsontext.NewDecoder(&buf))
	if err != nil || !EqualAuthMethod(dec, comp) {
		t.Fatalf("UnmarshalAuthMethodFrom 往返失败: err=%v raw=%s", err, buf.String())
	}
	var c1, c2 bytes.Buffer
	if err := WriteAuthMethodCanonical(&c1, comp); err != nil {
		t.Fatalf("WriteAuthMethodCanonical(comp) 失败: %v", err)
	}
	if err := WriteAuthMethodCanonical(&c2, dec); err != nil || !bytes.Equal(c1.Bytes(), c2.Bytes()) {
		t.Fatalf("规范编码不一致: err=%v", err)
	}
}

func assertAuthCompositeDepthLimit(t *testing.T, leaf AuthMethod) {
	t.Helper()
	deep := leaf
	for range maxAuthCompositeDepth {
		var err error
		if deep, err = NewAuthComposite(algebraic.NewNonEmpty(deep)); err != nil {
			t.Fatalf("合法深度嵌套失败: %v", err)
		}
	}
	if _, err := NewAuthComposite(algebraic.NewNonEmpty(deep)); !errors.Is(err, ErrAuthCompositeTooDeep) {
		t.Fatalf("超深嵌套期望 ErrAuthCompositeTooDeep，实际=%v", err)
	}
}

func TestNodeOriginAndEntitiesJSONRoundTrip(t *testing.T) {
	assertAllNodeOriginsRoundTrip(t)
	assertEntityRoundTripsAndRejects(t)
}

func assertAllNodeOriginsRoundTrip(t *testing.T) {
	t.Helper()
	pid, _ := ParseNodeID("web-01")
	origins := []NodeOrigin{
		NewOriginManaged(),
		mustOrigin(t, func() (NodeOrigin, error) { return NewOriginOpenSSHVirtual("bastion-*", "~/.ssh/config") }),
		mustOrigin(t, func() (NodeOrigin, error) { return NewOriginOpenSSHDerived("bastion", "~/.ssh/config") }),
		mustOrigin(t, func() (NodeOrigin, error) { return NewOriginAdHoc(algebraic.Some(pid)) }),
	}
	wantKinds := []option.OriginKind{
		option.OriginManaged, option.OriginOpenSSHVirtual, option.OriginOpenSSHDerived, option.OriginAdHoc,
	}
	for i, o := range origins {
		if ToOptionOriginKind(o) != wantKinds[i] {
			t.Fatalf("origins[%d]: kind=%v want=%v", i, ToOptionOriginKind(o), wantKinds[i])
		}
		var buf bytes.Buffer
		if err := MarshalNodeOriginTo(jsontext.NewEncoder(&buf), o); err != nil {
			t.Fatalf("MarshalNodeOriginTo[%d] 失败: %v", i, err)
		}
		dec, err := UnmarshalNodeOriginFrom(jsontext.NewDecoder(&buf))
		if err != nil || !EqualNodeOrigin(dec, o) {
			t.Fatalf("NodeOrigin[%d] JSON 往返失败: err=%v", i, err)
		}
	}
}

func assertEntityRoundTripsAndRejects(t *testing.T) {
	t.Helper()
	hid, _ := ParseHostID("web-01-host")
	ep, _ := netaddr.ParseEndpoint("192.0.2.10:22")
	tagProd, _ := ParseTag("prod")
	if _, err := NewHost(HostSpec{ID: hid, Endpoint: ep, Description: "prod web", Tags: []Tag{tagProd}}); err != nil {
		t.Fatalf("NewHost 失败: %v", err)
	}
	iid, _ := ParseIdentityID("deploy-id")
	user, _ := option.ParseUsername("deploy")
	auth, _ := NewAuthAgent(algebraic.None[AgentSpec]())
	if _, err := NewIdentity(IdentitySpec{ID: iid, User: user, Auth: auth, Tags: []Tag{tagProd}}); err != nil {
		t.Fatalf("NewIdentity 失败: %v", err)
	}
	nid, _ := ParseNodeID("web-01")
	al, _ := ParseAlias("w1")
	jump, _ := option.ParseProxyJump("bastion-01")
	prof, _ := execution.POSIXLaunchProfile(execution.InterpreterSH, execution.LoginModeDisabled)
	node, err := NewNode(NodeSpec{
		ID: nid, HostRef: hid, IdentityRef: iid, Aliases: []Alias{al}, Tags: []Tag{tagProd},
		Proxy: jump, Execution: algebraic.Some(prof), Options: option.UnsetOptionLayer().WithForwardAgent(false),
		PrivilegePasswordRef: algebraic.Some(mustSecretRef(t, "local", "sudo_pw")), Origin: NewOriginManaged(), Description: "web node",
	})
	if err != nil {
		t.Fatalf("NewNode 失败: %v", err)
	}
	raw, err := jsonv2.Marshal(node, jsonv2.Deterministic(true))
	if err != nil {
		t.Fatalf("Marshal Node 失败: %v", err)
	}
	var decNode Node
	if err := jsonv2.Unmarshal(raw, &decNode); err != nil || !decNode.Equal(node) {
		t.Fatalf("Node JSON 往返失败: err=%v raw=%s", err, raw)
	}
	for _, bad := range []string{`null`, `{}`, `{"id":"web-01","host":"h1"}`} {
		if err := jsonv2.Unmarshal([]byte(bad), &decNode); err == nil || decNode.IsValid() {
			t.Fatalf("非法 Node JSON %s 期望拒绝", bad)
		}
	}
	if _, err := UnmarshalAuthMethodFrom(jsontext.NewDecoder(strings.NewReader(`{"kind":"password"}`))); err == nil {
		t.Fatal("缺失 password_ref 的 AuthPassword 必须拒绝")
	}
}

func mustOrigin(t *testing.T, fn func() (NodeOrigin, error)) NodeOrigin {
	t.Helper()
	o, err := fn()
	if err != nil {
		t.Fatalf("构造 NodeOrigin 失败: %v", err)
	}
	return o
}
