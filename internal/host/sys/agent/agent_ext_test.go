package agent_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/host/sys/agent"
	"go.uber.org/goleak"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

// 编译期接口契约断言（ADR-002 / P4-T4）。
var _ ports.SSHAgentPort = (*agent.SystemAgent)(nil)

type staticEnv struct {
	vals map[string]string
}

func (e staticEnv) LookupEnv(key string) (string, bool) {
	v, ok := e.vals[key]
	return v, ok
}

func (e staticEnv) Environ() map[string]string {
	out := make(map[string]string, len(e.vals))
	for k, v := range e.vals {
		out[k] = v
	}
	return out
}

func (e staticEnv) LookupLocalIdentity() (ports.LocalIdentityInfo, error) {
	return ports.NewLocalIdentityInfo(ports.LocalIdentityInfoSpec{
		LocalHost: "test-host",
		LocalUser: "test-user",
		HomeDir:   "/tmp",
	})
}

func buildTestKeyring() (sshagent.Agent, error) {
	ring := sshagent.NewKeyring()
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := ring.Add(sshagent.AddedKey{PrivateKey: edPriv, Comment: "tck-ed25519"}); err != nil {
		return nil, err
	}
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	if err := ring.Add(sshagent.AddedKey{PrivateKey: rsaPriv, Comment: "tck-rsa2048"}); err != nil {
		return nil, err
	}
	return ring, nil
}

// TestSystemAgentZeroValueAndKeywordNone 验证零值失败关闭及 AgentSpec("none") 显式禁用语义。
func TestSystemAgentZeroValueAndKeywordNone(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	var zero agent.SystemAgent
	if _, err := zero.DialAgent(ctx, algebraic.None[inventory.AgentSpec]()); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("零值 DialAgent 期望 ErrInvalidArgument，实际得到: %v", err)
	}
	noneSpec, err := inventory.ParseAgentSpec("none")
	if err != nil {
		t.Fatalf("ParseAgentSpec(none) 失败: %v", err)
	}
	ag := agent.NewSystemAgent(agent.Spec{Env: staticEnv{}})
	if _, err := ag.DialAgent(ctx, algebraic.Some(noneSpec)); !errors.Is(err, ports.ErrSignerUnavailable) {
		t.Fatalf("AgentSpec(none) 期望 ErrSignerUnavailable，实际得到: %v", err)
	}
}

func verifyAgentRSASHA256Sign(t *testing.T, ag ports.SSHAgentPort, spec algebraic.Option[inventory.AgentSpec]) {
	t.Helper()
	ctx := context.Background()
	keys, err := ag.ListAgentKeys(ctx, spec)
	if err != nil {
		t.Fatalf("ListAgentKeys 失败: %v", err)
	}
	var rsaKey ports.PublicKeyInfo
	for _, k := range keys {
		if k.Algorithm() == ssh.KeyAlgoRSA {
			rsaKey = k
			break
		}
	}
	if !rsaKey.IsValid() {
		t.Fatalf("测试 Agent 中未找到 RSA 公钥")
	}
	payload := []byte("xops-v2-rsa-sha2-256-challenge")
	sig, err := ag.SignWithAgent(ctx, spec, rsaKey.Fingerprint(), ssh.KeyAlgoRSASHA256, payload)
	if err != nil {
		t.Fatalf("SignWithAgent(rsa-sha2-256) 失败: %v", err)
	}
	if sig.Format() != ssh.KeyAlgoRSASHA256 {
		t.Fatalf("期望签名格式 %q，实际得到 %q", ssh.KeyAlgoRSASHA256, sig.Format())
	}
	pub, err := ssh.ParsePublicKey(rsaKey.WireBlob())
	if err != nil {
		t.Fatalf("ParsePublicKey 失败: %v", err)
	}
	if err := pub.Verify(payload, &ssh.Signature{Format: sig.Format(), Blob: sig.Blob()}); err != nil {
		t.Fatalf("RSA-SHA256 签名验签失败: %v", err)
	}
}
