package adapter

import (
	"testing"

	"github.com/wentf9/xops-cli/core/concurrent"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/testleak"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestCharacterization_SSHAdapter_Connector_DoesNotLeakSecretsInLogsOrErrors(t *testing.T) {
	const (
		sensitivePassword   = "adapter-sensitive-pass-9999"
		sensitivePassphrase = "adapter-sensitive-keypass-8888"
	)

	nodes := concurrent.NewMap[string, models.Node](concurrent.HashString)
	nodes.Set("node-secure", models.Node{
		HostRef:     "host-secure",
		IdentityRef: "id-secure",
	})

	hosts := concurrent.NewMap[string, models.Host](concurrent.HashString)
	hosts.Set("host-secure", models.Host{Address: "192.168.10.10", Port: 22})

	identities := concurrent.NewMap[string, models.Identity](concurrent.HashString)
	identities.Set("id-secure", models.Identity{
		User:       "secadmin",
		AuthType:   "password",
		Password:   sensitivePassword,
		Passphrase: sensitivePassphrase,
	})

	cfg := &config.Configuration{
		Nodes:      nodes,
		Hosts:      hosts,
		Identities: identities,
	}

	provider := config.NewProviderWithoutOpenSSH(cfg)
	bufLogger := testleak.NewBufferLogger()
	conn := NewConnector(provider, ssh.WithLogger(bufLogger))
	t.Cleanup(func() {
		_ = conn.CloseAll()
	})

	// 请求连接一个不存在的节点
	ctx := t.Context()
	_, err := conn.Connect(ctx, "non-existent-node")
	if err == nil {
		t.Fatal("expected connect to non-existent node to fail, got nil")
	}

	// 验证错误信息和日志流中不包含配置中的任何敏感凭据
	testleak.AssertNoSecretInError(t, err, sensitivePassword, sensitivePassphrase)
	testleak.AssertNoSecretInLogs(t, bufLogger, sensitivePassword, sensitivePassphrase)
}
