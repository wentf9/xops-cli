package adapter

import (
	"errors"
	"reflect"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestProbeConnectionProviderMasksOnlyExecution(t *testing.T) {
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	login := true
	cfg.Execution = &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX, Login: &login}
	cfg.Hosts.Set("host", models.Host{Address: "192.0.2.1", Port: 2222})
	cfg.Identities.Set("identity", models.Identity{User: "fixture", AuthType: "auto"})
	cfg.Nodes.Set("target", models.Node{
		HostRef: "host", IdentityRef: "identity", ProxyJump: "jump", Tags: []string{"fixture"},
		Execution: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterPowerShell},
	})
	cfg.Nodes.Set("jump", models.Node{
		HostRef: "host", IdentityRef: "identity", Execution: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterCmd},
	})
	original := config.NewProviderWithoutOpenSSH(cfg)
	masked := probeConnectionProvider{ConfigProvider: original.Frozen()}
	for _, nodeID := range []string{"target", "jump"} {
		if _, err := NewSSHAdapter(original).GetConfig(nodeID); !errors.Is(err, ssh.ErrExecutionValidation) {
			t.Fatalf("test did not reproduce inherited execution conflict: %v", err)
		}
		connection, err := NewSSHAdapter(masked).GetConfig(nodeID)
		if err != nil {
			t.Fatal(err)
		}
		want := ssh.CommandOptions{Interpreter: ssh.InterpreterServer, LaunchDialect: ssh.LaunchUnknown, Login: ssh.LoginInherit}
		if !reflect.DeepEqual(connection.Execution.CommandOptions(), want) {
			t.Fatalf("probe inherited command settings: %+v", connection.Execution)
		}
		before, err := original.ResolveConnection(nodeID)
		if err != nil {
			t.Fatal(err)
		}
		after, err := masked.ResolveConnection(nodeID)
		if err != nil {
			t.Fatal(err)
		}
		before.Node.Execution, after.Node.Execution = nil, nil
		if !reflect.DeepEqual(before, after) {
			t.Fatal("probe altered connection metadata, identity, host or ProxyJump")
		}
	}
	if !reflect.DeepEqual(original.Snapshot().Execution, cfg.Execution) {
		t.Fatal("probe changed the source global execution")
	}
	node, _ := original.GetNode("target")
	if node.Execution.Interpreter != ssh.InterpreterPowerShell || node.Execution.LaunchDialect != "" {
		t.Fatal("probe changed the source node execution")
	}
	if _, err := masked.ResolveConnection("missing"); !errors.Is(err, config.ErrNodeNotFound) {
		t.Fatalf("probe provider lost the underlying resolution error: %v", err)
	}
}
