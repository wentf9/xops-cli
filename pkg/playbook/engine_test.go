package playbook_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/playbook"
	"github.com/wentf9/xops-cli/pkg/ssh"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
)

// createTestProvider 创建一个包含测试节点和标签的 ConfigProvider
func createTestProvider() config.ConfigProvider {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}

	// 节点 1：带有 web 标签
	cfg.Hosts.Set("host-1", models.Host{Address: "10.0.0.1", Port: 22})
	cfg.Identities.Set("id-1", models.Identity{User: "root", AuthType: "password"})
	cfg.Nodes.Set("web-1", models.Node{
		HostRef:     "host-1",
		IdentityRef: "id-1",
		Tags:        []string{"web", "prod"},
	})

	// 节点 2：带有 web 标签
	cfg.Hosts.Set("host-2", models.Host{Address: "10.0.0.2", Port: 22})
	cfg.Nodes.Set("web-2", models.Node{
		HostRef:     "host-2",
		IdentityRef: "id-1",
		Tags:        []string{"web"},
	})

	// 节点 3：带有 db 标签
	cfg.Hosts.Set("host-3", models.Host{Address: "10.0.0.3", Port: 22})
	cfg.Nodes.Set("db-1", models.Node{
		HostRef:     "host-3",
		IdentityRef: "id-1",
		Tags:        []string{"db", "prod"},
	})

	return config.NewProvider(cfg)
}

func TestEngine_ResolveTargets(t *testing.T) {
	provider := createTestProvider()

	tests := []struct {
		name    string
		targets playbook.Targets
		want    []string
		wantErr bool
	}{
		{
			name: "Resolve by tag",
			targets: playbook.Targets{
				Tags: []string{"web"},
			},
			want: []string{"web-1", "web-2"},
		},
		{
			name: "Resolve by node",
			targets: playbook.Targets{
				Nodes: []string{"db-1"},
			},
			want: []string{"db-1"},
		},
		{
			name: "Resolve by hosts (ad-hoc matching in config)",
			targets: playbook.Targets{
				Hosts: []string{"db-1"}, // 匹配 nodeName 或者是 alias/address 的查找
			},
			want: []string{"db-1"},
		},
		{
			name: "Resolve multiple with deduplication",
			targets: playbook.Targets{
				Tags:  []string{"web", "prod"},
				Nodes: []string{"web-1"},
			},
			want: []string{"web-1", "web-2", "db-1"},
		},
		{
			name: "Node not found error",
			targets: playbook.Targets{
				Nodes: []string{"nonexistent"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pb := &playbook.Playbook{
				Name:    "test",
				Targets: tt.targets,
				Steps: []playbook.Step{
					{Name: "test-step", Shell: "echo"},
				},
			}
			connector := ssh.NewConnector(provider)
			engine := playbook.NewEngine(pb, provider, connector)

			// 我们通过调用 Run 来间接触发 resolveTargets
			// 因为 Connect 会失败（没启动真实的 SSH 且没缓存），所以如果解析没问题，最终会返回连接失败的 report，或者提前报错。
			report, err := engine.Run(context.Background())
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error but got nil")
				}
				return
			}

			if err != nil {
				// 如果 err 不是 nil，但我们预期没有解析错误，
				// 我们需要确保 err 不是解析错误，而是连接错误。
				// 在 resolveTargets 成功后，如果 len(nodeIDs) > 0 且 connector 连不上，会返回包含 Hosts 报告的 report，err 为 nil。
				// 如果 len(nodeIDs) == 0，Run 会返回 play_err_no_targets 错误。
				if strings.Contains(err.Error(), "no targets") {
					t.Fatalf("resolveTargets resolved 0 nodes: %v", err)
				}
			}

			if report == nil {
				t.Fatal("expected non-nil report")
			}

			// 检查解析出来的节点是否一致
			if len(report.Hosts) != len(tt.want) {
				t.Fatalf("resolved %d hosts, want %d", len(report.Hosts), len(tt.want))
			}

			resolvedMap := make(map[string]bool)
			for _, h := range report.Hosts {
				resolvedMap[h.NodeID] = true
			}

			for _, w := range tt.want {
				if !resolvedMap[w] {
					t.Errorf("missing expected node %q in report", w)
				}
			}
		})
	}
}

func TestEngine_NoTargets(t *testing.T) {
	provider := createTestProvider()
	pb := &playbook.Playbook{
		Name: "test",
		Targets: playbook.Targets{
			Tags: []string{"nonexistent-tag"},
		},
		Steps: []playbook.Step{
			{Name: "test-step", Shell: "echo"},
		},
	}
	connector := ssh.NewConnector(provider)
	engine := playbook.NewEngine(pb, provider, connector)

	_, err := engine.Run(context.Background())
	if err == nil {
		t.Fatal("expected error due to no targets resolved, got nil")
	}
}

func TestEngine_Timeout(t *testing.T) {
	provider := createTestProvider()
	pb := &playbook.Playbook{
		Name: "test",
		Targets: playbook.Targets{
			Nodes: []string{"web-1"},
		},
		Settings: playbook.Settings{
			// 设置一个极短的超时，让它很快超时
			Timeout: playbook.Duration{Duration: 1 * time.Microsecond},
		},
		Steps: []playbook.Step{
			{Name: "test-step", Shell: "sleep 1"},
		},
	}
	connector := ssh.NewConnector(provider)
	engine := playbook.NewEngine(pb, provider, connector)

	// 运行，由于超时极短，context 应该在执行中被超时取消
	report, err := engine.Run(context.Background())
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if len(report.Hosts) != 1 {
		t.Fatalf("expected 1 host report, got %d", len(report.Hosts))
	}

	// 应该因为 context 取消而连接失败或中断
	hr := report.Hosts[0]
	if hr.Status != playbook.HostStatusFailed && hr.Status != playbook.HostStatusAborted {
		t.Errorf("host status should be failed or aborted due to timeout, got %s", hr.Status)
	}
}

func TestEngine_OnErrorAbortAll(t *testing.T) {
	provider := createTestProvider()
	pb := &playbook.Playbook{
		Name: "test",
		Targets: playbook.Targets{
			// 确保有多个节点，因为 Connect 失败会耗费一些时间（或者我们直接利用它来触发 abort_all）
			Nodes: []string{"web-1", "web-2", "db-1"},
		},
		Settings: playbook.Settings{
			OnError:     playbook.OnErrorAbortAll,
			Concurrency: 3, // 三个并发
		},
		Steps: []playbook.Step{
			{Name: "test-step", Shell: "echo"},
		},
	}
	connector := ssh.NewConnector(provider)
	engine := playbook.NewEngine(pb, provider, connector)

	report, err := engine.Run(context.Background())
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	// 验证在 OnErrorAbortAll 策略下，第一个节点连接失败触发了 cancel，导致其余节点可能被取消/中止
	// 会有一些节点是 failed，有一些节点可能是 aborted (即由于 context 取消提前退出)
	abortedCount := 0
	failedCount := 0
	for _, hr := range report.Hosts {
		switch hr.Status {
		case playbook.HostStatusAborted:
			abortedCount++
		case playbook.HostStatusFailed:
			failedCount++
		}
	}

	// 至少有一个节点是 failed，且应该有至少一个节点被 aborted 或者是 failed。
	if failedCount == 0 {
		t.Error("expected at least one failed host connection")
	}
}
