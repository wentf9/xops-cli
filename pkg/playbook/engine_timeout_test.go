package playbook

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/ssh"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
)

func TestEngine_Timeout(t *testing.T) {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	cfg.Hosts.Set("host-1", models.Host{Address: "127.0.0.1", Port: 22})
	cfg.Identities.Set("identity-1", models.Identity{User: "test"})
	cfg.Nodes.Set("web-1", models.Node{HostRef: "host-1", IdentityRef: "identity-1"})

	pb := &Playbook{
		Name:     "test",
		Targets:  Targets{Nodes: []string{"web-1"}},
		Settings: Settings{Timeout: Duration{Duration: 20 * time.Millisecond}},
		Steps:    []Step{{Name: "never-runs", Shell: "true"}},
	}
	e := NewEngine(pb, config.NewProviderWithoutOpenSSH(cfg), nil)
	e.connect = func(ctx context.Context, _ string) (*ssh.Client, error) {
		guard := time.NewTimer(time.Second)
		defer guard.Stop()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-guard.C:
			return nil, errors.New("timeout test guard expired")
		}
	}

	report, err := e.Run(t.Context())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run error = %v, want context.DeadlineExceeded", err)
	}
	if len(report.Hosts) != 1 {
		t.Fatalf("host report count = %d, want 1", len(report.Hosts))
	}
	if report.Hosts[0].Status != HostStatusAborted {
		t.Fatalf("host status = %q, want %q", report.Hosts[0].Status, HostStatusAborted)
	}
	if len(report.Hosts[0].Steps) != 1 || !errors.Is(report.Hosts[0].Steps[0].Err, context.DeadlineExceeded) {
		t.Fatalf("connect step = %+v, want context deadline error", report.Hosts[0].Steps)
	}
}
