package playbook

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/ssh"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
)

func TestEngine_OnErrorContinue_RunsFollowingStepAndMarksHostFailed(t *testing.T) {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	cfg.Hosts.Set("host-1", models.Host{Address: "127.0.0.1", Port: 22})
	cfg.Identities.Set("identity-1", models.Identity{User: "test"})
	cfg.Nodes.Set("web-1", models.Node{HostRef: "host-1", IdentityRef: "identity-1"})

	pb := &Playbook{
		Settings: Settings{OnError: OnErrorContinue},
		Steps: []Step{
			{Name: "step-fail", Shell: "exit 1"},
			{Name: "step-next", Shell: "echo next"},
		},
	}
	e := &Engine{
		pb:       pb,
		provider: config.NewProviderWithoutOpenSSH(cfg),
		listener: NopEventListener,
		connect: func(context.Context, string) (*ssh.Client, error) {
			return nil, nil
		},
	}

	var executed []string
	e.runStepFn = func(_ context.Context, _ *ssh.Client, step Step, _ bool) StepResult {
		executed = append(executed, step.Name)
		if step.Name == "step-fail" {
			return StepResult{StepName: step.Name, Status: StatusFailed, Err: errors.New("step failed")}
		}
		return StepResult{StepName: step.Name, Status: StatusOK}
	}

	hr := e.runOnHost(t.Context(), "web-1", func() {}, OnErrorContinue)
	if hr.Status != HostStatusFailed {
		t.Fatalf("host status = %q, want %q", hr.Status, HostStatusFailed)
	}
	if len(executed) != 2 || executed[0] != "step-fail" || executed[1] != "step-next" {
		t.Fatalf("executed steps = %v, want [step-fail step-next]", executed)
	}
	if len(hr.Steps) != 2 {
		t.Fatalf("step result count = %d, want 2", len(hr.Steps))
	}
}

func TestEngine_OnErrorAbortAll_ConnectFailureCancelsOtherConnections(t *testing.T) {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	for _, nodeID := range []string{"web-1", "web-2"} {
		hostID := nodeID + "-host"
		identityID := nodeID + "-identity"
		cfg.Hosts.Set(hostID, models.Host{Address: nodeID, Port: 22})
		cfg.Identities.Set(identityID, models.Identity{User: "test"})
		cfg.Nodes.Set(nodeID, models.Node{HostRef: hostID, IdentityRef: identityID})
	}

	pb := &Playbook{
		Targets: Targets{Nodes: []string{"web-1", "web-2"}},
		Settings: Settings{
			OnError:     OnErrorAbortAll,
			Concurrency: 2,
		},
		Steps: []Step{{Name: "never-runs", Shell: "true"}},
	}
	e := NewEngine(pb, config.NewProviderWithoutOpenSSH(cfg), nil)

	bothStarted := make(chan struct{})
	var started sync.WaitGroup
	started.Add(2)
	e.connect = func(ctx context.Context, nodeID string) (*ssh.Client, error) {
		started.Done()
		started.Wait()
		if nodeID == "web-1" {
			close(bothStarted)
			return nil, errors.New("connect failed")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-bothStarted:
			<-ctx.Done()
			return nil, ctx.Err()
		}
	}

	report, err := e.Run(t.Context())
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(report.Hosts) != 2 {
		t.Fatalf("host report count = %d, want 2", len(report.Hosts))
	}

	var canceled bool
	for _, host := range report.Hosts {
		for _, step := range host.Steps {
			if errors.Is(step.Err, context.Canceled) {
				canceled = true
			}
		}
	}
	if !canceled {
		t.Fatal("expected abort_all connection failure to cancel another in-flight connection")
	}
}
