// Package corecontract verifies the legacy-facing compatibility boundary.
// It stays outside core because these tests intentionally import CLI adapters.
package corecontract

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/wentf9/xops-cli/core/auth"
	coremap "github.com/wentf9/xops-cli/core/concurrent"
	corelog "github.com/wentf9/xops-cli/core/log"
	"github.com/wentf9/xops-cli/core/mcp/policy"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/wentf9/xops-cli/pkg/mcpserver/guardrail"
	"github.com/wentf9/xops-cli/pkg/ssh"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
	"gopkg.in/yaml.v3"
)

// Assignments preserve downstream source compatibility, including function
// signatures: a wrapper type with merely similar fields is insufficient.
var (
	_ func(*config.GuardrailConfig) *guardrail.Guardrail = guardrail.New
	_ func(*policy.Config) *guardrail.Guardrail          = guardrail.New
	_ func(corelog.DebugLogger) ssh.Option               = ssh.WithLogger
	_ func(logger.DebugLogger) ssh.Option                = ssh.WithLogger
)

func TestLegacyPolicyRoundTrip(t *testing.T) {
	const source = "enabled: true\naudit_log: /var/lib/xops/audit.jsonl\napproval_threshold: dangerous\nblocked_patterns:\n    - '*forbidden*'\nprotected_paths:\n    - /etc\nnodes:\n    production:\n        approval_threshold: safe\nno_elicit_fallback: deny\n"
	var legacy config.GuardrailConfig
	if err := yaml.Unmarshal([]byte(source), &legacy); err != nil {
		t.Fatal(err)
	}
	shared := &legacy
	encoded, err := yaml.Marshal(shared)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, []byte(source)) {
		t.Fatalf("legacy policy serialization changed:\n%s", encoded)
	}
	if got := guardrail.NewPolicy(shared).Evaluate(guardrail.Safe, guardrail.RiskInput{
		ToolName: "xops_ssh_run", NodeID: "production", Command: "echo ok",
	}); got != guardrail.NeedApproval {
		t.Fatalf("legacy per-node policy = %v, want approval", got)
	}
}

func TestLegacyErrorIdentity(t *testing.T) {
	for _, pair := range []struct{ legacy, shared error }{
		{credential.ErrCredentialNotFound, auth.ErrCredentialNotFound},
		{credential.ErrCredentialStoreLocked, auth.ErrCredentialStoreLocked},
		{credential.ErrCredentialStoreUnavailable, auth.ErrCredentialStoreUnavailable},
		{credential.ErrCredentialAccessDenied, auth.ErrCredentialAccessDenied},
		{credential.ErrConfigConflict, auth.ErrConfigConflict},
		{credential.ErrInvalidRef, auth.ErrInvalidRef},
		{credential.ErrStoreNotFound, auth.ErrStoreNotFound},
		{config.ErrProxyCycle, auth.ErrProxyCycle},
	} {
		if !errors.Is(pair.legacy, pair.shared) || !errors.Is(pair.shared, pair.legacy) ||
			!errors.Is(fmt.Errorf("source: %w", pair.shared), pair.legacy) {
			t.Errorf("legacy error identity lost: %v", pair.legacy)
		}
	}
	cycle := &ssh.ProxyCycleError{NodeID: "node", Path: []string{"node", "jump", "node"}}
	for _, target := range []error{config.ErrProxyCycle, ssh.ErrProxyCycle, auth.ErrProxyCycle} {
		if !errors.Is(cycle, target) {
			t.Errorf("cycle no longer matches %v", target)
		}
	}
}

func TestLegacyConcurrentMapSharesTypeAndState(t *testing.T) {
	legacy := concurrent.NewMap(concurrent.HashString, coremap.WithShardCount[string, int](8))
	shared := legacy
	shared.Set("version", 1)
	legacy.Set("version", 2)
	if concurrent.RemoveIfMatch(shared, "version", 1) {
		t.Fatal("stale consumer removed the updated value")
	}
	if !coremap.RemoveIfMatch(legacy, "version", 2) || shared.Count() != 0 {
		t.Fatal("old and new import paths do not share the same map")
	}
}
