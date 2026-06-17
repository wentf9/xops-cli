package firewall

import (
	"context"
	"fmt"
	"strings"

	"github.com/wentf9/xops-cli/pkg/executor"
)

type UfwBackend struct {
	exec executor.Executor
}

func NewUfwBackend(exec executor.Executor) *UfwBackend {
	return &UfwBackend{exec: exec}
}

func (b *UfwBackend) Name() string {
	return "ufw"
}

func (b *UfwBackend) Status(ctx context.Context) (string, error) {
	return b.exec.RunWithSudo(ctx, "ufw status")
}

func (b *UfwBackend) IsOpen(ctx context.Context) (bool, error) {
	out, err := b.Status(ctx)
	if err != nil {
		return false, err
	}
	return strings.Contains(out, "Status: active"), nil
}

func (b *UfwBackend) Enable(ctx context.Context) (string, error) {
	return b.exec.RunWithSudo(ctx, "ufw --force enable")
}

func (b *UfwBackend) Disable(ctx context.Context) (string, error) {
	return b.exec.RunWithSudo(ctx, "ufw disable")
}

func (b *UfwBackend) ListRules(ctx context.Context) (string, error) {
	return b.exec.RunWithSudo(ctx, "ufw status numbered")
}

func (b *UfwBackend) AddRule(ctx context.Context, rule Rule) (string, error) {
	cmd := b.buildRuleCmd(rule, false)
	return b.exec.RunWithSudo(ctx, cmd)
}

func (b *UfwBackend) RemoveRule(ctx context.Context, rule Rule) (string, error) {
	cmd := b.buildRuleCmd(rule, true)
	return b.exec.RunWithSudo(ctx, cmd)
}

func (b *UfwBackend) Reload(ctx context.Context) (string, error) {
	return b.exec.RunWithSudo(ctx, "ufw reload")
}

func (b *UfwBackend) buildRuleCmd(rule Rule, remove bool) string {
	verb := "allow"
	if rule.Action == ActionDeny || rule.Action == ActionReject || rule.Action == ActionDrop {
		verb = "deny"
	}

	prefix := "ufw "
	if remove {
		prefix += "delete "
	}

	cmd := fmt.Sprintf("%s%s ", prefix, verb)
	if rule.Source != "" {
		cmd += fmt.Sprintf("from %s ", rule.Source)
	}

	if rule.Port != "" {
		cmd += fmt.Sprintf("to any port %s", rule.Port)
		if rule.Protocol != ProtocolAny && rule.Protocol != "" {
			cmd += fmt.Sprintf(" proto %s", rule.Protocol)
		}
	} else if rule.Service != "" {
		cmd += rule.Service
	}

	return cmd
}
