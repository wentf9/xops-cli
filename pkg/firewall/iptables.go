package firewall

import (
	"context"
	"fmt"

	"github.com/wentf9/xops-cli/pkg/executor"
)

type IptablesBackend struct {
	exec executor.Executor
}

func NewIptablesBackend(exec executor.Executor) *IptablesBackend {
	return &IptablesBackend{exec: exec}
}

func (b *IptablesBackend) Name() string {
	return "iptables"
}

func (b *IptablesBackend) Status(ctx context.Context) (string, error) {
	return b.exec.RunWithSudo(ctx, "iptables -L -n")
}

func (b *IptablesBackend) IsOpen(ctx context.Context) (bool, error) {
	_, err := b.Status(ctx)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (b *IptablesBackend) Enable(ctx context.Context) (string, error) {
	return "iptables is always enabled if installed", nil
}

func (b *IptablesBackend) Disable(ctx context.Context) (string, error) {
	return b.exec.RunWithSudo(ctx, "iptables -F")
}

func (b *IptablesBackend) ListRules(ctx context.Context) (string, error) {
	return b.exec.RunWithSudo(ctx, "iptables -S")
}

func (b *IptablesBackend) AddRule(ctx context.Context, rule Rule) (string, error) {
	cmd := b.buildRuleCmd(rule, "-A")
	return b.exec.RunWithSudo(ctx, cmd)
}

func (b *IptablesBackend) RemoveRule(ctx context.Context, rule Rule) (string, error) {
	cmd := b.buildRuleCmd(rule, "-D")
	return b.exec.RunWithSudo(ctx, cmd)
}

func (b *IptablesBackend) Reload(ctx context.Context) (string, error) {
	return "", nil
}

func (b *IptablesBackend) buildRuleCmd(rule Rule, op string) string {
	chain := "INPUT"
	target := "ACCEPT"
	switch rule.Action {
	case ActionDeny, ActionDrop:
		target = "DROP"
	case ActionReject:
		target = "REJECT"
	}

	cmd := fmt.Sprintf("iptables %s %s", op, chain)
	if rule.Source != "" {
		cmd += fmt.Sprintf(" -s %s", rule.Source)
	}
	if rule.Protocol != ProtocolAny && rule.Protocol != "" {
		cmd += fmt.Sprintf(" -p %s", rule.Protocol)
		if rule.Port != "" {
			cmd += fmt.Sprintf(" --dport %s", rule.Port)
		}
	}
	cmd += fmt.Sprintf(" -j %s", target)
	return cmd
}
