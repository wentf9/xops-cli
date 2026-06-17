package firewall

import (
	"context"
	"fmt"
	"strings"

	"github.com/wentf9/xops-cli/pkg/executor"
)

type NftablesBackend struct {
	exec executor.Executor
}

func NewNftablesBackend(exec executor.Executor) *NftablesBackend {
	return &NftablesBackend{exec: exec}
}

func (b *NftablesBackend) Name() string {
	return "nftables"
}

func (b *NftablesBackend) Status(ctx context.Context) (string, error) {
	return b.exec.RunWithSudo(ctx, "nft list ruleset")
}

func (b *NftablesBackend) IsOpen(ctx context.Context) (bool, error) {
	out, err := b.exec.RunWithSudo(ctx, "systemctl is-active nftables")
	if err != nil {
		if strings.TrimSpace(out) == "inactive" || strings.Contains(err.Error(), "inactive") {
			return false, nil
		}
		if strings.TrimSpace(out) == "unknown" {
			return false, nil
		}
		return false, err
	}
	return strings.TrimSpace(out) == "active", nil
}

func (b *NftablesBackend) Enable(ctx context.Context) (string, error) {
	return b.exec.RunWithSudo(ctx, "systemctl enable --now nftables")
}

func (b *NftablesBackend) Disable(ctx context.Context) (string, error) {
	return b.exec.RunWithSudo(ctx, "systemctl disable --now nftables")
}

func (b *NftablesBackend) ListRules(ctx context.Context) (string, error) {
	return b.exec.RunWithSudo(ctx, "nft list ruleset")
}

func (b *NftablesBackend) AddRule(ctx context.Context, rule Rule) (string, error) {
	cmd := "nft add rule inet filter input "
	if rule.Source != "" {
		cmd += fmt.Sprintf("ip saddr %s ", rule.Source)
	}
	if rule.Protocol != ProtocolAny && rule.Protocol != "" {
		cmd += string(rule.Protocol) + " "
	}
	if rule.Port != "" {
		cmd += fmt.Sprintf("dport %s ", rule.Port)
	}

	target := "accept"
	if rule.Action == ActionDeny || rule.Action == ActionDrop {
		target = "drop"
	}
	cmd += target

	return b.exec.RunWithSudo(ctx, cmd)
}

func (b *NftablesBackend) RemoveRule(ctx context.Context, rule Rule) (string, error) {
	return "", fmt.Errorf("remove rule by object not implemented for nftables, use handle")
}

func (b *NftablesBackend) Reload(ctx context.Context) (string, error) {
	return "", nil
}
