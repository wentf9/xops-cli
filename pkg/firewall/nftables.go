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

func (b *NftablesBackend) ClearPorts(ctx context.Context) (string, error) {
	return b.clearNftRulesByType(ctx, "port")
}

func (b *NftablesBackend) ClearServices(ctx context.Context) (string, error) {
	return b.clearNftRulesByType(ctx, "service")
}

func (b *NftablesBackend) ClearRules(ctx context.Context) (string, error) {
	return b.clearNftRulesByType(ctx, "rule")
}

func (b *NftablesBackend) clearNftRulesByType(ctx context.Context, ruleType string) (string, error) {
	rulesStr, err := b.exec.RunWithSudo(ctx, "nft -a list chain inet filter input")
	if err != nil {
		return "", err
	}

	lines := strings.Split(rulesStr, "\n")
	var handles []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "handle ") {
			continue
		}
		idx := strings.Index(line, "handle ")
		handleNum := strings.TrimSpace(line[idx+len("handle "):])
		fields := strings.Fields(handleNum)
		if len(fields) > 0 {
			handleNum = fields[0]
		}

		ruleContent := line[:idx]
		hasSaddr := strings.Contains(ruleContent, "saddr")
		hasDport := strings.Contains(ruleContent, "dport")

		match := false
		switch ruleType {
		case "port":
			if hasDport && !hasSaddr {
				match = true
			}
		case "service":
			match = false
		case "rule":
			if hasSaddr {
				match = true
			}
		}

		if match {
			handles = append(handles, handleNum)
		}
	}

	if len(handles) == 0 {
		return "no rules found to clear\n", nil
	}

	var outBuilder strings.Builder
	for i := len(handles) - 1; i >= 0; i-- {
		cmd := fmt.Sprintf("nft delete rule inet filter input handle %s", handles[i])
		out, err := b.exec.RunWithSudo(ctx, cmd)
		outBuilder.WriteString(out)
		if err != nil {
			return outBuilder.String(), err
		}
	}
	return outBuilder.String(), nil
}
