package firewall

import (
	"context"
	"fmt"
	"strings"

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

func (b *IptablesBackend) ClearPorts(ctx context.Context) (string, error) {
	return b.clearIptablesRulesByType(ctx, "port")
}

func (b *IptablesBackend) ClearServices(ctx context.Context) (string, error) {
	return b.clearIptablesRulesByType(ctx, "service")
}

func (b *IptablesBackend) ClearRules(ctx context.Context) (string, error) {
	return b.clearIptablesRulesByType(ctx, "rule")
}

func parseIptablesPort(fields []string) (bool, bool) {
	hasDpt := false
	isPort := false
	for _, f := range fields {
		if strings.Contains(f, "dpt:") {
			hasDpt = true
			portStr := f[strings.Index(f, "dpt:")+len("dpt:"):]
			isPort = true
			for _, char := range portStr {
				if (char < '0' || char > '9') && char != ':' {
					isPort = false
					break
				}
			}
		}
	}
	return hasDpt, isPort
}

func (b *IptablesBackend) matchIptablesRule(fields []string, ruleType string) (string, bool) {
	if len(fields) < 6 {
		return "", false
	}
	numStr := fields[0]
	var numVal int
	if _, scanErr := fmt.Sscanf(numStr, "%d", &numVal); scanErr != nil {
		return "", false
	}

	source := fields[4]
	isAnywhere := source == "0.0.0.0/0" || source == "::/0"

	hasDpt, isPort := parseIptablesPort(fields[5:])

	match := false
	if ruleType == "port" && hasDpt && isPort && isAnywhere {
		match = true
	} else if ruleType == "service" && hasDpt && !isPort && isAnywhere {
		match = true
	} else if ruleType == "rule" && !isAnywhere {
		match = true
	}
	return numStr, match
}

func (b *IptablesBackend) clearIptablesRulesByType(ctx context.Context, ruleType string) (string, error) {
	rulesStr, err := b.exec.RunWithSudo(ctx, "iptables -L INPUT --line-numbers -n")
	if err != nil {
		return "", err
	}

	lines := strings.Split(rulesStr, "\n")
	var nums []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		fields := strings.Fields(line)
		if numStr, match := b.matchIptablesRule(fields, ruleType); match {
			nums = append(nums, numStr)
		}
	}

	if len(nums) == 0 {
		return "no rules found to clear\n", nil
	}

	var outBuilder strings.Builder
	for i := len(nums) - 1; i >= 0; i-- {
		cmd := fmt.Sprintf("iptables -D INPUT %s", nums[i])
		out, err := b.exec.RunWithSudo(ctx, cmd)
		outBuilder.WriteString(out)
		if err != nil {
			return outBuilder.String(), err
		}
	}
	return outBuilder.String(), nil
}
