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

func (b *UfwBackend) ClearPorts(ctx context.Context) (string, error) {
	return b.clearUfwRulesByType(ctx, "port")
}

func (b *UfwBackend) ClearServices(ctx context.Context) (string, error) {
	return b.clearUfwRulesByType(ctx, "service")
}

func (b *UfwBackend) ClearRules(ctx context.Context) (string, error) {
	return b.clearUfwRulesByType(ctx, "rule")
}

func parseUfwAnywhere(fields []string, fromField string) bool {
	if fromField == "Anywhere" || fromField == "(v6)" {
		return true
	}
	if len(fields) >= 2 && fields[len(fields)-2] == "Anywhere" {
		return true
	}
	return false
}

func parseUfwPort(toField string) bool {
	if strings.Contains(toField, "/") {
		return true
	}
	var val int
	_, err := fmt.Sscanf(toField, "%d", &val)
	return err == nil
}

func (b *UfwBackend) matchUfwRule(line string, ruleType string) (string, bool) {
	if !strings.HasPrefix(line, "[") {
		return "", false
	}
	endIdx := strings.Index(line, "]")
	if endIdx == -1 {
		return "", false
	}
	numStr := strings.TrimSpace(line[1:endIdx])
	content := strings.TrimSpace(line[endIdx+1:])
	fields := strings.Fields(content)
	if len(fields) < 3 {
		return "", false
	}

	toField := fields[0]
	fromField := fields[len(fields)-1]

	isAnywhere := parseUfwAnywhere(fields, fromField)
	isPort := parseUfwPort(toField)

	match := false
	if ruleType == "port" && isPort && isAnywhere {
		match = true
	} else if ruleType == "service" && !isPort && isAnywhere {
		if toField != "Anywhere" && toField != "Anywhere (v6)" {
			match = true
		}
	} else if ruleType == "rule" && !isAnywhere {
		match = true
	}
	return numStr, match
}

func (b *UfwBackend) clearUfwRulesByType(ctx context.Context, ruleType string) (string, error) {
	rulesStr, err := b.ListRules(ctx)
	if err != nil {
		return "", err
	}

	lines := strings.Split(rulesStr, "\n")
	var nums []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if numStr, match := b.matchUfwRule(line, ruleType); match {
			nums = append(nums, numStr)
		}
	}

	if len(nums) == 0 {
		return "no rules found to clear\n", nil
	}

	var outBuilder strings.Builder
	for i := len(nums) - 1; i >= 0; i-- {
		cmd := fmt.Sprintf("ufw --force delete %s", nums[i])
		out, err := b.exec.RunWithSudo(ctx, cmd)
		outBuilder.WriteString(out)
		if err != nil {
			return outBuilder.String(), err
		}
	}
	return outBuilder.String(), nil
}
