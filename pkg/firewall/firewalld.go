package firewall

import (
	"context"
	"fmt"
	"strings"

	"github.com/wentf9/xops-cli/pkg/executor"
)

type FirewalldBackend struct {
	exec executor.Executor
	zone string
}

func NewFirewalldBackend(exec executor.Executor, zone string) *FirewalldBackend {
	if zone == "" {
		zone = "public"
	}
	return &FirewalldBackend{exec: exec, zone: zone}
}

func (b *FirewalldBackend) Name() string {
	return "firewalld"
}

func (b *FirewalldBackend) Status(ctx context.Context) (string, error) {
	return b.exec.RunWithSudo(ctx, "firewall-cmd --state")
}

func (b *FirewalldBackend) IsOpen(ctx context.Context) (bool, error) {
	out, err := b.Status(ctx)
	if err != nil {
		if strings.Contains(out, "not running") || strings.Contains(err.Error(), "not running") {
			return false, nil
		}
		return false, err
	}
	return strings.TrimSpace(out) == "running", nil
}

func (b *FirewalldBackend) Enable(ctx context.Context) (string, error) {
	return b.exec.RunWithSudo(ctx, "systemctl enable --now firewalld")
}

func (b *FirewalldBackend) Disable(ctx context.Context) (string, error) {
	return b.exec.RunWithSudo(ctx, "systemctl disable --now firewalld")
}

func (b *FirewalldBackend) ListRules(ctx context.Context) (string, error) {
	cmd := fmt.Sprintf("firewall-cmd --zone=%s --list-all", b.zone)
	return b.exec.RunWithSudo(ctx, cmd)
}

func (b *FirewalldBackend) AddRule(ctx context.Context, rule Rule) (string, error) {
	args := b.buildRuleArgs(rule, false)
	cmd := fmt.Sprintf("firewall-cmd --permanent --zone=%s %s", b.zone, args)
	return b.exec.RunWithSudo(ctx, cmd)
}

func (b *FirewalldBackend) RemoveRule(ctx context.Context, rule Rule) (string, error) {
	args := b.buildRuleArgs(rule, true)
	cmd := fmt.Sprintf("firewall-cmd --permanent --zone=%s %s", b.zone, args)
	return b.exec.RunWithSudo(ctx, cmd)
}

func (b *FirewalldBackend) Reload(ctx context.Context) (string, error) {
	return b.exec.RunWithSudo(ctx, "firewall-cmd --reload")
}

func (b *FirewalldBackend) buildRuleArgs(rule Rule, remove bool) string {
	op := "--add"
	if remove {
		op = "--remove"
	}

	if rule.Source != "" {
		// 使用富规则 (Rich Rules) 以支持源 IP 过滤
		family := "ipv4"
		if strings.Contains(rule.Source, ":") {
			family = "ipv6"
		}

		target := "accept"
		switch rule.Action {
		case ActionDeny, ActionDrop:
			target = "drop"
		case ActionReject:
			target = "reject"
		}

		richRule := fmt.Sprintf("rule family='%s' source address='%s' ", family, rule.Source)
		if rule.Port != "" {
			proto := string(rule.Protocol)
			if proto == "any" || proto == "" {
				proto = "tcp"
			}
			richRule += fmt.Sprintf("port port='%s' protocol='%s' ", rule.Port, proto)
		} else if rule.Service != "" {
			richRule += fmt.Sprintf("service name='%s' ", rule.Service)
		}
		richRule += target

		return fmt.Sprintf("%s-rich-rule='%s'", op, richRule)
	}

	if rule.Port != "" {
		proto := string(rule.Protocol)
		if proto == "any" || proto == "" {
			proto = "tcp"
		}
		return fmt.Sprintf("%s-port=%s/%s", op, rule.Port, proto)
	}

	if rule.Service != "" {
		return fmt.Sprintf("%s-service=%s", op, rule.Service)
	}
	return ""
}

func (b *FirewalldBackend) ClearPorts(ctx context.Context) (string, error) {
	cmd := fmt.Sprintf("firewall-cmd --zone=%s --list-ports", b.zone)
	portsStr, err := b.exec.RunWithSudo(ctx, cmd)
	if err != nil {
		return "", err
	}
	ports := strings.Fields(portsStr)
	if len(ports) == 0 {
		return "no ports found to clear\n", nil
	}
	var outBuilder strings.Builder
	for _, p := range ports {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		removeCmd := fmt.Sprintf("firewall-cmd --permanent --zone=%s --remove-port=%s", b.zone, p)
		out, err := b.exec.RunWithSudo(ctx, removeCmd)
		outBuilder.WriteString(out)
		if err != nil {
			return outBuilder.String(), err
		}
	}
	return outBuilder.String(), nil
}

func (b *FirewalldBackend) ClearServices(ctx context.Context) (string, error) {
	cmd := fmt.Sprintf("firewall-cmd --zone=%s --list-services", b.zone)
	servicesStr, err := b.exec.RunWithSudo(ctx, cmd)
	if err != nil {
		return "", err
	}
	services := strings.Fields(servicesStr)
	if len(services) == 0 {
		return "no services found to clear\n", nil
	}

	keepServices := map[string]bool{
		"ssh":           true,
		"dhcpv6-client": true,
	}

	var outBuilder strings.Builder
	for _, s := range services {
		s = strings.TrimSpace(s)
		if s == "" || keepServices[s] {
			continue
		}
		removeCmd := fmt.Sprintf("firewall-cmd --permanent --zone=%s --remove-service=%s", b.zone, s)
		out, err := b.exec.RunWithSudo(ctx, removeCmd)
		outBuilder.WriteString(out)
		if err != nil {
			return outBuilder.String(), err
		}
	}
	return outBuilder.String(), nil
}

func (b *FirewalldBackend) ClearRules(ctx context.Context) (string, error) {
	cmd := fmt.Sprintf("firewall-cmd --zone=%s --list-rich-rules", b.zone)
	rulesStr, err := b.exec.RunWithSudo(ctx, cmd)
	if err != nil {
		return "", err
	}
	lines := strings.Split(rulesStr, "\n")
	var outBuilder strings.Builder
	hasRules := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		hasRules = true
		removeCmd := fmt.Sprintf("firewall-cmd --permanent --zone=%s --remove-rich-rule='%s'", b.zone, line)
		out, err := b.exec.RunWithSudo(ctx, removeCmd)
		outBuilder.WriteString(out)
		if err != nil {
			return outBuilder.String(), err
		}
	}
	if !hasRules {
		return "no rich rules found to clear\n", nil
	}
	return outBuilder.String(), nil
}
