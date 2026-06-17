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
