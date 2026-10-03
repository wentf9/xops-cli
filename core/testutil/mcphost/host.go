// Package mcphost supplies immutable synthetic hosts for core protocol tests.
package mcphost

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/core/concurrent"
	"github.com/wentf9/xops-cli/core/mcp/guardrail"
	"github.com/wentf9/xops-cli/core/mcp/policy"
	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/mcphost/models"
)

type GuardrailConfig = policy.Config
type NodeGuardrailCfg = policy.NodeConfig
type Configuration struct {
	Nodes                 *concurrent.Map[string, models.Node]
	Hosts                 *concurrent.Map[string, models.Host]
	Identities            *concurrent.Map[string, models.Identity]
	Guardrail             *policy.Config
	PasswordPromptPattern string
}
type Provider struct {
	configuration *Configuration
	domain        string
}

func clone(cfg *Configuration) *Configuration {
	copy := &Configuration{Nodes: concurrent.NewMap[string, models.Node](concurrent.HashString), Hosts: concurrent.NewMap[string, models.Host](concurrent.HashString), Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString)}
	if cfg == nil {
		return copy
	}
	copy.PasswordPromptPattern = cfg.PasswordPromptPattern
	if cfg.Guardrail != nil {
		pol := policy.Clone(*cfg.Guardrail)
		copy.Guardrail = &pol
	}
	if cfg.Nodes != nil {
		cfg.Nodes.IterCb(func(id string, node models.Node) bool {
			node.Alias = slices.Clone(node.Alias)
			node.Tags = slices.Clone(node.Tags)
			copy.Nodes.Set(id, node)
			return true
		})
	}
	if cfg.Hosts != nil {
		cfg.Hosts.IterCb(func(id string, host models.Host) bool {
			host.Alias = slices.Clone(host.Alias)
			copy.Hosts.Set(id, host)
			return true
		})
	}
	if cfg.Identities != nil {
		cfg.Identities.IterCb(func(id string, identity models.Identity) bool { copy.Identities.Set(id, identity); return true })
	}
	return copy
}
func NewProviderWithoutOpenSSH(cfg *Configuration) *Provider {
	p := &Provider{configuration: clone(cfg)}
	p.domain = fmt.Sprintf("fixture-%p", p)
	return p
}
func (p *Provider) Snapshot() *Configuration { return clone(p.configuration) }
func (p *Provider) DomainID() string         { return p.domain }
func (p *Provider) Policy() policy.Config {
	if p.configuration.Guardrail != nil {
		return policy.Clone(*p.configuration.Guardrail)
	}
	return *guardrail.DefaultGuardrailConfig()
}
func (p *Provider) ResolveSelector(selector string) (string, error) {
	if _, ok := p.configuration.Nodes.Get(selector); ok {
		return selector, nil
	}
	var matches []string
	p.configuration.Nodes.IterCb(func(id string, node models.Node) bool {
		if slices.Contains(node.Alias, selector) {
			matches = append(matches, id)
			return true
		}
		host, ok := p.configuration.Hosts.Get(node.HostRef)
		if ok && slices.Contains(host.Alias, selector) {
			matches = append(matches, id)
		}
		return true
	})
	if len(matches) != 1 {
		return "", fmt.Errorf("fixture selector %q did not identify one node", selector)
	}
	return matches[0], nil
}
func (p *Provider) GetConfig(id string) (*ssh.ClientConfig, error) {
	node, ok := p.configuration.Nodes.Get(id)
	if !ok {
		return nil, ports.ErrNotFound
	}
	host, ok := p.configuration.Hosts.Get(node.HostRef)
	if !ok {
		return nil, errors.New("fixture host is missing")
	}
	identity, ok := p.configuration.Identities.Get(node.IdentityRef)
	if !ok {
		return nil, errors.New("fixture identity is missing")
	}
	return &ssh.ClientConfig{NodeID: id, Address: host.Address, Port: int(host.Port), User: identity.User, AuthType: identity.AuthType, KeyPath: identity.KeyPath, AuthUpdateToken: "fixture", SudoUpdateToken: "fixture", ProxyJump: node.ProxyJump, SudoMode: node.SudoMode, PasswordPromptPattern: node.PasswordPromptPattern}, nil
}
func (p *Provider) nodeInfo(id string) (ports.NodeInfo, error) {
	config, err := p.GetConfig(id)
	if err != nil {
		return ports.NodeInfo{}, err
	}
	node, _ := p.configuration.Nodes.Get(id)
	return ports.NodeInfo{ID: id, Alias: slices.Clone(node.Alias), Tags: slices.Clone(node.Tags), Address: fmt.Sprintf("%s:%d", config.Address, config.Port), User: config.User, AuthType: config.AuthType, ProxyJump: config.ProxyJump}, nil
}
func (p *Provider) List(ctx context.Context, query ports.NodeQuery) (ports.InventorySnapshot, error) {
	if err := ctx.Err(); err != nil {
		return ports.InventorySnapshot{}, err
	}
	view := ports.InventorySnapshot{DomainID: p.domain, Policy: p.Policy()}
	for _, id := range p.configuration.Nodes.Keys() {
		node, _ := p.configuration.Nodes.Get(id)
		if query.Tag != "" && !slices.Contains(node.Tags, query.Tag) {
			continue
		}
		info, err := p.nodeInfo(id)
		if err != nil {
			return ports.InventorySnapshot{}, err
		}
		view.Nodes = append(view.Nodes, info)
	}
	return view, nil
}
func (p *Provider) Resolve(ctx context.Context, request ports.ResolveRequest) (ports.OperationSnapshot, error) {
	view := ports.OperationSnapshot{DomainID: p.domain, Policy: p.Policy(), Targets: make(map[string]ports.Target), Selectors: make(map[string]string)}
	for _, selector := range request.Selectors {
		if selector == "" {
			continue
		}
		id, err := p.ResolveSelector(selector)
		if err != nil {
			return ports.OperationSnapshot{}, err
		}
		plan, err := ssh.CapturePlan(ctx, p, id, p.domain)
		if err != nil {
			return ports.OperationSnapshot{}, err
		}
		info, err := p.nodeInfo(id)
		if err != nil {
			return ports.OperationSnapshot{}, err
		}
		view.Targets[id] = ports.Target{Info: info, Plan: plan}
		view.Selectors[selector] = id
	}
	return view, nil
}
func (p *Provider) Enter(ctx context.Context, admission ports.Admission) (ports.Permit, error) {
	if admission.Snapshot.DomainID != p.domain {
		return nil, ports.ErrStaleBinding
	}
	return ports.NewPermit(ctx, admission, nil)
}
func (p *Provider) ResolveSecret(ctx context.Context, request ssh.SecretRequest) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	node, ok := p.configuration.Nodes.Get(request.NodeID)
	if !ok {
		return nil, ports.ErrNotFound
	}
	identity, ok := p.configuration.Identities.Get(node.IdentityRef)
	if !ok {
		return nil, ports.ErrNotFound
	}
	var value string
	switch request.Kind {
	case ssh.SecretKindPrivateKeyPassphrase:
		value = identity.Passphrase
	case ssh.SecretKindSuPassword:
		value = node.SuPwd
	default:
		value = identity.Password
	}
	if value == "" {
		return nil, ssh.ErrInteractionRequired
	}
	return []byte(value), nil
}

// Tests set HOME/USERPROFILE to fixture-owned directories. Discovery is limited
// to this synthetic host; production core never reads these process defaults.
func (p *Provider) SSHOptions() []ssh.Option {
	home, err := os.UserHomeDir()
	environment := ssh.Environment{InitializationError: err, KnownHostsFile: filepath.Join(home, ".ssh", "known_hosts")}
	environment.ResolveKeyPath = func(path string) string {
		if strings.HasPrefix(path, "~/") {
			return filepath.Join(home, path[2:])
		}
		return path
	}
	return []ssh.Option{ssh.WithEnvironment(environment), ssh.WithSecretResolver(p), ssh.WithPasswordPromptPattern(p.configuration.PasswordPromptPattern)}
}

type fixtureAudit struct{ writer *guardrail.AuditLogger }

func (a fixtureAudit) Append(ctx context.Context, event ports.AuditEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return a.writer.Log(event)
}
func (p *Provider) Dependencies() ports.Dependencies {
	return ports.Dependencies{State: p, Gate: p, NewBackend: p.NewBackend, Audit: fixtureAudit{guardrail.NewAuditLogger(p.Policy().AuditLog)}}
}
