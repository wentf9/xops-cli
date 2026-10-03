package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"

	"github.com/wentf9/xops-cli/core/mcp/guardrail"
	"github.com/wentf9/xops-cli/core/mcp/policy"
	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/mcp/remotefile"
	"github.com/wentf9/xops-cli/core/mcp/sshexec"
	"github.com/wentf9/xops-cli/core/mcp/tunnel"
	coressh "github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	legacyguard "github.com/wentf9/xops-cli/pkg/mcpserver/guardrail"
	"github.com/wentf9/xops-cli/pkg/sftp"
	"github.com/wentf9/xops-cli/pkg/ssh"
)

type legacyHost struct {
	config legacyConfig
	domain string
	policy policy.Config
}

type legacyProviderKey struct{}

func newLegacyHost(cfg legacyConfig) *legacyHost {
	pol := cfg.provider.Snapshot().Guardrail
	defaultPolicy := pol == nil
	if pol == nil {
		pol = legacyguard.DefaultGuardrailConfig()
	}
	copy := policy.Clone(*pol)
	if (cfg.http != nil || cfg.recovery) && (defaultPolicy || copy.NoElicitFallback == "") {
		copy.NoElicitFallback = guardrail.FallbackDeny
	}
	return &legacyHost{config: cfg, domain: "xops-cli", policy: copy}
}
func (h *legacyHost) DomainID() string { return h.domain }
func (h *legacyHost) provider() config.ConfigProvider {
	if frozen, ok := h.config.provider.(interface{ Frozen() config.ConfigProvider }); ok {
		return frozen.Frozen()
	}
	return h.config.provider
}
func (h *legacyHost) dependencies() ports.Dependencies {
	return ports.Dependencies{State: h, Gate: h, Audit: legacyAudit{legacyguard.NewAuditLogger(h.policy.AuditLog)}, NewBackend: func(ctx context.Context) (ports.Backend, error) {
		return &legacyBackend{connector: newMCPConnector(ctx, h.config.provider, h.config.logger, h.config.registry), config: h.config}, nil
	}}
}

type legacyAudit struct{ writer guardrail.AuditWriter }

func (a legacyAudit) Append(ctx context.Context, event ports.AuditEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return a.writer.Log(event)
}

func (h *legacyHost) List(ctx context.Context, query ports.NodeQuery) (ports.InventorySnapshot, error) {
	if err := ctx.Err(); err != nil {
		return ports.InventorySnapshot{}, err
	}
	p := h.provider()
	nodes := p.ListNodes()
	if query.Tag != "" {
		nodes = p.GetNodesByTag(query.Tag)
	}
	view := ports.InventorySnapshot{DomainID: h.domain, Policy: h.policy}
	for id := range nodes {
		info, err := legacyNodeInfo(p, id)
		if err != nil {
			return ports.InventorySnapshot{}, err
		}
		view.Nodes = append(view.Nodes, info)
	}
	slices.SortFunc(view.Nodes, func(a, b ports.NodeInfo) int { return strings.Compare(a.ID, b.ID) })
	return view, nil
}

func legacyNodeInfo(provider config.ConfigProvider, id string) (ports.NodeInfo, error) {
	node, host, identity, err := provider.Resolve(id)
	if err != nil {
		return ports.NodeInfo{}, err
	}
	return ports.NodeInfo{ID: id, Alias: slices.Clone(node.Alias), Tags: slices.Clone(node.Tags), Address: fmt.Sprintf("%s:%d", host.Address, host.Port), User: identity.User, AuthType: identity.AuthType, ProxyJump: node.ProxyJump}, nil
}

func (h *legacyHost) Resolve(ctx context.Context, request ports.ResolveRequest) (ports.OperationSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return ports.OperationSnapshot{}, err
	}
	return h.resolveSnapshot(ctx, request, h.provider())
}

func (h *legacyHost) resolveSnapshot(ctx context.Context, request ports.ResolveRequest, p config.ConfigProvider) (ports.OperationSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return ports.OperationSnapshot{}, err
	}
	view := ports.OperationSnapshot{DomainID: h.domain, Policy: h.policy, Targets: make(map[string]ports.Target), Selectors: make(map[string]string)}
	adp := adapter.NewSSHAdapter(p, adapter.WithNonInteractive(true), adapter.WithCredentialSource(h.config.registry), adapter.WithCredentialRecording(false))
	for _, selector := range request.Selectors {
		if selector == "" {
			continue
		}
		id, err := legacyResolveSelector(p, selector)
		if err != nil {
			return ports.OperationSnapshot{}, err
		}
		plan, err := coressh.CapturePlan(ctx, adp, id, h.domain)
		if err != nil {
			return ports.OperationSnapshot{}, err
		}
		info, err := legacyNodeInfo(p, id)
		if err != nil {
			return ports.OperationSnapshot{}, err
		}
		version, err := legacyCredentialVersion(p, plan)
		if err != nil {
			return ports.OperationSnapshot{}, err
		}
		view.Targets[id] = ports.Target{Info: info, Plan: plan, Version: version}
		view.Selectors[selector] = id
	}
	return view, nil
}

func legacyResolveSelector(provider config.ConfigProvider, selector string) (string, error) {
	if strings.HasPrefix(selector, config.OpenSSHNodePrefix) {
		if strings.IndexFunc(selector, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
			return "", errors.New("OpenSSH node IDs must not contain whitespace or control characters")
		}
		return selector, nil
	}
	id, err := provider.ResolveSelector(selector)
	if err != nil {
		return "", err
	}
	if id == "" {
		return "", ports.ErrNotFound
	}
	if strings.HasPrefix(id, config.OpenSSHNodePrefix) && strings.IndexFunc(id, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return "", errors.New("OpenSSH node IDs must not contain whitespace or control characters")
	}
	return id, nil
}

func (h *legacyHost) Enter(ctx context.Context, admission ports.Admission) (ports.Permit, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	selectors := make([]string, 0, len(admission.Snapshot.Selectors))
	for selector := range admission.Snapshot.Selectors {
		selectors = append(selectors, selector)
	}
	if len(selectors) == 0 {
		for id := range admission.Snapshot.Targets {
			selectors = append(selectors, id)
		}
	}
	provider := h.provider()
	current, err := h.resolveSnapshot(ctx, ports.ResolveRequest{Selectors: selectors}, provider)
	if err != nil {
		return nil, err
	}
	if err := admission.Binding.Validate(current); err != nil {
		return nil, err
	}
	// Retain the exact provider used for admission, including private credential
	// references and OpenSSH fallback. It must never enter a public snapshot.
	return ports.NewPermit(context.WithValue(ctx, legacyProviderKey{}, provider), admission, nil)
}

func (b *legacyBackend) RunTunnel(ctx context.Context, permit ports.Permit, spec tunnel.Spec, ready func(string) bool, report func(error)) (retErr error) {
	work, cancel, err := ports.WorkContext(ctx, permit, ports.Execute)
	if err != nil {
		return err
	}
	defer cancel()
	id, _, err := permit.Snapshot().Resolve(spec.NodeID)
	if err != nil {
		return err
	}
	provider, ok := permit.Context().Value(legacyProviderKey{}).(config.ConfigProvider)
	if !ok || ports.Nil(provider) {
		return errors.New("legacy tunnel requires its admitted configuration snapshot")
	}
	connector := newNonInteractiveMCPConnector(provider, b.config.logger, b.config.registry)
	defer func() { retErr = errors.Join(retErr, connector.CloseAll()) }()
	client, err := connector.Connect(work, id)
	if err != nil {
		if work.Err() != nil {
			return nil
		}
		return fmt.Errorf("connect tunnel SSH node: %w", FormatMCPError(err))
	}
	return sshexec.RunDedicatedForward(work, client, spec, ready, report)
}

type legacyBackend struct {
	connector *ssh.Connector
	config    legacyConfig
}

var _ ports.TunnelBackend = (*legacyBackend)(nil)

func (b *legacyBackend) Run(ctx context.Context, permit ports.Permit, nodeID string, command ports.Command) (ports.CommandResult, error) {
	work, cancel, err := ports.WorkContext(ctx, permit, ports.Execute)
	if err != nil {
		return ports.CommandResult{}, err
	}
	defer cancel()
	id, _, err := permit.Snapshot().Resolve(nodeID)
	if err != nil {
		return ports.CommandResult{}, err
	}
	client, err := b.connector.Connect(work, id)
	if err != nil {
		return ports.CommandResult{}, err
	}
	var output string
	if command.Sudo {
		output, err = client.RunWithSudo(work, command.Text)
	} else {
		output, err = client.Run(work, command.Text)
	}
	return ports.CommandResult{Output: output, Connected: true}, err
}
func (b *legacyBackend) files(ctx context.Context, permit ports.Permit, nodeID string, phases ...ports.Phase) (*sftp.Client, error) {
	work, cancel, err := ports.WorkContext(ctx, permit, phases...)
	if err != nil {
		return nil, err
	}
	defer cancel()
	id, _, err := permit.Snapshot().Resolve(nodeID)
	if err != nil {
		return nil, err
	}
	client, err := b.connector.Connect(work, id)
	if err != nil {
		return nil, err
	}
	return sftp.NewClient(work, client)
}
func (b *legacyBackend) OpenFiles(ctx context.Context, permit ports.Permit, nodeID string) (ports.FileSession, error) {
	return b.files(ctx, permit, nodeID, ports.Execute)
}
func (b *legacyBackend) Inspect(ctx context.Context, permit ports.Permit, nodeID string, request ports.InspectRequest) (_ remotefile.Metadata, retErr error) {
	files, err := b.files(ctx, permit, nodeID, ports.Inspect, ports.Execute, ports.Recovery)
	if err != nil {
		return remotefile.Metadata{}, err
	}
	remote := remotefile.New(files)
	defer func() { retErr = errors.Join(retErr, remote.Close()) }()
	return remote.Inspect(ctx, request.Path, request.Upload, request.Overwrite)
}
func (b *legacyBackend) OpenTransfer(ctx context.Context, permit ports.Permit, nodeID string) (ports.TransferSession, error) {
	files, err := b.files(ctx, permit, nodeID, ports.TransferStart, ports.Commit, ports.Recovery)
	if err != nil {
		return nil, err
	}
	return ports.GuardTransfer(context.WithoutCancel(ctx), remotefile.New(files), permit)
}
func (b *legacyBackend) Shutdown(context.Context) error { return b.connector.CloseAll() }
