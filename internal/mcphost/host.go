package mcphost

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
	mcpruntime "github.com/wentf9/xops-cli/core/mcp/runtime"
	"github.com/wentf9/xops-cli/core/mcp/sshexec"
	"github.com/wentf9/xops-cli/core/mcp/tunnel"
	"github.com/wentf9/xops-cli/core/sftp"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	cryptoSSH "golang.org/x/crypto/ssh"
)

type host struct {
	config Config
	domain string
	policy policy.Config
}

type providerKey struct{}

func newHost(cfg Config) *host {
	pol := cfg.Provider.Snapshot().Guardrail
	defaultPolicy := pol == nil
	if pol == nil {
		pol = defaultPolicyConfig()
	}
	copy := policy.Clone(*pol)
	if (cfg.HTTP != nil || cfg.Recovery) && (defaultPolicy || copy.NoElicitFallback == "") {
		copy.NoElicitFallback = guardrail.FallbackDeny
	}
	return &host{config: cfg, domain: "xops-cli", policy: copy}
}
func (h *host) DomainID() string { return h.domain }
func (h *host) provider() config.ConfigProvider {
	if frozen, ok := h.config.Provider.(interface{ Frozen() config.ConfigProvider }); ok {
		return frozen.Frozen()
	}
	return h.config.Provider
}
func (h *host) dependencies() ports.Dependencies {
	return ports.Dependencies{State: h, Gate: h, Audit: auditSink{newAuditLogger(h.policy.AuditLog)}, NewBackend: func(ctx context.Context) (ports.Backend, error) {
		return &backend{connector: newMCPConnector(ctx, h.config.Provider, h.config.Logger, h.config.Registry), config: h.config}, nil
	}}
}

type auditSink struct{ writer guardrail.AuditWriter }

func (a auditSink) Append(ctx context.Context, event ports.AuditEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return a.writer.Log(event)
}

func (h *host) List(ctx context.Context, query ports.NodeQuery) (ports.InventorySnapshot, error) {
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
		info, err := nodeInfo(p, id)
		if err != nil {
			return ports.InventorySnapshot{}, err
		}
		view.Nodes = append(view.Nodes, info)
	}
	slices.SortFunc(view.Nodes, func(a, b ports.NodeInfo) int { return strings.Compare(a.ID, b.ID) })
	return view, nil
}

func nodeInfo(provider config.ConfigProvider, id string) (ports.NodeInfo, error) {
	node, host, identity, err := provider.Resolve(id)
	if err != nil {
		return ports.NodeInfo{}, err
	}
	return ports.NodeInfo{ID: id, Alias: slices.Clone(node.Alias), Tags: slices.Clone(node.Tags), Address: fmt.Sprintf("%s:%d", host.Address, host.Port), User: identity.User, AuthType: identity.AuthType, ProxyJump: node.ProxyJump}, nil
}

func (h *host) Resolve(ctx context.Context, request ports.ResolveRequest) (ports.OperationSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return ports.OperationSnapshot{}, err
	}
	return h.resolveSnapshot(ctx, request, h.provider())
}

func (h *host) resolveSnapshot(ctx context.Context, request ports.ResolveRequest, p config.ConfigProvider) (ports.OperationSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return ports.OperationSnapshot{}, err
	}
	view := ports.OperationSnapshot{DomainID: h.domain, Policy: h.policy, Targets: make(map[string]ports.Target), Selectors: make(map[string]string)}
	adp := adapter.NewSSHAdapter(p, adapter.WithNonInteractive(true), adapter.WithCredentialSource(h.config.Registry), adapter.WithCredentialRecording(false))
	for _, selector := range request.Selectors {
		if selector == "" {
			continue
		}
		id, err := resolveSelector(p, selector)
		if err != nil {
			return ports.OperationSnapshot{}, err
		}
		plan, err := ssh.CapturePlan(ctx, adp, id, h.domain)
		if err != nil {
			return ports.OperationSnapshot{}, err
		}
		info, err := nodeInfo(p, id)
		if err != nil {
			return ports.OperationSnapshot{}, err
		}
		version, err := credentialVersion(p, plan)
		if err != nil {
			return ports.OperationSnapshot{}, err
		}
		var globalExec *ssh.ExecutionConfig
		if cfg := p.Snapshot(); cfg != nil {
			globalExec = cfg.Execution
		}
		node, _, _, err := p.Resolve(id)
		if err != nil {
			return ports.OperationSnapshot{}, err
		}
		effectiveExec, err := ssh.ResolveExecution(node.Execution, globalExec)
		if err != nil {
			return ports.OperationSnapshot{}, err
		}
		execVersion := ports.ExecutionVersion(effectiveExec)
		view.Targets[id] = ports.Target{
			Info:             info,
			Plan:             plan,
			Version:          version,
			ExecutionVersion: execVersion,
			Execution:        effectiveExec,
		}
		view.Selectors[selector] = id
	}
	return view, nil
}

func resolveSelector(provider config.ConfigProvider, selector string) (string, error) {
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

func (h *host) Enter(ctx context.Context, admission ports.Admission) (ports.Permit, error) {
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
	return ports.NewPermit(context.WithValue(ctx, providerKey{}, provider), admission, nil)
}

func (b *backend) RunTunnel(ctx context.Context, permit ports.Permit, spec tunnel.Spec, ready func(string) bool, report func(error)) (retErr error) {
	work, cancel, err := ports.WorkContext(ctx, permit, ports.Execute)
	if err != nil {
		return err
	}
	defer cancel()
	id, _, err := permit.Snapshot().Resolve(spec.NodeID)
	if err != nil {
		return err
	}
	provider, ok := permit.Context().Value(providerKey{}).(config.ConfigProvider)
	if !ok || ports.Nil(provider) {
		return errors.New("legacy tunnel requires its admitted configuration snapshot")
	}
	connector := newNonInteractiveMCPConnector(provider, b.config.Logger, b.config.Registry)
	defer func() { retErr = errors.Join(retErr, connector.CloseAll()) }()
	client, err := connector.Connect(work, id)
	if err != nil {
		if work.Err() != nil {
			return nil
		}
		return fmt.Errorf("connect tunnel SSH node: %w", mcpruntime.FormatMCPError(err))
	}
	return sshexec.RunDedicatedForward(work, client, spec, ready, report)
}

type backend struct {
	connector *ssh.Connector
	config    Config
}

var _ ports.TunnelBackend = (*backend)(nil)

func (b *backend) Run(ctx context.Context, permit ports.Permit, nodeID string, command ports.Command) (ports.CommandResult, error) {
	work, cancel, err := ports.WorkContext(ctx, permit, ports.Execute)
	if err != nil {
		return ports.CommandResult{}, err
	}
	defer cancel()
	id, target, err := permit.Snapshot().Resolve(nodeID)
	if err != nil {
		return ports.CommandResult{}, err
	}
	effectiveExec, err := ssh.ResolveExecution(command.Execution, target.Execution)
	if err != nil {
		return ports.CommandResult{
			Outcome:      ssh.ExecutionNotStarted,
			ExecutionErr: err,
		}, err
	}
	if command.Sudo {
		if _, err := effectiveExec.SudoRunOptions(command.Text); err != nil {
			return ports.CommandResult{Outcome: ssh.ExecutionNotStarted, ExecutionErr: err}, err
		}
	}
	var plan ssh.CommandPlan
	if command.Plan != nil {
		plan = *command.Plan
	} else {
		plan, err = ssh.PlanCommand(command.Text, effectiveExec.CommandOptions())
		if err != nil {
			return ports.CommandResult{
				Outcome:      ssh.ExecutionNotStarted,
				ExecutionErr: err,
			}, err
		}
	}
	if command.Filesystem || command.RequirePOSIX {
		if plan.LaunchDialect() != ssh.LaunchPOSIX {
			err = fmt.Errorf("%w: non-POSIX execution dialect %q is not supported for generated filesystem commands", ssh.ErrExecutionValidation, plan.LaunchDialect())
			return ports.CommandResult{
				Outcome:      ssh.ExecutionNotStarted,
				ExecutionErr: err,
			}, err
		}
	}
	client, err := b.connector.Connect(work, id)
	if err != nil {
		return ports.CommandResult{}, err
	}
	if command.Sudo {
		output, err := client.RunWithSudoExecution(work, command.Text, effectiveExec)
		var exitCode *uint32
		var signal string
		outcome := ssh.ExecutionCompleted
		if err != nil {
			var exitErr *cryptoSSH.ExitError
			if errors.As(err, &exitErr) {
				if sig := exitErr.Signal(); sig != "" {
					signal = sig
					exitCode = nil
				} else {
					code := uint32(exitErr.ExitStatus())
					exitCode = &code
				}
			} else if errors.Is(err, ssh.ErrExecutionValidation) {
				outcome = ssh.ExecutionNotStarted
			} else {
				outcome = ssh.ExecutionUnknown
			}
		} else {
			zero := uint32(0)
			exitCode = &zero
		}
		return ports.CommandResult{
			Output:       output,
			Connected:    true,
			Outcome:      outcome,
			ExitCode:     exitCode,
			Signal:       signal,
			ExecutionErr: err,
		}, err
	}

	res := client.ExecuteCommand(work, plan)
	return ports.FromSSHResult(res, true), res.Err()
}
func (b *backend) files(ctx context.Context, permit ports.Permit, nodeID string, phases ...ports.Phase) (*sftp.Client, error) {
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
func (b *backend) OpenFiles(ctx context.Context, permit ports.Permit, nodeID string) (ports.FileSession, error) {
	return b.files(ctx, permit, nodeID, ports.Execute)
}
func (b *backend) Inspect(ctx context.Context, permit ports.Permit, nodeID string, request ports.InspectRequest) (_ remotefile.Metadata, retErr error) {
	files, err := b.files(ctx, permit, nodeID, ports.Inspect, ports.Execute, ports.Recovery)
	if err != nil {
		return remotefile.Metadata{}, err
	}
	remote := remotefile.New(files)
	defer func() { retErr = errors.Join(retErr, remote.Close()) }()
	return remote.Inspect(ctx, request.Path, request.Upload, request.Overwrite)
}
func (b *backend) OpenTransfer(ctx context.Context, permit ports.Permit, nodeID string) (ports.TransferSession, error) {
	files, err := b.files(ctx, permit, nodeID, ports.TransferStart, ports.Commit, ports.Recovery)
	if err != nil {
		return nil, err
	}
	return ports.GuardTransfer(context.WithoutCancel(ctx), remotefile.New(files), permit)
}
func (b *backend) Shutdown(context.Context) error { return b.connector.CloseAll() }
