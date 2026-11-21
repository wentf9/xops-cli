package mcphost

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode"

	pkgsftp "github.com/pkg/sftp"
	"github.com/wentf9/xops-cli/core/mcp/guardrail"
	"github.com/wentf9/xops-cli/core/mcp/policy"
	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/mcp/remotefile"
	mcpruntime "github.com/wentf9/xops-cli/core/mcp/runtime"
	"github.com/wentf9/xops-cli/core/mcp/sshexec"
	"github.com/wentf9/xops-cli/core/mcp/tunnel"
	"github.com/wentf9/xops-cli/core/sftp"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/internal/sshenv"
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
	port := host.Port
	if port == 0 {
		port = 22
	}
	user := strings.TrimSpace(identity.User)
	if user == "" {
		user = sshenv.Discover().LocalUser
	}
	return ports.NodeInfo{ID: id, Alias: slices.Clone(node.Alias), Tags: slices.Clone(node.Tags), Address: fmt.Sprintf("%s:%d", host.Address, port), User: user, AuthType: identity.AuthType, ProxyJump: node.ProxyJump}, nil
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
	adp := adapter.NewSSHAdapter(p, adapter.WithStrictIsolation(), adapter.WithCredentialSource(h.config.Registry), adapter.WithCredentialRecording(false))
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
		version, err := bindPlanCredentials(p, &plan)
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

func hasWhitespaceOrControl(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r) || r == '\u2028' || r == '\u2029'
	}) >= 0
}

func hasControlOrLineSep(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool {
		return unicode.IsControl(r) || r == '\u2028' || r == '\u2029'
	}) >= 0
}

func isExactSavedSelector(provider config.ConfigProvider, selector string) bool {
	if provider == nil || selector == "" {
		return false
	}
	if snap := provider.Snapshot(); snap != nil && snap.Nodes != nil {
		if _, ok := snap.Nodes.Get(selector); ok {
			return true
		}
	}
	if fa, ok := provider.(interface{ FindAlias(string) string }); ok && fa.FindAlias(selector) != "" {
		return true
	}
	return false
}

func isConcreteOpenSSHHost(provider config.ConfigProvider, host string) bool {
	if provider == nil || host == "" {
		return false
	}
	if src, ok := provider.(interface{ GetOpenSSHParser() *config.OpenSSHParser }); ok {
		if parser := src.GetOpenSSHParser(); parser != nil {
			return parser.HasHost(host)
		}
	}
	return false
}

func isIPLiteralHost(host string) bool {
	if host == "" {
		return false
	}
	clean := config.StripHostBrackets(host)
	if zoneIdx := strings.IndexByte(clean, '%'); zoneIdx >= 0 {
		clean = clean[:zoneIdx]
	}
	_, err := netip.ParseAddr(clean)
	return err == nil
}

func hasLeadingZeroPortInOpenSSHSpec(raw string, ref config.TargetRef) bool {
	if !ref.HasPort {
		return false
	}
	spec := strings.TrimPrefix(raw, config.OpenSSHNodePrefix)
	lastColon := strings.LastIndexByte(spec, ':')
	if lastColon < 0 || lastColon+1 >= len(spec) {
		return false
	}
	return spec[lastColon+1:] != strconv.Itoa(int(ref.Port))
}

func canonicalizeOpenSSHSelector(provider config.ConfigProvider, raw string) (string, error) {
	if hasWhitespaceOrControl(raw) {
		return "", errors.New("OpenSSH node IDs must not contain whitespace or control characters")
	}
	ref, err := config.ParseTargetRef(raw)
	if err != nil {
		// Let malformed explicit openssh: specs (e.g. "openssh:", "openssh:web:65536")
		// reach connection validation so they fail closed with a config error.
		return raw, nil
	}
	if hasLeadingZeroPortInOpenSSHSpec(raw, ref) {
		return "", fmt.Errorf("non-canonical OpenSSH node ID %q: leading-zero port is not allowed", raw)
	}
	host := config.StripHostBrackets(ref.Host)
	canonHost := host
	if isIPLiteralHost(host) {
		canonHost = config.NormalizeHostAddress(host)
	} else if !isConcreteOpenSSHHost(provider, host) {
		canonHost = strings.ToLower(strings.TrimSuffix(host, "."))
	}
	baseID := config.OpenSSHNodePrefix + canonHost

	effUser := ref.User
	effPort := ref.Port
	hasPort := ref.HasPort
	if effUser != "" || hasPort {
		if _, baseHost, baseIdent, baseErr := provider.Resolve(baseID); baseErr == nil {
			baseUser := strings.TrimSpace(baseIdent.User)
			if baseUser == "" {
				baseUser = sshenv.Discover().LocalUser
			}
			basePort := baseHost.Port
			if basePort == 0 {
				basePort = 22
			}
			if effUser != "" && effUser == baseUser {
				effUser = ""
			}
			if hasPort && effPort == basePort {
				hasPort = false
				effPort = 0
			}
		}
	}
	return config.TargetRef{
		OpenSSH: true,
		User:    effUser,
		Host:    canonHost,
		Port:    effPort,
		HasPort: hasPort,
	}.NormalizedString(), nil
}

func resolveSelector(provider config.ConfigProvider, selector string) (string, error) {
	if len(selector) >= len(config.OpenSSHNodePrefix) &&
		strings.EqualFold(selector[:len(config.OpenSSHNodePrefix)], config.OpenSSHNodePrefix) &&
		!strings.HasPrefix(selector, config.OpenSSHNodePrefix) {
		return "", errors.New("OpenSSH node IDs must use lowercase \"openssh:\" prefix")
	}
	if strings.HasPrefix(selector, config.OpenSSHNodePrefix) {
		return canonicalizeOpenSSHSelector(provider, selector)
	}
	if strings.TrimSpace(selector) != selector || hasControlOrLineSep(selector) {
		return "", errors.New("node selectors must not contain leading/trailing whitespace or control characters")
	}
	if !isExactSavedSelector(provider, selector) && hasWhitespaceOrControl(selector) {
		return "", errors.New("node selectors must not contain whitespace or control characters")
	}
	id, err := provider.ResolveSelector(selector)
	if err != nil {
		return "", err
	}
	if id == "" {
		return "", ports.ErrNotFound
	}
	if strings.HasPrefix(id, config.OpenSSHNodePrefix) {
		return canonicalizeOpenSSHSelector(provider, id)
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
	view := permit.Snapshot().Clone()
	if err := permit.Binding().Validate(view); err != nil {
		return err
	}
	_, target, err := view.Resolve(spec.NodeID)
	if err != nil {
		return err
	}
	provider, ok := permit.Context().Value(providerKey{}).(config.ConfigProvider)
	if !ok || ports.Nil(provider) {
		return errors.New("legacy tunnel requires its admitted configuration snapshot")
	}
	connector := newNonInteractiveMCPConnector(provider, b.config.Logger, b.config.Registry)
	defer func() { retErr = errors.Join(retErr, connector.CloseAll()) }()
	connection, err := connector.ConnectPlan(work, target.Plan)
	if err != nil {
		if work.Err() != nil {
			return nil
		}
		return fmt.Errorf("connect tunnel SSH node: %w", mcpruntime.FormatMCPError(err))
	}
	defer func() { retErr = errors.Join(retErr, connection.Close()) }()
	return sshexec.RunDedicatedForward(work, connection.Client, spec, ready, report)
}

type backend struct {
	connector *ssh.Connector
	config    Config
}

var _ ports.TunnelBackend = (*backend)(nil)
var _ ports.ExecutionProber = (*backend)(nil)
var _ ports.PTYBackend = (*backend)(nil)

func (b *backend) ProbeExecution(ctx context.Context, permit ports.Permit, nodeID string) (_ *ssh.ProbeResult, retErr error) {
	work, cancel, err := ports.WorkContext(ctx, permit, ports.Inspect)
	if err != nil {
		return nil, err
	}
	defer cancel()
	_, target, err := permit.Snapshot().Resolve(nodeID)
	if err != nil {
		return nil, err
	}
	connection, err := b.connector.ConnectPlan(work, target.Plan)
	if err != nil {
		return nil, fmt.Errorf("connect MCP execution probe: %w", err)
	}
	defer func() { retErr = errors.Join(retErr, connection.Close()) }()
	return connection.Client.ProbeExecutionConfig(work)
}

func (b *backend) Run(ctx context.Context, permit ports.Permit, nodeID string, command ports.Command) (_ ports.CommandResult, retErr error) {
	work, cancel, err := ports.WorkContext(ctx, permit, ports.Execute)
	if err != nil {
		return ports.CommandResult{}, err
	}
	defer cancel()
	_, target, err := permit.Snapshot().Resolve(nodeID)
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
		plan, err = ssh.PlanCommand(command.Text, command.CommandOptions(effectiveExec))
		if err != nil {
			return ports.CommandResult{
				Outcome:      ssh.ExecutionNotStarted,
				ExecutionErr: err,
			}, err
		}
	}
	if command.RequirePOSIX {
		if plan.LaunchDialect() != ssh.LaunchPOSIX {
			err = fmt.Errorf("%w: non-POSIX execution dialect %q is not supported; POSIX shell target (X11/Wayland) is required", ssh.ErrExecutionValidation, plan.LaunchDialect())
			return ports.CommandResult{
				Outcome:      ssh.ExecutionNotStarted,
				ExecutionErr: err,
			}, err
		}
	} else if command.Filesystem {
		if plan.LaunchDialect() != ssh.LaunchPOSIX {
			err = fmt.Errorf("%w: non-POSIX execution dialect %q is not supported for generated filesystem commands", ssh.ErrExecutionValidation, plan.LaunchDialect())
			return ports.CommandResult{
				Outcome:      ssh.ExecutionNotStarted,
				ExecutionErr: err,
			}, err
		}
	}
	connection, err := b.connector.ConnectPlan(work, target.Plan)
	if err != nil {
		return ports.CommandResult{}, err
	}
	defer func() { retErr = errors.Join(retErr, connection.Close()) }()
	client := connection.Client
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

type leasedFileSession struct {
	*sftp.Client
	permit  ports.Permit
	phases  []ports.Phase
	release func() error
}

var _ ports.FileSession = (*leasedFileSession)(nil)

func (s *leasedFileSession) Close() error { return s.release() }
func (s *leasedFileSession) Do(ctx context.Context, operation func(*pkgsftp.Client) error) error {
	work, cancel, err := ports.WorkContext(ctx, s.permit, s.phases...)
	if err != nil {
		return err
	}
	defer cancel()
	return s.Client.Do(work, operation)
}
func (s *leasedFileSession) Upload(ctx context.Context, local, remote string, progress sftp.ProgressCallback) error {
	work, cancel, err := ports.WorkContext(ctx, s.permit, s.phases...)
	if err != nil {
		return err
	}
	defer cancel()
	return s.Client.Upload(work, local, remote, progress)
}
func (s *leasedFileSession) Download(ctx context.Context, remote, local string, progress sftp.ProgressCallback) error {
	work, cancel, err := ports.WorkContext(ctx, s.permit, s.phases...)
	if err != nil {
		return err
	}
	defer cancel()
	return s.Client.Download(work, remote, local, progress)
}
func (s *leasedFileSession) CreatePrivateExclusive(ctx context.Context, name string, write func(io.Writer) error) (bool, bool, error) {
	work, cancel, err := ports.WorkContext(ctx, s.permit, s.phases...)
	if err != nil {
		return false, false, err
	}
	defer cancel()
	return s.Client.CreatePrivateExclusive(work, name, write)
}
func (s *leasedFileSession) RemoveAll(ctx context.Context, remotePath string) error {
	work, cancel, err := ports.WorkContext(ctx, s.permit, s.phases...)
	if err != nil {
		return err
	}
	defer cancel()
	return s.Client.RemoveAll(work, remotePath)
}
func (s *leasedFileSession) RemoteCopy(ctx context.Context, src, dst string) error {
	work, cancel, err := ports.WorkContext(ctx, s.permit, s.phases...)
	if err != nil {
		return err
	}
	defer cancel()
	return s.Client.RemoteCopy(work, src, dst)
}
func (s *leasedFileSession) Stat(ctx context.Context, remotePath string) (os.FileInfo, error) {
	work, cancel, err := ports.WorkContext(ctx, s.permit, s.phases...)
	if err != nil {
		return nil, err
	}
	defer cancel()
	return s.Client.Stat(work, remotePath)
}
func (s *leasedFileSession) Lstat(ctx context.Context, remotePath string) (os.FileInfo, error) {
	work, cancel, err := ports.WorkContext(ctx, s.permit, s.phases...)
	if err != nil {
		return nil, err
	}
	defer cancel()
	return s.Client.Lstat(work, remotePath)
}
func (s *leasedFileSession) RealPath(ctx context.Context, remotePath string) (string, error) {
	work, cancel, err := ports.WorkContext(ctx, s.permit, s.phases...)
	if err != nil {
		return "", err
	}
	defer cancel()
	return s.Client.RealPath(work, remotePath)
}

type leasedTransferFiles struct {
	*sftp.Client
	release func() error
}

func (f *leasedTransferFiles) Close() error { return f.release() }

func (b *backend) connectPlan(work context.Context, permit ports.Permit, plan ssh.ConnectionPlan) (*ssh.PlanConnection, func() error, error) {
	if provider, ok := permit.Context().Value(providerKey{}).(config.ConfigProvider); ok && !ports.Nil(provider) {
		connector := newNonInteractiveMCPConnector(provider, b.config.Logger, b.config.Registry)
		kaCtx, kaCancel := context.WithCancel(context.WithoutCancel(work))
		connector.EnableKeepAlive(kaCtx, ssh.DefaultKeepAliveInterval, ssh.DefaultKeepAliveTimeout)
		connection, err := connector.ConnectPlan(work, plan)
		if err != nil {
			kaCancel()
			return nil, nil, errors.Join(err, connector.CloseAll())
		}
		release := sync.OnceValue(func() error {
			kaCancel()
			return errors.Join(connection.Close(), connector.CloseAll())
		})
		return connection, release, nil
	}
	connection, err := b.connector.ConnectPlan(work, plan)
	if err != nil {
		return nil, nil, err
	}
	return connection, connection.Close, nil
}

func (b *backend) openFiles(ctx context.Context, permit ports.Permit, nodeID string, phases ...ports.Phase) (*leasedFileSession, error) {
	work, cancel, err := ports.WorkContext(ctx, permit, phases...)
	if err != nil {
		return nil, err
	}
	defer cancel()
	return b.openFilesWithWork(work, permit, nodeID, phases...)
}

func (b *backend) openFilesWithWork(work context.Context, permit ports.Permit, nodeID string, phases ...ports.Phase) (*leasedFileSession, error) {
	view := permit.Snapshot().Clone()
	if err := permit.Binding().Validate(view); err != nil {
		return nil, err
	}
	_, target, err := view.Resolve(nodeID)
	if err != nil {
		return nil, err
	}
	connection, releaseConn, err := b.connectPlan(work, permit, target.Plan)
	if err != nil {
		return nil, err
	}
	files, err := sftp.NewClient(work, connection.Client)
	if err != nil {
		return nil, errors.Join(err, releaseConn())
	}
	return &leasedFileSession{
		Client: files,
		permit: permit,
		phases: slices.Clone(phases),
		release: sync.OnceValue(func() error {
			return errors.Join(files.Close(), releaseConn())
		}),
	}, nil
}

func (b *backend) OpenFiles(ctx context.Context, permit ports.Permit, nodeID string) (ports.FileSession, error) {
	return b.openFiles(ctx, permit, nodeID, ports.Execute)
}

func (b *backend) Inspect(ctx context.Context, permit ports.Permit, nodeID string, request ports.InspectRequest) (_ remotefile.Metadata, retErr error) {
	work, cancel, err := ports.WorkContext(ctx, permit, ports.Inspect, ports.Execute, ports.TransferStart, ports.Recovery)
	if err != nil {
		return remotefile.Metadata{}, err
	}
	defer cancel()
	files, err := b.openFilesWithWork(work, permit, nodeID, ports.Inspect, ports.Execute, ports.TransferStart, ports.Recovery)
	if err != nil {
		return remotefile.Metadata{}, err
	}
	remote := remotefile.New(files)
	defer func() { retErr = errors.Join(retErr, remote.Close()) }()
	return remote.Inspect(work, request.Path, request.Upload, request.Overwrite)
}

func (b *backend) OpenTransfer(ctx context.Context, permit ports.Permit, nodeID string) (ports.TransferSession, error) {
	files, err := b.openFiles(ctx, permit, nodeID, ports.TransferStart, ports.Commit, ports.Recovery)
	if err != nil {
		return nil, err
	}
	return ports.GuardTransfer(context.WithoutCancel(ctx), remotefile.New(&leasedTransferFiles{Client: files.Client, release: files.release}), permit)
}
func (b *backend) OpenPTY(ctx context.Context, permit ports.Permit, nodeID string) (ports.PTYSession, error) {
	work, cancel, err := ports.WorkContext(ctx, permit, ports.Execute)
	if err != nil {
		return nil, err
	}
	defer cancel()
	_, target, err := permit.Snapshot().Resolve(nodeID)
	if err != nil {
		return nil, err
	}
	connection, err := b.connector.ConnectPlan(work, target.Plan)
	if err != nil {
		return nil, err
	}
	return sshexec.OpenClientPTY(work, connection.Client, connection.Close)
}
func (b *backend) Shutdown(context.Context) error { return b.connector.CloseAll() }
