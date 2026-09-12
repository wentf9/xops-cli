package tui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/ssh"
)

type terminalConnectionKind uint8

const (
	terminalShell terminalConnectionKind = iota
	terminalMonitor
	terminalLogs
)

// terminalAccess is active only while Bubble Tea has released its terminal.
// Background clients retain read access, but cannot open prompts or write back.
type terminalAccess struct {
	active      atomic.Bool
	saveFailed  atomic.Bool
	interaction ssh.InteractionHandler
	forbidden   bool
}

func (a *terminalAccess) allowed() bool { return a.active.Load() && !a.forbidden }
func (a *terminalAccess) PromptSecret(ctx context.Context, req ssh.SecretRequest) (string, error) {
	if !a.allowed() || a.interaction == nil {
		return "", ssh.ErrInteractionRequired
	}
	return a.interaction.PromptSecret(ctx, req)
}
func (a *terminalAccess) ConfirmHostKey(ctx context.Context, req ssh.HostKeyConfirmation) (bool, error) {
	if !a.allowed() || a.interaction == nil {
		return false, ssh.ErrInteractionRequired
	}
	return a.interaction.ConfirmHostKey(ctx, req)
}
func (a *terminalAccess) CredentialRecoveryAllowed() bool {
	reporter, ok := a.interaction.(ssh.CredentialFailureReporter)
	return a.allowed() && ok && reporter.CredentialRecoveryAllowed()
}
func (a *terminalAccess) ReportCredentialFailure(ctx context.Context, operation string) error {
	reporter, ok := a.interaction.(ssh.CredentialFailureReporter)
	if !a.allowed() || !ok {
		return ssh.ErrInteractionRequired
	}
	if operation == "save" {
		a.saveFailed.Store(true)
	}
	return reporter.ReportCredentialFailure(ctx, operation)
}

type terminalCredentialPorts struct {
	*adapter.SSHAdapter
	access *terminalAccess
}

func (p *terminalCredentialPorts) ResolveSecret(ctx context.Context, req ssh.SecretRequest) ([]byte, error) {
	if ctx == nil {
		return nil, fmt.Errorf("TUI credential resolution context is nil")
	}
	if !p.access.allowed() {
		ctx = credential.WithoutInteraction(ctx)
	}
	return p.SSHAdapter.ResolveSecret(ctx, req)
}
func (p *terminalCredentialPorts) UpdateAuth(ctx context.Context, node, token, password, key, passphrase string) (string, error) {
	if !p.access.allowed() {
		return token, nil
	}
	return p.SSHAdapter.UpdateAuth(ctx, node, token, password, key, passphrase)
}
func (p *terminalCredentialPorts) UpdateSudo(ctx context.Context, node, token string, mode ssh.SudoMode, password string) (string, error) {
	if !p.access.allowed() {
		return token, nil
	}
	return p.SSHAdapter.UpdateSudo(ctx, node, token, mode, password)
}

func newTerminalConnector(repo *config.Repository, cfg modelConfig) (*ssh.Connector, *terminalAccess) {
	access := &terminalAccess{interaction: cfg.interaction, forbidden: cfg.ctx != nil && credential.InteractionDisabled(cfg.ctx)}
	adapterConfig := cfg
	if cfg.rememberConfirmation != nil {
		adapterConfig.rememberConfirmation = func(ctx context.Context, node string) (bool, error) {
			if !access.allowed() {
				return false, ssh.ErrInteractionRequired
			}
			work, cancel := context.WithTimeout(ctx, ssh.DefaultInteractionTimeout)
			defer cancel()
			return cfg.rememberConfirmation(work, node)
		}
	}
	ports := &terminalCredentialPorts{SSHAdapter: adapter.NewSSHAdapter(repo, credentialAdapterOptions(repo, adapterConfig)...), access: access}
	opts := []ssh.Option{ssh.WithInteractionHandler(access), ssh.WithLogger(cfg.logger)}
	if snapshot := repo.Snapshot(); snapshot.PasswordPromptPattern != "" {
		opts = append(opts, ssh.WithPasswordPromptPattern(snapshot.PasswordPromptPattern))
	}
	return ssh.NewConnector(ports, opts...), access
}

// A terminalConnection owns both the pending handshake and the preceding
// connector. Close cancels and joins Run, including shared SSH connect workers.
type terminalConnection struct {
	kind                       terminalConnectionKind
	nodeID                     string
	connector, previous        *ssh.Connector
	access                     *terminalAccess
	ctx                        context.Context
	cancel                     context.CancelFunc
	mu                         sync.Mutex
	done                       chan struct{}
	started, finished, closing bool
	observed                   bool
	runErr                     error
	warnUnavailable            bool
	stdin                      io.Reader
	stdout, stderr             io.Writer
	client                     *ssh.Client
}

func (a *terminalConnection) SetStdin(r io.Reader)  { a.stdin = r }
func (a *terminalConnection) SetStdout(w io.Writer) { a.stdout = w }
func (a *terminalConnection) SetStderr(w io.Writer) { a.stderr = w }
func (a *terminalConnection) Run() (retErr error) {
	a.mu.Lock()
	if a.closing || a.started {
		a.mu.Unlock()
		return context.Canceled
	}
	a.started = true
	a.mu.Unlock()
	defer func() {
		// A canceled Connect may still have a shared handshake running. Join it
		// before Bubble Tea is allowed to restore its input reader.
		if retErr != nil || a.kind == terminalShell {
			retErr = errors.Join(retErr, a.connector.CloseAll())
		}
		a.access.active.Store(false)
		a.cancel()
		a.mu.Lock()
		a.finished = true
		a.runErr = retErr
		close(a.done)
		a.mu.Unlock()
	}()
	if a.previous != nil {
		if err := a.previous.CloseAll(); err != nil {
			return fmt.Errorf("close previous TUI connection: %w", err)
		}
	}
	if err := a.ctx.Err(); err != nil {
		return err
	}
	var input *os.File
	if a.kind == terminalShell {
		var ok bool
		input, ok = a.stdin.(*os.File)
		if !ok || input == nil {
			return fmt.Errorf("interactive SSH requires a terminal input file")
		}
	}
	a.access.active.Store(true)
	client, err := a.connector.Connect(a.ctx, a.nodeID)
	if err != nil {
		return err
	}
	a.client = client
	if a.warnUnavailable && a.access.CredentialRecoveryAllowed() {
		if err := a.access.ReportCredentialFailure(a.ctx, "save"); err != nil {
			return err
		}
	}
	if a.kind == terminalShell {
		return client.ShellWithIO(a.ctx, ssh.InteractiveIO{Stdin: input, Stdout: a.stdout, Stderr: a.stderr})
	}
	return nil
}
func (a *terminalConnection) Close() error {
	a.mu.Lock()
	a.closing = true
	a.cancel()
	if !a.started && !a.finished {
		a.finished = true
		close(a.done)
	}
	a.mu.Unlock()
	a.access.active.Store(false)
	err := a.connector.CloseAll()
	if a.previous != nil {
		err = errors.Join(err, a.previous.CloseAll())
	}
	<-a.done
	a.mu.Lock()
	if !a.observed {
		err = errors.Join(err, a.runErr)
	}
	a.mu.Unlock()
	return err
}

type terminalConnectionResult struct {
	action *terminalConnection
	err    error
}

func (m *Model) beginTerminalConnection(kind terminalConnectionKind, node string) tea.Cmd {
	if m.terminalConnection != nil || m.ctx.Err() != nil {
		return nil
	}
	connector, access := newTerminalConnector(m.repository, m.connectionConfig)
	ctx, cancel := context.WithCancel(m.terminalContext)
	action := &terminalConnection{kind: kind, nodeID: node, connector: connector, previous: m.connector, access: access, ctx: ctx, cancel: cancel, done: make(chan struct{}), warnUnavailable: automaticSavingUnavailable(m.repository, m.connectionConfig)}
	m.connector = connector
	m.terminalConnection = action
	return tea.Exec(action, func(err error) tea.Msg { return terminalConnectionResult{action, err} })
}
func (m *Model) handleTerminalConnection(result terminalConnectionResult) tea.Cmd {
	action := result.action
	if action == nil {
		return nil
	}
	action.mu.Lock()
	action.observed = true
	action.mu.Unlock()
	if action != m.terminalConnection || m.ctx.Err() != nil {
		if err := action.Close(); err != nil {
			m.status = errorStyle.Render(fmt.Sprintf("Close TUI connection: %v", err))
		}
		return nil
	}
	m.terminalConnection = nil
	m.refreshAfterTerminal(action.nodeID)
	// ReleaseTerminal can fail before Run starts. Always reclaim that action.
	if result.err != nil {
		err := errors.Join(result.err, action.Close())
		m.status = errorStyle.Render(i18n.Tf("tui_connection_failed", map[string]any{"Error": err}))
		*m, _ = m.updateList(m.lastSize)
		return nil
	}
	var next tea.Cmd
	switch action.kind {
	case terminalMonitor:
		_, next = m.handleAsyncMessage(monitorConnectedMsg{nodeID: action.nodeID, client: action.client})
	case terminalLogs:
		_, next = m.handleAsyncMessage(logScannerConnectedMsg{nodeID: action.nodeID, client: action.client})
	default:
		m.status = ""
	}
	if action.warnUnavailable {
		m.status = i18n.T("tui_credential_saving_unavailable")
	} else if action.access.saveFailed.Load() {
		m.status = i18n.T("tui_credential_not_saved")
	}
	*m, _ = m.updateList(m.lastSize)
	return next
}

func automaticSavingUnavailable(repo *config.Repository, cfg modelConfig) bool {
	snapshot := repo.Snapshot()
	return cfg.persistenceUnavailable && snapshot.CanRememberCredentials() && tuiRememberPolicy(snapshot, cfg) != "never"
}

func (m *Model) refreshAfterTerminal(nodeID string) {
	filter, state := m.list.FilterValue(), m.list.FilterState()
	selected := make(map[string]bool)
	for _, item := range m.list.Items() {
		if node, ok := item.(*nodeItem); ok {
			selected[node.id] = node.selected
		}
	}
	m.refreshList()
	for _, item := range m.list.Items() {
		if node, ok := item.(*nodeItem); ok {
			node.selected = selected[node.id]
		}
	}
	if filter != "" {
		m.list.SetFilterText(filter)
		m.list.SetFilterState(state)
	}
	for index, item := range m.list.VisibleItems() {
		if node, ok := item.(*nodeItem); ok && node.id == nodeID {
			m.list.Select(index)
			break
		}
	}
}
