package tui

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/ssh"
	cryptoSSH "golang.org/x/crypto/ssh"
)

type terminalTestInteraction struct {
	prompts, reports atomic.Int32
	password         string
	entered          chan struct{}
	block            bool
	once             sync.Once
}

func (h *terminalTestInteraction) PromptSecret(ctx context.Context, _ ssh.SecretRequest) (string, error) {
	h.prompts.Add(1)
	if h.entered != nil {
		h.once.Do(func() { close(h.entered) })
	}
	if h.block {
		<-ctx.Done()
		return "", ctx.Err()
	}
	return h.password, nil
}
func (*terminalTestInteraction) ConfirmHostKey(context.Context, ssh.HostKeyConfirmation) (bool, error) {
	return true, nil
}
func (*terminalTestInteraction) CredentialRecoveryAllowed() bool { return true }
func (h *terminalTestInteraction) ReportCredentialFailure(context.Context, string) error {
	h.reports.Add(1)
	return nil
}

func startTUITestSSH(t *testing.T) string {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cryptoSSH.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := &cryptoSSH.ServerConfig{PasswordCallback: func(_ cryptoSSH.ConnMetadata, value []byte) (*cryptoSSH.Permissions, error) {
		if string(value) == "verified-password" {
			return nil, nil
		}
		return nil, errors.New("password rejected")
	}}
	serverConfig.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	var mu sync.Mutex
	connections := make(map[net.Conn]bool)
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			connections[conn] = true
			mu.Unlock()
			wg.Go(func() {
				defer func() { closeTUITestResource(t, conn); mu.Lock(); delete(connections, conn); mu.Unlock() }()
				if ctx.Err() != nil {
					return
				}
				if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
					t.Error(err)
					return
				}
				server, channels, requests, err := cryptoSSH.NewServerConn(conn, serverConfig)
				if err != nil {
					return
				}
				defer closeTUITestResource(t, server)
				wg.Go(func() {
					for request := range requests {
						replyTUITestGlobal(t, ctx, request)
					}
				})
				for {
					select {
					case <-ctx.Done():
						return
					case request, ok := <-channels:
						if !ok {
							return
						}
						channel, reqs, err := request.Accept()
						if err != nil {
							return
						}
						wg.Go(func() { serveTUITestShell(t, channel, reqs) })
					}
				}
			})
		}
	})
	t.Cleanup(func() {
		cancel()
		closeTUITestResource(t, listener)
		mu.Lock()
		var active []net.Conn
		for conn := range connections {
			active = append(active, conn)
		}
		mu.Unlock()
		for _, conn := range active {
			closeTUITestResource(t, conn)
		}
		wg.Wait()
	})
	return listener.Addr().String()
}
func closeTUITestResource(t *testing.T, closer io.Closer) {
	t.Helper()
	if err := closer.Close(); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
		t.Error(err)
	}
}
func serveTUITestShell(t *testing.T, channel cryptoSSH.Channel, requests <-chan *cryptoSSH.Request) {
	t.Helper()
	defer closeTUITestResource(t, channel)
	for request := range requests {
		if request.Type == "pty-req" {
			if err := request.Reply(true, nil); err != nil {
				return
			}
			continue
		}
		if request.Type == "shell" {
			if err := request.Reply(true, nil); err != nil {
				return
			}
			if _, err := io.WriteString(channel, "tui-shell\n"); err != nil {
				return
			}
			if _, err := channel.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0})); err != nil && !errors.Is(err, io.EOF) {
				t.Error(err)
			}
			return
		}
		if err := request.Reply(false, nil); err != nil {
			return
		}
	}
}

func terminalTestModel(t *testing.T, store credential.Store, ui ssh.InteractionHandler, options ...ModelOption) (*Model, *config.Repository) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("SSH_AUTH_SOCK", "")
	address := startTUITestSSH(t)
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	cfg := newFormCredentialTestConfiguration("")
	cfg.SchemaVersion = 2
	// The list hides exact localhost entries. A bracketed mapped IPv4 literal stays
	// visible without requiring an extra loopback alias on macOS or Windows.
	if host == "127.0.0.1" {
		host = "[::ffff:127.0.0.1]"
	}
	cfg.Hosts.Set("192.168.1.50:22", models.Host{Address: host, Port: uint16(port)})
	cfg.Credential.RememberPrompted = "always"
	cfg.Credential.Stores = map[string]config.StoreConfig{"mem": {Type: config.StoreTypeHelper, Command: "unused", Timeout: time.Second}}
	repo := newTestRepository(t, cfg)
	registry := credential.NewRegistry()
	if err := registry.Register("mem", store); err != nil {
		t.Fatal(err)
	}
	service := newFormCredentialTestService(t, repo, store)
	opts := []ModelOption{WithContext(t.Context()), WithCredentialRegistry(registry), WithCredentialService(service), WithInteractionHandler(ui)}
	opts = append(opts, options...)
	model, err := NewModel(repo, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := model.Close(); err != nil && !errors.Is(err, context.Canceled) {
			t.Error(err)
		}
	})
	return &model, repo
}

func TestTUITerminalConnectionSavesAndRefreshesReferences(t *testing.T) {
	store := newMemoryCredentialStore()
	ui := &terminalTestInteraction{password: "verified-password"}
	model, repo := terminalTestModel(t, store, ui)
	model.lastSize = tea.WindowSizeMsg{Width: 100, Height: 30}
	model.list.SetFilterText("127.0.0.1")
	selected, ok := model.list.SelectedItem().(*nodeItem)
	if !ok {
		t.Fatal("expected visible test node")
	}
	selected.selected = true
	cmd := model.beginTerminalConnection(terminalMonitor, formCredentialTestNodeID)
	action := model.terminalConnection
	if cmd == nil || ui.prompts.Load() != 0 || action.access.allowed() {
		t.Fatal("connection prompted before terminal release")
	}
	if model.beginTerminalConnection(terminalLogs, formCredentialTestNodeID) != nil {
		t.Fatal("queued overlapping terminal actions")
	}
	model.Update(tickMsg{generation: model.statusGeneration})
	if model.list.FilterValue() != "127.0.0.1" {
		t.Fatal("queued status timer reset the filter during terminal handoff")
	}
	if err := action.Run(); err != nil {
		t.Fatal(err)
	}
	if action.access.allowed() {
		t.Fatal("terminal access remained active after handoff")
	}
	snapshot, err := repo.ResolveConnection(formCredentialTestNodeID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Identity.LoginPasswordRef == nil || snapshot.Identity.Password != "" {
		t.Fatal("credential did not persist as a reference")
	}
	value, err := store.Get(t.Context(), *snapshot.Identity.LoginPasswordRef)
	defer value.Zero()
	if err != nil || string(value.Value) != "verified-password" {
		t.Fatalf("saved value unavailable: %v", err)
	}
	model.handleTerminalConnection(terminalConnectionResult{action: action})
	if model.state != viewMonitor || model.terminalConnection != nil || model.listRevision != repo.View().Revision {
		t.Fatal("TUI did not adopt the updated repository view")
	}
	if model.list.FilterValue() != "127.0.0.1" || !model.list.SelectedItem().(*nodeItem).selected {
		t.Fatal("terminal return lost list selection or filter")
	}
	if _, err := action.access.PromptSecret(t.Context(), ssh.SecretRequest{}); !errors.Is(err, ssh.ErrInteractionRequired) {
		t.Fatal("background prompt allowed")
	}
}

func TestTUITerminalSaveFailureKeepsConnection(t *testing.T) {
	store := &failingCredentialStore{memoryCredentialStore: newMemoryCredentialStore(), failPut: true}
	ui := &terminalTestInteraction{password: "verified-password"}
	model, repo := terminalTestModel(t, store, ui)
	model.beginTerminalConnection(terminalLogs, formCredentialTestNodeID)
	action := model.terminalConnection
	if err := action.Run(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := action.client.SSHClient().SendRequest("connection-alive", true, nil); err != nil {
		t.Fatal(err)
	}
	snapshot, err := repo.ResolveConnection(formCredentialTestNodeID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Identity.LoginPasswordRef != nil || snapshot.Identity.Password != "" || ui.reports.Load() != 1 {
		t.Fatal("failed save altered configuration or was not reported")
	}
	model.handleTerminalConnection(terminalConnectionResult{action: action})
	if model.status == "" {
		t.Fatal("save warning was lost when the TUI resumed")
	}
}

func TestTUITerminalCancellationJoinsPrompt(t *testing.T) {
	ui := &terminalTestInteraction{block: true, entered: make(chan struct{})}
	model, _ := terminalTestModel(t, newMemoryCredentialStore(), ui)
	model.beginTerminalConnection(terminalMonitor, formCredentialTestNodeID)
	action := model.terminalConnection
	done := make(chan error, 1)
	go func() { done <- action.Run() }()
	select {
	case <-ui.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("prompt did not start")
	}
	closeErr := action.Close()
	if closeErr != nil && !errors.Is(closeErr, context.Canceled) {
		t.Fatal(closeErr)
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	if action.access.allowed() {
		t.Fatal("canceled action retained input access")
	}
	if _, err := action.connector.Connect(t.Context(), formCredentialTestNodeID); !errors.Is(err, ssh.ErrConnectorClosed) {
		t.Fatal("shared connector work survived cancellation")
	}
}

func TestTUITerminalReleaseFailureAndNeverPolicy(t *testing.T) {
	ui := &terminalTestInteraction{password: "verified-password"}
	model, repo := terminalTestModel(t, newMemoryCredentialStore(), ui, WithRememberPolicy("never"))
	model.beginTerminalConnection(terminalMonitor, formCredentialTestNodeID)
	failed := model.terminalConnection
	model.handleTerminalConnection(terminalConnectionResult{action: failed, err: errors.New("terminal release failed")})
	if ui.prompts.Load() != 0 || model.terminalConnection != nil || model.status == "" {
		t.Fatal("release failure was not safely handled")
	}
	if err := failed.Run(); !errors.Is(err, context.Canceled) {
		t.Fatal("closed action ran after release failure")
	}
	model.beginTerminalConnection(terminalMonitor, formCredentialTestNodeID)
	action := model.terminalConnection
	if err := action.Run(); err != nil {
		t.Fatal(err)
	}
	snapshot, err := repo.ResolveConnection(formCredentialTestNodeID)
	if err != nil || snapshot.Identity.LoginPasswordRef != nil || snapshot.Identity.Password != "" {
		t.Fatal("never policy persisted input")
	}
	if repo.Snapshot().Credential.RememberPrompted != "always" {
		t.Fatal("invocation override changed global policy")
	}
}

func TestTUIUnavailableSavingDoesNotBlockConnection(t *testing.T) {
	ui := &terminalTestInteraction{password: "verified-password"}
	model, repo := terminalTestModel(t, newMemoryCredentialStore(), ui, WithCredentialService(nil), WithCredentialPersistenceUnavailable(true))
	if model.status == "" {
		t.Fatal("missing saving-unavailable status")
	}
	model.beginTerminalConnection(terminalMonitor, formCredentialTestNodeID)
	action := model.terminalConnection
	if err := action.Run(); err != nil {
		t.Fatal(err)
	}
	snapshot, err := repo.ResolveConnection(formCredentialTestNodeID)
	if err != nil || snapshot.Identity.LoginPasswordRef != nil {
		t.Fatal("unavailable persistence changed credentials")
	}
	if ui.reports.Load() != 1 {
		t.Fatal("successful connection did not report unavailable saving")
	}
	if strings.Contains(model.status, "verified-password") {
		t.Fatal("secret reached TUI status")
	}
}

func TestTUITerminalAskPolicyRunsAfterAuthentication(t *testing.T) {
	for _, accept := range []bool{false, true} {
		t.Run(strconv.FormatBool(accept), func(t *testing.T) {
			ui := &terminalTestInteraction{password: "verified-password"}
			var action *terminalConnection
			var confirmations atomic.Int32
			model, repo := terminalTestModel(t, newMemoryCredentialStore(), ui, WithRememberPolicy("ask"), WithRememberConfirmation(func(context.Context, string) (bool, error) {
				if action == nil || !action.access.allowed() || ui.prompts.Load() != 1 {
					return false, errors.New("confirmation outside verified terminal action")
				}
				confirmations.Add(1)
				return accept, nil
			}))
			model.beginTerminalConnection(terminalMonitor, formCredentialTestNodeID)
			action = model.terminalConnection
			if confirmations.Load() != 0 {
				t.Fatal("asked before terminal ownership")
			}
			if err := action.Run(); err != nil {
				t.Fatal(err)
			}
			snapshot, err := repo.ResolveConnection(formCredentialTestNodeID)
			if err != nil || (snapshot.Identity.LoginPasswordRef != nil) != accept || confirmations.Load() != 1 {
				t.Fatalf("ask policy not honored: %v", err)
			}
		})
	}
}

type tuiContextResolver struct{ disabled bool }

func (r *tuiContextResolver) Resolve(ctx context.Context, _ credential.Ref) (credential.Secret, error) {
	r.disabled = credential.InteractionDisabled(ctx)
	return credential.NewSecret([]byte("existing-value")), nil
}
func TestTUIBackgroundPortsCannotPromptOrRecord(t *testing.T) {
	cfg := newFormCredentialTestConfiguration("")
	identity, _ := cfg.Identities.Get("user@192.168.1.50")
	original := credential.Ref{StoreID: "mem", ItemID: "existing"}
	identity.LoginPasswordRef = &original
	cfg.Identities.Set("user@192.168.1.50", identity)
	repo := newTestRepository(t, cfg)
	source := &tuiContextResolver{}
	access := &terminalAccess{}
	ports := &terminalCredentialPorts{SSHAdapter: adapter.NewSSHAdapter(repo, adapter.WithCredentialSource(source)), access: access}
	snapshot, err := repo.ResolveConnection(formCredentialTestNodeID)
	if err != nil {
		t.Fatal(err)
	}
	token := string(snapshot.UpdateRef.AuthVersion[:])
	secret, err := ports.ResolveSecret(t.Context(), ssh.SecretRequest{NodeID: formCredentialTestNodeID, Kind: ssh.SecretKindLoginPassword})
	clear(secret)
	if err != nil || !source.disabled {
		t.Fatalf("background backend prompt was not disabled: %v", err)
	}
	if got, err := ports.UpdateAuth(t.Context(), formCredentialTestNodeID, token, "unverified", "", ""); err != nil || got != token {
		t.Fatal("background recording attempted")
	}
	after, err := repo.ResolveConnection(formCredentialTestNodeID)
	if err != nil || *after.Identity.LoginPasswordRef != original || after.Identity.Password != "" {
		t.Fatal("background recording changed credentials")
	}
	access.active.Store(true)
	secret, err = ports.ResolveSecret(t.Context(), ssh.SecretRequest{NodeID: formCredentialTestNodeID, Kind: ssh.SecretKindLoginPassword})
	clear(secret)
	if err != nil || source.disabled {
		t.Fatal("terminal-owned backend could not interact")
	}
	secret, err = ports.ResolveSecret(credential.WithoutInteraction(t.Context()), ssh.SecretRequest{NodeID: formCredentialTestNodeID, Kind: ssh.SecretKindLoginPassword})
	clear(secret)
	if err != nil || !source.disabled {
		t.Fatal("explicit no-interaction request was bypassed")
	}
}

func TestTUITerminalConnectionDoesNotReuseOldTarget(t *testing.T) {
	secondAddress := startTUITestSSH(t)
	ui := &terminalTestInteraction{password: "verified-password"}
	model, repo := terminalTestModel(t, newMemoryCredentialStore(), ui)
	model.beginTerminalConnection(terminalMonitor, formCredentialTestNodeID)
	first := model.terminalConnection
	if err := first.Run(); err != nil {
		t.Fatal(err)
	}
	model.handleTerminalConnection(terminalConnectionResult{action: first})
	if err := model.monitor.collector.Close(); err != nil {
		t.Fatal(err)
	}
	model.state = viewList
	hostText, portText, err := net.SplitHostPort(secondAddress)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	node, host, identity, err := repo.Resolve(formCredentialTestNodeID)
	if err != nil {
		t.Fatal(err)
	}
	if hostText == "127.0.0.1" {
		hostText = "[::ffff:127.0.0.1]"
	}
	host.Address, host.Port = hostText, uint16(port)
	ref := repo.View().NodeRefs[formCredentialTestNodeID]
	if err := repo.ReplaceNodeAtRefContext(t.Context(), ref, formCredentialTestNodeID, node, host, identity); err != nil {
		t.Fatal(err)
	}
	model.beginTerminalConnection(terminalLogs, formCredentialTestNodeID)
	second := model.terminalConnection
	if err := second.Run(); err != nil {
		t.Fatal(err)
	}
	if second.client.ConnectionConfig().Port != port {
		t.Fatal("connection reused the previous target")
	}
	if _, err := first.connector.Connect(t.Context(), formCredentialTestNodeID); !errors.Is(err, ssh.ErrConnectorClosed) {
		t.Fatal("previous connector was not closed")
	}
	if ui.prompts.Load() != 1 {
		t.Fatal("saved credential was not reused across TUI actions")
	}
}

func replyTUITestGlobal(t *testing.T, ctx context.Context, request *cryptoSSH.Request) {
	t.Helper()
	if err := request.Reply(false, nil); err != nil && !errors.Is(err, io.EOF) && ctx.Err() == nil {
		t.Error(err)
	}
}
