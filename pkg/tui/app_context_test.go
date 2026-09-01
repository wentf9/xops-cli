package tui

import (
	"context"
	"errors"
	"io"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/ssh"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
)

func TestNewModelUsesInjectedContext(t *testing.T) {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	ctx, cancel := context.WithCancel(t.Context())
	model, err := NewModel(newTestRepository(t, cfg), WithContext(ctx))
	if err != nil {
		t.Fatalf("NewModel() error = %v", err)
	}
	t.Cleanup(func() {
		if err := model.connector.CloseAll(); err != nil {
			t.Logf("CloseAll failed: %v", err)
		}
	})

	cancel()
	if !errors.Is(model.ctx.Err(), context.Canceled) {
		t.Fatalf("expected injected context cancellation, got %v", model.ctx.Err())
	}
}

func TestLogStreamerCloseCancelsPendingCommands(t *testing.T) {
	streamer := newLogStreamerModel(t.Context(), 1, nil, "/var/log/app.log", tea.WindowSizeMsg{})
	if err := streamer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	select {
	case <-streamer.ctx.Done():
	default:
		t.Fatal("Close did not cancel the log stream context")
	}
}

type trackingReadCloser struct {
	closed bool
}

func (r *trackingReadCloser) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (r *trackingReadCloser) Close() error {
	r.closed = true
	return nil
}

func TestModelClosesStaleLogStreamSession(t *testing.T) {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	model, err := NewModel(newTestRepository(t, cfg), WithContext(t.Context()))
	if err != nil {
		t.Fatalf("NewModel() error = %v", err)
	}
	t.Cleanup(func() {
		if err := model.connector.CloseAll(); err != nil {
			t.Logf("CloseAll failed: %v", err)
		}
	})
	model.state = viewLogSelect
	model.logSessionID = 2

	reader := &trackingReadCloser{}
	updated, cmd := model.Update(logStreamSessionMsg{sessionID: 1, reader: reader})
	if cmd != nil {
		t.Fatal("stale log stream session should not schedule another command")
	}
	if updated == nil {
		t.Fatal("Update returned a nil model")
	}
	if !reader.closed {
		t.Fatal("stale log stream reader was not closed")
	}
}

func TestModelRoutesCurrentLogStreamCloseToStreamer(t *testing.T) {
	model, err := NewModel(newTestRepository(t, &config.Configuration{}), WithContext(t.Context()))
	if err != nil {
		t.Fatalf("NewModel() error = %v", err)
	}
	t.Cleanup(func() {
		if err := model.connector.CloseAll(); err != nil {
			t.Logf("CloseAll failed: %v", err)
		}
	})
	model.state = viewLogStream
	model.logSessionID = 1
	model.logStreamer = newLogStreamerModel(t.Context(), 1, nil, "/var/log/app.log", tea.WindowSizeMsg{})
	wantErr := errors.New("stream closed")

	updated, cmd := model.Update(logStreamClosedMsg{sessionID: 1, err: wantErr})
	if cmd != nil {
		t.Fatal("current log stream close should not schedule another command")
	}
	result, ok := updated.(*Model)
	if !ok {
		t.Fatalf("Update() model = %T, want *Model", updated)
	}
	if !errors.Is(result.logStreamer.err, wantErr) {
		t.Fatalf("log streamer error = %v, want %v", result.logStreamer.err, wantErr)
	}
}

func TestModelCloseClosesOwnedConnector(t *testing.T) {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	model, err := NewModel(newTestRepository(t, cfg), WithContext(t.Context()))
	if err != nil {
		t.Fatalf("NewModel() error = %v", err)
	}

	if err := model.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if _, err := model.connector.Connect(t.Context(), "missing"); !errors.Is(err, ssh.ErrConnectorClosed) {
		t.Fatalf("Connect() error after model close = %v, want ErrConnectorClosed", err)
	}
	if err := model.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}
