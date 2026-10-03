package runtime

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	pkgsftp "github.com/pkg/sftp"
	"github.com/wentf9/xops-cli/core/mcp/guardrail"
	"github.com/wentf9/xops-cli/core/mcp/transfer"
)

type uploadDeadlineWriter struct {
	*httptest.ResponseRecorder
	deadlines []time.Time
	renewErr  error
	clearErr  error
}

func (w *uploadDeadlineWriter) SetReadDeadline(deadline time.Time) error {
	w.deadlines = append(w.deadlines, deadline)
	if deadline.IsZero() {
		return w.clearErr
	}
	return w.renewErr
}

type uploadReadFunc func([]byte) (int, error)

func (f uploadReadFunc) Read(p []byte) (int, error) { return f(p) }

func TestUploadReadDeadlineEOF(t *testing.T) {
	for _, payload := range []string{"", "body"} {
		t.Run(payload, func(t *testing.T) {
			writer := &uploadDeadlineWriter{ResponseRecorder: httptest.NewRecorder()}
			reader := transferRequestReader{source: bytes.NewBufferString(payload), controller: http.NewResponseController(writer), idle: time.Second}
			data, err := io.ReadAll(reader)
			if err != nil || string(data) != payload {
				t.Fatalf("read body: %q, %v", data, err)
			}
			if len(writer.deadlines) < 2 || !writer.deadlines[len(writer.deadlines)-1].IsZero() {
				t.Fatalf("completed body retained a read deadline: %v", writer.deadlines)
			}
			for _, deadline := range writer.deadlines[:len(writer.deadlines)-1] {
				if deadline.IsZero() {
					t.Fatal("body read was not protected by a deadline")
				}
			}
		})
	}
}

func TestUploadReadDeadlineErrors(t *testing.T) {
	fault := errors.New("injected read deadline failure")
	for _, phase := range []string{"renew", "clear", "source"} {
		t.Run(phase, func(t *testing.T) {
			writer := &uploadDeadlineWriter{ResponseRecorder: httptest.NewRecorder()}
			switch phase {
			case "renew":
				writer.renewErr = fault
			case "clear":
				writer.clearErr = fault
			}
			read := false
			source := uploadReadFunc(func(p []byte) (int, error) {
				read = true
				if phase == "source" {
					return 0, fault
				}
				return copy(p, "body"), io.EOF
			})
			reader := transferRequestReader{source: source, controller: http.NewResponseController(writer), idle: time.Second}
			n, err := reader.Read(make([]byte, 4))
			if !errors.Is(err, fault) || errors.Is(err, io.EOF) {
				t.Fatalf("deadline failure was lost or reported as successful EOF: %v", err)
			}
			if phase == "renew" && read {
				t.Fatal("read body without establishing a deadline")
			}
			if phase == "clear" && n != 4 {
				t.Fatalf("lost bytes returned with EOF: %d", n)
			}
			if phase != "clear" && (len(writer.deadlines) != 1 || writer.deadlines[0].IsZero()) {
				t.Fatalf("cleared deadline before EOF: %v", writer.deadlines)
			}
		})
	}
}

type delayedCommitAudit struct {
	ctx     context.Context
	entered atomic.Bool
}

func (a *delayedCommitAudit) Log(entry guardrail.AuditEntry) error {
	if entry.Outcome == "commit_started" {
		a.entered.Store(true)
		// Model verification/audit persistence taking longer than the final
		// body-read deadline, after the stream's own idle watcher has stopped.
		return waitTransferTestDelay(a.ctx, transferTestIdle+time.Second)
	}
	return nil
}

func TestUploadVerificationOutlivesBodyReadDeadline(t *testing.T) {
	for _, payload := range [][]byte{nil, []byte("complete upload body")} {
		name := "nonempty"
		if len(payload) == 0 {
			name = "empty"
		}
		t.Run(name, func(t *testing.T) {
			audit := &delayedCommitAudit{ctx: t.Context()}
			r, server, client := startTransferRuntime(t, func(o *HTTPOptions) {
				o.StreamIdle = transferTestIdle
			}, pkgsftp.InMemHandler(), func(r *Runtime) {
				r.guardrail.SetAuditWriter(audit)
			})
			p := prepareTransferTest(t, client, "xops_prepare_upload", uploadBoundaryInput("slow-verification", "/destination", payload))
			response, body := transferTestRequest(t, server, p.Method, p.URL, p.Headers, bytes.NewReader(payload))
			if !audit.entered.Load() {
				t.Fatal("upload never reached verification/commit boundary")
			}
			if response.StatusCode != http.StatusOK {
				t.Fatalf("completed upload body cancelled verification: %d %s", response.StatusCode, body)
			}
			status := transferTestStatus(t, server, p)
			if status.State != transfer.Completed || status.Bytes != int64(len(payload)) {
				t.Fatalf("upload not committed: %+v", status)
			}
			withBoundarySFTP(t, r, func(c *pkgsftp.Client) error {
				info, err := c.Stat("/destination")
				if err == nil && info.Size() != int64(len(payload)) {
					t.Errorf("committed size = %d, want %d", info.Size(), len(payload))
				}
				return err
			})
		})
	}
}
