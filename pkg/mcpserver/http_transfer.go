package mcpserver

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wentf9/xops-cli/pkg/mcpserver/transfer"
	"github.com/wentf9/xops-cli/pkg/sftp"
)

type transferResponse struct {
	Task  *transfer.Status `json:"task,omitempty"`
	Error string           `json:"error,omitempty"`
}

func transferPath(req *http.Request) (id string, content bool, ok bool) {
	if req.URL.RawQuery != "" || req.URL.RawPath != "" {
		return "", false, false
	}
	parts := strings.Split(strings.TrimPrefix(req.URL.Path, "/v1/transfers/"), "/")
	if len(parts) > 2 || len(parts[0]) != 32 {
		return "", false, false
	}
	if _, err := hex.DecodeString(parts[0]); err != nil {
		return "", false, false
	}
	if len(parts) == 2 && parts[1] != "content" {
		return "", false, false
	}
	return parts[0], len(parts) == 2, true
}

func bearerValue(req *http.Request) string {
	fields := strings.Fields(req.Header.Get("Authorization"))
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") {
		return ""
	}
	return fields[1]
}

func (r *Runtime) serveTransferHTTP(w http.ResponseWriter, req *http.Request) {
	id, content, ok := transferPath(req)
	if !ok {
		r.transferError(w, nil, transfer.ErrUnauthorized)
		return
	}
	token := bearerValue(req)
	status, err := r.transfers.Authenticate(id, token)
	if err != nil {
		r.transferError(w, nil, err)
		return
	}
	controller := http.NewResponseController(w)
	if err := controller.SetReadDeadline(time.Now().Add(r.http.BodyTimeout)); err != nil {
		r.transferError(w, &status, err)
		return
	}
	w = &deadlineResponseWriter{ResponseWriter: w, idle: r.http.StreamIdle}
	if !content {
		r.serveTransferControl(w, req, id, token, status)
		return
	}
	expectedMethod := http.MethodGet
	if status.Direction == transfer.Upload {
		expectedMethod = http.MethodPut
	}
	if req.Method != expectedMethod {
		w.Header().Set("Allow", expectedMethod)
		r.writeTransferJSON(w, http.StatusMethodNotAllowed, transferResponse{Error: "method_not_allowed"})
		return
	}
	if err := validateTransferBody(req, status); err != nil {
		w.Header().Set("Connection", "close")
		r.writeTransferJSON(w, http.StatusBadRequest, transferResponse{Error: "invalid_transfer_body"})
		return
	}
	if status.Direction == transfer.Download {
		// There is no body left to read. A stale body deadline also expires
		// net/http's background disconnect read and cancels a healthy stream.
		if err := controller.SetReadDeadline(time.Time{}); err != nil {
			r.transferError(w, &status, err)
			return
		}
	}
	lease, err := r.transfers.Claim(req.Context(), id, token, status.Direction)
	if err != nil {
		r.transferError(w, &status, err)
		return
	}
	writer := &transferResponseWriter{ResponseWriter: w}
	final, err := r.runFileTransfer(writer, req, lease, id, controller)
	if status.Direction == transfer.Download && writer.started {
		return
	}
	if err != nil && final.State != transfer.Completed && final.State != transfer.Streamed {
		w.Header().Set("Connection", "close")
		r.transferError(w, &final, err)
		return
	}
	if status.Direction == transfer.Upload {
		r.writeTransferJSON(w, http.StatusOK, transferResponse{Task: &final})
	}
}

func validateTransferBody(req *http.Request, status transfer.Status) error {
	if status.Direction == transfer.Download {
		if req.ContentLength != 0 || len(req.TransferEncoding) != 0 {
			return errors.New("download GET cannot carry a request body")
		}
		return nil
	}
	mediaType, _, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/octet-stream" {
		return errors.New("upload requires application/octet-stream")
	}
	if req.ContentLength >= 0 && req.ContentLength != status.Size {
		return errors.New("upload Content-Length differs from approved size")
	}
	return nil
}

func (r *Runtime) serveTransferControl(w http.ResponseWriter, req *http.Request, id, token string, status transfer.Status) {
	switch req.Method {
	case http.MethodGet:
		r.writeTransferJSON(w, http.StatusOK, transferResponse{Task: &status})
	case http.MethodDelete:
		status, err := r.transfers.CancelWithToken(id, token)
		if err == nil {
			err = r.auditTransfer(id, "cancel_requested", nil)
		}
		if err != nil {
			r.transferError(w, &status, err)
			return
		}
		r.writeTransferJSON(w, http.StatusOK, transferResponse{Task: &status})
	default:
		w.Header().Set("Allow", "GET, DELETE")
		r.writeTransferJSON(w, http.StatusMethodNotAllowed, transferResponse{Error: "method_not_allowed"})
	}
}

type transferResponseWriter struct {
	http.ResponseWriter
	started bool
}

func (w *transferResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *transferResponseWriter) Write(data []byte) (int, error) {
	w.started = true
	return w.ResponseWriter.Write(data)
}
func (w *transferResponseWriter) FlushError() error {
	w.started = true
	return http.NewResponseController(w.ResponseWriter).Flush()
}

type transferRequestReader struct {
	source     io.Reader
	controller *http.ResponseController
	idle       time.Duration
}

func (r transferRequestReader) Read(data []byte) (int, error) {
	if err := r.controller.SetReadDeadline(time.Now().Add(r.idle)); err != nil {
		return 0, fmt.Errorf("renew upload read deadline: %w", err)
	}
	n, err := r.source.Read(data)
	if errors.Is(err, io.EOF) {
		// A completed body leaves net/http reading for peer disconnects. Do not
		// let the last body-read deadline cancel verification or commit setup.
		// The stream watcher and the lease still bound the remaining work.
		if clearErr := r.controller.SetReadDeadline(time.Time{}); clearErr != nil {
			return n, fmt.Errorf("clear completed upload body deadline: %w", clearErr)
		}
	}
	return n, err
}

// interruptTransferIO supplies cancellation for HTTP reads/writes that cannot
// be interrupted by closing the separate SFTP subsystem. stop joins the callback.
func (r *Runtime) interruptHTTPIO(ctx context.Context, c *http.ResponseController) func() {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(done)
		err := errors.Join(c.SetReadDeadline(time.Now()), c.SetWriteDeadline(time.Now()))
		if err != nil {
			r.logger.Debugf("interrupt transfer HTTP I/O failed: %v", err)
		}
	})
	return sync.OnceFunc(func() {
		if !stop() {
			<-done
		}
	})
}

func (r *Runtime) runFileTransfer(w *transferResponseWriter, req *http.Request, lease *transfer.Lease, id string, controller *http.ResponseController) (final transfer.Status, retErr error) {
	defer joinCloseError(&retErr, lease, "transfer lease")
	stopIO := r.interruptHTTPIO(lease.Context(), controller)
	defer stopIO()
	defer func() {
		stopIO()
		if retErr != nil {
			status, err := lease.Fail(retErr)
			final = status
			retErr = errors.Join(retErr, err)
		}
		if err := r.auditTransfer(id, string(final.State), retErr); err != nil {
			retErr = errors.Join(retErr, err, r.transfers.Warn(id, "transfer outcome audit failed; inspect status before retrying"))
		}
		if err := r.cleanupTransfer(id); err != nil {
			retErr = errors.Join(retErr, err, r.transfers.Warn(id, "temporary-file cleanup is pending"))
		}
		if status, err := r.transfers.Lookup(lease.Spec().Scope, id); err == nil {
			final = status
		} else {
			retErr = errors.Join(retErr, err)
		}
	}()
	if err := r.auditTransfer(id, "started", nil); err != nil {
		return final, err
	}
	_, target, err := r.resolveTransferTarget(lease.Spec().NodeID)
	if err != nil || target != lease.Spec().TargetID {
		return final, errors.Join(errors.New("transfer target identity changed"), err)
	}
	remote, err := r.openTransferRemote(lease.Context(), lease.Spec().NodeID)
	if err != nil {
		return final, err
	}
	defer joinCloseError(&retErr, remote, "file transfer connection")
	if lease.Spec().Direction == transfer.Upload {
		return r.runUpload(req, lease, id, controller, remote, stopIO)
	}
	return r.runDownload(w, lease, remote, stopIO)
}

func (r *Runtime) runUpload(req *http.Request, lease *transfer.Lease, id string, controller *http.ResponseController, remote transferRemote, stopIO func()) (transfer.Status, error) {
	spec := lease.Spec()
	var temporary string
	source := transferRequestReader{source: io.LimitReader(req.Body, spec.Size+1), controller: controller, idle: r.http.StreamIdle}
	result, err := r.forwardFileStream(lease.Context(), controller, lease.Progress, func(ctx context.Context, progress func(int64) error) (streamResult, error) {
		// Metadata resolution after claim is part of the same no-progress
		// window as exclusive creation and streaming, not the two-hour budget.
		metadata, err := remote.Inspect(ctx, spec.RemotePath, true, spec.Overwrite)
		if err != nil {
			return streamResult{}, err
		}
		if metadata.Path != spec.RemotePath {
			return streamResult{}, errors.New("upload destination resolution changed")
		}
		temporary, err = lease.Temporary()
		if err != nil {
			return streamResult{}, err
		}
		return remote.Upload(ctx, temporary, source, spec.Size, lease.ConfirmTemporary, progress)
	})
	if temporary != "" && !result.Created && (!result.CreationAttempted || result.CreationRejected) {
		// Exclusive-create failure does not authorize deleting a preexisting path.
		err = errors.Join(err, r.transfers.Cleaned(id))
	}
	if err != nil {
		return transfer.Status{}, err
	}
	if err := lease.Verify(result.Bytes, result.SHA256); err != nil {
		return transfer.Status{}, err
	}
	if err := r.auditTransfer(id, "commit_started", nil); err != nil {
		return transfer.Status{}, err
	}
	stopIO()
	commitCtx, err := lease.BeginCommit()
	if err != nil {
		return transfer.Status{}, err
	}
	commit, err := remote.Commit(commitCtx, temporary, spec.RemotePath, spec.Overwrite)
	if commit.Committed {
		status, finishErr := lease.Complete()
		if combined := errors.Join(err, finishErr); combined != nil {
			warnErr := r.transfers.Warn(id, "upload committed; final confirmation or metadata persistence reported an error; do not retry")
			return status, errors.Join(combined, warnErr)
		}
		return status, nil
	}
	if err == nil {
		err = errors.New("remote commit did not confirm completion")
	}
	if !commit.Attempted || commit.Rejected {
		status, finishErr := lease.RejectCommit(err)
		return status, errors.Join(err, finishErr)
	}
	return transfer.Status{}, err
}

func (r *Runtime) runDownload(w *transferResponseWriter, lease *transfer.Lease, remote transferRemote, stopIO func()) (transfer.Status, error) {
	spec := lease.Spec()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(spec.Size, 10))
	metadata := remoteFileMetadata{Path: spec.RemotePath, Size: spec.Size, ModTime: spec.SourceModTime}
	// Retain one byte until source verification/close succeeds. Otherwise a
	// Content-Length client can receive the full body and close its connection
	// before SFTP close/stat finishes, cancelling a successful download.
	tail := &transferTailWriter{destination: w}
	result, err := r.forwardFileStream(lease.Context(), http.NewResponseController(w), lease.Progress, func(ctx context.Context, progress func(int64) error) (streamResult, error) {
		return remote.Download(ctx, metadata, tail, progress)
	})
	if err != nil {
		return transfer.Status{}, err
	}
	if err := lease.Verify(result.Bytes, result.SHA256); err != nil {
		return transfer.Status{}, err
	}
	stopIO()
	if err := tail.flush(); err != nil {
		return transfer.Status{}, fmt.Errorf("finish download stream: %w", err)
	}
	if err := http.NewResponseController(w).Flush(); err != nil {
		return transfer.Status{}, fmt.Errorf("flush download stream: %w", err)
	}
	return lease.Complete()
}

type transferTailWriter struct {
	destination io.Writer
	pending     byte
	hasPending  bool
}

func (w *transferTailWriter) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	if err := w.flush(); err != nil {
		return 0, err
	}
	n, err := w.destination.Write(data[:len(data)-1])
	if err != nil {
		return n, err
	}
	if n != len(data)-1 {
		return n, io.ErrShortWrite
	}
	w.pending, w.hasPending = data[len(data)-1], true
	return len(data), nil
}

func (w *transferTailWriter) flush() error {
	if !w.hasPending {
		return nil
	}
	w.hasPending = false
	n, err := w.destination.Write([]byte{w.pending})
	if err != nil {
		return err
	}
	if n != 1 {
		return io.ErrShortWrite
	}
	return nil
}

// cleanupTransfer uses a new bounded context and subsystem, never the failed
// transfer connection. It refuses uncertain commits and revalidates target IDs.
func (r *Runtime) cleanupTransfer(id string) error {
	return r.cleanupTransferContext(context.WithoutCancel(r.ctx), id)
}

func (r *Runtime) cleanupTransferContext(parent context.Context, id string) error {
	record, err := r.transfers.Record(id)
	if err != nil {
		return err
	}
	if !record.CleanupPending || (record.State == transfer.Unknown && !record.Resolved) {
		return nil
	}
	if !record.TempOwned {
		return errors.New("temporary creation was not confirmed; verify ownership before manual cleanup")
	}
	_, target, err := r.resolveTransferTarget(record.Spec.NodeID)
	if err != nil || target != record.Spec.TargetID {
		return errors.Join(errors.New("cannot clean temporary file after target identity changed"), err)
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	var cleanupErr error
	for attempt := 0; attempt < 3; attempt++ {
		if err := ctx.Err(); err != nil {
			return errors.Join(cleanupErr, err)
		}
		cleanupErr = r.removeTransferTemporary(ctx, record.Spec.NodeID, record.TempPath)
		if cleanupErr == nil {
			return errors.Join(r.transfers.Cleaned(id), r.auditTransfer(id, "cleaned", nil))
		}
	}
	return errors.Join(cleanupErr, r.auditTransfer(id, "cleanup_pending", cleanupErr))
}

func (r *Runtime) removeTransferTemporary(ctx context.Context, nodeID, temporary string) (retErr error) {
	var remote transferRemote
	if r.transferDial != nil {
		var err error
		remote, err = r.transferDial(ctx, nodeID)
		if err != nil {
			return err
		}
	} else {
		client, err := r.connector.Connect(ctx, nodeID)
		if err != nil {
			return fmt.Errorf("connect for transfer cleanup: %w", err)
		}
		sftpClient, err := sftp.NewClient(ctx, client)
		if err != nil {
			return fmt.Errorf("open SFTP cleanup channel: %w", err)
		}
		remote = &sftpTransferRemote{client: sftpClient}
	}
	defer joinCloseError(&retErr, remote, "cleanup connection")
	return remote.Remove(ctx, temporary)
}

func (r *Runtime) transferError(w http.ResponseWriter, status *transfer.Status, err error) {
	code, message := http.StatusBadGateway, "transfer_failed"
	switch {
	case errors.Is(err, transfer.ErrUnauthorized):
		code, message = http.StatusUnauthorized, "invalid_transfer_credential"
	case errors.Is(err, transfer.ErrExpired):
		code, message = http.StatusGone, "transfer_expired"
	case errors.Is(err, transfer.ErrBusy):
		code, message = http.StatusTooManyRequests, "transfer_busy"
	case errors.Is(err, transfer.ErrConflict), errors.Is(err, transfer.ErrInvalidState):
		code, message = http.StatusConflict, "transfer_conflict"
	case errors.Is(err, transfer.ErrClosed), errors.Is(err, transfer.ErrStoreUnusable):
		code, message = http.StatusServiceUnavailable, "transfer_unavailable"
	case status != nil && status.State == transfer.Unknown:
		code, message = http.StatusConflict, "commit_outcome_unknown"
	}
	r.writeTransferJSON(w, code, transferResponse{Task: status, Error: message})
}

func (r *Runtime) writeTransferJSON(w http.ResponseWriter, code int, value transferResponse) {
	w.Header().Del("Content-Length")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		r.logger.Debugf("write transfer HTTP result failed: %v", err)
	}
}
