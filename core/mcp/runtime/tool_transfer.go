package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wentf9/xops-cli/core/mcp/guardrail"
	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/mcp/transfer"
)

// TransferFileInput is the Stdio transfer tool input (direct local <-> remote SFTP).
type TransferFileInput struct {
	NodeID     string `json:"nodeID" jsonschema:"Target SSH node ID or alias"`
	Direction  string `json:"direction" jsonschema:"Transfer direction: push (upload local to remote) or pull (download remote to local)"`
	LocalPath  string `json:"localPath" jsonschema:"Absolute path to the local file or directory"`
	RemotePath string `json:"remotePath" jsonschema:"Absolute path to the remote file or directory"`
}

type TransferFileOutput struct {
	Direction string `json:"direction,omitempty" jsonschema:"Executed transfer direction"`
	Status    string `json:"status" jsonschema:"Operation status"`
}

func (r *Runtime) stdioTransferHandler(ctx context.Context, _ *mcp.CallToolRequest, input TransferFileInput) (_ *mcp.CallToolResult, _ TransferFileOutput, handlerErr error) {
	if input.NodeID == "" || input.LocalPath == "" || input.RemotePath == "" || input.Direction == "" {
		return nil, TransferFileOutput{}, fmt.Errorf("nodeID, direction, localPath, and remotePath are required")
	}
	if input.Direction != "push" && input.Direction != "pull" {
		return nil, TransferFileOutput{}, fmt.Errorf("unsupported transfer direction %q (expected push or pull)", input.Direction)
	}

	sftpClient, err := r.getMCPSFTPClient(ctx, input.NodeID)
	if err != nil {
		return nil, TransferFileOutput{}, err
	}
	defer joinCloseError(&handlerErr, sftpClient, "sftp client")

	switch input.Direction {
	case "push":
		if err := sftpClient.Upload(ctx, input.LocalPath, input.RemotePath, nil); err != nil {
			return nil, TransferFileOutput{}, fmt.Errorf("push failed: %w", err)
		}
	case "pull":
		if err := sftpClient.Download(ctx, input.RemotePath, input.LocalPath, nil); err != nil {
			return nil, TransferFileOutput{}, fmt.Errorf("pull failed: %w", err)
		}
	}

	return nil, TransferFileOutput{
		Direction: input.Direction,
		Status:    "success",
	}, nil
}

// HTTPTransferInput is the polymorphic HTTP out-of-band transfer tool input.
type HTTPTransferInput struct {
	Action     string `json:"action" jsonschema:"Transfer action: prepare_push, prepare_pull, status, or cancel"`
	RequestID  string `json:"requestID,omitempty" jsonschema:"Client-generated idempotency key for prepare_push or prepare_pull; keep the same key when retrying preparation"`
	NodeID     string `json:"nodeID,omitempty" jsonschema:"Managed SSH node ID for prepare_push or prepare_pull"`
	RemotePath string `json:"remotePath,omitempty" jsonschema:"Absolute file path on the SSH target for prepare_push or prepare_pull"`
	Size       int64  `json:"size,omitempty" jsonschema:"Exact client file size in bytes for prepare_push"`
	SHA256     string `json:"sha256,omitempty" jsonschema:"Lowercase SHA-256 of the client file for prepare_push"`
	Overwrite  bool   `json:"overwrite,omitempty" jsonschema:"Explicitly replace an existing ordinary file atomically for prepare_push; new file mode is 0600"`
	TransferID string `json:"transferID,omitempty" jsonschema:"Transfer task ID returned by prepare_push or prepare_pull, used by status and cancel"`
}

type PrepareUploadInput struct {
	Action     string `json:"action,omitempty"`
	RequestID  string `json:"requestID"`
	NodeID     string `json:"nodeID"`
	RemotePath string `json:"remotePath"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"`
	Overwrite  bool   `json:"overwrite,omitempty"`
}

type PrepareDownloadInput struct {
	Action     string `json:"action,omitempty"`
	RequestID  string `json:"requestID"`
	NodeID     string `json:"nodeID"`
	RemotePath string `json:"remotePath"`
}

type TransferTaskInput struct {
	Action     string `json:"action,omitempty"`
	TransferID string `json:"transferID"`
}

type PreparedTransferOutput struct {
	Task      transfer.Status   `json:"task"`
	URL       string            `json:"url,omitempty"`
	Method    string            `json:"method,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	StatusURL string            `json:"statusURL,omitempty"`
	CancelURL string            `json:"cancelURL,omitempty"`
}

func (r *Runtime) preparedTransfer(p transfer.Prepared) PreparedTransferOutput {
	base := r.http.PublicURL + "/v1/transfers/" + p.Status.ID
	out := PreparedTransferOutput{Task: p.Status, StatusURL: base, CancelURL: base}
	if p.Token != "" {
		out.URL = base + "/content"
		out.Method = "GET"
		out.Headers = map[string]string{"Authorization": "Bearer " + p.Token}
		if p.Status.Direction == transfer.Upload {
			out.Method = "PUT"
			out.Headers["Content-Type"] = "application/octet-stream"
		}
	}
	return out
}

func (r *Runtime) httpTransferHandler(ctx context.Context, req *mcp.CallToolRequest, input HTTPTransferInput) (*mcp.CallToolResult, PreparedTransferOutput, error) {
	action := input.Action
	if action == "" {
		switch {
		case input.TransferID != "":
			action = "status"
		case input.SHA256 != "":
			action = "prepare_push"
		case input.RequestID != "":
			action = "prepare_pull"
		}
	}

	switch action {
	case "prepare_push", "upload", "prepare_upload":
		return r.prepareUpload(ctx, req, PrepareUploadInput{
			RequestID:  input.RequestID,
			NodeID:     input.NodeID,
			RemotePath: input.RemotePath,
			Size:       input.Size,
			SHA256:     input.SHA256,
			Overwrite:  input.Overwrite,
		})
	case "prepare_pull", "download", "prepare_download":
		return r.prepareDownload(ctx, req, PrepareDownloadInput{
			RequestID:  input.RequestID,
			NodeID:     input.NodeID,
			RemotePath: input.RemotePath,
		})
	case "status":
		res, st, err := r.transferStatus(ctx, req, TransferTaskInput{TransferID: input.TransferID})
		return res, PreparedTransferOutput{Task: st}, err
	case "cancel":
		res, st, err := r.transferCancel(ctx, req, TransferTaskInput{TransferID: input.TransferID})
		return res, PreparedTransferOutput{Task: st}, err
	default:
		return nil, PreparedTransferOutput{}, fmt.Errorf("unsupported transfer action %q (expected prepare_push, prepare_pull, status, or cancel)", input.Action)
	}
}

func (r *Runtime) prepareUpload(ctx context.Context, req *mcp.CallToolRequest, input PrepareUploadInput) (*mcp.CallToolResult, PreparedTransferOutput, error) {
	input.Action = ""
	if input.Size < 0 || input.Size > r.http.Transfers.MaxFileBytes {
		return nil, PreparedTransferOutput{}, errors.New("upload size exceeds the permitted range")
	}
	digest, err := hex.DecodeString(input.SHA256)
	if err != nil || len(digest) != sha256.Size || input.SHA256 != strings.ToLower(input.SHA256) {
		return nil, PreparedTransferOutput{}, errors.New("upload requires a lowercase SHA-256 digest")
	}
	spec := transfer.Spec{RequestID: input.RequestID, NodeID: input.NodeID, RequestedPath: input.RemotePath,
		RemotePath: input.RemotePath, Direction: transfer.Upload, Size: input.Size, SHA256: input.SHA256, Overwrite: input.Overwrite}
	return r.prepareTransfer(ctx, req, spec, input)
}

func (r *Runtime) prepareDownload(ctx context.Context, req *mcp.CallToolRequest, input PrepareDownloadInput) (*mcp.CallToolResult, PreparedTransferOutput, error) {
	input.Action = ""
	spec := transfer.Spec{RequestID: input.RequestID, NodeID: input.NodeID, RequestedPath: input.RemotePath,
		RemotePath: input.RemotePath, Direction: transfer.Download}
	return r.prepareTransfer(ctx, req, spec, input)
}

func validateTransferRequest(spec transfer.Spec) error {
	if spec.RequestID == "" || len(spec.RequestID) > 128 || spec.NodeID == "" || len(spec.NodeID) > 1024 {
		return errors.New("bounded requestID and nodeID are required")
	}
	if !path.IsAbs(spec.RemotePath) || path.Clean(spec.RemotePath) == "/" || len(spec.RemotePath) > 4096 || strings.ContainsRune(spec.RemotePath, '\x00') {
		return errors.New("an absolute remote file path is required")
	}
	return nil
}

func (r *Runtime) prepareTransfer(ctx context.Context, req *mcp.CallToolRequest, spec transfer.Spec, input any) (_ *mcp.CallToolResult, _ PreparedTransferOutput, retErr error) {
	ctx, cancel := r.toolContext(ctx)
	defer cancel()
	if err := validateTransferRequest(spec); err != nil {
		return nil, PreparedTransferOutput{}, err
	}
	requestDigest, err := transferRequestDigest(spec.Direction, input)
	if err != nil {
		return nil, PreparedTransferOutput{}, err
	}
	spec.Scope, spec.RequestDigest = r.scope(ctx), requestDigest
	if existing, found, err := r.retryTransfer(ctx, spec); err != nil || found {
		if err != nil {
			return nil, PreparedTransferOutput{}, err
		}
		return nil, r.preparedTransfer(existing), nil
	}
	view, err := r.resolve(ctx, []string{spec.NodeID})
	if err != nil {
		return nil, PreparedTransferOutput{}, err
	}
	spec.NodeID, spec.TargetID, err = transferTarget(view, spec.NodeID)
	if err != nil {
		return nil, PreparedTransferOutput{}, err
	}
	ctx, _, err = r.operationContext(ctx, view, "transfer", input)
	if err != nil {
		return nil, PreparedTransferOutput{}, err
	}
	ri := transferRisk(spec)
	if r.guardrail.EvaluateContext(ctx, ri) == guardrail.Deny {
		_, pending, err := r.guardrail.Authorize(ctx, req, ri, input)
		return pending, PreparedTransferOutput{}, err
	}
	metadata, err := r.inspectTransfer(ctx, spec)
	if err != nil {
		return nil, PreparedTransferOutput{}, err
	}
	spec.RemotePath = metadata.Path
	if spec.Direction == transfer.Download {
		spec.Size, spec.SourceModTime = metadata.Size, metadata.ModTime
	}
	if spec.Size > r.http.Transfers.MaxFileBytes {
		return nil, PreparedTransferOutput{}, errors.New("source file exceeds transfer size limit")
	}
	ctx, op, err := r.operationContext(ctx, view, "transfer", spec)
	if err != nil {
		return nil, PreparedTransferOutput{}, err
	}
	opID, pending, err := r.guardrail.Authorize(ctx, req, transferRisk(spec), spec)
	if err != nil || pending != nil {
		return pending, PreparedTransferOutput{}, err
	}
	if err := ctx.Err(); err != nil {
		return nil, PreparedTransferOutput{}, fmt.Errorf("prepare transfer cancelled: %w", err)
	}
	permit, err := r.enter(ctx, op.snapshot, op.binding, ports.Inspect, opID)
	if err != nil {
		return nil, PreparedTransferOutput{}, err
	}
	defer func() { retErr = errors.Join(retErr, permit.Close()) }()
	if err := permit.Context().Err(); err != nil {
		return nil, PreparedTransferOutput{}, err
	}
	output, err := r.savePreparedTransfer(ctx, spec, opID, permit)
	return nil, output, err
}

func (r *Runtime) savePreparedTransfer(ctx context.Context, spec transfer.Spec, opID string, permit ports.Permit) (PreparedTransferOutput, error) {
	prepared, err := r.transfers.PrepareBound(spec, opID, permit)
	if err != nil {
		return PreparedTransferOutput{}, err
	}
	if err := r.guardrail.RecordAuthorizedContext(ctx, prepared.Status.OperationID, transferRisk(spec), "ready", nil); err != nil {
		_, cancelErr := r.transfers.Cancel(spec.Scope, prepared.Status.ID)
		return PreparedTransferOutput{}, errors.Join(err, cancelErr)
	}
	return r.preparedTransfer(prepared), nil
}

func transferTarget(view ports.OperationSnapshot, selector string) (string, string, error) {
	id, target, err := view.Resolve(selector)
	if err != nil {
		return "", "", err
	}
	connection := target.Plan.Hops[len(target.Plan.Hops)-1]
	address := strings.TrimSuffix(strings.ToLower(connection.Address), ".")
	if ip := net.ParseIP(address); ip != nil {
		address = ip.String()
	}
	port := connection.Port
	if port == 0 {
		// Match ssh.Connector.dialAndHandshake so an omitted default port
		// cannot bypass destination locks or unresolved-commit protection.
		port = 22
	}
	identity := net.JoinHostPort(address, strconv.Itoa(port)) + "\x00" + connection.User
	digest := sha256.Sum256([]byte(identity))
	return id, hex.EncodeToString(digest[:]), nil
}

func (r *Runtime) inspectTransfer(ctx context.Context, spec transfer.Spec) (_ remoteFileMetadata, retErr error) {
	op, ok := ctx.Value(operationKey{}).(*operation)
	if !ok {
		return remoteFileMetadata{}, errors.New("transfer inspection requires a captured operation")
	}
	permit, err := r.enter(ctx, op.snapshot, op.binding, ports.Inspect, "")
	if err != nil {
		return remoteFileMetadata{}, err
	}
	defer func() { retErr = errors.Join(retErr, permit.Close()) }()
	work, cancel, err := ports.WorkContext(ctx, permit, ports.Inspect)
	if err != nil {
		return remoteFileMetadata{}, err
	}
	defer cancel()
	if r.transferDial == nil {
		return r.backend.Inspect(work, permit, spec.NodeID, ports.InspectRequest{Path: spec.RemotePath, Upload: spec.Direction == transfer.Upload, Overwrite: spec.Overwrite})
	}
	remote, err := r.transferDial(work, spec.NodeID)
	if err != nil {
		return remoteFileMetadata{}, err
	}
	defer joinCloseError(&retErr, remote, "transfer metadata connection")
	return remote.Inspect(work, spec.RemotePath, spec.Direction == transfer.Upload, spec.Overwrite)
}

func transferRisk(spec transfer.Spec) guardrail.RiskInput {
	action := "prepare_pull"
	if spec.Direction == transfer.Upload {
		action = "prepare_push"
	}
	input := guardrail.RiskInput{ToolName: "transfer", Action: action, NodeID: spec.NodeID, Paths: []string{spec.RemotePath}}
	if spec.RequestedPath != "" && spec.RequestedPath != spec.RemotePath {
		input.Paths = append(input.Paths, spec.RequestedPath)
	}
	if spec.Direction == transfer.Upload {
		input.Details = fmt.Sprintf("size=%d bytes; SHA-256=%s; overwrite=%t; destination mode=0600", spec.Size, spec.SHA256, spec.Overwrite)
	}
	return input
}

func (r *Runtime) transferStatus(ctx context.Context, _ *mcp.CallToolRequest, input TransferTaskInput) (*mcp.CallToolResult, transfer.Status, error) {
	status, err := r.transfers.Lookup(r.scope(ctx), input.TransferID)
	return nil, status, err
}

func (r *Runtime) transferCancel(ctx context.Context, _ *mcp.CallToolRequest, input TransferTaskInput) (*mcp.CallToolResult, transfer.Status, error) {
	status, err := r.transfers.Cancel(r.scope(ctx), input.TransferID)
	if errors.Is(err, transfer.ErrInvalidState) {
		status.Warning = "commit has started or its outcome is unknown; cancellation is not confirmed"
		return nil, status, nil
	}
	if err == nil {
		err = r.auditTransfer(input.TransferID, "cancel_requested", nil)
	}
	return nil, status, err
}

func (r *Runtime) auditTransfer(id, outcome string, cause error) error {
	record, err := r.transfers.Record(id)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.ctx), 5*time.Second)
	defer cancel()
	if record.Authorization != nil {
		digest, err := record.Authorization.Binding.Digest()
		if err != nil {
			return err
		}
		ctx = guardrail.WithPolicy(ctx, record.Authorization.Snapshot.Policy, digest)
	}
	return r.guardrail.RecordAuthorizedContext(ctx, record.OperationID, transferRisk(record.Spec), outcome, cause)
}

func (r *Runtime) registerTransfer(server *mcp.Server, g *guardrail.Guardrail) {
	if r.http != nil {
		destructive := true
		mcp.AddTool(server, &mcp.Tool{
			Name:        "transfer",
			Description: "Out-of-band HTTP binary file transfer controller. Actions: 'prepare_push' (prepare single-file upload, returns PUT URL & headers), 'prepare_pull' (prepare single-file download, returns GET URL & headers), 'status' (query transfer state & SHA-256), 'cancel' (request cancellation).",
			Annotations: &mcp.ToolAnnotations{DestructiveHint: &destructive},
		}, r.httpTransferHandler)
		return
	}

	notDestructive := false
	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "transfer",
			Description: "Transfer files or directories between the local MCP host and a remote SSH node via SFTP. Directions: 'push' (local to remote) or 'pull' (remote to local).",
			Annotations: &mcp.ToolAnnotations{DestructiveHint: &notDestructive},
		},
		withOperation(r, g, "transfer",
			func(in TransferFileInput) guardrail.RiskInput {
				paths := []string{in.RemotePath}
				if in.Direction == "push" && in.LocalPath != "" {
					paths = []string{in.LocalPath, in.RemotePath}
				}
				return guardrail.RiskInput{
					Action: in.Direction,
					NodeID: in.NodeID,
					Paths:  paths,
				}
			},
			r.stdioTransferHandler,
		),
	)
}

func transferRequestDigest(direction transfer.Direction, input any) (string, error) {
	encoded, err := json.Marshal(struct {
		Direction transfer.Direction
		Input     any
	}{direction, input})
	if err != nil {
		return "", fmt.Errorf("bind transfer input: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}
