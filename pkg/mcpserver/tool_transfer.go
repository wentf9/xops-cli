package mcpserver

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

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wentf9/xops-cli/pkg/mcpserver/guardrail"
	"github.com/wentf9/xops-cli/pkg/mcpserver/transfer"
)

type PrepareUploadInput struct {
	RequestID  string `json:"requestID" jsonschema:"Client-generated idempotency key; keep the same key when retrying preparation"`
	NodeID     string `json:"nodeID" jsonschema:"Managed SSH node ID"`
	RemotePath string `json:"remotePath" jsonschema:"Absolute destination file path on the SSH target"`
	Size       int64  `json:"size" jsonschema:"Exact client file size in bytes"`
	SHA256     string `json:"sha256" jsonschema:"Lowercase SHA-256 of the client file"`
	Overwrite  bool   `json:"overwrite,omitempty" jsonschema:"Explicitly replace an existing ordinary file atomically; new file mode is 0600"`
}

type PrepareDownloadInput struct {
	RequestID  string `json:"requestID" jsonschema:"Client-generated idempotency key"`
	NodeID     string `json:"nodeID" jsonschema:"Managed SSH node ID"`
	RemotePath string `json:"remotePath" jsonschema:"Absolute source file path on the SSH target"`
}

type TransferTaskInput struct {
	TransferID string `json:"transferID" jsonschema:"Transfer task ID returned by a prepare tool"`
}

type PreparedTransferOutput struct {
	Task      transfer.Status   `json:"task"`
	URL       string            `json:"url,omitempty"`
	Method    string            `json:"method,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	StatusURL string            `json:"statusURL"`
	CancelURL string            `json:"cancelURL"`
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

func (r *Runtime) prepareUpload(ctx context.Context, req *mcp.CallToolRequest, input PrepareUploadInput) (*mcp.CallToolResult, PreparedTransferOutput, error) {
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

func (r *Runtime) prepareTransfer(ctx context.Context, req *mcp.CallToolRequest, spec transfer.Spec, input any) (*mcp.CallToolResult, PreparedTransferOutput, error) {
	if err := validateTransferRequest(spec); err != nil {
		return nil, PreparedTransferOutput{}, err
	}
	encoded, err := json.Marshal(struct {
		Direction transfer.Direction
		Input     any
	}{spec.Direction, input})
	if err != nil {
		return nil, PreparedTransferOutput{}, fmt.Errorf("bind transfer input: %w", err)
	}
	digest := sha256.Sum256(encoded)
	spec.Scope, spec.RequestDigest = r.http.scope, hex.EncodeToString(digest[:])
	if existing, found, err := r.transfers.Retry(spec.Scope, spec.RequestID, spec.RequestDigest); err != nil || found {
		if err != nil {
			return nil, PreparedTransferOutput{}, err
		}
		return nil, r.preparedTransfer(existing), nil
	}
	spec.NodeID, spec.TargetID, err = r.resolveTransferTarget(spec.NodeID)
	if err != nil {
		return nil, PreparedTransferOutput{}, err
	}
	ri := transferRisk(spec)
	if r.guardrail.Evaluate(ri) == guardrail.Deny {
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
	opID, pending, err := r.guardrail.Authorize(ctx, req, transferRisk(spec), spec)
	if err != nil || pending != nil {
		return pending, PreparedTransferOutput{}, err
	}
	if err := ctx.Err(); err != nil {
		return nil, PreparedTransferOutput{}, fmt.Errorf("prepare transfer cancelled: %w", err)
	}
	prepared, err := r.transfers.Prepare(spec, opID)
	if err != nil {
		return nil, PreparedTransferOutput{}, err
	}
	if err := r.guardrail.RecordAuthorized(prepared.Status.OperationID, transferRisk(spec), "ready", nil); err != nil {
		_, cancelErr := r.transfers.Cancel(spec.Scope, prepared.Status.ID)
		return nil, PreparedTransferOutput{}, errors.Join(err, cancelErr)
	}
	return nil, r.preparedTransfer(prepared), nil
}

func (r *Runtime) resolveTransferTarget(selector string) (string, string, error) {
	provider := r.provider
	if provider == nil {
		return "", "", errors.New("MCP configuration is unavailable")
	}
	id, err := provider.ResolveSelector(selector)
	if err != nil {
		return "", "", err
	}
	if id == "" {
		return "", "", errors.New("transfer node does not exist")
	}
	connection, err := provider.ResolveConnection(id)
	if err != nil {
		return "", "", fmt.Errorf("resolve transfer target: %w", err)
	}
	address := strings.TrimSuffix(strings.ToLower(connection.Host.Address), ".")
	if ip := net.ParseIP(address); ip != nil {
		address = ip.String()
	}
	port := connection.Host.Port
	if port == 0 {
		// Match ssh.Connector.dialAndHandshake so an omitted default port
		// cannot bypass destination locks or unresolved-commit protection.
		port = 22
	}
	identity := net.JoinHostPort(address, strconv.Itoa(int(port))) + "\x00" + connection.Identity.User
	digest := sha256.Sum256([]byte(identity))
	return id, hex.EncodeToString(digest[:]), nil
}

func (r *Runtime) inspectTransfer(ctx context.Context, spec transfer.Spec) (_ remoteFileMetadata, retErr error) {
	remote, err := r.openTransferRemote(ctx, spec.NodeID)
	if err != nil {
		return remoteFileMetadata{}, err
	}
	defer joinCloseError(&retErr, remote, "transfer metadata connection")
	return remote.Inspect(ctx, spec.RemotePath, spec.Direction == transfer.Upload, spec.Overwrite)
}

func transferRisk(spec transfer.Spec) guardrail.RiskInput {
	input := guardrail.RiskInput{ToolName: "xops_prepare_" + string(spec.Direction), NodeID: spec.NodeID, Paths: []string{spec.RemotePath}}
	if spec.RequestedPath != "" && spec.RequestedPath != spec.RemotePath {
		input.Paths = append(input.Paths, spec.RequestedPath)
	}
	if spec.Direction == transfer.Upload {
		input.Details = fmt.Sprintf("size=%d bytes; SHA-256=%s; overwrite=%t; destination mode=0600", spec.Size, spec.SHA256, spec.Overwrite)
	}
	return input
}

func (r *Runtime) transferStatus(_ context.Context, _ *mcp.CallToolRequest, input TransferTaskInput) (*mcp.CallToolResult, transfer.Status, error) {
	status, err := r.transfers.Lookup(r.http.scope, input.TransferID)
	return nil, status, err
}

func (r *Runtime) transferCancel(_ context.Context, _ *mcp.CallToolRequest, input TransferTaskInput) (*mcp.CallToolResult, transfer.Status, error) {
	status, err := r.transfers.Cancel(r.http.scope, input.TransferID)
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
	return r.guardrail.RecordAuthorized(record.OperationID, transferRisk(record.Spec), outcome, cause)
}

func (r *Runtime) registerTransfers(server *mcp.Server) {
	destructive := true
	mcp.AddTool(server, &mcp.Tool{Name: "xops_prepare_upload", Description: "Prepare a single-file upload. Does not transfer the file. Read the CLIENT file with a local command and PUT its binary bytes to the returned URL with the returned headers. Then query task status. Overwrite requires atomic replacement; destination mode is 0600. Keep requestID when retrying preparation, never automatically retry data transfer.", Annotations: &mcp.ToolAnnotations{DestructiveHint: &destructive}}, r.prepareUpload)
	mcp.AddTool(server, &mcp.Tool{Name: "xops_prepare_download", Description: "Prepare a single-file download. Use a CLIENT-local command to GET the binary stream into a temporary file. Query status and compare size and SHA-256 before promoting the local file. Server state streamed does not confirm local saving.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}, r.prepareDownload)
	mcp.AddTool(server, &mcp.Tool{Name: "xops_transfer_status", Description: "Query transfer state, checksum and cleanup status. Never automatically retry an unknown commit.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}, r.transferStatus)
	mcp.AddTool(server, &mcp.Tool{Name: "xops_transfer_cancel", Description: "Request transfer cancellation. A committing or unknown upload cannot be reported as safely cancelled."}, r.transferCancel)
}
