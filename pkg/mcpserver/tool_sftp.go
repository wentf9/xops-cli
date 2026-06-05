package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wentf9/xops-cli/pkg/mcpserver/guardrail"
	"github.com/wentf9/xops-cli/pkg/sftp"
)

type TransferFileInput struct {
	NodeID     string `json:"nodeID" jsonschema:"Node ID for the remote machine"`
	LocalPath  string `json:"localPath" jsonschema:"Absolute path to the local file or directory"`
	RemotePath string `json:"remotePath" jsonschema:"Absolute path to the remote file or directory"`
}

type TransferFileOutput struct {
	Status string `json:"status" jsonschema:"Operation status"`
}

const defaultReadLimit int64 = 50 * 1024 // 50KB default

type ReadFileInput struct {
	NodeID string `json:"nodeID" jsonschema:"Node ID for the remote machine"`
	Path   string `json:"path" jsonschema:"Absolute path to the remote file"`
	Offset int64  `json:"offset,omitempty" jsonschema:"Byte offset to start reading from"`
	Limit  int64  `json:"limit,omitempty" jsonschema:"Max bytes to read (default 50KB, max 100KB)"`
}

type ReadFileOutput struct {
	Content string `json:"content" jsonschema:"File content represented as string"`
	EOF     bool   `json:"eof" jsonschema:"True if end of file reached"`
	Size    int64  `json:"size" jsonschema:"Total size of the remote file"`
	Status  string `json:"status" jsonschema:"Operation status"`
}

func getSFTPClient(ctx context.Context, nodeID string) (*sftp.Client, error) {
	connector, err := getMCPConnector()
	if err != nil {
		return nil, err
	}

	sshClient, err := connector.Connect(ctx, nodeID)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to ssh: %w", err)
	}

	// TODO(optimization): Consider caching/pooling *sftp.Client instances per node to avoid
	// creating and closing SFTP subsystems (SSH channel negotiation + SFTP handshake) on every call.
	sftpClient, err := sftp.NewClient(sshClient)
	if err != nil {
		return nil, fmt.Errorf("failed to create sftp client: %w", err)
	}

	return sftpClient, nil
}

func readFileHandler(ctx context.Context, req *mcp.CallToolRequest, input ReadFileInput) (*mcp.CallToolResult, ReadFileOutput, error) {
	if input.NodeID == "" || input.Path == "" {
		return nil, ReadFileOutput{}, fmt.Errorf("nodeID and path are required")
	}

	limit := input.Limit
	if limit <= 0 {
		limit = defaultReadLimit
	}
	if limit > 100*1024 {
		limit = 100 * 1024 // cap at 100KB to prevent memory/context explosion
	}

	sftpClient, err := getSFTPClient(ctx, input.NodeID)
	if err != nil {
		return nil, ReadFileOutput{}, err
	}
	defer func() { _ = sftpClient.Close() }()

	file, err := sftpClient.SFTPClient().Open(input.Path)
	if err != nil {
		return nil, ReadFileOutput{}, fmt.Errorf("failed to open remote file: %w", err)
	}
	defer func() { _ = file.Close() }()

	stat, err := file.Stat()
	if err != nil {
		return nil, ReadFileOutput{}, fmt.Errorf("failed to stat file: %w", err)
	}

	if input.Offset > 0 {
		if _, err := file.Seek(input.Offset, io.SeekStart); err != nil {
			return nil, ReadFileOutput{}, fmt.Errorf("failed to seek: %w", err)
		}
	}

	buf := make([]byte, limit)
	n, readErr := file.Read(buf)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return nil, ReadFileOutput{}, fmt.Errorf("failed to read file: %w", readErr)
	}

	isEOF := errors.Is(readErr, io.EOF) || int64(n) < limit || (input.Offset+int64(n)) >= stat.Size()

	return nil, ReadFileOutput{
		Content: string(buf[:n]),
		EOF:     isEOF,
		Size:    stat.Size(),
		Status:  "success",
	}, nil
}

type WriteFileInput struct {
	NodeID  string `json:"nodeID" jsonschema:"Node ID for the remote machine"`
	Path    string `json:"path" jsonschema:"Absolute path to the remote file"`
	Content string `json:"content" jsonschema:"Content to write"`
	Append  bool   `json:"append,omitempty" jsonschema:"If true, append to existing file; if false, overwrite completely"`
}

type WriteFileOutput struct {
	BytesWritten int    `json:"bytesWritten" jsonschema:"Number of bytes written"`
	Status       string `json:"status" jsonschema:"Operation status"`
}

func writeFileHandler(ctx context.Context, req *mcp.CallToolRequest, input WriteFileInput) (*mcp.CallToolResult, WriteFileOutput, error) {
	if input.NodeID == "" || input.Path == "" || input.Content == "" {
		return nil, WriteFileOutput{}, fmt.Errorf("nodeID, path, and content are required")
	}

	sftpClient, err := getSFTPClient(ctx, input.NodeID)
	if err != nil {
		return nil, WriteFileOutput{}, err
	}
	defer func() { _ = sftpClient.Close() }()

	flags := os.O_WRONLY | os.O_CREATE
	if input.Append {
		flags |= os.O_APPEND
	} else {
		flags |= os.O_TRUNC
	}

	file, err := sftpClient.SFTPClient().OpenFile(input.Path, flags)
	if err != nil {
		return nil, WriteFileOutput{}, fmt.Errorf("failed to open remote file for writing: %w", err)
	}
	defer func() { _ = file.Close() }()

	n, err := file.Write([]byte(input.Content))
	if err != nil {
		return nil, WriteFileOutput{}, fmt.Errorf("failed to write file: %w", err)
	}

	return nil, WriteFileOutput{
		BytesWritten: n,
		Status:       "success",
	}, nil
}

func uploadFileHandler(ctx context.Context, req *mcp.CallToolRequest, input TransferFileInput) (*mcp.CallToolResult, TransferFileOutput, error) {
	if input.NodeID == "" || input.LocalPath == "" || input.RemotePath == "" {
		return nil, TransferFileOutput{}, fmt.Errorf("nodeID, localPath, and remotePath are required")
	}

	sftpClient, err := getSFTPClient(ctx, input.NodeID)
	if err != nil {
		return nil, TransferFileOutput{}, err
	}
	defer func() { _ = sftpClient.Close() }()

	if err := sftpClient.Upload(ctx, input.LocalPath, input.RemotePath, nil); err != nil {
		return nil, TransferFileOutput{}, fmt.Errorf("upload failed: %w", err)
	}

	return nil, TransferFileOutput{Status: "success"}, nil
}

func downloadFileHandler(ctx context.Context, req *mcp.CallToolRequest, input TransferFileInput) (*mcp.CallToolResult, TransferFileOutput, error) {
	if input.NodeID == "" || input.LocalPath == "" || input.RemotePath == "" {
		return nil, TransferFileOutput{}, fmt.Errorf("nodeID, localPath, and remotePath are required")
	}

	sftpClient, err := getSFTPClient(ctx, input.NodeID)
	if err != nil {
		return nil, TransferFileOutput{}, err
	}
	defer func() { _ = sftpClient.Close() }()

	if err := sftpClient.Download(ctx, input.RemotePath, input.LocalPath, nil); err != nil {
		return nil, TransferFileOutput{}, fmt.Errorf("download failed: %w", err)
	}

	return nil, TransferFileOutput{Status: "success"}, nil
}

func RegisterSFTP(server *mcp.Server, g *guardrail.Guardrail) {
	notDestructive := false

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "xops_read_file",
			Description: "Read a remote file via SFTP. Supports chunked reading via offset and limit to prevent memory overflow on large files. Returns EOF=true if the end of file is reached.",
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
		},
		guardrail.WithGuardrail(g, "xops_read_file",
			func(in ReadFileInput) guardrail.RiskInput {
				return guardrail.RiskInput{NodeID: in.NodeID, Paths: []string{in.Path}}
			},
			readFileHandler,
		),
	)

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "xops_write_file",
			Description: "Write or append content to a remote file via SFTP. Use the append flag for chunked writing of large files.",
			Annotations: &mcp.ToolAnnotations{DestructiveHint: &notDestructive},
		},
		guardrail.WithGuardrail(g, "xops_write_file",
			func(in WriteFileInput) guardrail.RiskInput {
				return guardrail.RiskInput{NodeID: in.NodeID, Paths: []string{in.Path}}
			},
			writeFileHandler,
		),
	)

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "xops_upload",
			Description: "Upload a local file or directory (from the machine running the MCP server) to the remote node via SFTP. Highly concurrent.",
			Annotations: &mcp.ToolAnnotations{DestructiveHint: &notDestructive},
		},
		guardrail.WithGuardrail(g, "xops_upload",
			func(in TransferFileInput) guardrail.RiskInput {
				return guardrail.RiskInput{NodeID: in.NodeID, Paths: []string{in.LocalPath, in.RemotePath}}
			},
			uploadFileHandler,
		),
	)

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "xops_download",
			Description: "Download a remote file or directory from the node to the machine running the MCP server via SFTP. Highly concurrent.",
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
		},
		guardrail.WithGuardrail(g, "xops_download",
			func(in TransferFileInput) guardrail.RiskInput {
				return guardrail.RiskInput{NodeID: in.NodeID, Paths: []string{in.RemotePath}}
			},
			downloadFileHandler,
		),
	)
}
