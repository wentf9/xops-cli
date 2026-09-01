package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	pkgsftp "github.com/pkg/sftp"
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
	sftpClient, err := sftp.NewClient(ctx, sshClient)
	if err != nil {
		return nil, fmt.Errorf("failed to create sftp client: %w", err)
	}

	return sftpClient, nil
}

type remoteFile interface {
	io.Reader
	io.Seeker
	Stat() (os.FileInfo, error)
	Close() error
}

func readOpenedRemoteFile(file remoteFile, input ReadFileInput) (output ReadFileOutput, retErr error) {
	defer func() {
		if closeErr := file.Close(); closeErr != nil && !errors.Is(closeErr, io.EOF) {
			retErr = errors.Join(retErr, fmt.Errorf("close remote file failed: %w", closeErr))
		}
	}()

	if input.Offset < 0 {
		return ReadFileOutput{}, fmt.Errorf("offset cannot be negative: %d", input.Offset)
	}
	if input.Limit < 0 {
		return ReadFileOutput{}, fmt.Errorf("limit cannot be negative: %d", input.Limit)
	}

	limit := input.Limit
	if limit == 0 {
		limit = defaultReadLimit
	}
	if limit > 100*1024 {
		limit = 100 * 1024 // cap at 100KB to prevent memory/context explosion
	}

	stat, statErr := file.Stat()
	if statErr != nil {
		return ReadFileOutput{}, fmt.Errorf("failed to stat file: %w", statErr)
	}

	if input.Offset > 0 {
		if _, seekErr := file.Seek(input.Offset, io.SeekStart); seekErr != nil {
			return ReadFileOutput{}, fmt.Errorf("failed to seek: %w", seekErr)
		}
	}

	limitedReader := io.LimitReader(file, limit)
	buf, readErr := io.ReadAll(limitedReader)
	if readErr != nil {
		return ReadFileOutput{}, fmt.Errorf("failed to read file: %w", readErr)
	}

	n := int64(len(buf))
	isEOF := n < limit || (input.Offset+n) >= stat.Size()

	return ReadFileOutput{
		Content: string(buf),
		EOF:     isEOF,
		Size:    stat.Size(),
		Status:  "success",
	}, nil
}

func readFileHandler(ctx context.Context, req *mcp.CallToolRequest, input ReadFileInput) (_ *mcp.CallToolResult, _ ReadFileOutput, handlerErr error) {
	if input.NodeID == "" || input.Path == "" {
		return nil, ReadFileOutput{}, fmt.Errorf("nodeID and path are required")
	}

	sftpClient, err := getSFTPClient(ctx, input.NodeID)
	if err != nil {
		return nil, ReadFileOutput{}, err
	}
	defer joinCloseError(&handlerErr, sftpClient, "sftp client")

	var output ReadFileOutput
	if err := sftpClient.Do(ctx, func(c *pkgsftp.Client) (retErr error) {
		file, openErr := c.Open(input.Path)
		if openErr != nil {
			return fmt.Errorf("failed to open remote file: %w", openErr)
		}
		var readErr error
		output, readErr = readOpenedRemoteFile(file, input)
		return readErr
	}); err != nil {
		return nil, ReadFileOutput{}, err
	}

	return nil, output, nil
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

func writeFileHandler(ctx context.Context, req *mcp.CallToolRequest, input WriteFileInput) (_ *mcp.CallToolResult, _ WriteFileOutput, handlerErr error) {
	if input.NodeID == "" || input.Path == "" || input.Content == "" {
		return nil, WriteFileOutput{}, fmt.Errorf("nodeID, path, and content are required")
	}

	sftpClient, err := getSFTPClient(ctx, input.NodeID)
	if err != nil {
		return nil, WriteFileOutput{}, err
	}
	defer joinCloseError(&handlerErr, sftpClient, "sftp client")

	flags := os.O_WRONLY | os.O_CREATE
	if input.Append {
		flags |= os.O_APPEND
	} else {
		flags |= os.O_TRUNC
	}

	var n int
	if err := sftpClient.Do(ctx, func(c *pkgsftp.Client) (retErr error) {
		file, openErr := c.OpenFile(input.Path, flags)
		if openErr != nil {
			return fmt.Errorf("failed to open remote file for writing: %w", openErr)
		}
		// Merge close error into the named return.
		defer func() {
			if closeErr := file.Close(); closeErr != nil && !errors.Is(closeErr, io.EOF) {
				retErr = errors.Join(retErr, fmt.Errorf("close remote file failed: %w", closeErr))
			}
		}()

		n, retErr = file.Write([]byte(input.Content))
		if retErr != nil {
			return fmt.Errorf("failed to write file: %w", retErr)
		}
		return nil
	}); err != nil {
		return nil, WriteFileOutput{}, err
	}

	return nil, WriteFileOutput{
		BytesWritten: n,
		Status:       "success",
	}, nil
}

func uploadFileHandler(ctx context.Context, req *mcp.CallToolRequest, input TransferFileInput) (_ *mcp.CallToolResult, _ TransferFileOutput, handlerErr error) {
	if input.NodeID == "" || input.LocalPath == "" || input.RemotePath == "" {
		return nil, TransferFileOutput{}, fmt.Errorf("nodeID, localPath, and remotePath are required")
	}

	sftpClient, err := getSFTPClient(ctx, input.NodeID)
	if err != nil {
		return nil, TransferFileOutput{}, err
	}
	defer joinCloseError(&handlerErr, sftpClient, "sftp client")

	if err := sftpClient.Upload(ctx, input.LocalPath, input.RemotePath, nil); err != nil {
		return nil, TransferFileOutput{}, fmt.Errorf("upload failed: %w", err)
	}

	return nil, TransferFileOutput{Status: "success"}, nil
}

func downloadFileHandler(ctx context.Context, req *mcp.CallToolRequest, input TransferFileInput) (_ *mcp.CallToolResult, _ TransferFileOutput, handlerErr error) {
	if input.NodeID == "" || input.LocalPath == "" || input.RemotePath == "" {
		return nil, TransferFileOutput{}, fmt.Errorf("nodeID, localPath, and remotePath are required")
	}

	sftpClient, err := getSFTPClient(ctx, input.NodeID)
	if err != nil {
		return nil, TransferFileOutput{}, err
	}
	defer joinCloseError(&handlerErr, sftpClient, "sftp client")

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
