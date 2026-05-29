package mcpserver

import (
	"context"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/mcpserver/guardrail"
	"github.com/wentf9/xops-cli/pkg/sftp"
)

// ======================== LS ========================

type FSListInput struct {
	NodeID string `json:"nodeID" jsonschema:"Node ID for the remote machine"`
	Path   string `json:"path" jsonschema:"Absolute path to the remote directory"`
}

type FileInfo struct {
	Name    string    `json:"name" jsonschema:"File name"`
	Size    int64     `json:"size" jsonschema:"Size in bytes"`
	Mode    string    `json:"mode" jsonschema:"File mode/permissions"`
	ModTime time.Time `json:"modTime" jsonschema:"Last modification time"`
	IsDir   bool      `json:"isDir" jsonschema:"True if it is a directory"`
}

type FSListOutput struct {
	Files  []FileInfo `json:"files" jsonschema:"List of files in the directory"`
	Status string     `json:"status" jsonschema:"Operation status"`
}

func fsLsHandler(ctx context.Context, req *mcp.CallToolRequest, input FSListInput) (*mcp.CallToolResult, FSListOutput, error) {
	if input.NodeID == "" || input.Path == "" {
		return nil, FSListOutput{}, fmt.Errorf("nodeID and path are required")
	}

	_, provider, _, err := utils.GetConfigStore()
	if err != nil {
		return nil, FSListOutput{}, fmt.Errorf("failed to load config: %w", err)
	}

	connector := adapter.NewConnector(provider)
	defer connector.CloseAll()

	sshClient, err := connector.Connect(ctx, input.NodeID)
	if err != nil {
		return nil, FSListOutput{}, fmt.Errorf("failed to connect to ssh: %w", err)
	}

	sftpClient, err := sftp.NewClient(sshClient)
	if err != nil {
		return nil, FSListOutput{}, fmt.Errorf("failed to create sftp client: %w", err)
	}
	defer func() { _ = sftpClient.Close() }()

	infos, err := sftpClient.SFTPClient().ReadDir(input.Path)
	if err != nil {
		return nil, FSListOutput{}, fmt.Errorf("ls failed: %w", err)
	}

	var files []FileInfo
	for _, info := range infos {
		files = append(files, FileInfo{
			Name:    info.Name(),
			Size:    info.Size(),
			Mode:    info.Mode().String(),
			ModTime: info.ModTime(),
			IsDir:   info.IsDir(),
		})
	}

	return nil, FSListOutput{
		Files:  files,
		Status: "success",
	}, nil
}

// ======================== MKDIR ========================

type FSMkdirInput struct {
	NodeID string `json:"nodeID" jsonschema:"Node ID for the remote machine"`
	Path   string `json:"path" jsonschema:"Absolute path to the directory to create"`
}

type FSBaseOutput struct {
	Status string `json:"status" jsonschema:"Operation status"`
}

func fsMkdirHandler(ctx context.Context, req *mcp.CallToolRequest, input FSMkdirInput) (*mcp.CallToolResult, FSBaseOutput, error) {
	if input.NodeID == "" || input.Path == "" {
		return nil, FSBaseOutput{}, fmt.Errorf("nodeID and path are required")
	}

	_, provider, _, err := utils.GetConfigStore()
	if err != nil {
		return nil, FSBaseOutput{}, err
	}

	connector := adapter.NewConnector(provider)
	defer connector.CloseAll()

	sshClient, err := connector.Connect(ctx, input.NodeID)
	if err != nil {
		return nil, FSBaseOutput{}, err
	}

	sftpClient, err := sftp.NewClient(sshClient)
	if err != nil {
		return nil, FSBaseOutput{}, err
	}
	defer func() { _ = sftpClient.Close() }()

	if err := sftpClient.SFTPClient().MkdirAll(input.Path); err != nil {
		return nil, FSBaseOutput{}, fmt.Errorf("mkdir failed: %w", err)
	}

	return nil, FSBaseOutput{Status: "success"}, nil
}

// ======================== TOUCH ========================

type FSTouchInput struct {
	NodeID string `json:"nodeID" jsonschema:"Node ID for the remote machine"`
	Path   string `json:"path" jsonschema:"Absolute path to the file to create"`
}

func fsTouchHandler(ctx context.Context, req *mcp.CallToolRequest, input FSTouchInput) (*mcp.CallToolResult, FSBaseOutput, error) {
	if input.NodeID == "" || input.Path == "" {
		return nil, FSBaseOutput{}, fmt.Errorf("nodeID and path are required")
	}

	_, provider, _, err := utils.GetConfigStore()
	if err != nil {
		return nil, FSBaseOutput{}, err
	}

	connector := adapter.NewConnector(provider)
	defer connector.CloseAll()

	sshClient, err := connector.Connect(ctx, input.NodeID)
	if err != nil {
		return nil, FSBaseOutput{}, err
	}

	sftpClient, err := sftp.NewClient(sshClient)
	if err != nil {
		return nil, FSBaseOutput{}, err
	}
	defer func() { _ = sftpClient.Close() }()

	file, err := sftpClient.SFTPClient().Create(input.Path)
	if err != nil {
		return nil, FSBaseOutput{}, fmt.Errorf("touch failed: %w", err)
	}
	_ = file.Close()

	return nil, FSBaseOutput{Status: "success"}, nil
}

// ======================== MV / RENAME ========================

type FSMvInput struct {
	NodeID string `json:"nodeID" jsonschema:"Node ID for the remote machine"`
	Old    string `json:"oldPath" jsonschema:"Original absolute path"`
	New    string `json:"newPath" jsonschema:"New absolute destination path"`
}

func fsMvHandler(ctx context.Context, req *mcp.CallToolRequest, input FSMvInput) (*mcp.CallToolResult, FSBaseOutput, error) {
	if input.NodeID == "" || input.Old == "" || input.New == "" {
		return nil, FSBaseOutput{}, fmt.Errorf("nodeID, oldPath and newPath are required")
	}

	_, provider, _, err := utils.GetConfigStore()
	if err != nil {
		return nil, FSBaseOutput{}, err
	}

	connector := adapter.NewConnector(provider)
	defer connector.CloseAll()

	sshClient, err := connector.Connect(ctx, input.NodeID)
	if err != nil {
		return nil, FSBaseOutput{}, err
	}

	sftpClient, err := sftp.NewClient(sshClient)
	if err != nil {
		return nil, FSBaseOutput{}, err
	}
	defer func() { _ = sftpClient.Close() }()

	if err := sftpClient.SFTPClient().Rename(input.Old, input.New); err != nil {
		return nil, FSBaseOutput{}, fmt.Errorf("mv failed: %w", err)
	}

	return nil, FSBaseOutput{Status: "success"}, nil
}

// ======================== RM (Bypass via SSH run) ========================

type FSRmInput struct {
	NodeID string `json:"nodeID" jsonschema:"Node ID for the remote machine"`
	Path   string `json:"path" jsonschema:"Absolute path to the file/directory to securely delete"`
}

func fsRmHandler(ctx context.Context, req *mcp.CallToolRequest, input FSRmInput) (*mcp.CallToolResult, FSBaseOutput, error) {
	if input.NodeID == "" || input.Path == "" {
		return nil, FSBaseOutput{}, fmt.Errorf("nodeID and path are required")
	}

	_, provider, _, err := utils.GetConfigStore()
	if err != nil {
		return nil, FSBaseOutput{}, err
	}

	connector := adapter.NewConnector(provider)
	defer connector.CloseAll()

	sshClient, err := connector.Connect(ctx, input.NodeID)
	if err != nil {
		return nil, FSBaseOutput{}, err
	}

	cmd := fmt.Sprintf("rm -rf '%s'", input.Path)
	output, err := sshClient.Run(ctx, cmd)
	if err != nil {
		return nil, FSBaseOutput{}, fmt.Errorf("rm failed: %w, output: %s", err, output)
	}

	return nil, FSBaseOutput{Status: "success"}, nil
}

// ======================== CP (Bypass via SSH run) ========================

type FSCpInput struct {
	NodeID string `json:"nodeID" jsonschema:"Node ID for the remote machine"`
	Src    string `json:"srcPath" jsonschema:"Absolute path to source"`
	Dest   string `json:"destPath" jsonschema:"Absolute path to destination"`
}

func fsCpHandler(ctx context.Context, req *mcp.CallToolRequest, input FSCpInput) (*mcp.CallToolResult, FSBaseOutput, error) {
	if input.NodeID == "" || input.Src == "" || input.Dest == "" {
		return nil, FSBaseOutput{}, fmt.Errorf("nodeID, srcPath and destPath are required")
	}

	_, provider, _, err := utils.GetConfigStore()
	if err != nil {
		return nil, FSBaseOutput{}, err
	}

	connector := adapter.NewConnector(provider)
	defer connector.CloseAll()

	sshClient, err := connector.Connect(ctx, input.NodeID)
	if err != nil {
		return nil, FSBaseOutput{}, err
	}

	cmd := fmt.Sprintf("cp -r '%s' '%s'", input.Src, input.Dest)
	output, err := sshClient.Run(ctx, cmd)
	if err != nil {
		return nil, FSBaseOutput{}, fmt.Errorf("cp failed: %w, output: %s", err, output)
	}

	return nil, FSBaseOutput{Status: "success"}, nil
}

// ======================== REGISTER ========================

func RegisterFS(server *mcp.Server, g *guardrail.Guardrail) {
	notDestructive := false
	destructive := true

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "xops_fs_ls",
			Description: "List remote directory files with attributes (size, modTime, isDir, permissions).",
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
		},
		guardrail.WithGuardrail(g, "xops_fs_ls",
			func(in FSListInput) guardrail.RiskInput {
				return guardrail.RiskInput{NodeID: in.NodeID, Paths: []string{in.Path}}
			},
			fsLsHandler,
		),
	)

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "xops_fs_mkdir",
			Description: "Create a remote directory, along with any necessary parents.",
			Annotations: &mcp.ToolAnnotations{DestructiveHint: &notDestructive},
		},
		guardrail.WithGuardrail(g, "xops_fs_mkdir",
			func(in FSMkdirInput) guardrail.RiskInput {
				return guardrail.RiskInput{NodeID: in.NodeID, Paths: []string{in.Path}}
			},
			fsMkdirHandler,
		),
	)

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "xops_fs_touch",
			Description: "Create a new empty remote file.",
			Annotations: &mcp.ToolAnnotations{DestructiveHint: &notDestructive},
		},
		guardrail.WithGuardrail(g, "xops_fs_touch",
			func(in FSTouchInput) guardrail.RiskInput {
				return guardrail.RiskInput{NodeID: in.NodeID, Paths: []string{in.Path}}
			},
			fsTouchHandler,
		),
	)

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "xops_fs_mv",
			Description: "Move or rename a remote file/directory.",
			Annotations: &mcp.ToolAnnotations{DestructiveHint: &notDestructive},
		},
		guardrail.WithGuardrail(g, "xops_fs_mv",
			func(in FSMvInput) guardrail.RiskInput {
				return guardrail.RiskInput{NodeID: in.NodeID, Paths: []string{in.Old, in.New}}
			},
			fsMvHandler,
		),
	)

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "xops_fs_rm",
			Description: "Remove a remote file or directory recursively safely.",
			Annotations: &mcp.ToolAnnotations{DestructiveHint: &destructive},
		},
		guardrail.WithGuardrail(g, "xops_fs_rm",
			func(in FSRmInput) guardrail.RiskInput {
				return guardrail.RiskInput{NodeID: in.NodeID, Paths: []string{in.Path}}
			},
			fsRmHandler,
		),
	)

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "xops_fs_cp",
			Description: "Copy a remote file or directory to another remote location recursively.",
			Annotations: &mcp.ToolAnnotations{DestructiveHint: &notDestructive},
		},
		guardrail.WithGuardrail(g, "xops_fs_cp",
			func(in FSCpInput) guardrail.RiskInput {
				return guardrail.RiskInput{NodeID: in.NodeID, Paths: []string{in.Src, in.Dest}}
			},
			fsCpHandler,
		),
	)
}
