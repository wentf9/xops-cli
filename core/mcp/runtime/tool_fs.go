package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	pkgsftp "github.com/pkg/sftp"
	"github.com/wentf9/xops-cli/core/mcp/guardrail"
	"github.com/wentf9/xops-cli/core/mcp/ports"
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

func (r *Runtime) fsLsHandler(ctx context.Context, req *mcp.CallToolRequest, input FSListInput) (_ *mcp.CallToolResult, _ FSListOutput, handlerErr error) {
	if input.NodeID == "" || input.Path == "" {
		return nil, FSListOutput{}, fmt.Errorf("nodeID and path are required")
	}

	sftpClient, err := r.getMCPSFTPClient(ctx, input.NodeID)
	if err != nil {
		return nil, FSListOutput{}, err
	}
	defer joinCloseError(&handlerErr, sftpClient, "sftp client")

	var infos []os.FileInfo
	err = sftpClient.Do(ctx, func(c *pkgsftp.Client) error {
		var readErr error
		infos, readErr = c.ReadDir(input.Path)
		return readErr
	})
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

func (r *Runtime) fsMkdirHandler(ctx context.Context, req *mcp.CallToolRequest, input FSMkdirInput) (_ *mcp.CallToolResult, _ FSBaseOutput, handlerErr error) {
	if input.NodeID == "" || input.Path == "" {
		return nil, FSBaseOutput{}, fmt.Errorf("nodeID and path are required")
	}

	sftpClient, err := r.getMCPSFTPClient(ctx, input.NodeID)
	if err != nil {
		return nil, FSBaseOutput{}, err
	}
	defer joinCloseError(&handlerErr, sftpClient, "sftp client")

	if err := sftpClient.Do(ctx, func(c *pkgsftp.Client) error {
		return c.MkdirAll(input.Path)
	}); err != nil {
		return nil, FSBaseOutput{}, fmt.Errorf("mkdir failed: %w", err)
	}

	return nil, FSBaseOutput{Status: "success"}, nil
}

// ======================== TOUCH ========================

type FSTouchInput struct {
	NodeID string `json:"nodeID" jsonschema:"Node ID for the remote machine"`
	Path   string `json:"path" jsonschema:"Absolute path to the file to create"`
}

func (r *Runtime) fsTouchHandler(ctx context.Context, req *mcp.CallToolRequest, input FSTouchInput) (_ *mcp.CallToolResult, _ FSBaseOutput, handlerErr error) {
	if input.NodeID == "" || input.Path == "" {
		return nil, FSBaseOutput{}, fmt.Errorf("nodeID and path are required")
	}

	sftpClient, err := r.getMCPSFTPClient(ctx, input.NodeID)
	if err != nil {
		return nil, FSBaseOutput{}, err
	}
	defer joinCloseError(&handlerErr, sftpClient, "sftp client")

	if err := sftpClient.Do(ctx, func(c *pkgsftp.Client) error {
		file, err := c.Create(input.Path)
		if err == nil {
			return file.Close()
		}
		return err
	}); err != nil {
		return nil, FSBaseOutput{}, fmt.Errorf("touch failed: %w", err)
	}

	return nil, FSBaseOutput{Status: "success"}, nil
}

// ======================== MV / RENAME ========================

type FSMvInput struct {
	NodeID string `json:"nodeID" jsonschema:"Node ID for the remote machine"`
	Old    string `json:"oldPath" jsonschema:"Original absolute path"`
	New    string `json:"newPath" jsonschema:"New absolute destination path"`
}

func (r *Runtime) fsMvHandler(ctx context.Context, req *mcp.CallToolRequest, input FSMvInput) (_ *mcp.CallToolResult, _ FSBaseOutput, handlerErr error) {
	if input.NodeID == "" || input.Old == "" || input.New == "" {
		return nil, FSBaseOutput{}, fmt.Errorf("nodeID, oldPath and newPath are required")
	}

	sftpClient, err := r.getMCPSFTPClient(ctx, input.NodeID)
	if err != nil {
		return nil, FSBaseOutput{}, err
	}
	defer joinCloseError(&handlerErr, sftpClient, "sftp client")

	if err := sftpClient.Do(ctx, func(c *pkgsftp.Client) error {
		return c.Rename(input.Old, input.New)
	}); err != nil {
		return nil, FSBaseOutput{}, fmt.Errorf("mv failed: %w", err)
	}

	return nil, FSBaseOutput{Status: "success"}, nil
}

// ======================== RM ========================

type FSRmInput struct {
	NodeID string `json:"nodeID" jsonschema:"Node ID for the remote machine"`
	Path   string `json:"path" jsonschema:"Absolute path to the file/directory to securely delete"`
}

func (r *Runtime) fsRmHandler(ctx context.Context, req *mcp.CallToolRequest, input FSRmInput) (_ *mcp.CallToolResult, _ FSBaseOutput, handlerErr error) {
	if input.NodeID == "" || input.Path == "" {
		return nil, FSBaseOutput{}, fmt.Errorf("nodeID and path are required")
	}
	if isRootEquivalentPath(input.Path) {
		return nil, FSBaseOutput{}, fmt.Errorf("rm failed: refusing to remove root directory %q (preserve-root)", input.Path)
	}
	if hasTerminalDotComponent(input.Path) {
		return nil, FSBaseOutput{}, fmt.Errorf("rm failed: refusing to remove %q: path ends with '.' or '..'", input.Path)
	}

	sftpClient, err := r.getMCPSFTPClient(ctx, input.NodeID)
	if err != nil {
		return nil, FSBaseOutput{}, err
	}
	defer joinCloseError(&handlerErr, sftpClient, "sftp client")

	if err := validateRmPath(ctx, sftpClient, input.Path); err != nil {
		return nil, FSBaseOutput{}, fmt.Errorf("rm failed: %w", err)
	}

	if err := sftpClient.RemoveAll(ctx, input.Path); err != nil {
		return nil, FSBaseOutput{}, fmt.Errorf("rm failed: %w", err)
	}

	return nil, FSBaseOutput{Status: "success"}, nil
}

func validateRmPath(ctx context.Context, sftpClient ports.FileSession, rawPath string) error {
	hasTrailingSlash := strings.HasSuffix(rawPath, "/")
	entryPath := strings.TrimRight(rawPath, "/")
	if entryPath == "" {
		entryPath = "/"
	}

	info, statErr := sftpClient.Lstat(ctx, rawPath)
	if statErr == nil && ((info.IsDir() && info.Mode()&os.ModeSymlink == 0) || hasTrailingSlash) {
		resolved, realErr := sftpClient.RealPath(ctx, rawPath)
		if realErr != nil {
			return realErr
		}
		if isRootEquivalentPath(resolved) {
			return fmt.Errorf("refusing to remove root directory %q (preserve-root)", rawPath)
		}
	} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) && !os.IsNotExist(statErr) {
		return statErr
	}

	if hasTrailingSlash && entryPath != "/" {
		entryInfo, entryErr := sftpClient.Lstat(ctx, entryPath)
		if entryErr == nil && entryInfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to remove symbolic link %q with trailing slash", rawPath)
		} else if entryErr != nil && !errors.Is(entryErr, os.ErrNotExist) && !os.IsNotExist(entryErr) {
			return entryErr
		}
	}

	return nil
}

func isRootEquivalentPath(raw string) bool {
	if strings.TrimSpace(raw) == "" {
		return true
	}
	normalized := strings.ReplaceAll(raw, "\\", "/")
	cleaned := path.Clean(normalized)

	if cleaned == "/" || cleaned == "." || cleaned == ".." {
		return true
	}

	cleanedDrive := strings.TrimPrefix(cleaned, "/")
	if len(cleanedDrive) == 2 && cleanedDrive[1] == ':' && isAlpha(cleanedDrive[0]) {
		return true
	}
	if len(cleanedDrive) == 3 && cleanedDrive[1] == ':' && cleanedDrive[2] == '/' && isAlpha(cleanedDrive[0]) {
		return true
	}

	return false
}

func isAlpha(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// ======================== CP ========================

type FSCpInput struct {
	NodeID string `json:"nodeID" jsonschema:"Node ID for the remote machine"`
	Src    string `json:"srcPath" jsonschema:"Absolute path to source"`
	Dest   string `json:"destPath" jsonschema:"Absolute path to destination"`
}

func (r *Runtime) fsCpHandler(ctx context.Context, req *mcp.CallToolRequest, input FSCpInput) (_ *mcp.CallToolResult, _ FSBaseOutput, handlerErr error) {
	if input.NodeID == "" || input.Src == "" || input.Dest == "" {
		return nil, FSBaseOutput{}, fmt.Errorf("nodeID, srcPath and destPath are required")
	}

	sftpClient, err := r.getMCPSFTPClient(ctx, input.NodeID)
	if err != nil {
		return nil, FSBaseOutput{}, err
	}
	defer joinCloseError(&handlerErr, sftpClient, "sftp client")

	effectiveSrc, err := resolveCopySource(ctx, sftpClient, input.Src)
	if err != nil {
		return nil, FSBaseOutput{}, fmt.Errorf("cp failed: %w", err)
	}

	effectiveDest, err := resolveCopyDestination(ctx, sftpClient, input.Src, effectiveSrc, input.Dest)
	if err != nil {
		return nil, FSBaseOutput{}, fmt.Errorf("cp failed: %w", err)
	}

	if err := sftpClient.RemoteCopy(ctx, effectiveSrc, effectiveDest); err != nil {
		return nil, FSBaseOutput{}, fmt.Errorf("cp failed: %w", err)
	}

	return nil, FSBaseOutput{Status: "success"}, nil
}

// resolveCopySource preserves unqualified symbolic-link entries. A trailing
// slash or terminal /. requests a directory referent instead. The original
// operand is kept separately for destination naming (link/, unlike link/.,
// still contributes the link's basename rather than its referent's basename).
func resolveCopySource(ctx context.Context, files ports.FileSession, src string) (string, error) {
	if !hasTrailingDot(src) && !strings.HasSuffix(src, "/") {
		return src, nil
	}
	resolved, err := resolveCopyReferent(ctx, files, src)
	if err != nil {
		return "", fmt.Errorf("resolve source directory failed: %w", err)
	}
	info, err := files.Stat(ctx, resolved)
	if err != nil {
		return "", fmt.Errorf("stat source directory failed: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("source %q is not a directory", src)
	}
	return resolved, nil
}

// SFTP paths use / only. Whitespace and backslashes are literal filename bytes;
// trimming them can turn a requested file into a different directory operand.
func hasTrailingDot(raw string) bool {
	trimmed := strings.TrimRight(raw, "/")
	return trimmed == "." || strings.HasSuffix(trimmed, "/.")
}

// Some SFTP peers implement REALPATH lexically, without dereferencing the final
// symbolic link. Resolve that entry explicitly before an entry-replacing copy.
func resolveCopyReferent(ctx context.Context, files ports.FileSession, remotePath string) (string, error) {
	resolved, err := files.RealPath(ctx, remotePath)
	if err != nil {
		return "", err
	}
	const maxLinks = 40
	for followed := 0; ; followed++ {
		info, err := files.Lstat(ctx, resolved)
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink == 0 {
			return resolved, nil
		}
		if followed == maxLinks {
			return "", fmt.Errorf("too many symbolic links resolving copy path %q", remotePath)
		}
		var target string
		if err := files.Do(ctx, func(c *pkgsftp.Client) error {
			var readErr error
			target, readErr = c.ReadLink(resolved)
			return readErr
		}); err != nil {
			return "", fmt.Errorf("read copy symbolic link %q failed: %w", resolved, err)
		}
		if !path.IsAbs(target) {
			target = path.Join(path.Dir(resolved), target)
		}
		resolved, err = files.RealPath(ctx, target)
		if err != nil {
			return "", err
		}
	}
}

// hasTerminalDotComponent reports whether the last path component is "." or
// "..", which rm -rf refuses to operate on.
func hasTerminalDotComponent(raw string) bool {
	trimmed := strings.TrimRight(raw, "/")
	last := trimmed
	if i := strings.LastIndex(trimmed, "/"); i >= 0 {
		last = trimmed[i+1:]
	}
	return last == "." || last == ".."
}

func resolveCopyDestination(ctx context.Context, files ports.FileSession, src, resolvedSrc, dest string) (string, error) {
	info, err := files.Stat(ctx, dest)
	if err == nil && info.IsDir() {
		if !hasTrailingDot(src) {
			// Use the literal source operand for naming, not the referent path.
			base := path.Base(strings.TrimRight(src, "/"))
			if base != "." && base != "/" && base != "" {
				dest = path.Join(dest, base)
			}
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("stat destination failed: %w", err)
	} else if strings.HasSuffix(dest, "/") {
		return "", fmt.Errorf("destination directory %q does not exist", dest)
	}

	sourceInfo, err := files.Lstat(ctx, resolvedSrc)
	if err != nil {
		return "", fmt.Errorf("stat copy source failed: %w", err)
	}
	if sourceInfo.IsDir() {
		destInfo, err := files.Lstat(ctx, dest)
		if err == nil && destInfo.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("cannot overwrite symbolic link %q with directory %q", dest, src)
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("lstat destination failed: %w", err)
		}
	}
	// cp -r preserves ordinary source links as entries. Only a regular-file
	// source follows a destination file link instead of replacing the link.
	if !sourceInfo.Mode().IsRegular() {
		return dest, nil
	}
	return resolveCopyFileDestination(ctx, files, dest)
}

func resolveCopyFileDestination(ctx context.Context, files ports.FileSession, dest string) (string, error) {
	info, err := files.Lstat(ctx, dest)
	if errors.Is(err, os.ErrNotExist) {
		return dest, nil
	}
	if err != nil {
		return "", fmt.Errorf("lstat destination failed: %w", err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("cannot overwrite destination directory %q with a file", dest)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return dest, nil
	}
	resolved, err := resolveCopyReferent(ctx, files, dest)
	if err != nil {
		return "", fmt.Errorf("resolve destination symbolic link failed: %w", err)
	}
	info, err = files.Stat(ctx, resolved)
	if err != nil {
		return "", fmt.Errorf("stat destination symbolic link target failed: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("destination symbolic link %q does not refer to a regular file", dest)
	}
	return resolved, nil
}

// ======================== REGISTER ========================

func (r *Runtime) registerFS(server *mcp.Server, g *guardrail.Guardrail) {
	notDestructive := false
	destructive := true

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "xops_fs_ls",
			Description: "List remote directory files with attributes (size, modTime, isDir, permissions).",
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
		},
		withOperation(r, g, "xops_fs_ls",
			func(in FSListInput) guardrail.RiskInput {
				return guardrail.RiskInput{NodeID: in.NodeID, Paths: []string{in.Path}}
			},
			r.fsLsHandler,
		),
	)

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "xops_fs_mkdir",
			Description: "Create a remote directory, along with any necessary parents.",
			Annotations: &mcp.ToolAnnotations{DestructiveHint: &notDestructive},
		},
		withOperation(r, g, "xops_fs_mkdir",
			func(in FSMkdirInput) guardrail.RiskInput {
				return guardrail.RiskInput{NodeID: in.NodeID, Paths: []string{in.Path}}
			},
			r.fsMkdirHandler,
		),
	)

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "xops_fs_touch",
			Description: "Create a new empty remote file.",
			Annotations: &mcp.ToolAnnotations{DestructiveHint: &notDestructive},
		},
		withOperation(r, g, "xops_fs_touch",
			func(in FSTouchInput) guardrail.RiskInput {
				return guardrail.RiskInput{NodeID: in.NodeID, Paths: []string{in.Path}}
			},
			r.fsTouchHandler,
		),
	)

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "xops_fs_mv",
			Description: "Move or rename a remote file/directory.",
			Annotations: &mcp.ToolAnnotations{DestructiveHint: &notDestructive},
		},
		withOperation(r, g, "xops_fs_mv",
			func(in FSMvInput) guardrail.RiskInput {
				return guardrail.RiskInput{NodeID: in.NodeID, Paths: []string{in.Old, in.New}}
			},
			r.fsMvHandler,
		),
	)

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "xops_fs_rm",
			Description: "Remove a remote file or directory recursively safely.",
			Annotations: &mcp.ToolAnnotations{DestructiveHint: &destructive},
		},
		withOperation(r, g, "xops_fs_rm",
			func(in FSRmInput) guardrail.RiskInput {
				return guardrail.RiskInput{NodeID: in.NodeID, Paths: []string{in.Path}}
			},
			r.fsRmHandler,
		),
	)

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "xops_fs_cp",
			Description: "Copy a remote file or directory to another remote location recursively.",
			Annotations: &mcp.ToolAnnotations{DestructiveHint: &notDestructive},
		},
		withOperation(r, g, "xops_fs_cp",
			func(in FSCpInput) guardrail.RiskInput {
				return guardrail.RiskInput{NodeID: in.NodeID, Paths: []string{in.Src, in.Dest}}
			},
			r.fsCpHandler,
		),
	)
}
