package runtime

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	pkgsftp "github.com/pkg/sftp"
	"github.com/wentf9/xops-cli/core/mcp/guardrail"
	"github.com/wentf9/xops-cli/core/mcp/patch"
	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/mcp/remotefile"
)

const (
	maxFileReadBytes   = 512 * 1024 // 512 KiB max SFTP read into memory
	defaultMaxReadLine = 500
	maxStatTreeDepth   = 2
	maxStatTreeEntries = 200
	defaultNewFileMode = 0o644
	posixRenameExt     = "posix-rename@openssh.com"
)

var ignoredStatDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"__pycache__":  true,
	".venv":        true,
	"venv":         true,
	"target":       true,
	"dist":         true,
	"build":        true,
}

type FileInput struct {
	NodeID  string `json:"nodeID" jsonschema:"Target SSH node ID or alias"`
	Action  string `json:"action" jsonschema:"File operation: read, write, patch, or stat"`
	Path    string `json:"path" jsonschema:"Absolute path to the remote file or directory"`
	Content string `json:"content,omitempty" jsonschema:"Full file content for write, or <<<< ==== >>>> search/replace blocks for patch"`
	Range   []int  `json:"range,omitempty" jsonschema:"Optional [start_line, end_line] (1-based, inclusive) for read"`
}

type FileOutput struct {
	Content       string `json:"content,omitempty" jsonschema:"Line-numbered file content (read) or metadata/directory tree (stat)"`
	TotalLines    int    `json:"totalLines,omitempty" jsonschema:"Total number of lines read (only the first 512 KiB when truncated)"`
	Size          int64  `json:"size,omitempty" jsonschema:"File size in bytes"`
	Mode          string `json:"mode,omitempty" jsonschema:"File mode/permissions"`
	IsDir         bool   `json:"isDir,omitempty" jsonschema:"True if the path is a directory"`
	Truncated     bool   `json:"truncated,omitempty" jsonschema:"True if read stopped at the 512 KiB limit"`
	BytesWritten  int    `json:"bytesWritten,omitempty" jsonschema:"Number of bytes written"`
	BlocksApplied int    `json:"blocksApplied,omitempty" jsonschema:"Number of search/replace blocks applied by patch"`
	FuzzyBlocks   int    `json:"fuzzyBlocks,omitempty" jsonschema:"Number of patch blocks matched only after ignoring per-line leading/trailing whitespace; review these edits"`
	InPlace       bool   `json:"inPlace,omitempty" jsonschema:"True when an existing file was updated in place (non-atomic) to preserve ownership or because the directory/server could not stage a temporary file"`
	LintWarning   string `json:"lintWarning,omitempty" jsonschema:"Syntax check warning if detected after write or patch"`
	Status        string `json:"status" jsonschema:"Operation status"`
}

type fileSnapshot struct {
	size    int64
	modTime time.Time
	sha256  [32]byte
}

type replacePreset struct {
	mode      os.FileMode
	existed   bool
	canAtomic bool
	hasOwner  bool
	uid       uint32
	gid       uint32
}

var errPreserveOwnerFallback = errors.New("cannot preserve original file ownership on temporary file")

func (r *Runtime) fileHandler(ctx context.Context, _ *mcp.CallToolRequest, input FileInput) (_ *mcp.CallToolResult, _ FileOutput, handlerErr error) {
	if input.NodeID == "" || input.Path == "" || input.Action == "" {
		return nil, FileOutput{}, errors.New("nodeID, action, and path are required")
	}
	input.Path = remotefile.NormalizeSFTPPath(input.Path)
	switch input.Action {
	case "read", "write", "patch", "stat":
	default:
		return nil, FileOutput{}, fmt.Errorf("unsupported file action %q (expected read, write, patch, or stat)", input.Action)
	}

	files, err := r.getMCPSFTPClient(ctx, input.NodeID)
	if err != nil {
		return nil, FileOutput{}, err
	}
	defer joinCloseError(&handlerErr, files, "sftp client")

	var out FileOutput
	switch input.Action {
	case "read":
		out, err = fileRead(ctx, files, input)
	case "write":
		out, err = fileWrite(ctx, files, input)
	case "patch":
		out, err = filePatch(ctx, files, input)
	case "stat":
		out, err = fileStat(ctx, files, input)
	}
	if err != nil {
		return nil, FileOutput{}, err
	}
	return nil, out, nil
}

// readBounded reads at most maxFileReadBytes from name and reports whether
// the file holds more data than was returned.
func readBounded(ctx context.Context, files ports.FileSession, name string) (data []byte, info os.FileInfo, truncated bool, err error) {
	err = files.Do(ctx, func(c *pkgsftp.Client) (retErr error) {
		f, err := c.Open(name)
		if err != nil {
			return fmt.Errorf("open remote file: %w", err)
		}
		defer func() {
			if closeErr := f.Close(); closeErr != nil && !errors.Is(closeErr, io.EOF) {
				retErr = errors.Join(retErr, fmt.Errorf("close remote file: %w", closeErr))
			}
		}()
		if info, err = f.Stat(); err != nil {
			return fmt.Errorf("stat remote file: %w", err)
		}
		if info.IsDir() {
			return fmt.Errorf("%s is a directory; use action=stat", name)
		}
		data, err = io.ReadAll(io.LimitReader(f, maxFileReadBytes+1))
		if err != nil {
			return fmt.Errorf("read remote file: %w", err)
		}
		if len(data) > maxFileReadBytes {
			data, truncated = data[:maxFileReadBytes], true
		}
		return nil
	})
	return data, info, truncated, err
}

func validateReadInput(input FileInput) (FileInput, error) {
	input.Path = remotefile.NormalizeSFTPPath(input.Path)
	if !path.IsAbs(input.Path) || strings.ContainsRune(input.Path, '\x00') {
		return FileInput{}, errors.New("file path must be absolute")
	}
	if remotefile.IsRootPath(input.Path) {
		return FileInput{}, errors.New("cannot read root directory as a file")
	}
	if len(input.Range) != 0 && len(input.Range) != 2 {
		return FileInput{}, errors.New("range must be [start_line, end_line]")
	}
	if len(input.Range) == 2 && (input.Range[0] < 1 || input.Range[1] < input.Range[0]) {
		return FileInput{}, fmt.Errorf("invalid line range [%d, %d]: lines are 1-based and end_line >= start_line", input.Range[0], input.Range[1])
	}
	return input, nil
}

func fileRead(ctx context.Context, files ports.FileSession, input FileInput) (FileOutput, error) {
	validInput, err := validateReadInput(input)
	if err != nil {
		return FileOutput{}, err
	}
	input = validInput

	data, info, truncated, err := readBounded(ctx, files, input.Path)
	if err != nil {
		return FileOutput{}, err
	}
	formatted, totalLines := formatLineNumberedContent(string(data), input.Range)
	if truncated {
		formatted += fmt.Sprintf("\n[... file is %d bytes; only the first %d bytes were read. Use terminal (e.g. sed -n) for later sections ...]", info.Size(), maxFileReadBytes)
	}
	return FileOutput{
		Content:    formatted,
		TotalLines: totalLines,
		Size:       info.Size(),
		Mode:       info.Mode().String(),
		Truncated:  truncated,
		Status:     "success",
	}, nil
}

func formatLineNumberedContent(raw string, lineRange []int) (string, int) {
	if raw == "" {
		return "", 0
	}
	normalized := strings.ReplaceAll(raw, "\r\n", "\n")
	trimmed := strings.TrimSuffix(normalized, "\n")
	lines := strings.Split(trimmed, "\n")
	total := len(lines)

	startLine := 1
	endLine := total
	truncatedHint := ""

	if len(lineRange) == 2 {
		startLine = lineRange[0]
		if startLine > total {
			return fmt.Sprintf("[File has %d lines; requested start_line %d is past EOF]", total, startLine), total
		}
		if lineRange[1] < endLine {
			endLine = lineRange[1]
		}
	} else if total > defaultMaxReadLine {
		endLine = defaultMaxReadLine
		nextEnd := min(total, defaultMaxReadLine*2)
		truncatedHint = fmt.Sprintf("\n[... %d more lines omitted. Specify range=[%d, %d] to continue reading ...]", total-defaultMaxReadLine, defaultMaxReadLine+1, nextEnd)
	}

	var b strings.Builder
	for i := startLine; i <= endLine; i++ {
		if i > startLine {
			b.WriteByte('\n')
		}
		fmt.Fprintf(&b, "%4d | %s", i, lines[i-1])
	}
	b.WriteString(truncatedHint)
	return b.String(), total
}

func fileWrite(ctx context.Context, files ports.FileSession, input FileInput) (FileOutput, error) {
	inPlace, err := replaceFile(ctx, files, input.Path, []byte(input.Content), nil)
	if err != nil {
		return FileOutput{}, err
	}
	return FileOutput{
		BytesWritten: len(input.Content),
		InPlace:      inPlace,
		LintWarning:  lintContent(input.Path, input.Content),
		Status:       "success",
	}, nil
}

func filePatch(ctx context.Context, files ports.FileSession, input FileInput) (FileOutput, error) {
	if input.Content == "" {
		return FileOutput{}, errors.New("patch action requires non-empty content with <<<< ==== >>>> blocks")
	}
	data, info, truncated, err := readBounded(ctx, files, input.Path)
	if err != nil {
		return FileOutput{}, err
	}
	// Patching a partial read and writing it back would silently drop the
	// unread tail of the file.
	if truncated {
		return FileOutput{}, fmt.Errorf("file is %d bytes; patch supports files up to %d bytes (use terminal for larger files)", info.Size(), maxFileReadBytes)
	}

	result, err := patch.Apply(string(data), input.Content)
	if err != nil {
		return FileOutput{}, fmt.Errorf("patch failed: %w", err)
	}
	snap := &fileSnapshot{
		size:    info.Size(),
		modTime: info.ModTime(),
		sha256:  sha256.Sum256(data),
	}
	inPlace, err := replaceFile(ctx, files, input.Path, []byte(result.Content), snap)
	if err != nil {
		return FileOutput{}, err
	}
	return FileOutput{
		BytesWritten:  len(result.Content),
		BlocksApplied: result.Blocks,
		FuzzyBlocks:   result.Fuzzy,
		InPlace:       inPlace,
		LintWarning:   lintContent(input.Path, result.Content),
		Status:        "success",
	}, nil
}

// replaceFile replaces name with content: it prefers an atomic write via a
// private temporary file in the destination directory and posix-rename (or
// SFTP v3 Rename when creating a new file), preserving the destination mode
// and owner. If the target already exists as a regular file and either the
// SFTP server lacks posix-rename, the parent directory denies temporary file
// creation, or original ownership cannot be applied to the temporary file, it
// falls back to an in-place write on the verified regular file and returns
// inPlace=true. When expected is non-nil, size, modification time, and SHA-256
// content hash must still match so concurrent edits are never overwritten.
// Symbolic links and special files are always refused.
func replaceFile(ctx context.Context, files ports.FileSession, name string, content []byte, expected *fileSnapshot) (bool, error) {
	name = remotefile.NormalizeSFTPPath(name)
	if !path.IsAbs(name) || strings.ContainsRune(name, '\x00') {
		return false, errors.New("file path must be absolute")
	}
	if remotefile.IsRootPath(name) {
		return false, errors.New("cannot replace root directory")
	}
	name = path.Clean(name)
	dir := path.Dir(name)

	preset, err := prepareReplace(ctx, files, name, dir, expected)
	if err != nil {
		return false, err
	}
	if preset.existed && !preset.canAtomic {
		return true, writeInPlace(ctx, files, name, content, expected)
	}

	err = atomicCommit(ctx, files, name, dir, content, preset, expected)
	if err != nil && preset.existed && (remotefile.IsPermissionDenied(err) || errors.Is(err, errPreserveOwnerFallback)) {
		return true, writeInPlace(ctx, files, name, content, expected)
	}
	return false, err
}

func prepareReplace(ctx context.Context, files ports.FileSession, name, dir string, expected *fileSnapshot) (preset replacePreset, err error) {
	preset.mode = defaultNewFileMode
	err = files.Do(ctx, func(c *pkgsftp.Client) error {
		_, preset.canAtomic = c.HasExtension(posixRenameExt)
		info, lstatErr := c.Lstat(name)
		switch {
		case errors.Is(lstatErr, os.ErrNotExist):
			if expected != nil {
				return fmt.Errorf("%s was removed since it was read", name)
			}
			if mkErr := c.MkdirAll(dir); mkErr != nil {
				return fmt.Errorf("create parent directory %s: %w", dir, mkErr)
			}
			return nil
		case lstatErr != nil:
			return fmt.Errorf("inspect %s: %w", name, lstatErr)
		case !info.Mode().IsRegular():
			return fmt.Errorf("%s is not a regular file (symbolic links and special files are not replaced)", name)
		}
		if expected != nil && (info.Size() != expected.size || !info.ModTime().Equal(expected.modTime)) {
			return fmt.Errorf("%s changed since it was read; re-read and retry", name)
		}
		preset.existed = true
		preset.mode = info.Mode().Perm()
		if st, ok := info.Sys().(*pkgsftp.FileStat); ok && st != nil {
			preset.hasOwner, preset.uid, preset.gid = true, st.UID, st.GID
		}
		return nil
	})
	return preset, err
}

func verifyUnchanged(c *pkgsftp.Client, name string, info os.FileInfo, expected *fileSnapshot) (retErr error) {
	if expected == nil {
		return nil
	}
	if info.Size() != expected.size || !info.ModTime().Equal(expected.modTime) {
		return fmt.Errorf("%s changed since it was read; re-read and retry", name)
	}
	f, err := c.Open(name)
	if err != nil {
		return fmt.Errorf("open %s for verification: %w", name, err)
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil && !errors.Is(closeErr, io.EOF) {
			retErr = errors.Join(retErr, fmt.Errorf("close %s: %w", name, closeErr))
		}
	}()
	cur, err := io.ReadAll(io.LimitReader(f, maxFileReadBytes+1))
	if err != nil {
		return fmt.Errorf("read %s for verification: %w", name, err)
	}
	if int64(len(cur)) != expected.size || sha256.Sum256(cur) != expected.sha256 {
		return fmt.Errorf("%s changed since it was read; re-read and retry", name)
	}
	return nil
}

func atomicCommit(ctx context.Context, files ports.FileSession, name, dir string, content []byte, preset replacePreset, expected *fileSnapshot) error {
	suffix, err := randomHex(6)
	if err != nil {
		return err
	}
	temporary := path.Join(dir, "."+path.Base(name)+".xops-"+suffix+".tmp")
	attempted, created, err := files.CreatePrivateExclusive(ctx, temporary, func(w io.Writer) error {
		_, err := io.Copy(w, bytes.NewReader(content))
		return err
	})
	if err != nil {
		if created || (attempted && !remotefile.ExplicitSFTPRejection(err)) {
			err = errors.Join(err, removeTemporary(ctx, files, temporary))
		}
		return fmt.Errorf("write temporary file for %s: %w", name, err)
	}

	commitErr := files.Do(ctx, func(c *pkgsftp.Client) error {
		if expected != nil {
			info, err := c.Lstat(name)
			if err != nil {
				return fmt.Errorf("inspect %s before commit: %w", name, err)
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("%s is no longer a regular file", name)
			}
			if err := verifyUnchanged(c, name, info, expected); err != nil {
				return err
			}
		}
		if err := preserveOwnership(c, temporary, preset); err != nil {
			return err
		}
		if err := c.Chmod(temporary, preset.mode); err != nil {
			return fmt.Errorf("apply mode %s: %w", preset.mode, err)
		}
		if preset.existed {
			if err := c.PosixRename(temporary, name); err != nil {
				return fmt.Errorf("commit %s: %w", name, err)
			}
			return nil
		}
		// SFTP v3 RENAME rejects an existing destination, so creating a new
		// file is atomic even when posix-rename is unavailable.
		if err := c.Rename(temporary, name); err != nil {
			return fmt.Errorf("commit %s: %w", name, err)
		}
		return nil
	})
	if commitErr != nil {
		return errors.Join(commitErr, removeTemporary(ctx, files, temporary))
	}
	return nil
}

func preserveOwnership(c *pkgsftp.Client, temporary string, preset replacePreset) error {
	if !preset.existed || !preset.hasOwner {
		return nil
	}
	tmpInfo, err := c.Lstat(temporary)
	if err != nil {
		return fmt.Errorf("inspect temporary file %s: %w", temporary, err)
	}
	tmpStat, ok := tmpInfo.Sys().(*pkgsftp.FileStat)
	if !ok || tmpStat == nil || (tmpStat.UID == preset.uid && tmpStat.GID == preset.gid) {
		return nil
	}
	if err := c.Chown(temporary, int(preset.uid), int(preset.gid)); err != nil {
		return fmt.Errorf("%w: %w", errPreserveOwnerFallback, err)
	}
	afterInfo, err := c.Lstat(temporary)
	if err != nil {
		return fmt.Errorf("inspect temporary file %s after chown: %w", temporary, err)
	}
	if afterStat, ok := afterInfo.Sys().(*pkgsftp.FileStat); ok && afterStat != nil {
		if afterStat.UID != preset.uid || afterStat.GID != preset.gid {
			return errPreserveOwnerFallback
		}
	}
	return nil
}

func writeInPlace(ctx context.Context, files ports.FileSession, name string, content []byte, expected *fileSnapshot) error {
	return files.Do(ctx, func(c *pkgsftp.Client) (retErr error) {
		info, err := c.Lstat(name)
		if err != nil {
			return fmt.Errorf("inspect %s: %w", name, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s is not a regular file (symbolic links and special files are not replaced)", name)
		}
		if err := verifyUnchanged(c, name, info, expected); err != nil {
			return err
		}
		f, err := c.OpenFile(name, os.O_WRONLY|os.O_TRUNC)
		if err != nil {
			return fmt.Errorf("open %s for in-place write: %w", name, err)
		}
		defer func() {
			if closeErr := f.Close(); closeErr != nil && !errors.Is(closeErr, io.EOF) {
				retErr = errors.Join(retErr, fmt.Errorf("close %s: %w", name, closeErr))
			}
		}()
		if _, err := f.Write(content); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
		return nil
	})
}

func removeTemporary(ctx context.Context, files ports.FileSession, name string) error {
	return files.Do(context.WithoutCancel(ctx), func(c *pkgsftp.Client) error {
		if err := c.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove temporary file %s: %w", name, err)
		}
		return nil
	})
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func fileStat(ctx context.Context, files ports.FileSession, input FileInput) (FileOutput, error) {
	var info os.FileInfo
	var treeContent string

	err := files.Do(ctx, func(c *pkgsftp.Client) error {
		var statErr error
		info, statErr = c.Stat(input.Path)
		if statErr != nil {
			return fmt.Errorf("stat failed: %w", statErr)
		}
		if !info.IsDir() {
			treeContent = fmt.Sprintf("%s (%s, %d bytes, modified %s)",
				input.Path, info.Mode().String(), info.Size(), info.ModTime().UTC().Format(time.RFC3339))
			return nil
		}

		var b strings.Builder
		b.WriteString(input.Path)
		if !strings.HasSuffix(input.Path, "/") {
			b.WriteByte('/')
		}
		b.WriteByte('\n')
		count := 0
		buildDirTree(c, input.Path, "", 1, &b, &count)
		treeContent = strings.TrimSuffix(b.String(), "\n")
		return nil
	})
	if err != nil {
		return FileOutput{}, err
	}

	return FileOutput{
		Content: treeContent,
		Size:    info.Size(),
		Mode:    info.Mode().String(),
		IsDir:   info.IsDir(),
		Status:  "success",
	}, nil
}

func buildDirTree(c *pkgsftp.Client, dirPath, prefix string, depth int, b *strings.Builder, count *int) {
	if depth > maxStatTreeDepth || *count >= maxStatTreeEntries {
		return
	}
	entries, err := c.ReadDir(dirPath)
	if err != nil {
		fmt.Fprintf(b, "%s└── [unreadable: %v]\n", prefix, err)
		return
	}
	var filtered []os.FileInfo
	for _, entry := range entries {
		if entry.IsDir() && ignoredStatDirs[entry.Name()] {
			continue
		}
		filtered = append(filtered, entry)
	}
	slices.SortFunc(filtered, func(a, b os.FileInfo) int {
		if a.IsDir() != b.IsDir() {
			if a.IsDir() {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Name(), b.Name())
	})

	for i, entry := range filtered {
		if *count >= maxStatTreeEntries {
			fmt.Fprintf(b, "%s└── [... truncated after %d entries ...]\n", prefix, maxStatTreeEntries)
			return
		}
		*count++
		connector := "├── "
		childPrefix := prefix + "│   "
		if i == len(filtered)-1 {
			connector = "└── "
			childPrefix = prefix + "    "
		}
		if entry.IsDir() {
			fmt.Fprintf(b, "%s%s%s/\n", prefix, connector, entry.Name())
			if depth < maxStatTreeDepth {
				buildDirTree(c, path.Join(dirPath, entry.Name()), childPrefix, depth+1, b, count)
			}
		} else {
			fmt.Fprintf(b, "%s%s%s (%d B)\n", prefix, connector, entry.Name(), entry.Size())
		}
	}
}

// lintContent performs a local syntax check for formats that can be validated
// without remote tooling.
func lintContent(remotePath, content string) string {
	if strings.ToLower(path.Ext(remotePath)) != ".json" {
		return ""
	}
	var js any
	if err := json.Unmarshal([]byte(content), &js); err != nil {
		return fmt.Sprintf("[Warning: Syntax error detected after edit] invalid JSON in %s: %v", remotePath, err)
	}
	return ""
}

func (r *Runtime) registerFile(server *mcp.Server, g *guardrail.Guardrail) {
	destructive := true
	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "file",
			Description: "Unified remote file and directory operator over SFTP. Actions: 'read' (line-numbered with optional [start, end] range, first 512 KiB), 'write' (atomic replace; creates parent dirs), 'patch' (applies <<<< ==== >>>> search/replace blocks atomically; files up to 512 KiB), 'stat' (file metadata or noise-filtered 2-level directory tree). Atomic replacement creates a new inode (use terminal when hard links or extended ACLs must be preserved).",
			Annotations: &mcp.ToolAnnotations{DestructiveHint: &destructive},
		},
		withOperation(r, g, "file",
			func(in FileInput) guardrail.RiskInput {
				return guardrail.RiskInput{
					Action: in.Action,
					NodeID: in.NodeID,
					Paths:  []string{remotefile.NormalizeSFTPPath(in.Path)},
				}
			},
			r.fileHandler,
		),
	)
}
