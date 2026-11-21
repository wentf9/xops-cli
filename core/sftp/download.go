package sftp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/wentf9/xops-cli/core/fsx"
)

var (
	// ErrUnsafeDownloadSymlink indicates a remote symbolic link target violates
	// download symlink policy (b): only relative POSIX targets whose traversal
	// stays inside the download root at every step are permitted.
	ErrUnsafeDownloadSymlink = errors.New("unsafe remote symbolic link target")
	// ErrGlobNoMatch indicates a remote glob pattern matched no entries.
	ErrGlobNoMatch = errors.New("no matching remote paths")
	// ErrLocalDestNotDir indicates multiple download sources targeted a local
	// destination that is not an existing directory.
	ErrLocalDestNotDir = errors.New("local destination must be an existing directory")
)

// LocalDestMode specifies how Client.Download interprets an existing local
// directory destination.
type LocalDestMode uint8

const (
	// LocalDestAuto places a downloaded single file inside an existing local
	// directory using the validated remote basename, and writes a downloaded
	// remote directory's contents directly into the local path itself (creating
	// it if absent).
	LocalDestAuto LocalDestMode = iota
	// LocalDestPreserveDirBasename places both downloaded files and downloaded
	// directories inside an existing local directory under their validated
	// remote basename (matching OpenSSH scp and sftp get semantics), unless
	// DownloadOptions.ContentsOnly is true (e.g. remote "dir/.", ".", or "/").
	LocalDestPreserveDirBasename
	// LocalDestExact writes directly to the caller's validated local target
	// without appending the remote basename.
	LocalDestExact
)

// LocalDest is a validated local destination for Client.Download.
// Construct exclusively via LocalDestPath, LocalDestInto, or LocalDestFromTarget.
type LocalDest struct {
	path string
	mode LocalDestMode
}

// LocalDestPath constructs a LocalDest in LocalDestAuto mode.
func LocalDestPath(localPath string) (LocalDest, error) {
	return newLocalDest(localPath, LocalDestAuto)
}

// LocalDestInto constructs a LocalDest in LocalDestPreserveDirBasename mode
// (for CLI commands such as scp and sftp get).
func LocalDestInto(localPath string) (LocalDest, error) {
	return newLocalDest(localPath, LocalDestPreserveDirBasename)
}

// LocalDestFromTarget wraps an already-validated LocalTarget in LocalDestExact mode.
func LocalDestFromTarget(target LocalTarget) (LocalDest, error) {
	if !target.IsValid() {
		return LocalDest{}, fmt.Errorf("%w: local target is invalid", ErrInvalidLocalTarget)
	}
	return LocalDest{path: target.Path(), mode: LocalDestExact}, nil
}

func newLocalDest(localPath string, mode LocalDestMode) (LocalDest, error) {
	if localPath == "" || strings.TrimSpace(localPath) == "" {
		return LocalDest{}, fmt.Errorf("%w: local destination cannot be empty", ErrInvalidLocalTarget)
	}
	if hasPathControlChar(localPath) {
		return LocalDest{}, fmt.Errorf("%w: local destination %q contains NUL or control character", ErrInvalidLocalTarget, localPath)
	}
	return LocalDest{path: filepath.Clean(localPath), mode: mode}, nil
}

// IsValid reports whether d was constructed via a LocalDest constructor.
func (d LocalDest) IsValid() bool { return d.path != "" }

// Path returns the cleaned local destination path.
func (d LocalDest) Path() string { return d.path }

// Mode returns the destination interpretation mode.
func (d LocalDest) Mode() LocalDestMode { return d.mode }

// DownloadOverwriteDecision controls how Client.Download handles an already
// existing local destination.
type DownloadOverwriteDecision uint8

const (
	// DownloadOverwriteDefault follows Client.Config().Force semantics.
	DownloadOverwriteDefault DownloadOverwriteDecision = iota
	// DownloadOverwriteSkip skips downloading this item without error.
	DownloadOverwriteSkip
	// DownloadOverwriteForce forces overwriting the existing local destination.
	DownloadOverwriteForce
)

// DownloadTargetInfo describes one validated remote-to-local download target
// before any local file I/O begins.
type DownloadTargetInfo struct {
	Remote    RemotePath
	LocalPath string
	Info      os.FileInfo
	Exists    bool
}

// DownloadTransferHooks carries optional per-item callbacks and teardown owned
// by the caller of Client.Download.
type DownloadTransferHooks struct {
	Progress     ProgressCallback
	FileProgress FileProgressCallback
	Finish       func(transferErr error) error
}

// DownloadOptions configures Client.Download.
type DownloadOptions struct {
	Progress         ProgressCallback
	FileProgress     FileProgressCallback
	ContentsOnly     bool
	ExpandGlob       bool
	ConfirmOverwrite func(ctx context.Context, target DownloadTargetInfo) (DownloadOverwriteDecision, error)
	BeforeTransfer   func(ctx context.Context, target DownloadTargetInfo) (*DownloadTransferHooks, error)
}

// ParseRemoteDownloadPath validates a raw POSIX remote path intended for
// download or remote-to-remote copy before path.Clean collapses trailing
// traversal or directory-contents markers.
//
// It returns:
//   - the cleaned RemotePath,
//   - contentsOnly=true when raw explicitly names directory contents ("/", ".",
//     or a path ending in "/."), and
//   - an error if raw is empty, contains NUL/control characters, or ends in a
//     ".." parent traversal segment (e.g. "..", "/remote/..", "/remote/sub/..").
func ParseRemoteDownloadPath(raw string) (RemotePath, bool, error) {
	if raw == "" {
		return RemotePath{}, false, fmt.Errorf("%w: empty path", ErrInvalidRemotePath)
	}
	if hasPathControlChar(raw) {
		return RemotePath{}, false, fmt.Errorf("%w: unsafe remote filename %q: contains NUL or control character", ErrInvalidRemotePath, raw)
	}
	trimmed := strings.TrimRight(raw, "/")
	if trimmed == "" {
		p, err := ParseRemotePath(raw)
		return p, true, err
	}
	if trimmed == ".." || strings.HasSuffix(trimmed, "/..") {
		return RemotePath{}, false, fmt.Errorf("%w: unsafe remote filename %q: parent traversal component", ErrInvalidRemotePath, raw)
	}
	contentsOnly := trimmed == "." || strings.HasSuffix(trimmed, "/.")
	p, err := ParseRemotePath(raw)
	if err != nil {
		return RemotePath{}, false, err
	}
	return p, contentsOnly, nil
}

// ParseRemoteUploadTarget builds a typed remote destination path for uploading
// a local entry into a remote destination (appending localBaseName when
// remoteIsDir is true).
func ParseRemoteUploadTarget(remoteRaw, localBaseName string, remoteIsDir bool) (RemotePath, error) {
	dst, err := ParseRemotePath(remoteRaw)
	if err != nil {
		return RemotePath{}, err
	}
	if !remoteIsDir {
		return dst, nil
	}
	name, err := ParseRemoteName(localBaseName)
	if err != nil {
		return RemotePath{}, err
	}
	return dst.Join(name), nil
}

// Download is the sole exported download entry point on Client. It supports
// single files, recursive directories, and optional POSIX glob expansion
// (DownloadOptions.ExpandGlob), enforcing typed RemotePath/RemoteName/LocalTarget
// validation, core/fsx local component checks, and download symlink policy (b).
func (c *Client) Download(ctx context.Context, remote RemotePath, dest LocalDest, opts DownloadOptions) error {
	return runInterruptibleOperation(ctx, c.interruptTransfers, func() error {
		return c.download(ctx, remote, dest, opts)
	})
}

func (c *Client) download(ctx context.Context, remote RemotePath, dest LocalDest, opts DownloadOptions) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !remote.IsValid() {
		return fmt.Errorf("%w: remote path is invalid", ErrInvalidRemotePath)
	}
	if !dest.IsValid() {
		return fmt.Errorf("%w: local destination is invalid", ErrInvalidLocalTarget)
	}

	if opts.ExpandGlob {
		return c.downloadGlob(ctx, remote, dest, opts)
	}
	return c.downloadOne(ctx, remote, dest, opts)
}

func (c *Client) downloadGlob(ctx context.Context, pattern RemotePath, dest LocalDest, opts DownloadOptions) error {
	matches, err := c.SFTPClient().Glob(pattern.String())
	if err != nil {
		return fmt.Errorf("expand remote pattern %q failed: %w", pattern.String(), err)
	}
	if len(matches) == 0 {
		return fmt.Errorf("%w: %q", ErrGlobNoMatch, pattern.String())
	}

	itemOpts := opts
	itemOpts.ExpandGlob = false
	if len(matches) == 1 {
		itemRemote, contentsOnly, parseErr := ParseRemoteDownloadPath(matches[0])
		if parseErr != nil {
			return parseErr
		}
		itemOpts.ContentsOnly = contentsOnly
		return c.downloadOne(ctx, itemRemote, dest, itemOpts)
	}

	lStat, statErr := os.Stat(dest.path)
	if statErr != nil {
		if errors.Is(statErr, os.ErrNotExist) {
			return fmt.Errorf("%w: %q does not exist", ErrLocalDestNotDir, dest.path)
		}
		return fmt.Errorf("stat local destination failed: %w", statErr)
	}
	if !lStat.IsDir() {
		return fmt.Errorf("%w: %q", ErrLocalDestNotDir, dest.path)
	}

	dirDest := LocalDest{path: dest.path, mode: LocalDestPreserveDirBasename}
	for _, rawMatch := range matches {
		if err := ctx.Err(); err != nil {
			return err
		}
		itemRemote, contentsOnly, parseErr := ParseRemoteDownloadPath(rawMatch)
		if parseErr != nil {
			return parseErr
		}
		itemOpts.ContentsOnly = contentsOnly
		if err := c.downloadOne(ctx, itemRemote, dirDest, itemOpts); err != nil {
			return err
		}
	}
	return nil
}

//nolint:gocyclo
func (c *Client) downloadOne(ctx context.Context, remote RemotePath, dest LocalDest, opts DownloadOptions) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := c.SFTPClient().Stat(remote.String())
	if err != nil {
		return fmt.Errorf("stat remote path failed: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	resolvedLocal, err := resolveDownloadLocalPath(remote, info, dest, opts.ContentsOnly)
	if err != nil {
		return err
	}

	_, lstatErr := os.Lstat(resolvedLocal)
	if lstatErr != nil && !errors.Is(lstatErr, os.ErrNotExist) {
		return fmt.Errorf("lstat local destination %q failed: %w", resolvedLocal, lstatErr)
	}
	exists := lstatErr == nil

	targetInfo := DownloadTargetInfo{
		Remote:    remote,
		LocalPath: resolvedLocal,
		Info:      info,
		Exists:    exists,
	}

	clientToUse := c
	if exists && opts.ConfirmOverwrite != nil {
		decision, confirmErr := opts.ConfirmOverwrite(ctx, targetInfo)
		if confirmErr != nil {
			return confirmErr
		}
		switch decision {
		case DownloadOverwriteSkip:
			return nil
		case DownloadOverwriteForce:
			clientToUse = clientToUse.WithForce(true)
		}
	}

	progress := opts.Progress
	if opts.FileProgress != nil {
		clientToUse = clientToUse.WithFileProgress(opts.FileProgress)
	}
	var finishHook func(error) error
	if opts.BeforeTransfer != nil {
		hooks, hookErr := opts.BeforeTransfer(ctx, targetInfo)
		if hookErr != nil {
			return hookErr
		}
		if hooks != nil {
			if hooks.Progress != nil {
				progress = hooks.Progress
			}
			if hooks.FileProgress != nil {
				clientToUse = clientToUse.WithFileProgress(hooks.FileProgress)
			}
			finishHook = hooks.Finish
		}
	}

	var transferErr error
	if info.IsDir() {
		localRoot, rootErr := ResolveLocalTarget(resolvedLocal)
		if rootErr != nil {
			transferErr = fmt.Errorf("download %q to %q: %w", remote.String(), resolvedLocal, rootErr)
		} else {
			transferErr = clientToUse.downloadDirectory(ctx, remote, localRoot, progress)
		}
	} else {
		if dlErr := clientToUse.downloadFile(ctx, remote.String(), resolvedLocal, info.Size(), info.Mode(), progress); dlErr != nil {
			transferErr = fmt.Errorf("download %q to %q: %w", remote.String(), resolvedLocal, dlErr)
		}
	}
	if finishHook != nil {
		transferErr = errors.Join(transferErr, finishHook(transferErr))
	}
	return transferErr
}

func resolveDownloadLocalPath(remote RemotePath, info os.FileInfo, dest LocalDest, contentsOnly bool) (string, error) {
	lStat, statErr := os.Stat(dest.path)
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return "", fmt.Errorf("stat local destination failed: %w", statErr)
	}
	destIsDir := statErr == nil && lStat.IsDir()

	if info.IsDir() {
		if dest.mode != LocalDestPreserveDirBasename || !destIsDir || contentsOnly {
			return dest.path, nil
		}
		baseName, err := validatedDownloadBasename(remote, info)
		if err != nil {
			return "", fmt.Errorf("download %q into %q: %w", remote.String(), dest.path, err)
		}
		target, err := ResolveLocalTarget(dest.path, baseName)
		if err != nil {
			return "", fmt.Errorf("download %q into %q: unsafe remote filename %q: %w", remote.String(), dest.path, baseName.String(), err)
		}
		return target.Path(), nil
	}

	if contentsOnly {
		return "", fmt.Errorf("download %q into %q: unsafe remote filename %q: cannot download non-directory as directory contents", remote.String(), dest.path, info.Name())
	}
	if dest.mode == LocalDestExact || !destIsDir {
		return dest.path, nil
	}
	baseName, err := validatedDownloadBasename(remote, info)
	if err != nil {
		return "", fmt.Errorf("download %q into %q: %w", remote.String(), dest.path, err)
	}
	target, err := ResolveLocalTarget(dest.path, baseName)
	if err != nil {
		return "", fmt.Errorf("download %q into %q: unsafe remote filename %q: %w", remote.String(), dest.path, baseName.String(), err)
	}
	return target.Path(), nil
}

func validatedDownloadBasename(remote RemotePath, info os.FileInfo) (RemoteName, error) {
	pathBase := remote.Base()
	if !pathBase.IsValid() {
		return RemoteName{}, fmt.Errorf("unsafe remote filename %q: path has no valid basename", remote.String())
	}
	statName, err := ParseRemoteName(info.Name())
	if err != nil {
		return RemoteName{}, fmt.Errorf("unsafe remote filename %q: %w", info.Name(), err)
	}
	if !statName.Equal(pathBase) {
		return RemoteName{}, fmt.Errorf("unsafe remote filename %q: stat name does not match remote basename %q", info.Name(), pathBase.String())
	}
	return pathBase, nil
}

// validateDownloadSymlinkTarget enforces download symlink policy (b):
// only relative POSIX symlink targets whose step-by-step resolution stays
// inside the download root (depth >= 0) and whose components satisfy
// fsx.ValidateLocalComponent are permitted. Absolute targets, Windows drive
// prefixes, backslashes, control characters, and escaping targets return an
// error wrapping ErrUnsafeDownloadSymlink.
func validateDownloadSymlinkTarget(target string, linkDirDepth int) error {
	if target == "" {
		return fmt.Errorf("%w: empty target", ErrUnsafeDownloadSymlink)
	}
	if hasPathControlChar(target) {
		return fmt.Errorf("%w: %q contains NUL or control character", ErrUnsafeDownloadSymlink, target)
	}
	if strings.HasPrefix(target, "/") || strings.ContainsRune(target, '\\') || (len(target) >= 2 && target[1] == ':') {
		return fmt.Errorf("%w: %q must be a relative POSIX path inside download root", ErrUnsafeDownloadSymlink, target)
	}
	if linkDirDepth < 0 {
		return fmt.Errorf("%w: invalid link directory depth %d", ErrUnsafeDownloadSymlink, linkDirDepth)
	}

	depth := linkDirDepth
	for _, seg := range strings.Split(target, "/") {
		switch seg {
		case "", ".":
			continue
		case "..":
			depth--
			if depth < 0 {
				return fmt.Errorf("%w: %q escapes download root", ErrUnsafeDownloadSymlink, target)
			}
		default:
			if err := fsx.ValidateLocalComponent(seg); err != nil {
				return fmt.Errorf("%w: %q has unsafe component %q: %w", ErrUnsafeDownloadSymlink, target, seg, err)
			}
			depth++
		}
	}
	return nil
}

// DisplayRemoteName returns a safe display label for a RemotePath using POSIX
// path semantics (never OS-dependent filepath.Base).
func DisplayRemoteName(p RemotePath) string {
	if !p.IsValid() {
		return ""
	}
	if base := p.Base(); base.IsValid() {
		return base.String()
	}
	return path.Base(p.String())
}
