package sftp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

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

// LocalBaseName extracts the final component of a local OS filesystem path and
// validates it as a RemoteName. It is the sole allowlisted filepath.Base bridge
// in transfer code so remote paths cannot accidentally pass through OS-specific
// filepath.Base semantics.
func LocalBaseName(localPath string) (RemoteName, error) {
	if strings.TrimSpace(localPath) == "" {
		return RemoteName{}, fmt.Errorf("%w: local path is empty", ErrInvalidRemoteName)
	}
	base := filepath.Base(localPath) //nolint:forbidigo // sole allowlisted local OS path base bridge
	return ParseRemoteName(base)
}

// ParseRemoteUploadTarget builds a typed remote destination path for uploading
// a local entry into a remote destination (appending LocalBaseName(localPath)
// when remoteIsDir is true).
func ParseRemoteUploadTarget(remoteRaw, localPath string, remoteIsDir bool) (RemotePath, error) {
	dst, err := ParseRemotePath(remoteRaw)
	if err != nil {
		return RemotePath{}, err
	}
	if !remoteIsDir {
		return dst, nil
	}
	name, err := LocalBaseName(localPath)
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

const (
	maxDownloadSymlinkHops  = 40
	maxDownloadSymlinkSteps = 4096
)

// validateDownloadSymlinkTarget enforces download symlink policy (b):
// only relative POSIX symlink targets whose step-by-step resolution stays
// inside the download root (depth >= 0) and whose components satisfy
// fsx.ValidateLocalComponent are permitted. Absolute targets, Windows drive
// prefixes, backslashes, control characters, and escaping targets return an
// error wrapping ErrUnsafeDownloadSymlink.
func validateDownloadSymlinkTarget(target string, linkDirDepth int) error {
	if err := validateDownloadSymlinkSyntax(target); err != nil {
		return err
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
			depth++
		}
	}
	return nil
}

func validateDownloadSymlinkSyntax(target string) error {
	if target == "" {
		return fmt.Errorf("%w: empty target", ErrUnsafeDownloadSymlink)
	}
	if hasPathControlChar(target) {
		return fmt.Errorf("%w: %q contains NUL or control character", ErrUnsafeDownloadSymlink, target)
	}
	if strings.HasPrefix(target, "/") || strings.ContainsRune(target, '\\') || (len(target) >= 2 && target[1] == ':') {
		return fmt.Errorf("%w: %q must be a relative POSIX path inside download root", ErrUnsafeDownloadSymlink, target)
	}
	for _, seg := range strings.Split(target, "/") {
		if seg == "" || seg == "." || seg == ".." {
			continue
		}
		if err := fsx.ValidateLocalComponent(seg); err != nil {
			return fmt.Errorf("%w: %q has unsafe component %q: %w", ErrUnsafeDownloadSymlink, target, seg, err)
		}
	}
	return nil
}

// validateDownloadSymlinkInTree resolves a remote symlink target step-by-step
// against both the complete staged in-tree symlink map and any pre-existing
// symlinks on local disk beneath localRoot. It enforces:
//   - lexical policy (b) on target itself,
//   - no parent component of linkRelPath is a symlink,
//   - step-by-step expansion of every in-tree or pre-existing local symlink
//     encountered along the path (including chained symlinks and the final
//     component), bounded by maxDownloadSymlinkHops and maxDownloadSymlinkSteps,
//   - depth never dips below 0 (outside localRoot) at any point.
func validateDownloadSymlinkInTree(localRoot, linkRelPath, target string, inTreeSymlinks map[string]string) error {
	linkParts, err := parseDownloadLinkRelParts(linkRelPath)
	if err != nil {
		return err
	}
	parentParts := linkParts[:len(linkParts)-1]
	if err := validateDownloadSymlinkTarget(target, len(parentParts)); err != nil {
		return err
	}
	if err := validateDownloadSymlinkParents(localRoot, parentParts, inTreeSymlinks); err != nil {
		return err
	}

	cur := append([]string(nil), parentParts...)
	queue := splitPOSIXRelativeSegments(target)
	hops := 0
	steps := 0

	for len(queue) > 0 {
		steps++
		if steps > maxDownloadSymlinkSteps {
			return fmt.Errorf("%w: %q exceeds resolution step limit (%d)", ErrUnsafeDownloadSymlink, target, maxDownloadSymlinkSteps)
		}
		seg := queue[0]
		queue = queue[1:]
		if seg == ".." {
			if len(cur) == 0 {
				return fmt.Errorf("%w: %q escapes download root via chained symlink", ErrUnsafeDownloadSymlink, target)
			}
			cur = cur[:len(cur)-1]
			continue
		}

		nextCur := append(cur, seg)
		candRel := strings.Join(nextCur, "/")
		symTarget, fromTree, isSym, lookupErr := lookupDownloadSymlink(localRoot, candRel, inTreeSymlinks)
		if lookupErr != nil {
			return lookupErr
		}
		if !isSym {
			cur = nextCur
			continue
		}

		hops++
		if hops > maxDownloadSymlinkHops {
			return fmt.Errorf("%w: %q exceeds maximum symlink hops (%d)", ErrUnsafeDownloadSymlink, target, maxDownloadSymlinkHops)
		}
		expandedTarget, expandErr := validateExpandedDownloadSymlinkTarget(symTarget, fromTree)
		if expandErr != nil {
			return fmt.Errorf("%w: symlink %q -> %q in resolution of %q: %w", ErrUnsafeDownloadSymlink, candRel, symTarget, target, expandErr)
		}
		expanded := splitPOSIXRelativeSegments(expandedTarget)
		nextQueue := make([]string, 0, len(expanded)+len(queue))
		nextQueue = append(nextQueue, expanded...)
		nextQueue = append(nextQueue, queue...)
		queue = nextQueue
	}
	return nil
}

func parseDownloadLinkRelParts(linkRelPath string) ([]string, error) {
	if linkRelPath == "" || linkRelPath == "." || strings.HasPrefix(linkRelPath, "/") {
		return nil, fmt.Errorf("%w: invalid link relative path %q", ErrUnsafeDownloadSymlink, linkRelPath)
	}
	parts := strings.Split(linkRelPath, "/")
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			return nil, fmt.Errorf("%w: invalid link relative path %q", ErrUnsafeDownloadSymlink, linkRelPath)
		}
	}
	return parts, nil
}

func validateDownloadSymlinkParents(localRoot string, parentParts []string, inTreeSymlinks map[string]string) error {
	for i := range parentParts {
		prefix := strings.Join(parentParts[:i+1], "/")
		_, _, isSym, err := lookupDownloadSymlink(localRoot, prefix, inTreeSymlinks)
		if err != nil {
			return err
		}
		if isSym {
			return fmt.Errorf("%w: parent component %q is a symbolic link", ErrUnsafeDownloadSymlink, prefix)
		}
	}
	return nil
}

func lookupDownloadSymlink(localRoot, candRel string, inTreeSymlinks map[string]string) (target string, fromTree bool, isSym bool, err error) {
	if t, ok := inTreeSymlinks[candRel]; ok {
		return t, true, true, nil
	}
	if localRoot == "" {
		return "", false, false, nil
	}
	diskPath := filepath.Join(localRoot, filepath.FromSlash(candRel))
	fi, lstatErr := os.Lstat(diskPath)
	if lstatErr != nil {
		if errors.Is(lstatErr, os.ErrNotExist) || errors.Is(lstatErr, syscall.ENOTDIR) {
			return "", false, false, nil
		}
		return "", false, false, fmt.Errorf("%w: lstat %q failed: %w", ErrUnsafeDownloadSymlink, candRel, lstatErr)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		return "", false, false, nil
	}
	diskTarget, readErr := os.Readlink(diskPath)
	if readErr != nil {
		return "", false, false, fmt.Errorf("%w: read local symlink %q failed: %w", ErrUnsafeDownloadSymlink, candRel, readErr)
	}
	return diskTarget, false, true, nil
}

func validateExpandedDownloadSymlinkTarget(symTarget string, fromTree bool) (string, error) {
	if fromTree {
		if err := validateDownloadSymlinkSyntax(symTarget); err != nil {
			return "", err
		}
		return symTarget, nil
	}
	if symTarget == "" {
		return "", errors.New("empty local symlink target")
	}
	if hasPathControlChar(symTarget) {
		return "", errors.New("local symlink target contains control character")
	}
	if filepath.IsAbs(symTarget) || strings.HasPrefix(symTarget, "/") || strings.HasPrefix(symTarget, `\`) || (len(symTarget) >= 2 && symTarget[1] == ':') {
		return "", errors.New("local symlink target must be relative inside download root")
	}
	if runtime.GOOS == "windows" {
		symTarget = filepath.ToSlash(symTarget)
		if strings.HasPrefix(symTarget, "/") {
			return "", errors.New("local symlink target must be relative inside download root")
		}
	}
	return symTarget, nil
}

func splitPOSIXRelativeSegments(target string) []string {
	raw := strings.Split(target, "/")
	out := make([]string, 0, len(raw))
	for _, seg := range raw {
		if seg == "" || seg == "." {
			continue
		}
		out = append(out, seg)
	}
	return out
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
