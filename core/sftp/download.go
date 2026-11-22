package sftp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"unicode"

	"github.com/wentf9/xops-cli/core/fsx"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
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
	if err := validateRemoteDownloadMode(remote.String(), info.Mode(), false); err != nil {
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
		if dlErr := clientToUse.downloadFile(ctx, remote.String(), resolvedLocal, info.Size(), sanitizeTransferFilePerm(info.Mode()), progress); dlErr != nil {
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

type foldedSymlinkEntry struct {
	exactRel string
	target   string
}

type downloadSymlinkIndex struct {
	exact  map[string]string
	folded map[string]foldedSymlinkEntry
}

type downloadDiskInspector struct {
	lstat    func(string) (os.FileInfo, error)
	readlink func(string) (string, error)
}

func defaultDownloadDiskInspector() downloadDiskInspector {
	return downloadDiskInspector{
		lstat:    os.Lstat,
		readlink: os.Readlink,
	}
}

type downloadSymlinkMatch struct {
	target   string
	fromTree bool
}

// validateRemoteDownloadMode verifies that a remote entry's file-type bits are
// supported for download (regular file, directory, or symlink when allowSymlink
// is true), failing closed on FIFOs, sockets, devices, irregular entries, and
// malformed multi-type bitmasks before any SFTP Open or local side effect.
func validateRemoteDownloadMode(remotePath string, mode os.FileMode, allowSymlink bool) error {
	switch mode & os.ModeType {
	case 0, os.ModeDir:
		return nil
	case os.ModeSymlink:
		if allowSymlink {
			return nil
		}
	}
	return fmt.Errorf("download %q: unsupported non-regular remote entry (mode %s)", remotePath, mode)
}

func canonicalFoldRune(r rune) rune {
	minR := r
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		if f < minR {
			minR = f
		}
	}
	return minR
}

// foldDownloadSegment normalizes a single relative path segment into one
// canonical key covering NFC/NFD equivalence (macOS APFS/HFS+, Linux ext4 +F
// casefold), full multi-rune Unicode case folding (e.g. U+0130 "İ" vs "i\u0307"
// vs "I\u0307", "ß" vs "ss"), and remaining single-rune SimpleFold equivalence
// classes.
func foldDownloadSegment(seg string) string {
	decomposed := norm.NFD.String(seg)
	folded := cases.Fold().String(decomposed)
	canonical := norm.NFD.String(folded)
	return strings.Map(canonicalFoldRune, canonical)
}

func foldDownloadRelPath(rel string) string {
	if !strings.ContainsRune(rel, '/') {
		return foldDownloadSegment(rel)
	}
	parts := strings.Split(rel, "/")
	for i, seg := range parts {
		parts[i] = foldDownloadSegment(seg)
	}
	return strings.Join(parts, "/")
}

func buildDownloadSymlinkIndex(inTreeSymlinks map[string]string) (*downloadSymlinkIndex, error) {
	idx := &downloadSymlinkIndex{
		exact:  make(map[string]string, len(inTreeSymlinks)),
		folded: make(map[string]foldedSymlinkEntry, len(inTreeSymlinks)),
	}
	if len(inTreeSymlinks) == 0 {
		return idx, nil
	}
	keys := make([]string, 0, len(inTreeSymlinks))
	for k := range inTreeSymlinks {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, rel := range keys {
		target := inTreeSymlinks[rel]
		idx.exact[rel] = target
		folded := foldDownloadRelPath(rel)
		if existing, dup := idx.folded[folded]; dup && existing.exactRel != rel {
			return nil, fmt.Errorf("%w: case-colliding staged symbolic links %q and %q", ErrUnsafeDownloadSymlink, existing.exactRel, rel)
		}
		idx.folded[folded] = foldedSymlinkEntry{exactRel: rel, target: target}
	}
	return idx, nil
}

// validateDownloadSymlinkInTree resolves a remote symlink target step-by-step
// against both the complete staged in-tree symlink map (exact and Unicode
// case-folded) and any pre-existing symlinks or non-regular entries on local
// disk beneath localRoot. It enforces:
//   - lexical policy (b) on target itself,
//   - no case-folding collision among staged symlinks,
//   - no parent component of linkRelPath is a symlink or unsafe non-regular entry,
//   - step-by-step expansion of every in-tree or pre-existing local symlink
//     encountered along the path (including chained symlinks, case-folded hits,
//     both staged and on-disk targets when overlapping, and the final component),
//     bounded by maxDownloadSymlinkHops and maxDownloadSymlinkSteps,
//   - depth never dips below 0 (outside localRoot) at any point.
func validateDownloadSymlinkInTree(localRoot, linkRelPath, target string, inTreeSymlinks map[string]string) error {
	idx, err := buildDownloadSymlinkIndex(inTreeSymlinks)
	if err != nil {
		return err
	}
	return validateDownloadSymlinkInTreeWithIndex(localRoot, linkRelPath, target, idx, defaultDownloadDiskInspector())
}

func validateDownloadSymlinkInTreeWithIndex(
	localRoot, linkRelPath, target string,
	idx *downloadSymlinkIndex,
	inspector downloadDiskInspector,
) error {
	if inspector.lstat == nil {
		inspector.lstat = os.Lstat
	}
	if inspector.readlink == nil {
		inspector.readlink = os.Readlink
	}
	linkParts, err := parseDownloadLinkRelParts(linkRelPath)
	if err != nil {
		return err
	}
	if idx != nil {
		if existing, ok := idx.folded[foldDownloadRelPath(linkRelPath)]; ok && existing.exactRel != linkRelPath {
			return fmt.Errorf("%w: case-colliding staged symbolic links %q and %q", ErrUnsafeDownloadSymlink, existing.exactRel, linkRelPath)
		}
	}
	parentParts := linkParts[:len(linkParts)-1]
	if err := validateDownloadSymlinkTarget(target, len(parentParts)); err != nil {
		return err
	}
	if err := validateDownloadSymlinkParents(localRoot, parentParts, idx, inspector); err != nil {
		return err
	}

	cur := append([]string(nil), parentParts...)
	queue := splitPOSIXRelativeSegments(target)
	totalSteps := 0
	return resolveDownloadSymlinkBranch(localRoot, target, cur, queue, 0, &totalSteps, idx, inspector)
}

func resolveDownloadSymlinkBranch(
	localRoot, origTarget string,
	cur, queue []string,
	hops int,
	totalSteps *int,
	idx *downloadSymlinkIndex,
	inspector downloadDiskInspector,
) error {
	for len(queue) > 0 {
		*totalSteps++
		if *totalSteps > maxDownloadSymlinkSteps {
			return fmt.Errorf("%w: %q exceeds resolution step limit (%d)", ErrUnsafeDownloadSymlink, origTarget, maxDownloadSymlinkSteps)
		}
		seg := queue[0]
		queue = queue[1:]
		if seg == ".." {
			if len(cur) == 0 {
				return fmt.Errorf("%w: %q escapes download root via chained symlink", ErrUnsafeDownloadSymlink, origTarget)
			}
			cur = cur[:len(cur)-1]
			continue
		}

		nextCur := append(slices.Clip(cur), seg)
		candRel := strings.Join(nextCur, "/")
		matches, lookupErr := lookupDownloadSymlinks(localRoot, candRel, idx, inspector)
		if lookupErr != nil {
			return lookupErr
		}
		if len(matches) == 0 {
			cur = nextCur
			continue
		}

		nextHops := hops + 1
		if nextHops > maxDownloadSymlinkHops {
			return fmt.Errorf("%w: %q exceeds maximum symlink hops (%d)", ErrUnsafeDownloadSymlink, origTarget, maxDownloadSymlinkHops)
		}
		if len(matches) == 1 {
			expanded, expandErr := expandDownloadSymlinkMatch(candRel, origTarget, matches[0], queue)
			if expandErr != nil {
				return expandErr
			}
			hops = nextHops
			queue = expanded
			continue
		}
		for _, match := range matches {
			expanded, expandErr := expandDownloadSymlinkMatch(candRel, origTarget, match, queue)
			if expandErr != nil {
				return expandErr
			}
			branchCur := append([]string(nil), cur...)
			if err := resolveDownloadSymlinkBranch(localRoot, origTarget, branchCur, expanded, nextHops, totalSteps, idx, inspector); err != nil {
				return err
			}
		}
		return nil
	}
	return nil
}

func expandDownloadSymlinkMatch(candRel, origTarget string, match downloadSymlinkMatch, remaining []string) ([]string, error) {
	expandedTarget, expandErr := validateExpandedDownloadSymlinkTarget(match.target, match.fromTree)
	if expandErr != nil {
		return nil, fmt.Errorf("%w: symlink %q -> %q in resolution of %q: %w", ErrUnsafeDownloadSymlink, candRel, match.target, origTarget, expandErr)
	}
	expanded := splitPOSIXRelativeSegments(expandedTarget)
	nextQueue := make([]string, 0, len(expanded)+len(remaining))
	nextQueue = append(nextQueue, expanded...)
	nextQueue = append(nextQueue, remaining...)
	return nextQueue, nil
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

func validateDownloadSymlinkParents(localRoot string, parentParts []string, idx *downloadSymlinkIndex, inspector downloadDiskInspector) error {
	for i := range parentParts {
		prefix := strings.Join(parentParts[:i+1], "/")
		matches, err := lookupDownloadSymlinks(localRoot, prefix, idx, inspector)
		if err != nil {
			return err
		}
		if len(matches) > 0 {
			return fmt.Errorf("%w: parent component %q is a symbolic link", ErrUnsafeDownloadSymlink, prefix)
		}
	}
	return nil
}

func lookupDownloadSymlinks(localRoot, candRel string, idx *downloadSymlinkIndex, inspector downloadDiskInspector) ([]downloadSymlinkMatch, error) {
	var matches []downloadSymlinkMatch
	var treeExactRel string
	if idx != nil {
		if t, ok := idx.exact[candRel]; ok {
			treeExactRel = candRel
			matches = append(matches, downloadSymlinkMatch{target: t, fromTree: true})
		} else if entry, ok := idx.folded[foldDownloadRelPath(candRel)]; ok {
			treeExactRel = entry.exactRel
			matches = append(matches, downloadSymlinkMatch{target: entry.target, fromTree: true})
		}
	}

	diskTarget, isSym, err := inspectDownloadDiskPath(localRoot, candRel, inspector)
	if err != nil {
		return nil, err
	}
	if isSym {
		matches = appendDownloadSymlinkMatch(matches, downloadSymlinkMatch{target: diskTarget, fromTree: false})
	}
	if treeExactRel != "" && treeExactRel != candRel {
		exactDiskTarget, exactIsSym, exactErr := inspectDownloadDiskPath(localRoot, treeExactRel, inspector)
		if exactErr != nil {
			return nil, exactErr
		}
		if exactIsSym {
			matches = appendDownloadSymlinkMatch(matches, downloadSymlinkMatch{target: exactDiskTarget, fromTree: false})
		}
	}
	return matches, nil
}

func appendDownloadSymlinkMatch(matches []downloadSymlinkMatch, cand downloadSymlinkMatch) []downloadSymlinkMatch {
	for _, existing := range matches {
		if existing.target == cand.target && (existing.fromTree || !cand.fromTree) {
			return matches
		}
	}
	return append(matches, cand)
}

func inspectDownloadDiskPath(localRoot, rel string, inspector downloadDiskInspector) (string, bool, error) {
	if localRoot == "" {
		return "", false, nil
	}
	diskPath := filepath.Join(localRoot, filepath.FromSlash(rel))
	fi, lstatErr := inspector.lstat(diskPath)
	if lstatErr != nil {
		if errors.Is(lstatErr, os.ErrNotExist) || errors.Is(lstatErr, syscall.ENOTDIR) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("%w: lstat %q failed: %w", ErrUnsafeDownloadSymlink, rel, lstatErr)
	}
	modeType := fi.Mode() & os.ModeType
	if modeType&os.ModeSymlink != 0 {
		diskTarget, readErr := inspector.readlink(diskPath)
		if readErr != nil {
			return "", false, fmt.Errorf("%w: read local symlink %q failed: %w", ErrUnsafeDownloadSymlink, rel, readErr)
		}
		return diskTarget, true, nil
	}
	if modeType != 0 && modeType != os.ModeDir {
		return "", false, fmt.Errorf("%w: local path %q has unsafe non-regular mode %s", ErrUnsafeDownloadSymlink, rel, fi.Mode())
	}
	return "", false, nil
}

// probeCaseInsensitiveDir probes whether dir resides on a case-insensitive
// filesystem by creating and removing a unique temporary subdirectory via a
// pinned os.Root handle and comparing flipped-case Lstat metadata with
// os.SameFile. When probing is inconclusive (e.g. a read-only empty directory),
// it fails closed by returning true so case-colliding siblings are rejected.
func probeCaseInsensitiveDir(dir string) bool {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return true
	}
	defer func() { _ = root.Close() }()

	rb := make([]byte, 12)
	if _, randErr := rand.Read(rb); randErr == nil {
		suffix := hex.EncodeToString(rb)
		lower := ".xops-case-" + suffix
		upper := ".XOPS-CASE-" + suffix
		if mkErr := root.Mkdir(lower, 0o700); mkErr == nil {
			defer func() { _ = root.Remove(lower) }()
			fiLower, errLower := root.Lstat(lower)
			fiUpper, errUpper := root.Lstat(upper)
			if errLower == nil {
				if errUpper == nil {
					return os.SameFile(fiLower, fiUpper)
				}
				if errors.Is(errUpper, os.ErrNotExist) {
					return false
				}
			}
		}
	}

	if caseInsensitive, ok := probeCaseInsensitiveExistingDir(root, dir); ok {
		return caseInsensitive
	}
	return true
}

func probeCaseInsensitiveExistingDir(root *os.Root, dir string) (bool, bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, false
	}
	for _, entry := range entries {
		name := entry.Name()
		flipped, ok := flipFirstASCIILetter(name)
		if !ok {
			continue
		}
		fiOrig, errOrig := root.Lstat(name)
		if errOrig != nil {
			continue
		}
		fiFlip, errFlip := root.Lstat(flipped)
		if errors.Is(errFlip, os.ErrNotExist) {
			return false, true
		}
		if errFlip != nil {
			continue
		}
		if !os.SameFile(fiOrig, fiFlip) {
			return false, true
		}
		// Only treat SameFile as conclusive for directories so regular-file
		// hardlinks on case-sensitive filesystems cannot trigger false positives.
		if fiOrig.Mode()&os.ModeType == os.ModeDir {
			return true, true
		}
	}
	return false, false
}

func flipFirstASCIILetter(name string) (string, bool) {
	b := []byte(name)
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z':
			b[i] = c - ('a' - 'A')
			return string(b), true
		case c >= 'A' && c <= 'Z':
			b[i] = c + ('a' - 'A')
			return string(b), true
		}
	}
	return "", false
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
