package sftp

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"

	"github.com/pkg/sftp"
)

// ErrUnsafeRemoteDirEntry indicates a remote SFTP server returned a malformed,
// duplicate, or parent-escaping directory entry during ReadDir validation.
var ErrUnsafeRemoteDirEntry = errors.New("unsafe remote directory entry")

func saturatingAddInt64(a, b int64) int64 {
	if a < 0 {
		a = 0
	}
	if b <= 0 {
		return a
	}
	if a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}

// validatedRemoteDirEntry holds a single remote directory entry whose name has
// been validated via ParseRemoteName and whose joined path is verified to stay
// strictly beneath its parent directory.
type validatedRemoteDirEntry struct {
	info  os.FileInfo
	name  RemoteName
	child RemotePath
}

// validateRemoteDirEntries is the single authority validating raw SFTP ReadDir
// entries: non-nil metadata, ParseRemoteName validation (rejecting ".", "..",
// "/", path separators, NUL, and control characters), exact duplicate entry
// rejection, and strict parent containment via RemotePath.Join and RelativeTo.
func validateRemoteDirEntries(
	ctx context.Context,
	parent RemotePath,
	entries []os.FileInfo,
	op string,
) ([]validatedRemoteDirEntry, error) {
	if !parent.IsValid() {
		return nil, fmt.Errorf("%s: %w: invalid remote directory path", op, ErrInvalidRemotePath)
	}
	seen := make(map[string]struct{}, len(entries))
	validated := make([]validatedRemoteDirEntry, 0, len(entries))
	for _, entry := range entries {
		if ctx != nil {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		if entry == nil {
			return nil, fmt.Errorf("%s %q: %w: %w: missing file metadata", op, parent.String(), ErrUnsafeRemoteDirEntry, ErrInvalidRemoteName)
		}
		entryName, nameErr := ParseRemoteName(entry.Name())
		if nameErr != nil {
			return nil, fmt.Errorf("%s %q: %w: unsafe remote filename %q: %w", op, parent.String(), ErrUnsafeRemoteDirEntry, entry.Name(), nameErr)
		}
		rawName := entryName.String()
		if _, dup := seen[rawName]; dup {
			return nil, fmt.Errorf("%s %q: %w: duplicate remote directory entry %q", op, parent.String(), ErrUnsafeRemoteDirEntry, rawName)
		}
		seen[rawName] = struct{}{}

		child := parent.Join(entryName)
		rels, relErr := child.RelativeTo(parent)
		if relErr != nil || len(rels) != 1 || !rels[0].Equal(entryName) {
			return nil, fmt.Errorf("%s %q: %w: entry %q escapes parent directory", op, parent.String(), ErrUnsafeRemoteDirEntry, child.String())
		}
		validated = append(validated, validatedRemoteDirEntry{
			info:  entry,
			name:  entryName,
			child: child,
		})
	}
	return validated, nil
}

// ValidateRemoteDirEntries validates raw SFTP ReadDir entries beneath parent
// through ParseRemoteName (rejecting ".", "..", "/", path separators, NUL, and
// control characters), exact duplicate rejection, and strict parent containment.
func ValidateRemoteDirEntries(parent string, entries []os.FileInfo) ([]os.FileInfo, error) {
	parentPath, err := ParseRemotePath(parent)
	if err != nil {
		return nil, err
	}
	validated, err := validateRemoteDirEntries(context.Background(), parentPath, entries, "readdir")
	if err != nil {
		return nil, err
	}
	out := make([]os.FileInfo, len(validated))
	for i, item := range validated {
		out[i] = item.info
	}
	return out, nil
}

// ReadValidatedDir lists dir on a raw *sftp.Client and validates every returned
// entry through ValidateRemoteDirEntries before yielding any child to the caller.
func ReadValidatedDir(client *sftp.Client, dir string) ([]os.FileInfo, error) {
	return ReadValidatedDirContext(context.Background(), client, dir)
}

// ReadValidatedDirContext lists dir on a raw *sftp.Client using ctx and
// validates every returned entry through ValidateRemoteDirEntries before
// yielding any child to the caller.
func ReadValidatedDirContext(ctx context.Context, client *sftp.Client, dir string) ([]os.FileInfo, error) {
	if client == nil {
		return nil, fmt.Errorf("sftp client is nil")
	}
	if ctx == nil {
		return nil, fmt.Errorf("context is nil")
	}
	parent, err := ParseRemotePath(dir)
	if err != nil {
		return nil, err
	}
	validated, err := readValidatedRemoteDir(ctx, client, parent, "readdir")
	if err != nil {
		return nil, err
	}
	out := make([]os.FileInfo, len(validated))
	for i, item := range validated {
		out[i] = item.info
	}
	return out, nil
}

// readValidatedRemoteDir reads parent via SFTP ReadDir and validates every
// returned entry before yielding any child to the caller.
func readValidatedRemoteDir(
	ctx context.Context,
	client *sftp.Client,
	parent RemotePath,
	op string,
) ([]validatedRemoteDirEntry, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	if !parent.IsValid() {
		return nil, fmt.Errorf("%s: %w: invalid remote directory path", op, ErrInvalidRemotePath)
	}
	readCtx := ctx
	if readCtx == nil {
		readCtx = context.Background()
	}
	entries, err := client.ReadDirContext(readCtx, parent.String())
	if err != nil {
		return nil, fmt.Errorf("read remote directory %q failed: %w", parent.String(), err)
	}
	return validateRemoteDirEntries(ctx, parent, entries, op)
}

// readValidatedRemoteDirIgnoreReadErr reads and validates parent, ignoring
// non-context SFTP read errors (matching Glob semantics) while still failing
// closed on hostile directory entries.
func readValidatedRemoteDirIgnoreReadErr(
	ctx context.Context,
	client *sftp.Client,
	parent RemotePath,
	op string,
) ([]validatedRemoteDirEntry, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	if !parent.IsValid() {
		return nil, fmt.Errorf("%s: %w: invalid remote directory path", op, ErrInvalidRemotePath)
	}
	readCtx := ctx
	if readCtx == nil {
		readCtx = context.Background()
	}
	entries, err := client.ReadDirContext(readCtx, parent.String())
	if err != nil {
		if ctx != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
		}
		return nil, nil
	}
	return validateRemoteDirEntries(ctx, parent, entries, op)
}

// ReadDir lists dir over SFTP and validates every returned entry through
// ParseRemoteName, rejecting ".", "..", "/", path separators, NUL/control
// characters, exact duplicates, and any child escaping dir. Cancellation
// interrupts this SFTP subsystem, so the client must not be reused afterwards.
func (c *Client) ReadDir(ctx context.Context, dir string) ([]os.FileInfo, error) {
	if c == nil || c.SFTPClient() == nil {
		return nil, fmt.Errorf("sftp client is nil")
	}
	if ctx == nil {
		return nil, fmt.Errorf("context is nil")
	}
	parent, err := ParseRemotePath(dir)
	if err != nil {
		return nil, err
	}
	var out []os.FileInfo
	err = runInterruptibleOperation(ctx, c.interruptTransfers, func() error {
		validated, readErr := readValidatedRemoteDir(ctx, c.SFTPClient(), parent, "readdir")
		if readErr != nil {
			return readErr
		}
		out = make([]os.FileInfo, len(validated))
		for i, item := range validated {
			out[i] = item.info
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// WalkFunc is the callback invoked by Client.Walk for each validated remote
// entry visited under remoteRoot.
type WalkFunc func(remotePath RemotePath, info os.FileInfo) error

// Walk traverses remoteRoot over SFTP, dereferencing remoteRoot via Stat
// (matching Download/Upload top-level semantics) and recursively reading
// directories through the ParseRemoteName-validated directory reader. Child
// symbolic links are visited as links and never followed. Cancellation
// interrupts this SFTP subsystem, so the client must not be reused afterwards.
func (c *Client) Walk(ctx context.Context, remoteRoot RemotePath, fn WalkFunc) error {
	if c == nil || c.SFTPClient() == nil {
		return fmt.Errorf("sftp client is nil")
	}
	if !remoteRoot.IsValid() {
		return fmt.Errorf("%w: remote walk root is invalid", ErrInvalidRemotePath)
	}
	if fn == nil {
		return fmt.Errorf("sftp walk callback is nil")
	}
	return runInterruptibleOperation(ctx, c.interruptTransfers, func() error {
		return c.walkRemote(ctx, remoteRoot, fn)
	})
}

func (c *Client) walkRemote(ctx context.Context, remoteRoot RemotePath, fn WalkFunc) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	rootInfo, err := c.SFTPClient().Stat(remoteRoot.String())
	if err != nil {
		return fmt.Errorf("stat remote path %q failed: %w", remoteRoot.String(), err)
	}
	if err := fn(remoteRoot, rootInfo); err != nil {
		return err
	}
	if rootInfo.Mode()&os.ModeType != os.ModeDir {
		return nil
	}
	return c.walkRemoteDir(ctx, remoteRoot, remoteRoot, fn)
}

func (c *Client) walkRemoteDir(ctx context.Context, root, current RemotePath, fn WalkFunc) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	entries, err := readValidatedRemoteDir(ctx, c.SFTPClient(), current, "walk")
	if err != nil {
		return err
	}
	for _, item := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, relErr := item.child.RelativeTo(root); relErr != nil {
			return fmt.Errorf("walk %q: entry %q escapes root %q: %w", current.String(), item.child.String(), root.String(), relErr)
		}
		if err := fn(item.child, item.info); err != nil {
			return err
		}
		if item.info.Mode()&os.ModeType == os.ModeDir {
			if err := c.walkRemoteDir(ctx, root, item.child, fn); err != nil {
				return err
			}
		}
	}
	return nil
}

// DownloadTransferSize calculates the total progress byte count that
// Client.Download will emit for remoteRoot. It dereferences remoteRoot via Stat
// (matching downloadOne), walks directories through the ParseRemoteName-validated
// directory reader without following child symlinks, and accounts for child
// symlinks using int64(len(ReadLink(child))) to match createDownloadLink.
// Cancellation interrupts this SFTP subsystem, so the client must not be reused
// afterwards.
func (c *Client) DownloadTransferSize(ctx context.Context, remoteRoot RemotePath) (int64, error) {
	if c == nil || c.SFTPClient() == nil {
		return 0, fmt.Errorf("sftp client is nil")
	}
	if !remoteRoot.IsValid() {
		return 0, fmt.Errorf("%w: remote path is invalid", ErrInvalidRemotePath)
	}
	var total int64
	err := runInterruptibleOperation(ctx, c.interruptTransfers, func() error {
		size, walkErr := c.downloadTransferSize(ctx, remoteRoot)
		if walkErr != nil {
			return walkErr
		}
		total = size
		return nil
	})
	if err != nil {
		return 0, err
	}
	return total, nil
}

func (c *Client) downloadTransferSize(ctx context.Context, remoteRoot RemotePath) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	rootInfo, err := c.SFTPClient().Stat(remoteRoot.String())
	if err != nil {
		return 0, fmt.Errorf("stat remote path %q failed: %w", remoteRoot.String(), err)
	}
	if err := validateRemoteDownloadMode(remoteRoot.String(), rootInfo.Mode(), false); err != nil {
		return 0, err
	}
	if rootInfo.Mode()&os.ModeType != os.ModeDir {
		return saturatingAddInt64(0, rootInfo.Size()), nil
	}

	var total int64
	err = c.walkRemoteDir(ctx, remoteRoot, remoteRoot, func(child RemotePath, info os.FileInfo) error {
		if err := validateRemoteDownloadMode(child.String(), info.Mode(), true); err != nil {
			return err
		}
		switch info.Mode() & os.ModeType {
		case os.ModeDir:
			return nil
		case os.ModeSymlink:
			target, readErr := c.SFTPClient().ReadLink(child.String())
			if readErr != nil {
				return fmt.Errorf("read remote symbolic link %q failed: %w", child.String(), readErr)
			}
			total = saturatingAddInt64(total, int64(len(target)))
			return nil
		default:
			total = saturatingAddInt64(total, info.Size())
			return nil
		}
	})
	if err != nil {
		return 0, err
	}
	return total, nil
}
