//go:build (linux || darwin || windows) && (amd64 || arm64)

package credentialfile

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	unix "github.com/wentf9/xops-cli/internal/vaultsys"
)

// ProbeCompatibility tests the actual target filesystem in a private scratch
// directory. Existing vaults are locked while probing; an absent target uses
// its parent. Credential contents and key files are never read or changed.
func ProbeCompatibility(ctx context.Context, path string) (report CompatibilityReport, err error) {
	report.Platform = runtime.GOOS + "/" + runtime.GOARCH
	parent, parentPath, release, err := openProbeDirectory(ctx, path)
	if err != nil {
		return report, err
	}
	defer func() { err = errors.Join(err, release()); closeFile(&err, parent) }()
	report.Directory = parentPath
	var random [16]byte
	if err := (fileOps{}).randomBytes(random[:]); err != nil {
		return report, err
	}
	name := ".xops-compat-" + hex.EncodeToString(random[:])
	if err := unix.Mkdirat(int(parent.Fd()), name, 0700); err != nil {
		return report, fmt.Errorf("create compatibility probe directory: %w", err)
	}
	scratch, err := openRoot(ctx, filepath.Join(parentPath, name))
	if err != nil {
		return report, errors.Join(err, unix.Unlinkat(int(parent.Fd()), name, unix.AT_REMOVEDIR))
	}
	defer func() {
		for _, file := range []string{"data", "lock"} {
			if e := unix.Unlinkat(int(scratch.file.Fd()), file, 0); e != nil && !errors.Is(e, os.ErrNotExist) {
				err = errors.Join(err, e)
			}
		}
		for _, dir := range []string{"from", "existing", "published"} {
			if e := unix.Unlinkat(int(scratch.file.Fd()), dir, unix.AT_REMOVEDIR); e != nil && !errors.Is(e, os.ErrNotExist) {
				err = errors.Join(err, e)
			}
		}
		closeFile(&err, scratch.file)
		err = errors.Join(err, unix.Unlinkat(int(parent.Fd()), name, unix.AT_REMOVEDIR), unix.SyncFile(parent))
	}()
	report.Checks = append(report.Checks, "private directory and mount identity")
	if err := probeFilePublication(ctx, scratch); err != nil {
		return report, err
	}
	report.Checks = append(report.Checks, "exclusive file publication, atomic replacement and sync")
	if err := probeDirectoryPublication(ctx, scratch); err != nil {
		return report, err
	}
	report.Checks = append(report.Checks, "exclusive directory publication")
	if err := probeFilesystemLock(scratch); err != nil {
		return report, err
	}
	report.Checks = append(report.Checks, "file lock exclusion and release")
	return report, nil
}

func openProbeDirectory(ctx context.Context, path string) (*os.File, string, func() error, error) {
	root, err := openRoot(ctx, path)
	if errors.Is(err, os.ErrNotExist) {
		parentPath := filepath.Dir(path)
		parent, e := walkDirectory(ctx, parentPath)
		return parent, parentPath, func() error { return nil }, e
	}
	if err != nil {
		return nil, "", nil, fmt.Errorf("open probe target: %w", err)
	}
	store, err := Open(ctx, path, "compatibility-probe", Options{ReadOnly: true})
	if errors.Is(err, os.ErrNotExist) {
		return root.file, path, func() error { return nil }, nil
	}
	if err != nil {
		return nil, "", nil, errors.Join(err, root.file.Close())
	}
	lock, err := store.lock(ctx, true)
	if err != nil {
		return nil, "", nil, errors.Join(err, store.Close(), root.file.Close())
	}
	return root.file, path, func() error { return errors.Join(lock.close(), store.Close()) }, nil
}

func probeFilePublication(ctx context.Context, dir *directory) error {
	if _, err := dir.write(ctx, "data", []byte("probe"), false, "compat", fileOps{}); err != nil {
		return fmt.Errorf("probe exclusive file publication: %w", err)
	}
	if _, err := dir.write(ctx, "data", []byte("must-not-replace"), false, "compat", fileOps{}); !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("exclusive publication failed collision check: %w", errors.Join(ErrUnsupported, err))
	}
	data, err := dir.read(ctx, "data", 32)
	if err != nil || string(data) != "probe" {
		return fmt.Errorf("exclusive publication changed destination: %w", errors.Join(ErrUnsupported, err))
	}
	if _, err := dir.write(ctx, "data", []byte("replacement"), true, "compat", fileOps{}); err != nil {
		return fmt.Errorf("probe atomic replacement: %w", err)
	}
	return nil
}
func probeDirectoryPublication(ctx context.Context, dir *directory) (err error) {
	from, err := dir.mkdir(ctx, "from", false, fileOps{})
	if err != nil {
		return err
	}
	defer closeFile(&err, from.file)
	existing, err := dir.mkdir(ctx, "existing", false, fileOps{})
	if err != nil {
		return err
	}
	defer closeFile(&err, existing.file)
	fd := int(dir.file.Fd())
	if e := renameVaultEntry(fd, "from", fd, "existing", true); !errors.Is(e, os.ErrExist) {
		return fmt.Errorf("exclusive directory publication failed collision check: %w", errors.Join(ErrUnsupported, e))
	}
	if err := renameVaultEntry(fd, "from", fd, "published", true); err != nil {
		return fmt.Errorf("probe directory publication: %w", err)
	}
	return unix.SyncFile(dir.file)
}
func probeFilesystemLock(dir *directory) (err error) {
	first, err := dir.openHandle("lock", unix.O_RDWR|unix.O_CREAT|unix.O_EXCL)
	if err != nil {
		return err
	}
	defer closeFile(&err, first)
	second, err := dir.open("lock", unix.O_RDONLY)
	if err != nil {
		return err
	}
	defer closeFile(&err, second)
	if err := unix.Flock(int(first.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fmt.Errorf("probe exclusive lock: %w", err)
	}
	if e := unix.Flock(int(second.Fd()), unix.LOCK_EX|unix.LOCK_NB); !errors.Is(e, unix.EWOULDBLOCK) && !errors.Is(e, unix.EAGAIN) {
		return fmt.Errorf("filesystem does not enforce lock exclusion: %w", errors.Join(ErrUnsupported, e))
	}
	if err := unix.Flock(int(first.Fd()), unix.LOCK_UN); err != nil {
		return err
	}
	if err := unix.Flock(int(second.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return err
	}
	return unix.Flock(int(second.Fd()), unix.LOCK_UN)
}
