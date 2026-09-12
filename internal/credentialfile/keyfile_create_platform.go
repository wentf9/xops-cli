//go:build (linux || darwin || windows) && (amd64 || arm64)

package credentialfile

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	unix "github.com/wentf9/xops-cli/internal/vaultsys"
	"github.com/wentf9/xops-cli/pkg/credential"
)

// ensureWrappingKeyFile publishes complete random material without replacing an
// existing path. It is only used when preparing new wrapping material, never to
// unlock a vault or resume a transaction using its original wrapping key.
func ensureWrappingKeyFile(ctx context.Context, path string, ops fileOps) (err error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return credential.ErrCredentialAccessDenied
	}
	parent, err := walkDirectory(ctx, filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("open key file parent: %w", mapAccess(err))
	}
	defer closeFile(&err, parent)
	name := filepath.Base(path)
	if err := syncWrappingKeyFile(ctx, parent, name, ops); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	var key [32]byte
	defer clear(key[:])
	if err := ops.randomBytes(key[:]); err != nil {
		return err
	}
	var suffix [16]byte
	if err := ops.randomBytes(suffix[:]); err != nil {
		return err
	}
	temporary := ".xops-key-" + hex.EncodeToString(suffix[:])
	var fd int
	if err := ops.step(ctx, "key-file:create", func() error {
		var e error
		fd, e = unix.Openat(int(parent.Fd()), temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
		return e
	}); err != nil {
		return fmt.Errorf("create key file: %w", mapAccess(err))
	}
	file := os.NewFile(uintptr(fd), "new-unlock-material")
	published := false
	defer func() {
		closeFile(&err, file)
		if !published {
			if e := unix.Unlinkat(int(parent.Fd()), temporary, 0); e != nil {
				err = errors.Join(err, fmt.Errorf("remove temporary key file: %w", e))
			}
		}
	}()
	if err := file.Chmod(0600); err != nil {
		return fmt.Errorf("protect key file: %w", err)
	}
	if err := ops.step(ctx, "key-file:write", func() error { _, e := file.Write(key[:]); return e }); err != nil {
		return err
	}
	if err := ops.step(ctx, "key-file:sync", func() error { return unix.SyncFile(file) }); err != nil {
		return err
	}
	if err := ops.step(ctx, "key-file:publish", func() error {
		e := renameVaultEntry(int(parent.Fd()), temporary, int(parent.Fd()), name, true)
		if e == nil {
			published = true
		}
		return e
	}); err != nil {
		if errors.Is(err, os.ErrExist) {
			return syncWrappingKeyFile(ctx, parent, name, ops)
		}
		return fmt.Errorf("publish key file: %w", mapAccess(err))
	}
	if err := ops.step(ctx, "key-file:directory-sync", func() error { return unix.SyncFile(parent) }); err != nil {
		return err
	}
	return verifyPublishedKeyFile(ctx, path, key[:])
}

func verifyPublishedKeyFile(ctx context.Context, path string, key []byte) error {
	// Re-resolve the configured path: do not use a key published into a parent
	// directory that was moved or replaced while the operation was running.
	actual, err := readKeyFile(ctx, path)
	defer clear(actual)
	if err != nil {
		return err
	}
	if !bytes.Equal(actual, key) {
		return ErrRevisionChanged
	}
	return nil
}

func syncWrappingKeyFile(ctx context.Context, parent *os.File, name string, ops fileOps) (err error) {
	if err := context.Cause(ctx); err != nil {
		return err
	}
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return mapAccess(err)
	}
	file := os.NewFile(uintptr(fd), "existing-unlock-material")
	defer closeFile(&err, file)
	st, err := inspect(file)
	if err != nil {
		return err
	}
	if err := validateKeyPathStat(st, true); err != nil {
		return err
	}
	// Existing manual files and retries after a publication sync failure must be
	// durable before any vault metadata is allowed to depend on their key.
	if err := ops.step(ctx, "key-file:sync", func() error { return unix.SyncKeyFile(file) }); err != nil {
		return err
	}
	return ops.step(ctx, "key-file:directory-sync", func() error { return unix.SyncFile(parent) })
}

func validateWrappingKeyLocation(vaultPath string, material Wrapping) error {
	if material.Mode != "key-file" {
		return nil
	}
	// Windows keys may intentionally live on another drive/share. Physical
	// ancestor checks still run after opening the paths, including aliases.
	if filepath.IsAbs(vaultPath) && filepath.IsAbs(material.KeyFile) && !strings.EqualFold(filepath.VolumeName(vaultPath), filepath.VolumeName(material.KeyFile)) {
		return nil
	}
	relative, err := filepath.Rel(vaultPath, material.KeyFile)
	if err != nil {
		return fmt.Errorf("resolve wrapping key location: %w", err)
	}
	if relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("key_file must be outside the vault directory: %w", credential.ErrCredentialAccessDenied)
	}
	return nil
}

func validateKeyParent(ctx context.Context, path string, roots []*directory) (err error) {
	parent, err := walkDirectory(ctx, filepath.Dir(path))
	if err != nil {
		return err
	}
	defer closeFile(&err, parent)
	for _, root := range roots {
		inside, e := containsDirectory(ctx, parent, root.id)
		if e != nil {
			return e
		}
		if inside {
			return fmt.Errorf("key_file must be outside source and target vault directories: %w", credential.ErrCredentialAccessDenied)
		}
	}
	return nil
}
