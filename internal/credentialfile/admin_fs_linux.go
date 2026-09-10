//go:build linux && amd64

package credentialfile

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/wentf9/xops-cli/pkg/credential"
	"golang.org/x/sys/unix"
)

func (d *directory) mkdir(ctx context.Context, name string, existing bool, ops fileOps) (child *directory, err error) {
	if !component(name) {
		return nil, credential.ErrCredentialAccessDenied
	}
	if err := d.check(); err != nil {
		return nil, err
	}
	created := false
	err = ops.step(ctx, "admin:mkdir", func() error {
		e := unix.Mkdirat(int(d.file.Fd()), name, 0700)
		if e == nil {
			created = true
		}
		return e
	})
	if err != nil && (!existing || !errors.Is(err, os.ErrExist)) {
		return nil, err
	}
	child, err = d.child(name)
	if err != nil {
		if created {
			err = errors.Join(err, unix.Unlinkat(int(d.file.Fd()), name, unix.AT_REMOVEDIR), d.file.Sync())
		}
		return nil, err
	}
	if err := ops.step(ctx, "admin:mkdir-sync", d.file.Sync); err != nil {
		return nil, errors.Join(err, child.file.Close())
	}
	return child, nil
}

func (d *directory) each(ctx context.Context, fn func(string) error) (err error) {
	fd, err := unix.Openat(int(d.file.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), "vault-enumeration")
	defer closeFile(&err, f)
	for {
		if err := context.Cause(ctx); err != nil {
			return err
		}
		entries, e := f.ReadDir(64)
		for _, entry := range entries {
			if err := fn(entry.Name()); err != nil {
				return err
			}
		}
		if errors.Is(e, io.EOF) {
			return nil
		}
		if e != nil {
			return e
		}
	}
}

func nextNumber(ctx context.Context, parent *directory, minimum uint64) (uint64, error) {
	maximum := minimum
	err := parent.each(ctx, func(name string) error {
		n, err := strconv.ParseUint(name, 10, 64)
		if err != nil || n == 0 || strconv.FormatUint(n, 10) != name {
			return ErrMaintenanceRequired
		}
		if n > maximum {
			maximum = n
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	if maximum == math.MaxUint64 {
		return 0, ErrKeyUsageExhausted
	}
	return maximum + 1, nil
}

func createVaultRoot(ctx context.Context, path string) (root *directory, err error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, credential.ErrCredentialAccessDenied
	}
	parent, err := walkDirectory(ctx, filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer closeFile(&err, parent)
	st, err := inspect(parent)
	if err != nil {
		return nil, err
	}
	if _, err := checkExt4(parent, st); err != nil {
		return nil, err
	}
	created := false
	if err := unix.Mkdirat(int(parent.Fd()), filepath.Base(path), 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	} else if err == nil {
		created = true
	}
	root, err = openRoot(ctx, path)
	if err != nil {
		if created {
			err = errors.Join(err, unix.Unlinkat(int(parent.Fd()), filepath.Base(path), unix.AT_REMOVEDIR), parent.Sync())
		}
		return nil, err
	}
	if err := parent.Sync(); err != nil {
		return nil, errors.Join(err, root.file.Close())
	}
	return root, nil
}

func ensureVaultLock(ctx context.Context, root *directory, ops fileOps) (err error) {
	f, err := root.openHandle("vault.lock", unix.O_RDWR|unix.O_CREAT|unix.O_EXCL)
	if errors.Is(err, os.ErrExist) {
		_, err := root.syncExisting(ctx, "vault.lock", "admin:lock", ops)
		return err
	}
	if err != nil {
		return err
	}
	valid := false
	defer func() {
		closeFile(&err, f)
		if !valid {
			err = errors.Join(err, unix.Unlinkat(int(root.file.Fd()), "vault.lock", 0), root.file.Sync())
		}
	}()
	if err := root.validateFile(f); err != nil {
		return err
	}
	valid = true
	if err := ops.step(ctx, "admin:lock-file-sync", f.Sync); err != nil {
		return err
	}
	return ops.step(ctx, "admin:lock-dir-sync", root.file.Sync)
}

func unlinkFile(ctx context.Context, d *directory, name string, ops fileOps) error {
	if !component(name) {
		return credential.ErrCredentialAccessDenied
	}
	err := ops.step(ctx, "admin:unlink", func() error { return unix.Unlinkat(int(d.file.Fd()), name, 0) })
	if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	if err != nil {
		return err
	}
	return ops.step(ctx, "admin:unlink-sync", d.file.Sync)
}

func parseOperationID(name string) (id [16]byte, err error) {
	if len(name) != 32 {
		return id, ErrMaintenanceRequired
	}
	for _, c := range name {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return id, ErrMaintenanceRequired
		}
	}
	b, err := hex.DecodeString(name)
	if err == nil {
		copy(id[:], b)
	}
	return id, err
}

func emptyVault(ctx context.Context, root *directory) error {
	if _, err := root.read(ctx, "CURRENT", 128); err == nil {
		return ErrConflict
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return root.each(ctx, func(name string) error {
		if name == "vault.lock" {
			return nil
		}
		return ErrMaintenanceRequired
	})
}
