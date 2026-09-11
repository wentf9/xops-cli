//go:build (linux || darwin || windows) && (amd64 || arm64)

package credentialfile

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/wentf9/xops-cli/internal/credentialfile/format"
	unix "github.com/wentf9/xops-cli/internal/vaultsys"
	"github.com/wentf9/xops-cli/pkg/credential"
)

type fileID struct {
	dev uint64
	ino uint64
}

type directory struct {
	file  *os.File
	id    fileID
	mount uint64
}

// Fault injection stays package-private; production callers cannot bypass checks.
type fileOps struct {
	before func(string) error
	after  func(string)
	random io.Reader
}

func (o fileOps) step(ctx context.Context, name string, fn func() error) error {
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if o.before != nil {
		if err := o.before(name); err != nil {
			return err
		}
	}
	if err := fn(); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if o.after != nil {
		o.after(name)
	}
	return nil
}

func (o fileOps) randomBytes(b []byte) error {
	r := o.random
	if r == nil {
		r = rand.Reader
	}
	if _, err := io.ReadFull(r, b); err != nil {
		return fmt.Errorf("generate vault randomness: %w", err)
	}
	return nil
}

func inspect(file *os.File) (unix.Stat_t, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &st); err != nil {
		return st, fmt.Errorf("stat vault handle: %w", err)
	}
	return st, nil
}

func validatePrivate(st unix.Stat_t, dir bool) error {
	want := uint32(unix.S_IFREG | 0600)
	if dir {
		want = unix.S_IFDIR | 0700
	}
	if st.Mode != want || st.Uid != uint32(os.Geteuid()) || (!dir && st.Nlink != 1) {
		return credential.ErrCredentialAccessDenied
	}
	return nil
}

func newDirectory(file *os.File, root *directory) (d *directory, err error) {
	defer func() {
		if err != nil {
			err = errors.Join(err, file.Close())
		}
	}()
	st, err := inspect(file)
	if err != nil {
		return nil, err
	}
	if err := validatePrivate(st, true); err != nil {
		return nil, err
	}
	// Filesystem reliability belongs to the deployment. Keep handle/mount
	// identity checks, but do not admit or reject storage by filesystem name.
	mount, err := mountID(file)
	if err == nil && root != nil && (st.Dev != root.id.dev || mount != root.mount) {
		err = ErrUnsupported
	}
	if err != nil {
		return nil, err
	}
	return &directory{file: file, id: fileID{st.Dev, st.Ino}, mount: mount}, nil
}

func openRoot(ctx context.Context, path string) (*directory, error) {
	f, err := walkDirectory(ctx, path)
	if err != nil {
		return nil, err
	}
	return newDirectory(f, nil)
}

func walkDirectory(ctx context.Context, path string) (_ *os.File, err error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("vault path must be a clean absolute private directory")
	}
	f, err := os.Open(filepath.VolumeName(path) + string(filepath.Separator))
	if err != nil {
		return nil, err
	}
	defer func() {
		if f != nil {
			err = errors.Join(err, f.Close())
		}
	}()
	parts := strings.Split(strings.TrimPrefix(strings.TrimPrefix(path, filepath.VolumeName(path)), string(filepath.Separator)), string(filepath.Separator))
	if path == filepath.VolumeName(path)+string(filepath.Separator) {
		parts = nil
	}
	for _, part := range parts {
		if err := context.Cause(ctx); err != nil {
			return nil, err
		}
		fd, openErr := unix.Openat(int(f.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr != nil {
			return nil, fmt.Errorf("open vault directory component: %w", openErr)
		}
		next := os.NewFile(uintptr(fd), "vault-directory")
		closeErr := f.Close()
		f = next
		if closeErr != nil {
			return nil, fmt.Errorf("close ancestor directory: %w", closeErr)
		}
		{
			st, statErr := inspect(f)
			if statErr != nil {
				return nil, statErr
			}
			trustedOwner := st.Uid == 0 || st.Uid == uint32(os.Geteuid())
			protected := st.Mode&0022 == 0 || st.Mode&unix.S_ISVTX != 0
			if !trustedOwner || !protected {
				return nil, credential.ErrCredentialAccessDenied
			}
		}
	}
	owned := f
	f = nil
	return owned, nil
}

func component(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "/\\\x00")
}

func (d *directory) check() error {
	st, err := inspect(d.file)
	if err != nil {
		return err
	}
	if err := validatePrivate(st, true); err != nil {
		return err
	}
	if (fileID{st.Dev, st.Ino}) != d.id {
		return ErrRevisionChanged
	}
	return nil
}

func (d *directory) child(name string) (*directory, error) {
	if err := d.check(); err != nil {
		return nil, err
	}
	if !component(name) {
		return nil, credential.ErrCredentialAccessDenied
	}
	fd, err := unix.Openat(int(d.file.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open vault subdirectory: %w", err)
	}
	return newDirectory(os.NewFile(uintptr(fd), "vault-subdirectory"), d)
}

// openHandle transfers ownership immediately after openat, before validation.
// Creation callers must install both handle and pathname cleanup before checking it.
func (d *directory) openHandle(name string, flags int) (*os.File, error) {
	if err := d.check(); err != nil {
		return nil, err
	}
	if !component(name) {
		return nil, credential.ErrCredentialAccessDenied
	}
	fd, err := unix.Openat(int(d.file.Fd()), name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, fmt.Errorf("open vault file: %w", err)
	}
	return os.NewFile(uintptr(fd), "vault-file"), nil
}

func (d *directory) validateFile(f *os.File) error {
	st, err := inspect(f)
	if err == nil {
		err = validatePrivate(st, false)
	}
	if err == nil && st.Dev != d.id.dev {
		err = ErrUnsupported
	}
	if err == nil {
		var mount uint64
		mount, err = mountID(f)
		if err == nil && mount != d.mount {
			err = ErrUnsupported
		}
	}
	return err
}

func (d *directory) open(name string, flags int) (*os.File, error) {
	if flags&unix.O_CREAT != 0 {
		return nil, fmt.Errorf("vault file creation requires immediate pathname cleanup")
	}
	f, err := d.openHandle(name, flags)
	if err != nil {
		return nil, err
	}
	if err := d.validateFile(f); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return f, nil
}

func (d *directory) read(ctx context.Context, name string, max int) (data []byte, err error) {
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	f, err := d.open(name, unix.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, f.Close())
		if err != nil {
			data = nil
		}
	}()
	st, err := inspect(f)
	if err != nil {
		return nil, err
	}
	if st.Size < 0 || st.Size > int64(max) {
		return nil, fmt.Errorf("vault file exceeds size limit: %w", format.ErrCorrupt)
	}
	data, err = io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil {
		return nil, fmt.Errorf("read vault file: %w", err)
	}
	if len(data) > max {
		return nil, fmt.Errorf("vault file exceeds size limit: %w", format.ErrCorrupt)
	}
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	return data, nil
}

func (d *directory) pending(ctx context.Context, anyEntry bool) (err error) {
	if err := d.check(); err != nil {
		return err
	}
	fd, err := unix.Openat(int(d.file.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open directory listing: %w", err)
	}
	f := os.NewFile(uintptr(fd), "vault-listing")
	defer func() { err = errors.Join(err, f.Close()) }()
	for {
		if err := context.Cause(ctx); err != nil {
			return err
		}
		entries, readErr := f.ReadDir(64)
		for _, entry := range entries {
			if anyEntry || strings.HasPrefix(entry.Name(), ".tmp-") {
				return ErrMaintenanceRequired
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return fmt.Errorf("list vault directory: %w", readErr)
		}
	}
}

func (d *directory) syncExisting(ctx context.Context, name, scope string, ops fileOps) (durable bool, err error) {
	f, err := d.open(name, unix.O_RDONLY)
	if err != nil {
		return false, err
	}
	defer func() {
		err = errors.Join(err, f.Close())
		if ops.before != nil {
			err = errors.Join(err, ops.before(scope+":close"))
		}
	}()
	if err := ops.step(ctx, scope+":file-sync", func() error { return unix.SyncFile(f) }); err != nil {
		return false, err
	}
	if err := ops.step(ctx, scope+":dir-sync", func() error { return unix.SyncFile(d.file) }); err != nil {
		return false, err
	}
	return true, nil
}

type mutationOutcome struct{ applied, durable bool }

func (d *directory) write(ctx context.Context, name string, data []byte, replace bool, scope string, ops fileOps) (out mutationOutcome, err error) {
	var random [16]byte
	if err := ops.randomBytes(random[:]); err != nil {
		return out, err
	}
	temp := ".tmp-" + hex.EncodeToString(random[:])
	f, err := d.openHandle(temp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL)
	if err != nil {
		return out, err
	}
	published := false
	defer func() {
		err = errors.Join(err, f.Close())
		if ops.before != nil {
			err = errors.Join(err, ops.before(scope+":close"))
		}
		if !published {
			err = errors.Join(err, unix.Unlinkat(int(d.file.Fd()), temp, 0), unix.SyncFile(d.file))
		}
		if err != nil && out.applied {
			err = &DurabilityError{Op: scope, Applied: out.applied, Durable: out.durable, Cause: err}
		}
	}()
	if err := d.validateFile(f); err != nil {
		return out, err
	}
	if err := ops.step(ctx, scope+":write", func() error {
		n, err := f.Write(data)
		if err == nil && n != len(data) {
			err = io.ErrShortWrite
		}
		return err
	}); err != nil {
		return out, err
	}
	if err := ops.step(ctx, scope+":file-sync", func() error { return unix.SyncFile(f) }); err != nil {
		return out, err
	}
	if err := ops.step(ctx, scope+":publish", func() error {
		return renameVaultEntry(int(d.file.Fd()), temp, int(d.file.Fd()), name, !replace)
	}); err != nil {
		if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EOPNOTSUPP) {
			err = errors.Join(ErrUnsupported, err)
		}
		return out, err
	}
	published = true
	out.applied = true
	if err := ops.step(ctx, scope+":dir-sync", func() error { return unix.SyncFile(d.file) }); err != nil {
		return out, err
	}
	out.durable = true
	return out, nil
}
