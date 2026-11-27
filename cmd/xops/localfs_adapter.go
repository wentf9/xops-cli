package main

import (
	"context"
	"errors"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/entry/sftpshell"
)

// scopedLocalFSAdapter 基于 ports.ScopedRootFS 为 sftpshell 提供安全的本机目录探测与列举实现（零裸 os.*）。
type scopedLocalFSAdapter struct {
	fs    ports.ScopedRootFS
	valid bool
}

var _ sftpshell.LocalFS = (*scopedLocalFSAdapter)(nil)

func newScopedLocalFSAdapter(fsPort ports.ScopedRootFS) *scopedLocalFSAdapter {
	if fsPort == nil {
		return &scopedLocalFSAdapter{}
	}
	return &scopedLocalFSAdapter{fs: fsPort, valid: true}
}

func (a *scopedLocalFSAdapter) ReadDir(ctx context.Context, dir pathalg.LocalDir) ([]sftpshell.LocalDirEntry, error) {
	if ctx == nil {
		return nil, ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if a == nil || !a.valid || !dir.IsValid() {
		return nil, ports.ErrInvalidArgument
	}
	var out []sftpshell.LocalDirEntry
	err := a.fs.WithRoot(dir, func(root ports.RootHandle) error {
		entries, rErr := root.ReadDir(algebraic.None[pathalg.LocalRootedDest]())
		if rErr != nil {
			return rErr
		}
		out = make([]sftpshell.LocalDirEntry, 0, len(entries))
		for _, e := range entries {
			out = append(out, sftpshell.LocalDirEntry{
				Name:  e.Name(),
				IsDir: e.IsDir(),
				Size:  e.Size(),
				Mode:  e.Mode(),
			})
		}
		return nil
	})
	return out, err
}

func (a *scopedLocalFSAdapter) IsDir(ctx context.Context, dir pathalg.LocalDir) (bool, error) {
	if ctx == nil {
		return false, ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if a == nil || !a.valid || !dir.IsValid() {
		return false, ports.ErrInvalidArgument
	}
	parent, base, hasParent, splitErr := splitLocalDirParent(dir)
	if splitErr != nil {
		return false, splitErr
	}
	if hasParent {
		var isDir bool
		err := a.fs.WithRoot(parent, func(root ports.RootHandle) error {
			info, sErr := root.Stat(base)
			if sErr != nil {
				return sErr
			}
			isDir = info.IsDir()
			return nil
		})
		if errors.Is(err, ports.ErrNotFound) {
			return false, nil
		}
		return isDir, err
	}
	err := a.fs.WithRoot(dir, func(ports.RootHandle) error { return nil })
	if err == nil {
		return true, nil
	}
	if errors.Is(err, ports.ErrNotFound) || errors.Is(err, ports.ErrNotRegularFile) {
		return false, nil
	}
	return false, err
}

func splitLocalDirParent(dir pathalg.LocalDir) (pathalg.LocalDir, pathalg.LocalRootedDest, bool, error) {
	norm := strings.TrimRight(strings.ReplaceAll(dir.String(), `\`, "/"), "/")
	idx := strings.LastIndex(norm, "/")
	if idx < 0 || idx == len(norm)-1 {
		return zeroVal[pathalg.LocalDir](), zeroVal[pathalg.LocalRootedDest](), false, nil
	}
	parentRaw := norm[:idx]
	if parentRaw == "" {
		parentRaw = "/"
	} else if len(parentRaw) == 2 && parentRaw[1] == ':' {
		parentRaw += "/"
	}
	baseRaw := norm[idx+1:]
	if parentRaw == norm || baseRaw == "" || baseRaw == "." || baseRaw == ".." {
		return zeroVal[pathalg.LocalDir](), zeroVal[pathalg.LocalRootedDest](), false, nil
	}
	parentDir, err := pathalg.ParseLocalDir(parentRaw)
	if err != nil {
		return zeroVal[pathalg.LocalDir](), zeroVal[pathalg.LocalRootedDest](), false, err
	}
	baseDest, err := pathalg.ParseLocalRootedDest(baseRaw)
	if err != nil {
		return zeroVal[pathalg.LocalDir](), zeroVal[pathalg.LocalRootedDest](), false, err
	}
	return parentDir, baseDest, true, nil
}
