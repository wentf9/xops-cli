package osfs

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/ports"
)

func assertHandleExpired(t *testing.T, label string, err error) {
	t.Helper()
	if !errors.Is(err, ports.ErrHandleExpired) {
		t.Fatalf("过期 %s = %v, 期望 ErrHandleExpired", label, err)
	}
}

// TestBorrowedHandleExpirySentinels 验证全部借用句柄在 active=false 时严格返回 ports.ErrHandleExpired。
func TestBorrowedHandleExpirySentinels(t *testing.T) {
	dest, err := pathalg.ParseLocalRootedDest("sample.txt")
	if err != nil {
		t.Fatal(err)
	}
	lim, err := ports.NewReadLimits(64)
	if err != nil {
		t.Fatal(err)
	}
	r := &rootHandle{}
	_, err = r.ReadAllBounded(dest, lim)
	assertHandleExpired(t, "rootHandle.ReadAllBounded", err)
	assertHandleExpired(t, "rootHandle.WithReadRegular", r.WithReadRegular(dest, lim, func(ports.BoundedReadHandle, int64) error { return nil }))
	assertHandleExpired(t, "rootHandle.CreateExclusive", r.CreateExclusive(dest, 0o600, func(io.Writer) error { return nil }))
	assertHandleExpired(t, "rootHandle.AtomicReplace", r.AtomicReplace(dest, 0o600, func(io.Writer) error { return nil }))
	_, err = r.WriteChunk(dest, 0, bytes.NewReader([]byte("x")), 1, 0o600)
	assertHandleExpired(t, "rootHandle.WriteChunk", err)
	assertHandleExpired(t, "rootHandle.Rename", r.Rename(dest, dest))
	assertHandleExpired(t, "rootHandle.AppendLine", r.AppendLine(dest, 0o600, []byte("x")))
	_, err = r.Stat(dest)
	assertHandleExpired(t, "rootHandle.Stat", err)
	_, err = r.Lstat(dest)
	assertHandleExpired(t, "rootHandle.Lstat", err)
	_, err = r.ReadDir(algebraic.None[pathalg.LocalRootedDest]())
	assertHandleExpired(t, "rootHandle.ReadDir", err)
	assertHandleExpired(t, "rootHandle.MkdirAll", r.MkdirAll(dest, 0o700))
	assertHandleExpired(t, "rootHandle.CreateSymlink", r.CreateSymlink(dest, "target"))
	ts := time.Unix(1700000000, 0).UTC()
	assertHandleExpired(t, "rootHandle.Chtimes", r.Chtimes(dest, ts, ts))
	assertHandleExpired(t, "rootHandle.Remove", r.Remove(dest))

	var buf [4]byte
	lf := &lockedFile{}
	_, err = lf.Read(buf[:])
	assertHandleExpired(t, "lockedFile.Read", err)
	_, err = lf.Write(buf[:])
	assertHandleExpired(t, "lockedFile.Write", err)
	_, err = lf.Seek(0, io.SeekStart)
	assertHandleExpired(t, "lockedFile.Seek", err)
	assertHandleExpired(t, "lockedFile.Truncate", lf.Truncate(0))
	assertHandleExpired(t, "lockedFile.Sync", lf.Sync())
	_, err = lf.Stat()
	assertHandleExpired(t, "lockedFile.Stat", err)

	var off atomic.Bool
	_, err = (&borrowedReader{r: bytes.NewReader([]byte("hi")), active: &off}).Read(buf[:])
	assertHandleExpired(t, "borrowedReader.Read", err)
	_, err = (&borrowedReader{r: bytes.NewReader([]byte("hi")), active: &off}).ReadAt(buf[:], 0)
	assertHandleExpired(t, "borrowedReader.ReadAt", err)
	_, err = (&borrowedWriter{w: io.Discard, active: &off}).Write([]byte("hi"))
	assertHandleExpired(t, "borrowedWriter.Write", err)

	slot := &SocketSlot{}
	_, _, err = slot.AcceptVerified()
	assertHandleExpired(t, "SocketSlot.AcceptVerified", err)
	_, err = slot.Listener().Accept()
	assertHandleExpired(t, "Listener.Accept", err)
	assertHandleExpired(t, "Listener.Close", slot.Listener().Close())
}

func TestBorrowedReaderDetectsRuntimeGrowthPastLimit(t *testing.T) {
	var on atomic.Bool
	on.Store(true)
	br := &borrowedReader{r: bytes.NewReader([]byte("12345")), remaining: 4, maxBytes: 4, limited: true, active: &on}
	_, err := io.ReadAll(br)
	if !errors.Is(err, ports.ErrLimitExceeded) {
		t.Fatalf("超限增长读取 = %v, 期望 ErrLimitExceeded", err)
	}
	var chunk [6]byte
	if _, raErr := br.ReadAt(chunk[:], 0); !errors.Is(raErr, ports.ErrLimitExceeded) {
		t.Fatalf("超限增长 ReadAt(0..6) = %v, 期望 ErrLimitExceeded", raErr)
	}
	if _, raErr := br.ReadAt(chunk[:2], 4); !errors.Is(raErr, ports.ErrLimitExceeded) {
		t.Fatalf("超限增长 ReadAt(4..6) = %v, 期望 ErrLimitExceeded", raErr)
	}
	exact := &borrowedReader{r: bytes.NewReader([]byte("1234")), remaining: 4, maxBytes: 4, limited: true, active: &on}
	if n, raErr := exact.ReadAt(chunk[:], 0); !errors.Is(raErr, io.EOF) || n != 4 || string(chunk[:4]) != "1234" {
		t.Fatalf("边界内 ReadAt = (%d, %q, %v), 期望 (4, 1234, EOF)", n, string(chunk[:n]), raErr)
	}
}

func TestNormalizeWin32LongPathDeterministic(t *testing.T) {
	longSeg := strings.Repeat("x", 240)
	fullResolver := func(p string) (string, error) {
		if strings.HasPrefix(p, "C:") && !strings.HasPrefix(p, `C:\`) {
			return `C:\base\` + p[2:], nil
		}
		if strings.HasPrefix(p, `\\`) || strings.HasPrefix(p, `C:\`) {
			return p, nil
		}
		return `C:\wd\` + p, nil
	}
	wd := func() (string, error) { return `C:\wd`, nil }

	if got := normalizeWin32LongPathWithResolver(`C:\short.txt`, fullResolver, wd); got != `C:\short.txt` {
		t.Fatalf("短路径被误改写: %q", got)
	}
	longDrive := `C:\dir\` + longSeg + `\file.txt`
	if got := normalizeWin32LongPathWithResolver(longDrive, fullResolver, wd); got != `\\?\`+longDrive {
		t.Fatalf("超长盘符路径 = %q, 期望 \\\\?\\%s", got, longDrive)
	}
	longUNC := `\\server\share\` + longSeg + `\file.txt`
	if got := normalizeWin32LongPathWithResolver(longUNC, fullResolver, wd); got != `\\?\UNC\server\share\`+longSeg+`\file.txt` {
		t.Fatalf("超长 UNC 路径 = %q", got)
	}
	// 相对路径加上 cwd 超过 248 UTF-16 码元时必须触发 \\?\ 前缀。
	if got := normalizeWin32LongPathWithResolver(`sub\`+longSeg+`\a.txt`, fullResolver, wd); !strings.HasPrefix(got, `\\?\C:\wd\`) {
		t.Fatalf("超长相对路径 = %q, 期望 \\\\?\\C:\\wd\\...", got)
	}
	// 盘符相对路径展开后超过阈值同样触发 \\?\ 前缀。
	if got := normalizeWin32LongPathWithResolver(`C:`+longSeg+`\a.txt`, fullResolver, wd); !strings.HasPrefix(got, `\\?\C:\base\`) {
		t.Fatalf("超长盘符相对路径 = %q", got)
	}
	// 含辅助平面码点（2 UTF-16 码元/字符）精准触线 248 阈值。
	surrogatePath := `C:\` + strings.Repeat("\U0001F512", 123) // 3 + 246 = 249 UTF-16 码元
	if got := normalizeWin32LongPathWithResolver(surrogatePath, fullResolver, wd); got != `\\?\`+surrogatePath {
		t.Fatalf("UTF-16 代理对超长路径 = %q", got)
	}
}
