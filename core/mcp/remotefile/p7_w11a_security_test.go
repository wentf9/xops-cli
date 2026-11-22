package remotefile

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	pkgsftp "github.com/pkg/sftp"
	"github.com/wentf9/xops-cli/core/sftp"
)

type w11aFileInfo struct {
	name string
	size int64
	mode os.FileMode
}

func (f w11aFileInfo) Name() string       { return f.name }
func (f w11aFileInfo) Size() int64        { return f.size }
func (f w11aFileInfo) Mode() os.FileMode  { return f.mode }
func (f w11aFileInfo) ModTime() time.Time { return time.Unix(1700000000, 0) }
func (f w11aFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f w11aFileInfo) Sys() any           { return nil }

type w11aListerAt []os.FileInfo

func (l w11aListerAt) ListAt(dst []os.FileInfo, offset int64) (int, error) {
	if offset >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(dst, l[offset:])
	if offset+int64(n) >= int64(len(l)) {
		return n, io.EOF
	}
	return n, nil
}

type w11aHostileHandler struct {
	mu          sync.Mutex
	realPath    string
	stats       map[string]os.FileInfo
	lstats      map[string]os.FileInfo
	removeCalls []string
}

func (h *w11aHostileHandler) Fileread(*pkgsftp.Request) (io.ReaderAt, error) {
	return bytes.NewReader(nil), nil
}

func (h *w11aHostileHandler) Filewrite(*pkgsftp.Request) (io.WriterAt, error) {
	return nil, os.ErrPermission
}

func (h *w11aHostileHandler) Filecmd(r *pkgsftp.Request) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if r.Method == "Remove" {
		h.removeCalls = append(h.removeCalls, r.Filepath)
		return nil
	}
	return os.ErrPermission
}

func (h *w11aHostileHandler) Filelist(r *pkgsftp.Request) (pkgsftp.ListerAt, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if r.Method == "Stat" {
		if fi, ok := h.stats[r.Filepath]; ok {
			return w11aListerAt{fi}, nil
		}
		return nil, os.ErrNotExist
	}
	return nil, os.ErrInvalid
}

func (h *w11aHostileHandler) Lstat(r *pkgsftp.Request) (pkgsftp.ListerAt, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if fi, ok := h.lstats[r.Filepath]; ok {
		return w11aListerAt{fi}, nil
	}
	if fi, ok := h.stats[r.Filepath]; ok {
		return w11aListerAt{fi}, nil
	}
	return nil, os.ErrNotExist
}

func (h *w11aHostileHandler) RealPath(string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.realPath, nil
}

type w11aPipeClient struct {
	client *pkgsftp.Client
}

func (c *w11aPipeClient) Do(_ context.Context, fn func(*pkgsftp.Client) error) error {
	return fn(c.client)
}

func (c *w11aPipeClient) CreatePrivateExclusive(context.Context, string, func(io.Writer) error) (bool, bool, error) {
	return false, false, os.ErrPermission
}

func (c *w11aPipeClient) Close() error { return c.client.Close() }

func newW11aSession(t *testing.T, h *w11aHostileHandler) *Session {
	t.Helper()
	cConn, sConn := net.Pipe()
	srv := pkgsftp.NewRequestServer(sConn, pkgsftp.Handlers{
		FileGet:  h,
		FilePut:  h,
		FileCmd:  h,
		FileList: h,
	})
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = sConn.Close()
	})
	client, err := pkgsftp.NewClientPipe(cConn, cConn)
	if err != nil {
		t.Fatalf("NewClientPipe: %v", err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = cConn.Close()
	})
	return New(&w11aPipeClient{client: client})
}

// TestP7W11a_AB11M2_InspectAndRemoveRejectHostileRealPathAndNegativeSize verifies AB11-M2:
//   - inspectTransferFile validates client.RealPath against sftp.ParseRemotePath
//     and IsAbs(), rejecting empty, relative, NUL, C0/DEL/C1 control, and Unicode
//     line/paragraph separator runes (including segments hidden by "/..").
//   - inspectTransferFile rejects negative remote file sizes with sftp.ErrInvalidRemoteSize
//     and returns zero Metadata.
//   - Session.Remove validates both input name and client.RealPath, refusing to
//     issue Remove calls when RealPath returns hostile or non-absolute paths.
func TestP7W11a_AB11M2_InspectAndRemoveRejectHostileRealPathAndNegativeSize(t *testing.T) {
	hostileRealPaths := []struct {
		name string
		path string
	}{
		{"empty", ""},
		{"relative", "relative/dir"},
		{"dot", "."},
		{"dotdot", ".."},
		{"newline_spoof", "/tmp/good\nPaths: /etc/shadow"},
		{"carriage_return", "/tmp/good\rFake"},
		{"tab", "/tmp/good\tFake"},
		{"esc_osc", "/tmp/good\x1b]52;c;abc\x07"},
		{"del", "/tmp/good\x7f"},
		{"c1_csi", "/tmp/good\u009b2J"},
		{"line_separator", "/tmp/good\u2028Fake"},
		{"paragraph_separator", "/tmp/good\u2029Fake"},
		{"nul", "/tmp/good\x00evil"},
		{"dotdot_hidden_newline", "/tmp/bad\n/../tmp"},
	}

	t.Run("inspect_rejects_hostile_realpath", func(t *testing.T) {
		for _, tc := range hostileRealPaths {
			t.Run(tc.name, func(t *testing.T) {
				h := &w11aHostileHandler{
					realPath: tc.path,
					stats: map[string]os.FileInfo{
						"/tmp":  w11aFileInfo{name: "tmp", mode: os.ModeDir | 0o755},
						tc.path: w11aFileInfo{name: "dir", mode: os.ModeDir | 0o755},
					},
					lstats: map[string]os.FileInfo{
						"/tmp/file.bin": w11aFileInfo{name: "file.bin", size: 12, mode: 0o644},
					},
				}
				sess := newW11aSession(t, h)
				meta, err := sess.Inspect(t.Context(), "/tmp/file.bin", false, false)
				if !errors.Is(err, sftp.ErrInvalidRemotePath) {
					t.Fatalf("Inspect(realPath=%q) = (%+v, %v), want ErrInvalidRemotePath", tc.path, meta, err)
				}
				if meta != (Metadata{}) {
					t.Fatalf("Inspect(realPath=%q) returned non-zero metadata %+v", tc.path, meta)
				}
			})
		}
	})

	t.Run("inspect_rejects_negative_size", func(t *testing.T) {
		for _, negSize := range []int64{-1, -50, math.MinInt64} {
			h := &w11aHostileHandler{
				realPath: "/tmp",
				stats: map[string]os.FileInfo{
					"/tmp": w11aFileInfo{name: "tmp", mode: os.ModeDir | 0o755},
				},
				lstats: map[string]os.FileInfo{
					"/tmp/neg.bin": w11aFileInfo{name: "neg.bin", size: negSize, mode: 0o644},
				},
			}
			sess := newW11aSession(t, h)
			meta, err := sess.Inspect(t.Context(), "/tmp/neg.bin", false, false)
			if !errors.Is(err, sftp.ErrInvalidRemoteSize) {
				t.Fatalf("Inspect(size=%d) = (%+v, %v), want ErrInvalidRemoteSize", negSize, meta, err)
			}
			if meta != (Metadata{}) {
				t.Fatalf("Inspect(size=%d) returned non-zero metadata %+v", negSize, meta)
			}
		}
	})

	t.Run("inspect_rejects_control_chars_in_input_name", func(t *testing.T) {
		h := &w11aHostileHandler{
			realPath: "/tmp",
			stats: map[string]os.FileInfo{
				"/tmp": w11aFileInfo{name: "tmp", mode: os.ModeDir | 0o755},
			},
			lstats: map[string]os.FileInfo{
				"/tmp/good.bin": w11aFileInfo{name: "good.bin", size: 8, mode: 0o644},
			},
		}
		sess := newW11aSession(t, h)
		for _, badName := range []string{"/tmp/bad\n.bin", "/tmp/bad\u2028.bin", "/tmp/bad\n/../good.bin"} {
			if _, err := sess.Inspect(t.Context(), badName, false, false); !errors.Is(err, sftp.ErrInvalidRemotePath) {
				t.Fatalf("Inspect(%q) err = %v, want ErrInvalidRemotePath", badName, err)
			}
		}
	})

	t.Run("remove_rejects_hostile_realpath_and_issues_zero_removes", func(t *testing.T) {
		for _, tc := range hostileRealPaths {
			t.Run(tc.name, func(t *testing.T) {
				h := &w11aHostileHandler{
					realPath: tc.path,
					lstats: map[string]os.FileInfo{
						"/tmp/.xops-transfer-0123456789abcdef0123456789abcdef.tmp": w11aFileInfo{
							name: ".xops-transfer-0123456789abcdef0123456789abcdef.tmp",
							size: 4,
							mode: 0o600,
						},
					},
				}
				sess := newW11aSession(t, h)
				err := sess.Remove(t.Context(), "/tmp/.xops-transfer-0123456789abcdef0123456789abcdef.tmp")
				if !errors.Is(err, sftp.ErrInvalidRemotePath) {
					t.Fatalf("Remove(realPath=%q) err = %v, want ErrInvalidRemotePath", tc.path, err)
				}
				h.mu.Lock()
				calls := len(h.removeCalls)
				h.mu.Unlock()
				if calls != 0 {
					t.Fatalf("Remove(realPath=%q) issued %d Remove calls, want 0", tc.path, calls)
				}
			})
		}
	})
}
