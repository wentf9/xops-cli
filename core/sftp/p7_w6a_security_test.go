package sftp

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	pkgsftp "github.com/pkg/sftp"
)

const specialModeBits = os.ModeSetuid | os.ModeSetgid | os.ModeSticky

type stagingOpEvent struct {
	kind string // "chmod", "read", "write", "chtimes", "rename"
	path string
	mode os.FileMode
}

type stagingOpRecorder struct {
	mu     sync.Mutex
	events []stagingOpEvent
}

func (r *stagingOpRecorder) record(ev stagingOpEvent) {
	r.mu.Lock()
	r.events = append(r.events, ev)
	r.mu.Unlock()
}

func (r *stagingOpRecorder) reset() {
	r.mu.Lock()
	r.events = nil
	r.mu.Unlock()
}

func (r *stagingOpRecorder) snapshot() []stagingOpEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]stagingOpEvent, len(r.events))
	copy(out, r.events)
	return out
}

type stagingRecordingCmder struct {
	delegate pkgsftp.FileCmder
	rec      *stagingOpRecorder
}

func (c *stagingRecordingCmder) Filecmd(r *pkgsftp.Request) error {
	switch r.Method {
	case "Setstat":
		if r.AttrFlags().Permissions {
			c.rec.record(stagingOpEvent{
				kind: "chmod",
				path: r.Filepath,
				mode: r.Attributes().FileMode(),
			})
		}
		if r.AttrFlags().Acmodtime {
			c.rec.record(stagingOpEvent{
				kind: "chtimes",
				path: r.Filepath,
			})
		}
	case "Rename":
		c.rec.record(stagingOpEvent{
			kind: "rename",
			path: r.Filepath + "->" + r.Target,
		})
	}
	return c.delegate.Filecmd(r)
}

func (c *stagingRecordingCmder) PosixRename(r *pkgsftp.Request) error {
	c.rec.record(stagingOpEvent{
		kind: "rename",
		path: r.Filepath + "->" + r.Target,
	})
	if pr, ok := c.delegate.(pkgsftp.PosixRenameFileCmder); ok {
		return pr.PosixRename(r)
	}
	return pkgsftp.ErrSSHFxOpUnsupported
}

type stagingRecordingWriterAt struct {
	io.WriterAt
	path string
	rec  *stagingOpRecorder
}

func (w *stagingRecordingWriterAt) WriteAt(p []byte, off int64) (int, error) {
	w.rec.record(stagingOpEvent{kind: "write", path: w.path})
	return w.WriterAt.WriteAt(p, off)
}

func (w *stagingRecordingWriterAt) Close() error {
	if cl, ok := w.WriterAt.(io.Closer); ok {
		return cl.Close()
	}
	return nil
}

type stagingRecordingReadWriterAt struct {
	pkgsftp.WriterAtReaderAt
	path string
	rec  *stagingOpRecorder
}

func (rw *stagingRecordingReadWriterAt) ReadAt(p []byte, off int64) (int, error) {
	rw.rec.record(stagingOpEvent{kind: "read", path: rw.path})
	return rw.WriterAtReaderAt.ReadAt(p, off)
}

func (rw *stagingRecordingReadWriterAt) WriteAt(p []byte, off int64) (int, error) {
	rw.rec.record(stagingOpEvent{kind: "write", path: rw.path})
	return rw.WriterAtReaderAt.WriteAt(p, off)
}

func (rw *stagingRecordingReadWriterAt) Close() error {
	if cl, ok := rw.WriterAtReaderAt.(io.Closer); ok {
		return cl.Close()
	}
	return nil
}

type stagingRecordingFilePut struct {
	delegate pkgsftp.FileWriter
	rec      *stagingOpRecorder
}

func (p *stagingRecordingFilePut) Filewrite(r *pkgsftp.Request) (io.WriterAt, error) {
	w, err := p.delegate.Filewrite(r)
	if err != nil {
		return nil, err
	}
	return &stagingRecordingWriterAt{WriterAt: w, path: r.Filepath, rec: p.rec}, nil
}

func (p *stagingRecordingFilePut) OpenFile(r *pkgsftp.Request) (pkgsftp.WriterAtReaderAt, error) {
	if ofw, ok := p.delegate.(pkgsftp.OpenFileWriter); ok {
		rw, err := ofw.OpenFile(r)
		if err != nil {
			return nil, err
		}
		return &stagingRecordingReadWriterAt{WriterAtReaderAt: rw, path: r.Filepath, rec: p.rec}, nil
	}
	return nil, pkgsftp.ErrSSHFxOpUnsupported
}

type stagingLifecycleIndices struct {
	firstChmod0600 int
	firstRead      int
	firstWrite     int
	lastWrite      int
	finalChmod     int
	rename         int
}

func collectStagingLifecycleIndices(t *testing.T, events []stagingOpEvent, tempPath, dstPath string, wantFinalPerm os.FileMode) stagingLifecycleIndices {
	t.Helper()
	idx := stagingLifecycleIndices{
		firstChmod0600: -1,
		firstRead:      -1,
		firstWrite:     -1,
		lastWrite:      -1,
		finalChmod:     -1,
		rename:         -1,
	}
	renameTag := tempPath + "->" + dstPath
	for i, ev := range events {
		switch ev.kind {
		case "chmod":
			recordStagingChmodEvent(t, &idx, i, ev, tempPath, wantFinalPerm, events)
		case "read":
			if ev.path == tempPath && idx.firstRead == -1 {
				idx.firstRead = i
			}
		case "write":
			if ev.path == tempPath {
				if idx.firstWrite == -1 {
					idx.firstWrite = i
				}
				idx.lastWrite = i
			}
		case "rename":
			if ev.path == renameTag {
				idx.rename = i
			}
		}
	}
	return idx
}

func recordStagingChmodEvent(t *testing.T, idx *stagingLifecycleIndices, i int, ev stagingOpEvent, tempPath string, wantFinalPerm os.FileMode, events []stagingOpEvent) {
	t.Helper()
	if ev.path != tempPath {
		return
	}
	if ev.mode&specialModeBits != 0 {
		t.Fatalf("chmod on %q carried special bits: %v (events=%+v)", tempPath, ev.mode, events)
	}
	if idx.firstChmod0600 == -1 {
		if ev.mode.Perm() != 0o600 {
			t.Fatalf("first chmod on %q = %04o, want strictly 0600 (events=%+v)", tempPath, ev.mode.Perm(), events)
		}
		idx.firstChmod0600 = i
	}
	if ev.mode.Perm() == wantFinalPerm {
		idx.finalChmod = i
	}
}

func assertStrict0600StagingLifecycle(t *testing.T, events []stagingOpEvent, tempPath, dstPath string, wantFinalPerm os.FileMode, expectWrite, expectRead bool) {
	t.Helper()
	idx := collectStagingLifecycleIndices(t, events, tempPath, dstPath, wantFinalPerm)

	if idx.firstChmod0600 == -1 {
		t.Fatalf("missing pre-write Chmod(0600) on %q (events=%+v)", tempPath, events)
	}
	if expectRead && (idx.firstRead == -1 || idx.firstChmod0600 >= idx.firstRead) {
		t.Fatalf("Chmod(0600) (%d) must precede resume prefix ReadAt (%d) on %q (events=%+v)", idx.firstChmod0600, idx.firstRead, tempPath, events)
	}
	if expectWrite {
		assertNoWideChmodBeforeLastWrite(t, events, tempPath, idx)
	}
	if idx.rename == -1 {
		t.Fatalf("missing atomic rename %q->%q (events=%+v)", tempPath, dstPath, events)
	}
	if wantFinalPerm == 0 {
		return
	}
	if idx.finalChmod == -1 || idx.finalChmod >= idx.rename {
		t.Fatalf("final Chmod(%04o) (%d) must occur before rename (%d) (events=%+v)", wantFinalPerm, idx.finalChmod, idx.rename, events)
	}
	if expectWrite && wantFinalPerm != 0o600 && idx.finalChmod <= idx.lastWrite {
		t.Fatalf("final Chmod(%04o) (%d) must occur AFTER last write (%d) (events=%+v)", wantFinalPerm, idx.finalChmod, idx.lastWrite, events)
	}
}

func assertNoWideChmodBeforeLastWrite(t *testing.T, events []stagingOpEvent, tempPath string, idx stagingLifecycleIndices) {
	t.Helper()
	if idx.firstWrite == -1 || idx.firstChmod0600 >= idx.firstWrite {
		t.Fatalf("Chmod(0600) (%d) must precede first WriteAt (%d) on %q (events=%+v)", idx.firstChmod0600, idx.firstWrite, tempPath, events)
	}
	for i, ev := range events {
		if ev.kind == "chmod" && ev.path == tempPath && i < idx.lastWrite && ev.mode.Perm() != 0o600 {
			t.Fatalf("staging file %q widened to %04o at event %d before last write at %d (events=%+v)", tempPath, ev.mode.Perm(), i, idx.lastWrite, events)
		}
	}
}

func TestP7W6a_AB6H1_PermissionSanitizationAnd0600Staging(t *testing.T) {
	t.Run("sanitizers_strip_all_special_and_type_bits", testP7W6aSanitizersStripSpecialBits)
	t.Run("upload_stages_0600_and_strips_special_bits", testP7W6aUploadStagingAndSanitization)
	t.Run("upload_resume_tightens_to_0600_before_prefix_read_and_write", testP7W6aUploadResumeStaging0600)
	t.Run("remote_copy_file_and_dir_stage_0600_and_strip_special_bits", testP7W6aRemoteCopyStagingAndSanitization)
	t.Run("relay_file_from_stages_0600_and_strips_special_bits", testP7W6aRelayStagingAndSanitization)
}

func testP7W6aSanitizersStripSpecialBits(t *testing.T) {
	t.Helper()
	cases := []struct {
		in   os.FileMode
		want os.FileMode
	}{
		{in: 0, want: 0},
		{in: os.ModeSetuid, want: 0},
		{in: specialModeBits | 0o555, want: 0o555},
		{in: specialModeBits | 0o755, want: 0o755},
		{in: os.ModeDir | os.ModeSetgid | os.ModeSticky | 0o750, want: 0o750},
		{in: os.ModeIrregular | os.ModeSetuid | 0o666, want: 0o666},
	}
	for _, tc := range cases {
		if got := sanitizeTransferFilePerm(tc.in); got != tc.want {
			t.Fatalf("sanitizeTransferFilePerm(%v) = %v, want %v", tc.in, got, tc.want)
		}
		if got := sanitizeTransferDirPerm(tc.in); got != tc.want {
			t.Fatalf("sanitizeTransferDirPerm(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func testP7W6aUploadStagingAndSanitization(t *testing.T) {
	t.Helper()
	cases := []struct {
		name     string
		mode     os.FileMode
		payload  []byte
		wantPerm os.FileMode
	}{
		{name: "wide_0777", mode: 0o777, payload: bytes.Repeat([]byte("A"), 64*1024), wantPerm: 0o777},
		{name: "wide_0666", mode: 0o666, payload: []byte("shared-payload"), wantPerm: 0o666},
		{name: "setuid_setgid_sticky_0555_nonzero", mode: specialModeBits | 0o555, payload: []byte("bin"), wantPerm: 0o555},
		{name: "setuid_setgid_sticky_0555_zero", mode: specialModeBits | 0o555, payload: nil, wantPerm: 0o555},
		{name: "setuid_setgid_sticky_0755", mode: specialModeBits | 0o755, payload: []byte("elf"), wantPerm: 0o755},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &stagingOpRecorder{}
			handlers := pkgsftp.InMemHandler()
			handlers.FileCmd = &stagingRecordingCmder{delegate: handlers.FileCmd, rec: rec}
			handlers.FilePut = &stagingRecordingFilePut{delegate: handlers.FilePut, rec: rec}
			client := newTestSFTPClientWithHandlers(t, handlers)

			localPath := filepath.Join(t.TempDir(), tc.name+".bin")
			if err := os.WriteFile(localPath, tc.payload, 0o600); err != nil {
				t.Fatal(err)
			}
			remotePath := "/" + tc.name + ".bin"
			if err := client.UploadFile(t.Context(), localPath, remotePath, int64(len(tc.payload)), tc.mode, nil); err != nil {
				t.Fatalf("UploadFile(%s): %v", tc.name, err)
			}
			assertStrict0600StagingLifecycle(
				t,
				rec.snapshot(),
				remotePath+client.config.TempSuffix,
				remotePath,
				tc.wantPerm,
				len(tc.payload) > 0,
				false,
			)
		})
	}
}

func testP7W6aUploadResumeStaging0600(t *testing.T) {
	t.Helper()
	rec := &stagingOpRecorder{}
	handlers := pkgsftp.InMemHandler()
	handlers.FileCmd = &stagingRecordingCmder{delegate: handlers.FileCmd, rec: rec}
	handlers.FilePut = &stagingRecordingFilePut{delegate: handlers.FilePut, rec: rec}
	client := newTestSFTPClientWithHandlers(t, handlers)
	client.config.EnableResume = true
	client.config.ResumeMinSize = 4

	remotePath := "/resumed.bin"
	tempPath := remotePath + client.config.TempSuffix
	tf, err := client.state.sftpClient.Create(tempPath)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = tf.Write([]byte("01234567"))
	_ = tf.Close()
	rec.reset()

	localPath := filepath.Join(t.TempDir(), "resumed.bin")
	payload := []byte("0123456789abcdef")
	if err := os.WriteFile(localPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := client.UploadFile(t.Context(), localPath, remotePath, int64(len(payload)), 0o777, nil); err != nil {
		t.Fatalf("UploadFile resume: %v", err)
	}
	assertStrict0600StagingLifecycle(t, rec.snapshot(), tempPath, remotePath, 0o777, true, true)
}

func testP7W6aRemoteCopyStagingAndSanitization(t *testing.T) {
	t.Helper()
	cases := []struct {
		name     string
		srcMode  os.FileMode
		payload  []byte
		wantPerm os.FileMode
	}{
		{name: "wide_0777", srcMode: 0o777, payload: []byte("copy-payload"), wantPerm: 0o777},
		{name: "wide_0666", srcMode: 0o666, payload: []byte("copy-payload-2"), wantPerm: 0o666},
		{name: "setuid_0555_zero", srcMode: specialModeBits | 0o555, payload: nil, wantPerm: 0o555},
		{name: "setuid_0755_nonzero", srcMode: specialModeBits | 0o755, payload: []byte("elf-copy"), wantPerm: 0o755},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &stagingOpRecorder{}
			handlers := pkgsftp.InMemHandler()
			handlers.FileCmd = &stagingRecordingCmder{delegate: handlers.FileCmd, rec: rec}
			handlers.FilePut = &stagingRecordingFilePut{delegate: handlers.FilePut, rec: rec}
			handlers.FileList = &customModeFileLister{
				delegate: handlers.FileList,
				modeOverrides: map[string]os.FileMode{
					"/src_dir":            os.ModeDir | specialModeBits | 0o755,
					"/src_dir/" + tc.name: tc.srcMode,
				},
			}
			client := newTestSFTPClientWithHandlers(t, handlers)

			if err := client.state.sftpClient.MkdirAll("/src_dir"); err != nil {
				t.Fatal(err)
			}
			f, err := client.state.sftpClient.Create("/src_dir/" + tc.name)
			if err != nil {
				t.Fatal(err)
			}
			if len(tc.payload) > 0 {
				if _, err := f.Write(tc.payload); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			rec.reset()

			if err := client.RemoteCopy(t.Context(), "/src_dir", "/dst_dir"); err != nil {
				t.Fatalf("RemoteCopy(%s): %v", tc.name, err)
			}
			events := rec.snapshot()
			dstFile := "/dst_dir/" + tc.name
			assertStrict0600StagingLifecycle(t, events, dstFile+client.config.TempSuffix, dstFile, tc.wantPerm, len(tc.payload) > 0, false)
			assertDirChmodsSanitized(t, events, "/dst_dir")
		})
	}
}

func assertDirChmodsSanitized(t *testing.T, events []stagingOpEvent, dirPath string) {
	t.Helper()
	dirChmodCount := 0
	for _, ev := range events {
		if ev.kind == "chmod" && ev.path == dirPath {
			dirChmodCount++
			if ev.mode&specialModeBits != 0 {
				t.Fatalf("directory %q chmod carried special bits: %v", dirPath, ev.mode)
			}
		}
	}
	if dirChmodCount < 2 {
		t.Fatalf("expected initial and final chmod on %q, got %d", dirPath, dirChmodCount)
	}
}

func testP7W6aRelayStagingAndSanitization(t *testing.T) {
	t.Helper()
	for _, tc := range []struct {
		name     string
		srcMode  os.FileMode
		wantPerm os.FileMode
	}{
		{name: "wide_0777", srcMode: 0o777, wantPerm: 0o777},
		{name: "setuid_setgid_sticky_0755", srcMode: specialModeBits | 0o755, wantPerm: 0o755},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srcHandlers := pkgsftp.InMemHandler()
			srcHandlers.FileList = &customModeFileLister{
				delegate:      srcHandlers.FileList,
				modeOverrides: map[string]os.FileMode{"/src.bin": tc.srcMode},
			}
			srcClient := newTestSFTPClientWithHandlers(t, srcHandlers)
			sf, err := srcClient.state.sftpClient.Create("/src.bin")
			if err != nil {
				t.Fatal(err)
			}
			_, _ = sf.Write([]byte("relay-payload"))
			_ = sf.Close()

			rec := &stagingOpRecorder{}
			dstHandlers := pkgsftp.InMemHandler()
			dstHandlers.FileCmd = &stagingRecordingCmder{delegate: dstHandlers.FileCmd, rec: rec}
			dstHandlers.FilePut = &stagingRecordingFilePut{delegate: dstHandlers.FilePut, rec: rec}
			dstClient := newTestSFTPClientWithHandlers(t, dstHandlers)

			srcPath, _ := ParseRemotePath("/src.bin")
			dstPath, _ := ParseRemotePath("/dst.bin")
			if err := dstClient.RelayFileFrom(t.Context(), srcClient, srcPath, dstPath, nil, nil); err != nil {
				t.Fatalf("RelayFileFrom(%s): %v", tc.name, err)
			}
			assertStrict0600StagingLifecycle(t, rec.snapshot(), "/dst.bin"+dstClient.config.TempSuffix, "/dst.bin", tc.wantPerm, true, false)
		})
	}
}

type openCountingSFTPHandler struct {
	maliciousSFTPHandler
	openCount atomic.Int64
	fstatMode map[string]os.FileMode
}

func (h *openCountingSFTPHandler) Fileread(r *pkgsftp.Request) (io.ReaderAt, error) {
	h.openCount.Add(1)
	if h.fstatMode != nil {
		if m, ok := h.fstatMode[r.Filepath]; ok {
			if fi, exists := h.statInfos[r.Filepath]; exists {
				h.statInfos[r.Filepath] = customModeFileInfo{FileInfo: fi, mode: m}
			}
		}
	}
	return h.maliciousSFTPHandler.Fileread(r)
}

func TestP7W6a_AB6H2_UnicodeNFDAndFullCaseFold(t *testing.T) {
	t.Run("foldDownloadSegment_and_foldDownloadRelPath_canonical_equivalences", testP7W6aFoldCanonicalEquivalences)
	t.Run("chained_symlink_escape_nfc_nfd_and_turkish_i_rejected", testP7W6aChainedSymlinkUnicodeEscape)
	t.Run("sibling_collision_rejected_before_worker_side_effects", testP7W6aSiblingCollisionUnicode)
}

func testP7W6aFoldCanonicalEquivalences(t *testing.T) {
	t.Helper()
	groups := [][]string{
		{"caf\u00e9", "cafe\u0301", "CAF\u00c9", "CAFE\u0301"},
		{"\u0130", "i\u0307", "I\u0307"},
		{"\u00df", "ss", "SS", "\u1e9e"},
		{"\u212b", "\u00c5", "\u00e5", "a\u030a", "A\u030a"},
		{"σ", "ς", "Σ"},
		{"k", "K", "\u212A"},
		{"s", "S", "\u017F"},
	}
	for _, group := range groups {
		base := foldDownloadSegment(group[0])
		for _, candidate := range group[1:] {
			if got := foldDownloadSegment(candidate); got != base {
				t.Fatalf("foldDownloadSegment(%q) = %q, want %q (matching %q)", candidate, got, base, group[0])
			}
		}
	}
	if a, b := foldDownloadRelPath("a/b/c/caf\u00e9"), foldDownloadRelPath("A/B/c/cafe\u0301"); a != b {
		t.Fatalf("foldDownloadRelPath NFC vs NFD mismatch: %q != %q", a, b)
	}
	if a, b := foldDownloadRelPath("dir/\u0130/file"), foldDownloadRelPath("DIR/i\u0307/FILE"); a != b {
		t.Fatalf("foldDownloadRelPath U+0130 vs i+U+0307 mismatch: %q != %q", a, b)
	}
}

func testP7W6aChainedSymlinkUnicodeEscape(t *testing.T) {
	t.Helper()
	cases := []struct {
		name         string
		linkName     string
		escapeTarget string
	}{
		{
			name:         "nfc_vs_nfd_cafe",
			linkName:     "caf\u00e9",
			escapeTarget: "a/b/c/cafe\u0301/../../.ssh/id_ed25519",
		},
		{
			name:         "nfd_vs_nfc_cafe",
			linkName:     "cafe\u0301",
			escapeTarget: "a/b/c/caf\u00e9/../../.ssh/id_ed25519",
		},
		{
			name:         "turkish_dot_I_vs_i_combining_dot",
			linkName:     "\u0130",
			escapeTarget: "a/b/c/i\u0307/../../.ssh/id_ed25519",
		},
		{
			name:         "sharp_s_vs_ss",
			linkName:     "\u00df",
			escapeTarget: "a/b/c/SS/../../.ssh/id_ed25519",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler := &customReadLinkHandler{
				maliciousSFTPHandler: maliciousSFTPHandler{
					statInfos: map[string]os.FileInfo{
						"/remote":       syntheticFileInfo{name: "remote", mode: os.ModeDir | 0o755},
						"/remote/a":     syntheticFileInfo{name: "a", mode: os.ModeDir | 0o755},
						"/remote/a/b":   syntheticFileInfo{name: "b", mode: os.ModeDir | 0o755},
						"/remote/a/b/c": syntheticFileInfo{name: "c", mode: os.ModeDir | 0o755},
					},
					dirLists: map[string][]os.FileInfo{
						"/remote": {
							syntheticFileInfo{name: "a", mode: os.ModeDir | 0o755},
							syntheticFileInfo{name: "escape", mode: os.ModeSymlink | 0o777},
						},
						"/remote/a":     {syntheticFileInfo{name: "b", mode: os.ModeDir | 0o755}},
						"/remote/a/b":   {syntheticFileInfo{name: "c", mode: os.ModeDir | 0o755}},
						"/remote/a/b/c": {syntheticFileInfo{name: tc.linkName, mode: os.ModeSymlink | 0o777}},
					},
				},
				readLinks: map[string][]string{
					"/remote/a/b/c/" + tc.linkName: {"../../.."},
					"/remote/escape":               {tc.escapeTarget},
				},
			}
			client := newTestSFTPClientWithHandlers(t, pkgsftp.Handlers{
				FileGet:  handler,
				FilePut:  handler,
				FileCmd:  handler,
				FileList: handler,
			})

			localDst := t.TempDir()
			remoteRoot, _ := ParseRemotePath("/remote")
			dest, _ := LocalDestPath(localDst)
			err := client.Download(t.Context(), remoteRoot, dest, DownloadOptions{})
			if !errors.Is(err, ErrUnsafeDownloadSymlink) {
				t.Fatalf("Download(%s) = %v, want ErrUnsafeDownloadSymlink", tc.name, err)
			}
			for _, p := range []string{
				filepath.Join(localDst, "escape"),
				filepath.Join(localDst, "a", "b", "c", tc.linkName),
			} {
				if _, lstatErr := os.Lstat(p); !errors.Is(lstatErr, os.ErrNotExist) {
					t.Fatalf("symlink %q must not exist after rejection: %v", p, lstatErr)
				}
			}
		})
	}
}

func testP7W6aSiblingCollisionUnicode(t *testing.T) {
	t.Helper()
	cases := []struct {
		name            string
		caseInsensitive bool
		first           string
		second          string
	}{
		{name: "ci_nfc_vs_nfd_cafe", caseInsensitive: true, first: "caf\u00e9", second: "cafe\u0301"},
		{name: "ci_upper_nfc_vs_lower_nfd", caseInsensitive: true, first: "CAF\u00c9", second: "cafe\u0301"},
		{name: "ci_turkish_I_dot_vs_i_dot", caseInsensitive: true, first: "\u0130", second: "i\u0307"},
		{name: "ci_turkish_I_dot_vs_I_comb_dot", caseInsensitive: true, first: "\u0130", second: "I\u0307"},
		{name: "ci_sharp_s_vs_ss", caseInsensitive: true, first: "\u00df", second: "ss"},
		{name: "cs_nfc_vs_nfd_cafe_apfs_safe", caseInsensitive: false, first: "caf\u00e9", second: "cafe\u0301"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler := &openCountingSFTPHandler{
				maliciousSFTPHandler: maliciousSFTPHandler{
					statInfos: map[string]os.FileInfo{
						"/col":              syntheticFileInfo{name: "col", mode: os.ModeDir | 0o755},
						"/col/innocent.txt": syntheticFileInfo{name: "innocent.txt", size: 4, mode: 0o644},
						"/col/sub":          syntheticFileInfo{name: "sub", mode: os.ModeDir | 0o755},
						"/col/" + tc.first:  syntheticFileInfo{name: tc.first, size: 3, mode: 0o644},
						"/col/" + tc.second: syntheticFileInfo{name: tc.second, size: 3, mode: 0o644},
					},
					dirLists: map[string][]os.FileInfo{
						"/col": {
							syntheticFileInfo{name: "innocent.txt", size: 4, mode: 0o644},
							syntheticFileInfo{name: "sub", mode: os.ModeDir | 0o755},
							syntheticFileInfo{name: tc.first, size: 3, mode: 0o644},
							syntheticFileInfo{name: tc.second, size: 3, mode: 0o644},
						},
						"/col/sub": {},
					},
					files: map[string][]byte{
						"/col/innocent.txt": []byte("data"),
						"/col/" + tc.first:  []byte("one"),
						"/col/" + tc.second: []byte("two"),
					},
				},
			}
			client := newTestSFTPClientWithHandlers(t, pkgsftp.Handlers{
				FileGet:  handler,
				FilePut:  handler,
				FileCmd:  handler,
				FileList: handler,
			})
			client.caseInsensitiveDirProbe = func(string) bool { return tc.caseInsensitive }

			localDst := t.TempDir()
			remoteRoot, _ := ParseRemotePath("/col")
			dest, _ := LocalDestPath(localDst)
			if err := client.Download(t.Context(), remoteRoot, dest, DownloadOptions{}); err == nil {
				t.Fatalf("Download(%s) succeeded, want collision rejection", tc.name)
			}
			if got := handler.openCount.Load(); got != 0 {
				t.Fatalf("Download(%s) issued %d Open calls before collision rejection, want 0", tc.name, got)
			}
			entries, readErr := os.ReadDir(localDst)
			if readErr != nil || len(entries) != 0 {
				t.Fatalf("localDst must remain empty after pre-pass collision rejection: entries=%d err=%v", len(entries), readErr)
			}
		})
	}
}

type nonRegularModeCase struct {
	name string
	mode os.FileMode
}

var p7W6aNonRegularModes = []nonRegularModeCase{
	{name: "fifo_named_pipe", mode: os.ModeNamedPipe | 0o600},
	{name: "unix_socket", mode: os.ModeSocket | 0o600},
	{name: "block_device", mode: os.ModeDevice | 0o600},
	{name: "char_device", mode: os.ModeDevice | os.ModeCharDevice | 0o600},
}

func TestP7W6a_AB6M1_RejectNonRegularRemoteEntriesBeforeOpen(t *testing.T) {
	t.Run("single_target_download_rejects_with_zero_open_calls", testP7W6aSingleTargetNonRegularRejected)
	t.Run("recursive_dir_download_rejects_with_zero_open_calls_and_no_side_effects", testP7W6aDirNonRegularRejected)
	t.Run("validateDirEntries_rejects_mode_irregular_and_hybrid_bitmasks", testP7W6aValidateDirEntriesIrregularRejected)
	t.Run("downloadFile_rejects_toctou_race_from_regular_to_non_regular_on_fstat", testP7W6aDownloadFileFstatTOCTOURejected)
}

func testP7W6aSingleTargetNonRegularRejected(t *testing.T) {
	t.Helper()
	for _, tc := range p7W6aNonRegularModes {
		t.Run(tc.name, func(t *testing.T) {
			handler := &openCountingSFTPHandler{
				maliciousSFTPHandler: maliciousSFTPHandler{
					statInfos: map[string]os.FileInfo{
						"/remote/special": syntheticFileInfo{name: "special", size: 0, mode: tc.mode},
					},
					files: map[string][]byte{
						"/remote/special": []byte("should-never-open"),
					},
				},
			}
			client := newTestSFTPClientWithHandlers(t, pkgsftp.Handlers{
				FileGet:  handler,
				FilePut:  handler,
				FileCmd:  handler,
				FileList: handler,
			})

			localDst := t.TempDir()
			remotePath, _ := ParseRemotePath("/remote/special")
			dest, _ := LocalDestPath(localDst)
			err := client.Download(t.Context(), remotePath, dest, DownloadOptions{})
			if err == nil || !strings.Contains(err.Error(), "non-regular remote entry") {
				t.Fatalf("Download(%s) = %v, want non-regular remote entry error", tc.name, err)
			}
			if got := handler.openCount.Load(); got != 0 {
				t.Fatalf("Download(%s) called Open %d times, want 0", tc.name, got)
			}
			entries, readErr := os.ReadDir(localDst)
			if readErr != nil || len(entries) != 0 {
				t.Fatalf("localDst must remain empty, got %d entries (err=%v)", len(entries), readErr)
			}
		})
	}
}

func testP7W6aDirNonRegularRejected(t *testing.T) {
	t.Helper()
	for _, tc := range p7W6aNonRegularModes {
		t.Run(tc.name, func(t *testing.T) {
			handler := &openCountingSFTPHandler{
				maliciousSFTPHandler: maliciousSFTPHandler{
					statInfos: map[string]os.FileInfo{
						"/remote":          syntheticFileInfo{name: "remote", mode: os.ModeDir | 0o755},
						"/remote/good.txt": syntheticFileInfo{name: "good.txt", size: 4, mode: 0o644},
						"/remote/sub":      syntheticFileInfo{name: "sub", mode: os.ModeDir | 0o755},
						"/remote/special":  syntheticFileInfo{name: "special", size: 0, mode: tc.mode},
					},
					dirLists: map[string][]os.FileInfo{
						"/remote": {
							syntheticFileInfo{name: "good.txt", size: 4, mode: 0o644},
							syntheticFileInfo{name: "sub", mode: os.ModeDir | 0o755},
							syntheticFileInfo{name: "special", size: 0, mode: tc.mode},
						},
						"/remote/sub": {},
					},
					files: map[string][]byte{
						"/remote/good.txt": []byte("good"),
						"/remote/special":  []byte("never"),
					},
				},
			}
			client := newTestSFTPClientWithHandlers(t, pkgsftp.Handlers{
				FileGet:  handler,
				FilePut:  handler,
				FileCmd:  handler,
				FileList: handler,
			})

			localDst := t.TempDir()
			remoteRoot, _ := ParseRemotePath("/remote")
			dest, _ := LocalDestPath(localDst)
			err := client.Download(t.Context(), remoteRoot, dest, DownloadOptions{})
			if err == nil || !strings.Contains(err.Error(), "non-regular remote entry") {
				t.Fatalf("Download dir(%s) = %v, want non-regular remote entry error", tc.name, err)
			}
			if got := handler.openCount.Load(); got != 0 {
				t.Fatalf("Download dir(%s) called Open %d times, want 0", tc.name, got)
			}
			entries, readErr := os.ReadDir(localDst)
			if readErr != nil || len(entries) != 0 {
				t.Fatalf("localDst must remain empty after pre-pass non-regular rejection, got %d entries (err=%v)", len(entries), readErr)
			}
		})
	}
}

func testP7W6aValidateDirEntriesIrregularRejected(t *testing.T) {
	t.Helper()
	localRoot, err := ResolveLocalTarget(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	remoteRoot, err := ParseRemotePath("/remote")
	if err != nil {
		t.Fatal(err)
	}
	walker := &downloadDirWalkState{
		remoteRoot: remoteRoot,
		groupCtx:   t.Context(),
	}
	for _, badMode := range []os.FileMode{
		os.ModeIrregular | 0o644,
		os.ModeDir | os.ModeIrregular | 0o755,
		os.ModeSymlink | os.ModeNamedPipe | 0o777,
	} {
		_, valErr := walker.validateDirEntries(remoteRoot, localRoot, []os.FileInfo{
			syntheticFileInfo{name: "odd", mode: badMode},
		})
		if valErr == nil || !strings.Contains(valErr.Error(), "non-regular remote entry") {
			t.Fatalf("validateDirEntries(mode=%s) = %v, want non-regular remote entry error", badMode, valErr)
		}
	}
}

func testP7W6aDownloadFileFstatTOCTOURejected(t *testing.T) {
	t.Helper()
	for _, tc := range p7W6aNonRegularModes {
		t.Run(tc.name, func(t *testing.T) {
			handler := &openCountingSFTPHandler{
				maliciousSFTPHandler: maliciousSFTPHandler{
					statInfos: map[string]os.FileInfo{
						"/remote/raced": syntheticFileInfo{name: "raced", size: 5, mode: 0o644},
					},
					files: map[string][]byte{
						"/remote/raced": []byte("hello"),
					},
				},
				fstatMode: map[string]os.FileMode{
					"/remote/raced": tc.mode,
				},
			}
			client := newTestSFTPClientWithHandlers(t, pkgsftp.Handlers{
				FileGet:  handler,
				FilePut:  handler,
				FileCmd:  handler,
				FileList: handler,
			})

			localDst := t.TempDir()
			remotePath, _ := ParseRemotePath("/remote/raced")
			dest, _ := LocalDestPath(localDst)
			err := client.Download(t.Context(), remotePath, dest, DownloadOptions{})
			if err == nil || !strings.Contains(err.Error(), "not a regular file") {
				t.Fatalf("Download TOCTOU(%s) = %v, want not a regular file error", tc.name, err)
			}
			entries, readErr := os.ReadDir(localDst)
			if readErr != nil || len(entries) != 0 {
				t.Fatalf("localDst must remain empty after Fstat rejection, got %d entries (err=%v)", len(entries), readErr)
			}
		})
	}
}
