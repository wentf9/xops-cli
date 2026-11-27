package sftpshell_test

import (
	"bytes"
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/internal/entry/sftpshell"
	"go.uber.org/goleak"
)

type fakeRemoteObj struct {
	fileType engine.RemoteFileType
	data     []byte
	mode     fs.FileMode
	atime    time.Time
	mtime    time.Time
	linkTo   string
	ino      uint64
}

type fakeTransferClient struct {
	mu           sync.Mutex
	objs         map[string]*fakeRemoteObj
	homeDir      string
	nextIno      uint64
	lastUpload   engine.SCPUploadRequest
	lastDownload engine.SCPDownloadRequest
	onUpload     func(ctx context.Context, req engine.SCPUploadRequest) (engine.SCPUploadResult, error)
	onDownload   func(ctx context.Context, req engine.SCPDownloadRequest) (engine.SCPDownloadResult, error)
	halted       bool
}

func newFakeTransferClient() *fakeTransferClient {
	now := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)
	return &fakeTransferClient{
		homeDir: "/home/alice",
		nextIno: 100,
		objs: map[string]*fakeRemoteObj{
			"/":                    {fileType: engine.RemoteFileDir, mode: fs.ModeDir | 0o755, mtime: now, ino: 1},
			"/home":                {fileType: engine.RemoteFileDir, mode: fs.ModeDir | 0o755, mtime: now, ino: 2},
			"/home/alice":          {fileType: engine.RemoteFileDir, mode: fs.ModeDir | 0o755, mtime: now, ino: 3},
			"/home/alice/.hidden":  {fileType: engine.RemoteFileRegular, data: []byte("secret"), mode: 0o600, mtime: now, ino: 4},
			"/home/alice/note.txt": {fileType: engine.RemoteFileRegular, data: []byte("hello remote"), mode: 0o644, mtime: now, ino: 5},
			"/home/alice/sub":      {fileType: engine.RemoteFileDir, mode: fs.ModeDir | 0o755, mtime: now, ino: 6},
			"/home/alice/cur":      {fileType: engine.RemoteFileSymlink, linkTo: "/home/alice/note.txt", mode: fs.ModeSymlink | 0o777, mtime: now, ino: 7},
		},
	}
}

func (f *fakeTransferClient) checkHalted() error {
	if f.halted {
		return engine.ErrEngineHalted
	}
	return nil
}

func zeroVal[T any]() (z T) { return z }

func (f *fakeTransferClient) ResolveTarget(_ context.Context, _ engine.ResolveTargetRequest) (engine.ResolvedTarget, error) {
	return zeroVal[engine.ResolvedTarget](), f.checkHalted()
}

func (f *fakeTransferClient) NewOperationStream(_ context.Context, buffer int) (*events.OperationStream, error) {
	tid, _ := security.ParseTraceID("0123456789abcdef0123456789abcdef")
	oid, _ := security.ParseOperationID("fedcba9876543210fedcba9876543210")
	return events.NewOperationStream(events.OperationStreamConfig{TraceID: tid, OperationID: oid, OperationBuffer: max(buffer, 16)})
}

// SCPUpload 强制执行真实 transfer.Service.SCPUpload 的参数不变量（递归上传必须为 Scoped + SymlinkReject）。
func (f *fakeTransferClient) SCPUpload(ctx context.Context, req engine.SCPUploadRequest) (engine.SCPUploadResult, error) {
	if err := f.checkHalted(); err != nil {
		return engine.SCPUploadResult{}, err
	}
	if !req.Source.IsValid() {
		return engine.SCPUploadResult{}, engine.ErrInvalidRequest
	}
	if req.Recursive {
		if req.Source.Kind() != engine.LocalUploadSourceScoped {
			return engine.SCPUploadResult{}, fmt.Errorf("%w: 递归目录上传仅支持 ScopedRootFS 沙箱源", engine.ErrInvalidRequest)
		}
		if req.SymlinkPolicy != pathalg.SymlinkReject {
			return engine.SCPUploadResult{}, engine.ErrSymlinkRejected
		}
	}
	f.mu.Lock()
	f.lastUpload = req
	cb := f.onUpload
	f.mu.Unlock()
	if cb != nil {
		return cb(ctx, req)
	}
	if req.OperationStream != nil {
		emitFakeTransferProgress(req.OperationStream, 512, 1024)
	}
	return engine.SCPUploadResult{RemotePath: req.RemoteDest, FilesUploaded: 1, BytesTransferred: 1024}, nil
}

// SCPDownload 强制执行真实 transfer.Service.SCPDownload 的参数不变量（拒绝 SymlinkFollowOperatorSource）。
func (f *fakeTransferClient) SCPDownload(ctx context.Context, req engine.SCPDownloadRequest) (engine.SCPDownloadResult, error) {
	if err := f.checkHalted(); err != nil {
		return engine.SCPDownloadResult{}, err
	}
	if !req.LocalRoot.IsValid() || !req.LocalDest.IsValid() {
		return engine.SCPDownloadResult{}, engine.ErrInvalidRequest
	}
	if !req.SymlinkPolicy.IsValid() || req.SymlinkPolicy == pathalg.SymlinkFollowOperatorSource {
		return engine.SCPDownloadResult{}, engine.ErrSymlinkRejected
	}
	f.mu.Lock()
	f.lastDownload = req
	cb := f.onDownload
	f.mu.Unlock()
	if cb != nil {
		return cb(ctx, req)
	}
	return engine.SCPDownloadResult{LocalDest: req.LocalDest, FilesDownloaded: 1, BytesTransferred: 256}, nil
}

func (f *fakeTransferClient) ReadRemoteFile(_ context.Context, req engine.RemoteFileReadRequest) (engine.ReadFileResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.checkHalted(); err != nil {
		return engine.ReadFileResult{}, err
	}
	obj, ok := f.objs[req.Path.String()]
	if !ok {
		return engine.ReadFileResult{}, engine.ErrNotFound
	}
	if obj.fileType == engine.RemoteFileDir {
		return engine.ReadFileResult{}, engine.ErrRemoteIsDir
	}
	st, err := makeStat(req.Path.String(), obj)
	if err != nil {
		return engine.ReadFileResult{}, err
	}
	return engine.ReadFileResult{Stat: st, Content: bytes.Clone(obj.data), Digest: security.DigestBytes(obj.data)}, nil
}

func (f *fakeTransferClient) WriteRemoteFile(_ context.Context, req engine.RemoteFileWriteRequest) (engine.WriteFileResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.checkHalted(); err != nil {
		return engine.WriteFileResult{}, err
	}
	p := req.Path.String()
	if req.NoClobber {
		if _, exists := f.objs[p]; exists {
			return engine.WriteFileResult{}, engine.ErrAlreadyExists
		}
	}
	f.nextIno++
	obj := &fakeRemoteObj{fileType: engine.RemoteFileRegular, data: bytes.Clone(req.Content), mode: 0o644, mtime: time.Now().UTC(), ino: f.nextIno}
	f.objs[p] = obj
	st, err := makeStat(p, obj)
	if err != nil {
		return engine.WriteFileResult{}, err
	}
	return engine.WriteFileResult{Stat: st, BytesWritten: int64(len(req.Content)), Digest: security.DigestBytes(req.Content)}, nil
}

func (f *fakeTransferClient) StatRemoteFile(_ context.Context, req engine.RemoteStatRequest) (engine.RemoteFileStat, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.checkHalted(); err != nil {
		return zeroVal[engine.RemoteFileStat](), err
	}
	p := req.Path.String()
	obj, ok := f.objs[p]
	if !ok {
		return zeroVal[engine.RemoteFileStat](), engine.ErrNotFound
	}
	if req.FollowSymlinks && obj.fileType == engine.RemoteFileSymlink {
		p = obj.linkTo
		obj, ok = f.objs[p]
		if !ok {
			return zeroVal[engine.RemoteFileStat](), engine.ErrNotFound
		}
	}
	return makeStat(p, obj)
}

func (f *fakeTransferClient) RenameRemoteFile(_ context.Context, req engine.RemoteRenameRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.checkHalted(); err != nil {
		return err
	}
	oldP, newP := req.OldPath.String(), req.NewPath.String()
	obj, ok := f.objs[oldP]
	if !ok {
		return engine.ErrNotFound
	}
	if req.NoClobber {
		if _, exists := f.objs[newP]; exists {
			return engine.ErrAlreadyExists
		}
	}
	delete(f.objs, oldP)
	f.objs[newP] = obj
	return nil
}

func (f *fakeTransferClient) ListRemoteDir(_ context.Context, req engine.RemotePathOpRequest) (engine.ListDirResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.checkHalted(); err != nil {
		return engine.ListDirResult{}, err
	}
	dir := req.Path.String()
	obj, ok := f.objs[dir]
	if !ok {
		return engine.ListDirResult{}, engine.ErrNotFound
	}
	if obj.fileType != engine.RemoteFileDir {
		return engine.ListDirResult{}, engine.ErrInvalidRequest
	}
	var entries []engine.RemoteDirEntry
	for k, v := range f.objs {
		if k == dir || path.Dir(k) != dir {
			continue
		}
		entry, err := makeDirEntry(path.Base(k), v)
		if err != nil {
			return engine.ListDirResult{}, err
		}
		entries = append(entries, entry)
	}
	return engine.ListDirResult{Path: req.Path, Entries: entries}, nil
}

func (f *fakeTransferClient) MkdirRemoteAll(_ context.Context, req engine.RemotePathOpRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.checkHalted(); err != nil {
		return err
	}
	perm := req.Perm.OrElse(0o755)
	f.nextIno++
	f.objs[req.Path.String()] = &fakeRemoteObj{fileType: engine.RemoteFileDir, mode: fs.ModeDir | perm, mtime: time.Now().UTC(), ino: f.nextIno}
	return nil
}

func (f *fakeTransferClient) RemoveRemoteFile(_ context.Context, req engine.RemotePathOpRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.checkHalted(); err != nil {
		return err
	}
	obj, ok := f.objs[req.Path.String()]
	if !ok {
		return engine.ErrNotFound
	}
	if obj.fileType == engine.RemoteFileDir {
		return engine.ErrRemoteIsDir
	}
	delete(f.objs, req.Path.String())
	return nil
}

func (f *fakeTransferClient) RemoveRemoteDir(_ context.Context, req engine.RemotePathOpRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.checkHalted(); err != nil {
		return err
	}
	obj, ok := f.objs[req.Path.String()]
	if !ok {
		return engine.ErrNotFound
	}
	if obj.fileType != engine.RemoteFileDir {
		return engine.ErrInvalidRequest
	}
	delete(f.objs, req.Path.String())
	return nil
}

func (f *fakeTransferClient) ChmodRemote(_ context.Context, req engine.RemotePathOpRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.checkHalted(); err != nil {
		return err
	}
	obj, ok := f.objs[req.Path.String()]
	if !ok {
		return engine.ErrNotFound
	}
	obj.mode = (obj.mode &^ fs.ModePerm) | req.Perm.OrElse(0)
	return nil
}

func (f *fakeTransferClient) ChtimesRemote(_ context.Context, req engine.RemotePathOpRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.checkHalted(); err != nil {
		return err
	}
	obj, ok := f.objs[req.Path.String()]
	if !ok {
		return engine.ErrNotFound
	}
	obj.atime, obj.mtime = req.Atime, req.Mtime
	return nil
}

func (f *fakeTransferClient) RealPathRemote(_ context.Context, req engine.RemotePathOpRequest) (pathalg.RemotePath, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.checkHalted(); err != nil {
		return zeroVal[pathalg.RemotePath](), err
	}
	if req.Path.String() == "." {
		return pathalg.ParseAbsRemotePath(f.homeDir)
	}
	return req.Path, nil
}

func (f *fakeTransferClient) ReadLinkRemote(_ context.Context, req engine.RemotePathOpRequest) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.checkHalted(); err != nil {
		return "", err
	}
	obj, ok := f.objs[req.Path.String()]
	if !ok {
		return "", engine.ErrNotFound
	}
	if obj.fileType != engine.RemoteFileSymlink {
		return "", engine.ErrInvalidRequest
	}
	return obj.linkTo, nil
}

func makeStat(p string, obj *fakeRemoteObj) (engine.RemoteFileStat, error) {
	raw := fmt.Sprintf(`{"path":%q,"size":%d,"mode":%d,"mod_time":%q,"anchor":{"file_type":%q,"has_dev_ino":true,"dev":1,"ino":%d}}`,
		p, len(obj.data), uint32(obj.mode), obj.mtime.UTC().Format(time.RFC3339), obj.fileType.String(), obj.ino)
	var st engine.RemoteFileStat
	if err := jsonv2.Unmarshal([]byte(raw), &st); err != nil {
		return zeroVal[engine.RemoteFileStat](), err
	}
	return st, nil
}

func makeDirEntry(name string, obj *fakeRemoteObj) (engine.RemoteDirEntry, error) {
	raw := fmt.Sprintf(`{"name":%q,"file_type":%q,"size":%d,"mode":%d,"mod_time":%q}`,
		name, obj.fileType.String(), len(obj.data), uint32(obj.mode), obj.mtime.UTC().Format(time.RFC3339))
	var e engine.RemoteDirEntry
	if err := jsonv2.Unmarshal([]byte(raw), &e); err != nil {
		return zeroVal[engine.RemoteDirEntry](), err
	}
	return e, nil
}

func emitFakeTransferProgress(stream *events.OperationStream, done, total uint64) {
	meta, err := events.NewEventMeta(events.EventMetaSpec{
		TraceID:     stream.TraceID(),
		OperationID: algebraic.Some(stream.OperationID()),
		OccurredAt:  time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC),
	})
	if err != nil {
		return
	}
	ev, err := events.NewTransferProgressEvent(events.TransferProgressSpec{
		Meta:             meta,
		TransferID:       stream.OperationID(),
		Direction:        fsm.TransferDirectionUpload,
		BytesTransferred: done,
		TotalBytes:       total,
		Stage:            "upload",
	})
	if err == nil {
		_ = stream.Emit(context.Background(), ev)
	}
}

type fakeLocalFS struct {
	dirs map[string][]sftpshell.LocalDirEntry
}

func (l *fakeLocalFS) ReadDir(_ context.Context, dir pathalg.LocalDir) ([]sftpshell.LocalDirEntry, error) {
	entries, ok := l.dirs[dir.String()]
	if !ok {
		return nil, engine.ErrNotFound
	}
	return entries, nil
}

func (l *fakeLocalFS) IsDir(_ context.Context, dir pathalg.LocalDir) (bool, error) {
	_, ok := l.dirs[dir.String()]
	return ok, nil
}

func TestRun_ValidationFailClosed(t *testing.T) {
	var nilCtx context.Context
	if err := sftpshell.Run(nilCtx, sftpshell.Config{}); !errors.Is(err, sftpshell.ErrNilContext) {
		t.Fatalf("nil ctx 期望 ErrNilContext，实际=%v", err)
	}
	var zeroShell sftpshell.Shell
	if err := zeroShell.Run(context.Background()); !errors.Is(err, sftpshell.ErrNotInitialized) {
		t.Fatalf("零值 Shell 期望 ErrNotInitialized，实际=%v", err)
	}
	if !zeroShell.RemoteDir().IsZero() || !zeroShell.LocalDir().IsZero() {
		t.Fatalf("零值 Shell 目录必须返回零值")
	}
	if err := sftpshell.Run(context.Background(), sftpshell.Config{}); !errors.Is(err, sftpshell.ErrInvalidConfig) {
		t.Fatalf("空 Config 期望 ErrInvalidConfig，实际=%v", err)
	}
	var out, errBuf bytes.Buffer
	if err := sftpshell.Run(context.Background(), sftpshell.Config{
		Engine: newFakeTransferClient(),
		Stdout: &out,
		Stderr: &errBuf,
	}); !errors.Is(err, sftpshell.ErrInvalidConfig) {
		t.Fatalf("缺少 Target/TargetSpec 期望 ErrInvalidConfig，实际=%v", err)
	}
}

func TestShell_FullCommandSuiteNavigationTransfersMetadataAndErrors(t *testing.T) {
	defer goleak.VerifyNone(t)

	eng := newFakeTransferClient()
	initLocal, _ := pathalg.ParseLocalDir("/work")
	localFS := &fakeLocalFS{
		dirs: map[string][]sftpshell.LocalDirEntry{
			"/work":     {{Name: "a.bin", Size: 12, Mode: 0o644}, {Name: "out", IsDir: true, Mode: fs.ModeDir | 0o755}},
			"/work/out": {{Name: "kept.txt", Size: 5, Mode: 0o644}},
		},
	}

	script := strings.Join([]string{
		"pwd",
		"ls",
		"ls -la",
		"cd sub",
		"pwd",
		"cd ..",
		"lpwd",
		"lls -l",
		"lcd out",
		"lpwd",
		"lcd ..",
		"put -r -n --resume -p a.bin uploaded.bin",
		"get -p note.txt out/local_note.txt",
		"write -n fresh.txt 'hello atomic'",
		"cat fresh.txt",
		"mv -n fresh.txt moved.txt",
		"mkdir -m 0750 newdir",
		"chmod 0640 moved.txt",
		"chtimes 2026-06-02T03:04:05Z moved.txt",
		"stat moved.txt",
		"lstat cur",
		"readlink cur",
		"realpath moved.txt",
		"rm newdir",
		"rmdir newdir",
		"rm moved.txt",
		"help put",
		"quit",
	}, "\n") + "\n"

	var stdout, stderr bytes.Buffer
	err := sftpshell.Run(context.Background(), sftpshell.Config{
		Engine:          eng,
		TargetSpec:      "alice@example.com",
		Stdin:           strings.NewReader(script),
		Stdout:          &stdout,
		Stderr:          &stderr,
		InitialLocalDir: algebraic.Some(initLocal),
		LocalFS:         localFS,
		ShowProgress:    true,
	})
	if err != nil {
		t.Fatalf("sftpshell.Run 失败: %v\nstderr=%s", err, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{
		"/home/alice",
		"/home/alice/sub",
		".hidden",
		"/work",
		"/work/out",
		"uploaded a.bin -> /home/alice/uploaded.bin",
		"downloaded /home/alice/note.txt -> out/local_note.txt",
		"hello atomic",
		"Mode: -rw-r----- (0640)",
		"ModTime: 2026-06-02T03:04:05Z",
		"Anchor: regular(dev=1,ino=",
		"Type: symlink",
		"/home/alice/note.txt",
		"upload via SCPUpload",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("stdout 缺少 %q\n实际 stdout:\n%s\nstderr:\n%s", want, out, stderr.String())
		}
	}
	// rm newdir 应给出 rmdir 提示并继续执行后续 rmdir newdir 与 rm moved.txt
	if !strings.Contains(stderr.String(), "hint: use 'rmdir'") {
		t.Fatalf("对目录执行 rm 期望提示 rmdir，实际 stderr:\n%s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "progress [upload] 512/1024 bytes") {
		t.Fatalf("期望输出传输进度事件，实际 stderr:\n%s", stderr.String())
	}
	if !eng.lastUpload.Recursive || !eng.lastUpload.NoClobber || !eng.lastUpload.Resume || !eng.lastUpload.PreserveMode {
		t.Fatalf("put 选项未正确透传至 SCPUploadRequest: %+v", eng.lastUpload)
	}
	if !eng.lastDownload.PreserveTimes || eng.lastDownload.LocalRoot.String() != "/work" || eng.lastDownload.LocalDest.String() != "out/local_note.txt" {
		t.Fatalf("get 参数未正确透传至 SCPDownloadRequest: %+v", eng.lastDownload)
	}
}

func TestShell_PerCommandCancelRecoversCleanlyToPrompt_ZeroLeaks(t *testing.T) {
	defer goleak.VerifyNone(t)

	eng := newFakeTransferClient()
	uploadStarted := make(chan struct{}, 1)
	eng.onUpload = func(ctx context.Context, _ engine.SCPUploadRequest) (engine.SCPUploadResult, error) {
		uploadStarted <- struct{}{}
		<-ctx.Done()
		return engine.SCPUploadResult{}, ctx.Err()
	}

	interruptCh := make(chan struct{}, 1)
	pr, pw := io.Pipe()
	var stdout, stderr bytes.Buffer

	runErrCh := make(chan error, 1)
	err := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if err := n.Go(func(_ context.Context) error {
			runErrCh <- sftpshell.Run(context.Background(), sftpshell.Config{
				Engine:      eng,
				TargetSpec:  "alice@example.com",
				Stdin:       pr,
				Stdout:      &stdout,
				Stderr:      &stderr,
				InterruptCh: interruptCh,
			})
			return nil
		}); err != nil {
			return err
		}

		// 发起阻塞中的 put 命令，等待进入传输后触发单命令取消。
		_, _ = io.WriteString(pw, "put local.bin /home/alice/slow.bin\n")
		<-uploadStarted
		interruptCh <- struct{}{}

		// 取消恢复后立即发送 pwd 与 exit，验证会话未崩溃且正常响应后续命令。
		_, _ = io.WriteString(pw, "pwd\nexit\n")
		_ = pw.Close()
		return nil
	})
	if err != nil {
		t.Fatalf("conc.RunWait: %v", err)
	}
	if runErr := <-runErrCh; runErr != nil {
		t.Fatalf("单命令取消恢复后正常 exit 期望返回 nil，实际=%v", runErr)
	}
	if !strings.Contains(stderr.String(), "command canceled (returned to prompt)") {
		t.Fatalf("期望 stderr 输出取消恢复提示，实际:\n%s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "/home/alice") {
		t.Fatalf("取消后后续 pwd 命令未生效，stdout:\n%s", stdout.String())
	}
}

func TestShell_FatalHaltedAndLocalFSUnsupportedAndEOF(t *testing.T) {
	defer goleak.VerifyNone(t)

	// 1. 未注入 LocalFS 时 lls 失败关闭报错但不中断会话，随后 EOF 干净退出。
	eng := newFakeTransferClient()
	var out, errBuf bytes.Buffer
	err := sftpshell.Run(context.Background(), sftpshell.Config{
		Engine:     eng,
		TargetSpec: "alice@example.com",
		Stdin:      strings.NewReader("lls\nchmod 9999 note.txt\npwd\n"),
		Stdout:     &out,
		Stderr:     &errBuf,
	})
	if err != nil {
		t.Fatalf("EOF 退出期望 nil，实际=%v", err)
	}
	if !strings.Contains(errBuf.String(), "LocalFS") || !strings.Contains(errBuf.String(), "invalid octal permission") {
		t.Fatalf("缺少预期错误提示，stderr:\n%s", errBuf.String())
	}
	if !strings.Contains(out.String(), "/home/alice") {
		t.Fatalf("错误恢复后 pwd 未执行，stdout:\n%s", out.String())
	}

	// 2. 遇到 ErrEngineHalted 时立即失败关闭退出 Shell，不继续等待后续命令。
	eng2 := newFakeTransferClient()
	eng2.onUpload = func(_ context.Context, _ engine.SCPUploadRequest) (engine.SCPUploadResult, error) {
		return engine.SCPUploadResult{}, engine.ErrEngineHalted
	}
	out.Reset()
	errBuf.Reset()
	err = sftpshell.Run(context.Background(), sftpshell.Config{
		Engine:     eng2,
		TargetSpec: "alice@example.com",
		Stdin:      strings.NewReader("put a.bin\npwd\n"),
		Stdout:     &out,
		Stderr:     &errBuf,
	})
	if !errors.Is(err, engine.ErrEngineHalted) {
		t.Fatalf("Halted 熔断态期望返回 ErrEngineHalted，实际=%v", err)
	}
	if strings.Contains(out.String(), "/home/alice") {
		t.Fatalf("Halted 后不应继续执行后续命令，stdout:\n%s", out.String())
	}
}

func TestShell_TimeoutOperatorFeaturesAndEdgeCases(t *testing.T) {
	defer goleak.VerifyNone(t)

	eng := newFakeTransferClient()
	eng.onUpload = func(ctx context.Context, req engine.SCPUploadRequest) (engine.SCPUploadResult, error) {
		if strings.HasSuffix(req.RemoteDest.String(), "timeout.bin") {
			<-ctx.Done()
			return engine.SCPUploadResult{}, ctx.Err()
		}
		if strings.HasSuffix(req.RemoteDest.String(), "unknown.bin") {
			return engine.SCPUploadResult{}, engine.ErrOutcomeUnknown
		}
		return engine.SCPUploadResult{RemotePath: req.RemoteDest, FilesUploaded: 1, BytesTransferred: 64}, nil
	}

	initLocal, _ := pathalg.ParseLocalDir("C:/work/sub")
	script := strings.Join([]string{
		"lcd ..",
		"lpwd",
		"put ././nested/./file.bin",
		"put -r subdir",
		"put slow.bin timeout.bin",
		"put risky.bin unknown.bin",
		"get note.txt",
		"get note.txt .",
		"get note.txt out/",
		"get note.txt /tmp/abs_note.txt",
		"cd note.txt",
		"cd sub",
		"cd",
		"pwd",
		"write -p dir/a.txt '-n' -p --no-clobber",
		"cat dir/a.txt",
		"rename dir/a.txt dir/b.txt",
		"stat -L cur",
		"chtimes 1700000000 2026-06-03T01:02:03Z dir/b.txt",
		"chtimes 999999999999999 dir/b.txt",
		"help lstat",
		"quit",
	}, "\n") + "\n"

	var stdout, stderr bytes.Buffer
	err := sftpshell.Run(context.Background(), sftpshell.Config{
		Engine:          eng,
		TargetSpec:      "alice@example.com",
		Stdin:           strings.NewReader(script),
		Stdout:          &stdout,
		Stderr:          &stderr,
		InitialLocalDir: algebraic.Some(initLocal),
		SymlinkPolicy:   pathalg.SymlinkFollowOperatorSource,
		CommandTimeout:  algebraic.Some(algebraic.FromStdDuration(15 * time.Millisecond)),
	})
	if err != nil {
		t.Fatalf("Run 失败: %v\nstderr=%s", err, stderr.String())
	}
	assertContainsAll(t, stdout.String(), []string{
		"C:/work",
		"uploaded ././nested/./file.bin -> /home/alice/file.bin",
		"uploaded subdir -> /home/alice/subdir",
		"downloaded /home/alice/note.txt -> note.txt",
		"downloaded /home/alice/note.txt -> abs_note.txt",
		"-n -p --no-clobber",
		"Type: regular",
		"without following symlinks",
	})
	assertContainsAll(t, stderr.String(), []string{
		"command timed out (returned to prompt)",
		"CRITICAL OutcomeUnknown",
		"is not a directory",
		"outside RFC3339 year range",
	})
}

func TestShell_ScopedLocalOnlySandboxInescapableAndDisallowedPaths(t *testing.T) {
	defer goleak.VerifyNone(t)

	eng := newFakeTransferClient()
	sandbox, _ := pathalg.ParseLocalDir("/sandbox")
	var stdout, stderr bytes.Buffer

	// 1. ScopedLocalOnly + SymlinkFollowOperatorSource 必须在配置阶段失败关闭。
	if err := sftpshell.Run(context.Background(), sftpshell.Config{
		Engine:          eng,
		TargetSpec:      "alice@example.com",
		Stdout:          &stdout,
		Stderr:          &stderr,
		InitialLocalDir: algebraic.Some(sandbox),
		ScopedLocalOnly: true,
		SymlinkPolicy:   pathalg.SymlinkFollowOperatorSource,
	}); !errors.Is(err, sftpshell.ErrInvalidConfig) {
		t.Fatalf("ScopedLocalOnly + SymlinkFollowOperatorSource 期望 ErrInvalidConfig，实际=%v", err)
	}

	// 2. 沙箱内合法操作全部锚定于 /sandbox；所有越界、绝对路径、UNC/盘符相对路径全部失败关闭。
	localFS := &fakeLocalFS{
		dirs: map[string][]sftpshell.LocalDirEntry{
			"/sandbox":     {{Name: "sub", IsDir: true, Mode: fs.ModeDir | 0o755}},
			"/sandbox/sub": {{Name: "f.bin", Size: 10, Mode: 0o644}},
		},
	}
	script := strings.Join([]string{
		"lcd ..",
		"lcd /etc",
		"lls /etc",
		"lls ..",
		`lcd \\server\share\x`,
		`lcd \rootrel`,
		`lcd C:relpath`,
		"put /etc/passwd",
		"put ../outside.txt",
		"put .",
		"get note.txt /tmp/escape.txt",
		"get note.txt ../escape.txt",
		"lcd sub",
		"lpwd",
		"put ./f.bin",
		"get note.txt .",
		"lcd ..",
		"lpwd",
		"get note.txt sub/",
		"quit",
	}, "\n") + "\n"

	stdout.Reset()
	stderr.Reset()
	err := sftpshell.Run(context.Background(), sftpshell.Config{
		Engine:          eng,
		TargetSpec:      "alice@example.com",
		Stdin:           strings.NewReader(script),
		Stdout:          &stdout,
		Stderr:          &stderr,
		InitialLocalDir: algebraic.Some(sandbox),
		LocalFS:         localFS,
		ScopedLocalOnly: true,
	})
	if err != nil {
		t.Fatalf("ScopedLocalOnly Run 失败: %v\nstderr=%s", err, stderr.String())
	}
	assertContainsAll(t, stdout.String(), []string{
		"/sandbox/sub",
		"uploaded ./f.bin -> /home/alice/f.bin",
		"downloaded /home/alice/note.txt -> sub/note.txt",
	})
	if eng.lastUpload.Source.Kind() != engine.LocalUploadSourceScoped {
		t.Fatalf("ScopedLocalOnly 上传必须使用 LocalUploadSourceScoped")
	}
	if eng.lastDownload.LocalRoot.String() != "/sandbox" || eng.lastDownload.LocalDest.String() != "sub/note.txt" {
		t.Fatalf("ScopedLocalOnly 下载必须锚定 /sandbox: root=%s dest=%s", eng.lastDownload.LocalRoot, eng.lastDownload.LocalDest)
	}
	assertContainsAll(t, stderr.String(), []string{
		"outside sandbox root",
		"is forbidden in ScopedLocalOnly mode",
		"forbidden UNC, device namespace, or root-relative backslash prefix",
		"forbidden drive-relative path",
		"cannot be sandbox root '.'",
	})
}

func TestShell_StaleInterruptDrainConcurrentFatalAndOversizedLineRecovery(t *testing.T) {
	defer goleak.VerifyNone(t)

	// 1. 预置空闲期滞留中断信号 + 超过 1 MiB 的超长行 -> 滞留信号不误杀 pwd，超长行排空后恢复提示符。
	eng := newFakeTransferClient()
	staleCh := make(chan struct{}, 2)
	staleCh <- struct{}{}
	staleCh <- struct{}{}
	oversized := strings.Repeat("a", (1<<20)+128)
	var stdout, stderr bytes.Buffer
	err := sftpshell.Run(context.Background(), sftpshell.Config{
		Engine:      eng,
		TargetSpec:  "alice@example.com",
		Stdin:       strings.NewReader("pwd\n" + oversized + "\npwd\nquit\n"),
		Stdout:      &stdout,
		Stderr:      &stderr,
		InterruptCh: staleCh,
	})
	if err != nil {
		t.Fatalf("滞留中断与超长行恢复期望 nil，实际=%v", err)
	}
	if strings.Count(stdout.String(), "/home/alice") < 2 || !strings.Contains(stderr.String(), "exceeds maximum length") {
		t.Fatalf("滞留中断排空或超长行恢复异常:\nstdout=%s\nstderr=%s", stdout.String(), stderr.String())
	}

	// 2. 并发中断绝不掩盖 ErrEngineHalted，仍应立即失败关闭终止会话。
	eng2 := newFakeTransferClient()
	intCh2 := make(chan struct{}, 1)
	eng2.onUpload = func(_ context.Context, _ engine.SCPUploadRequest) (engine.SCPUploadResult, error) {
		intCh2 <- struct{}{}
		return engine.SCPUploadResult{}, engine.ErrEngineHalted
	}
	stdout.Reset()
	stderr.Reset()
	err = sftpshell.Run(context.Background(), sftpshell.Config{
		Engine:      eng2,
		TargetSpec:  "alice@example.com",
		Stdin:       strings.NewReader("put a.bin\npwd\n"),
		Stdout:      &stdout,
		Stderr:      &stderr,
		InterruptCh: intCh2,
	})
	if !errors.Is(err, engine.ErrEngineHalted) {
		t.Fatalf("并发中断下 ErrEngineHalted 不得被掩盖，实际=%v", err)
	}

	// 3. 并发中断下 ErrOutcomeUnknown 与已成功变更（err==nil）均不得被掩盖为 "command canceled"。
	eng3 := newFakeTransferClient()
	intCh3 := make(chan struct{}, 2)
	eng3.onUpload = func(_ context.Context, req engine.SCPUploadRequest) (engine.SCPUploadResult, error) {
		intCh3 <- struct{}{}
		if strings.HasSuffix(req.RemoteDest.String(), "unk.bin") {
			return engine.SCPUploadResult{}, engine.ErrOutcomeUnknown
		}
		return engine.SCPUploadResult{RemotePath: req.RemoteDest, FilesUploaded: 1, BytesTransferred: 8}, nil
	}
	stdout.Reset()
	stderr.Reset()
	err = sftpshell.Run(context.Background(), sftpshell.Config{
		Engine:      eng3,
		TargetSpec:  "alice@example.com",
		Stdin:       strings.NewReader("put a.bin unk.bin\nput b.bin ok.bin\nquit\n"),
		Stdout:      &stdout,
		Stderr:      &stderr,
		InterruptCh: intCh3,
	})
	if err != nil {
		t.Fatalf("Run 失败: %v", err)
	}
	if !strings.Contains(stderr.String(), "CRITICAL OutcomeUnknown") || strings.Contains(stderr.String(), "command canceled") {
		t.Fatalf("并发中断掩盖了 OutcomeUnknown 或成功变更:\nstdout=%s\nstderr=%s", stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "uploaded b.bin -> /home/alice/ok.bin") {
		t.Fatalf("已成功变更输出缺失: %s", stdout.String())
	}

	// 4. 显式 InitialRemoteDir 指向普通文件时 initSession 必须失败关闭。
	filePath, _ := pathalg.ParseAbsRemotePath("/home/alice/note.txt")
	if err := sftpshell.Run(context.Background(), sftpshell.Config{
		Engine:           eng,
		TargetSpec:       "alice@example.com",
		Stdin:            strings.NewReader("pwd\n"),
		Stdout:           &stdout,
		Stderr:           &stderr,
		InitialRemoteDir: algebraic.Some(filePath),
	}); !errors.Is(err, sftpshell.ErrInvalidConfig) {
		t.Fatalf("InitialRemoteDir 指向非目录期望 ErrInvalidConfig，实际=%v", err)
	}
}

func assertContainsAll(t *testing.T, haystack string, needles []string) {
	t.Helper()
	for _, want := range needles {
		if !strings.Contains(haystack, want) {
			t.Fatalf("输出缺少 %q\n实际:\n%s", want, haystack)
		}
	}
}
