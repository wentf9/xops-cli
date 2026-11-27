package cmdtransfer_test

import (
	"bytes"
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
	"github.com/wentf9/xops-cli/internal/entry/cli/cmdtransfer"
)

type transferStub struct {
	lastUpload   engine.SCPUploadRequest
	lastDownload engine.SCPDownloadRequest
	lastRecover  engine.RecoverTransferRequest
	readData     []byte
	recoverOne   engine.TransferRecoveryResult
	recoverAll   engine.RecoverAllResult
}

var _ clikit.TransferClient = (*transferStub)(nil)

func (s *transferStub) Close(_ context.Context) error { return nil }
func (s *transferStub) RunSSH(_ context.Context, _ engine.RunSSHRequest) (execution.ExecutionOutcome, error) {
	out, _ := execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	return out, nil
}

func (s *transferStub) SCPUpload(_ context.Context, req engine.SCPUploadRequest) (engine.SCPUploadResult, error) {
	s.lastUpload = req
	// 严格对齐 core/internal/usecase/transfer/scp_upload.go 真实不变量。
	if req.Recursive && (req.Source.Kind() != engine.LocalUploadSourceScoped || req.SymlinkPolicy != pathalg.SymlinkReject) {
		return engine.SCPUploadResult{}, engine.ErrInvalidRequest
	}
	return engine.SCPUploadResult{RemotePath: req.RemoteDest, FilesUploaded: 1, BytesTransferred: 10}, nil
}

func (s *transferStub) SCPDownload(_ context.Context, req engine.SCPDownloadRequest) (engine.SCPDownloadResult, error) {
	s.lastDownload = req
	if req.SymlinkPolicy == pathalg.SymlinkFollowOperatorSource {
		return engine.SCPDownloadResult{}, engine.ErrInvalidRequest
	}
	return engine.SCPDownloadResult{LocalDest: req.LocalDest, FilesDownloaded: 1, BytesTransferred: 20}, nil
}

func (s *transferStub) ReadRemoteFile(_ context.Context, _ engine.RemoteFileReadRequest) (engine.ReadFileResult, error) {
	data := s.readData
	if data == nil {
		data = []byte("hello")
	}
	var st engine.RemoteFileStat
	_ = jsonv2.Unmarshal([]byte(`{"path":"/bin/blob","size":4,"mode":420,"anchor":{"file_type":"regular"}}`), &st)
	return engine.ReadFileResult{Stat: st, Digest: security.DigestBytes(data), Content: data}, nil
}

func (s *transferStub) WriteRemoteFile(_ context.Context, _ engine.RemoteFileWriteRequest) (engine.WriteFileResult, error) {
	return engine.WriteFileResult{}, nil
}
func (s *transferStub) PatchRemoteFile(_ context.Context, _ engine.RemoteFilePatchRequest) (engine.PatchFileResult, error) {
	return engine.PatchFileResult{}, nil
}
func (s *transferStub) StatRemoteFile(_ context.Context, _ engine.RemoteStatRequest) (st engine.RemoteFileStat, err error) {
	return st, nil
}
func (s *transferStub) RenameRemoteFile(_ context.Context, _ engine.RemoteRenameRequest) error {
	return nil
}
func (s *transferStub) ListRemoteDir(_ context.Context, _ engine.RemotePathOpRequest) (engine.ListDirResult, error) {
	return engine.ListDirResult{}, nil
}
func (s *transferStub) MkdirRemoteAll(_ context.Context, _ engine.RemotePathOpRequest) error {
	return nil
}
func (s *transferStub) RemoveRemoteFile(_ context.Context, _ engine.RemotePathOpRequest) error {
	return nil
}
func (s *transferStub) RemoveRemoteDir(_ context.Context, _ engine.RemotePathOpRequest) error {
	return nil
}
func (s *transferStub) ChmodRemote(_ context.Context, _ engine.RemotePathOpRequest) error { return nil }
func (s *transferStub) ChtimesRemote(_ context.Context, _ engine.RemotePathOpRequest) error {
	return nil
}
func (s *transferStub) RealPathRemote(_ context.Context, req engine.RemotePathOpRequest) (pathalg.RemotePath, error) {
	return req.Path, nil
}
func (s *transferStub) ReadLinkRemote(_ context.Context, _ engine.RemotePathOpRequest) (string, error) {
	return "/target", nil
}
func (s *transferStub) RecoverTransfer(_ context.Context, req engine.RecoverTransferRequest) (engine.TransferRecoveryResult, error) {
	s.lastRecover = req
	if s.recoverOne.TransferID.IsValid() {
		return s.recoverOne, nil
	}
	return engine.TransferRecoveryResult{TransferID: req.TransferID, SelectedGen: 1}, nil
}
func (s *transferStub) RecoverAllTransfers(_ context.Context, _ engine.RecoverAllTransfersRequest) (engine.RecoverAllResult, error) {
	return s.recoverAll, nil
}
func (s *transferStub) InspectTransfer(_ context.Context, _ engine.InspectTransferRequest) (engine.TransferStatusSnapshot, error) {
	return engine.TransferStatusSnapshot{}, nil
}

func newTransferRuntime(stub *transferStub, workDir string) (*clikit.Runtime, *bytes.Buffer, *bytes.Buffer) {
	var stdout, stderr bytes.Buffer
	rt := &clikit.Runtime{
		Stdin:           strings.NewReader(""),
		Stdout:          &stdout,
		Stderr:          &stderr,
		ShutdownTimeout: time.Second,
		EngineFactory: func(context.Context, clikit.EngineInitOptions) (clikit.EngineHandle, error) {
			return clikit.EngineHandle{Runner: stub}, nil
		},
	}
	if workDir != "" {
		rt.Hooks.ResolveWorkDir = func() (pathalg.LocalDir, error) {
			return pathalg.ParseLocalDir(workDir)
		}
	}
	return rt, &stdout, &stderr
}

func TestRunSCP_RecursiveScopedSources(t *testing.T) {
	defer goleak.VerifyNone(t)

	stub := &transferStub{}
	rt, _, stderr := newTransferRuntime(stub, "/home/ops/work")
	for _, tc := range []struct {
		name     string
		src      string
		wantBase string
	}{
		{"rel_dir", "./myproj", "myproj"},
		{"abs_dir", "/abs/dir/app", "app"},
		{"dot_dir", ".", "work"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if code := cmdtransfer.RunSCP(context.Background(), rt, []string{"-r", tc.src, "web:/srv"}); code != 0 {
				t.Fatalf("scp -r %q 失败: code=%d stderr=%q", tc.src, code, stderr.String())
			}
			if stub.lastUpload.Source.Kind() != engine.LocalUploadSourceScoped || stub.lastUpload.Source.BaseName() != tc.wantBase || !stub.lastUpload.ExpandIntoDir {
				t.Fatalf("scp -r %q Scoped 失配: kind=%v base=%q expand=%v",
					tc.src, stub.lastUpload.Source.Kind(), stub.lastUpload.Source.BaseName(), stub.lastUpload.ExpandIntoDir)
			}
		})
	}
}

func TestRunSCP_EndpointSemanticsAndRejects(t *testing.T) {
	defer goleak.VerifyNone(t)

	stub := &transferStub{}
	rt, _, stderr := newTransferRuntime(stub, "/home/ops/work")
	// 空远端路径 `user@web:` -> `.`、--expand-into-dir=false 与 --local-root ./ 规整。
	if code := cmdtransfer.RunSCP(context.Background(), rt, []string{"--expand-into-dir=false", `C:\data\rel.txt`, "user@web:"}); code != 0 {
		t.Fatalf("空远端路径与 Windows 绝对盘符路径失败: code=%d stderr=%q", code, stderr.String())
	}
	if stub.lastUpload.RemoteDest.String() != "." || stub.lastUpload.ExpandIntoDir {
		t.Fatalf("空远端路径或 expand-into-dir=false 失配: dst=%s expand=%v", stub.lastUpload.RemoteDest, stub.lastUpload.ExpandIntoDir)
	}
	// 盘符相对路径 `C:rel.txt` 不得被误判为远端主机 `C`，而是进入本地源路径校验并由 pathalg 显式拒绝。
	rtDrive, _, errDrive := newTransferRuntime(&transferStub{}, "/tmp")
	if code := cmdtransfer.RunSCP(context.Background(), rtDrive, []string{"C:rel.txt", "web:/tmp/x"}); code != clikit.ExitUsage || !strings.Contains(errDrive.String(), "本地源路径") {
		t.Fatalf("C:rel.txt 应识别为本地盘符路径并由 pathalg 校验拒绝: code=%d stderr=%q", code, errDrive.String())
	}
	if code := cmdtransfer.RunSCP(context.Background(), rt, []string{"--local-root", "/tmp/sand", "./sub/a.txt", "web:/dst"}); code != 0 {
		t.Fatalf("--local-root ./sub/a.txt 规整失败: code=%d stderr=%q", code, stderr.String())
	}
	if stub.lastUpload.Source.Kind() != engine.LocalUploadSourceScoped || stub.lastUpload.Source.BaseName() != "a.txt" {
		t.Fatalf("--local-root 规整结果失配: kind=%v base=%q", stub.lastUpload.Source.Kind(), stub.lastUpload.Source.BaseName())
	}

	for _, bad := range [][]string{
		{"-r", "--symlink-policy", "follow_operator_source", "--json", "./dir", "web:/dst"},
		{"--symlink-policy", "follow_operator_source", "--json", "web:/etc/hosts", "."},
		{"--unknown-flag", "--json", "a", "web:/b"},
	} {
		assertSCPUsageJSON(t, bad)
	}
}

func assertSCPUsageJSON(t *testing.T, args []string) {
	t.Helper()
	rtBad, outBad, _ := newTransferRuntime(&transferStub{}, "/tmp")
	if code := cmdtransfer.RunSCP(context.Background(), rtBad, args); code != clikit.ExitUsage {
		t.Fatalf("非法 scp %v 应返回 ExitUsage，实际=%d", args, code)
	}
	var env clikit.ErrorEnvelope
	if err := jsonv2.Unmarshal(outBad.Bytes(), &env); err != nil || env.OK || env.ErrorCode != "usage_error" {
		t.Fatalf("非法 scp %v 应输出 JSON ErrorEnvelope: err=%v env=%+v", args, err, env)
	}
}

func TestRunSFTP_BinaryReadAndRecoveryFailClosed(t *testing.T) {
	defer goleak.VerifyNone(t)

	// 1) sftp cat --json 对非 UTF-8 二进制文件编码为 base64 而非损坏 UTF-8。
	stubBin := &transferStub{readData: []byte{0xff, 0xfe, 0x00, 0x80}}
	rtBin, outBin, errBin := newTransferRuntime(stubBin, "")
	if code := cmdtransfer.RunSFTP(context.Background(), rtBin, []string{"cat", "--json", "web", "/bin/blob"}); code != 0 {
		t.Fatalf("sftp cat 二进制失败: code=%d stderr=%q", code, errBin.String())
	}
	var catResp struct {
		OK            bool   `json:"ok"`
		Encoding      string `json:"encoding"`
		ContentBase64 string `json:"content_base64"`
	}
	if err := jsonv2.Unmarshal(outBin.Bytes(), &catResp); err != nil || !catResp.OK || catResp.Encoding != "base64" || catResp.ContentBase64 != "//4AgA==" {
		t.Fatalf("非 UTF-8 二进制 JSON 输出异常: err=%v resp=%+v raw=%q", err, catResp, outBin.String())
	}

	// 2) sftp recover 单条 UncertainCommit 必须失败关闭（exit 1, ok=false, do_not_retry=true）并透传 --local-root。
	tid, _ := security.ParseOperationID("fedcba9876543210")
	stubRec := &transferStub{
		recoverOne: engine.TransferRecoveryResult{TransferID: tid, SelectedGen: 2, UncertainCommit: true},
	}
	rtRec, outRec, _ := newTransferRuntime(stubRec, "")
	if code := cmdtransfer.RunSFTP(context.Background(), rtRec, []string{"recover", "--local-root", "/tmp/clean", "--prune", "--json", "web", "fedcba9876543210"}); code != clikit.ExitGeneral {
		t.Fatalf("UncertainCommit 必须返回 ExitGeneral，实际=%d", code)
	}
	if root, ok := stubRec.lastRecover.LocalRootForClean.Get(); !ok || root.String() != "/tmp/clean" {
		t.Fatalf("--local-root 未透传至 LocalRootForClean: root=%s ok=%v", root, ok)
	}
	if !strings.Contains(outRec.String(), `"ok":false`) || !strings.Contains(outRec.String(), `"do_not_retry":true`) {
		t.Fatalf("UncertainCommit JSON 必须标明 ok=false & do_not_retry=true: %q", outRec.String())
	}
}

func TestRunSFTP_RecoverAllFailClosedAndInteractiveJSONRejects(t *testing.T) {
	defer goleak.VerifyNone(t)

	// 1) sftp recover 全量遇到条目错误或 UncertainCommit 必须失败关闭（exit 1）并写 stderr 诊断。
	tid, _ := security.ParseOperationID("fedcba9876543210")
	tid2, _ := security.ParseOperationID("0123456789abcdef")
	stubAll := &transferStub{
		recoverAll: engine.RecoverAllResult{
			Entries: []engine.TransferRecoveryEntry{
				{TransferID: tid, Result: engine.TransferRecoveryResult{TransferID: tid, SelectedGen: 1, UncertainCommit: true}},
				{TransferID: tid2, Err: errors.New("journal-corrupt")},
			},
		},
	}
	rtAll, _, errAll := newTransferRuntime(stubAll, "")
	if code := cmdtransfer.RunSFTP(context.Background(), rtAll, []string{"recover"}); code != clikit.ExitGeneral {
		t.Fatalf("全量恢复存在失败或不确定提交时必须返回 ExitGeneral，实际=%d", code)
	}
	if !strings.Contains(errAll.String(), "journal-corrupt") || !strings.Contains(errAll.String(), "do not blindly retry") {
		t.Fatalf("全量恢复 stderr 诊断缺失: %q", errAll.String())
	}

	// 2) 交互式 `sftp --json web` 及非法 `-hfoo` 必须返回 ExitUsage 与 JSON ErrorEnvelope。
	for _, bad := range [][]string{
		{"--json", "web"},
		{"-hfoo", "--json", "web"},
		{"ls", "--bad", "--json", "web", "/etc"},
	} {
		rtBad, outBad, _ := newTransferRuntime(&transferStub{}, "")
		if code := cmdtransfer.RunSFTP(context.Background(), rtBad, bad); code != clikit.ExitUsage {
			t.Fatalf("非法 sftp %v 应返回 ExitUsage，实际=%d", bad, code)
		}
		var env clikit.ErrorEnvelope
		if err := jsonv2.Unmarshal(outBad.Bytes(), &env); err != nil || env.OK || env.ErrorCode != "usage_error" {
			t.Fatalf("非法 sftp %v 应输出 JSON ErrorEnvelope: err=%v env=%+v", bad, err, env)
		}
	}
}
