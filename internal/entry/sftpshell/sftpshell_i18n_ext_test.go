package sftpshell_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/entry/sftpshell"
	"github.com/wentf9/xops-cli/internal/i18n"
	"go.uber.org/goleak"
)

func mustLoadCatalog(t *testing.T) *i18n.Catalog {
	t.Helper()
	cat, err := i18n.LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog 失败: %v", err)
	}
	return cat
}

func TestShellI18n_HelpOutputsAndSyntaxErrorsBilingual(t *testing.T) {
	defer goleak.VerifyNone(t)
	cat := mustLoadCatalog(t)

	script := strings.Join([]string{
		"help",
		"help put",
		"help cd",
		"help unknown_topic",
		"bogus_cmd",
		"pwd extra",
		"ls -z",
		"chmod 9999 note.txt",
		"write fresh.txt 'hello world'",
		"put a.bin uploaded.bin",
		"get note.txt local_note.txt",
		"stat note.txt",
		"lls",
		"quit",
	}, "\n") + "\n"

	cases := []struct {
		name       string
		loc        *i18n.Localizer
		wantStdout []string
		wantStderr []string
	}{
		{
			name: "nil_localizer_defaults_to_english",
			loc:  nil,
			wantStdout: []string{
				"SFTP Shell Commands:",
				"put [-r] [-n|--no-clobber]",
				"command cd: run 'help' to see full command reference",
				"wrote /home/alice/fresh.txt (11 bytes)",
				"uploaded a.bin -> /home/alice/uploaded.bin (1 files, 1024 bytes)",
				"downloaded /home/alice/note.txt -> local_note.txt (1 files, 256 bytes)",
				"Path: /home/alice/note.txt",
				"Anchor: regular(dev=1,ino=",
			},
			wantStderr: []string{
				"unknown help topic unknown_topic",
				"unknown command bogus_cmd",
				"pwd accepts no arguments",
				"ls: unknown option -z",
				"invalid octal permission 9999 (must be in 0001..0777)",
				"sftp: progress [upload] 512/1024 bytes",
				"LocalFS is not configured; cannot list local directory",
			},
		},
		{
			name: "explicit_english",
			loc:  cat.For(domi18n.LocaleEn),
			wantStdout: []string{
				"SFTP Shell Commands:",
				"Transfer & Atomic File Operations:",
				"uploaded a.bin -> /home/alice/uploaded.bin",
			},
			wantStderr: []string{
				"unknown command bogus_cmd (type 'help' for available commands)",
				"sftp: progress [upload] 512/1024 bytes",
			},
		},
		{
			name: "simplified_chinese",
			loc:  cat.For(domi18n.LocaleZh),
			wantStdout: []string{
				"SFTP Shell 交互命令：",
				"文件传输与原子操作：",
				"经 SCPUpload 上传并流式汇报进度",
				"命令 cd：输入 'help' 查看完整命令列表",
				"已写入 /home/alice/fresh.txt（11 字节）",
				"已上传 a.bin -> /home/alice/uploaded.bin（1 个文件，1024 字节）",
				"已下载 /home/alice/note.txt -> local_note.txt（1 个文件，256 字节）",
				"路径：/home/alice/note.txt",
				"文件锚点：regular(dev=1,ino=",
			},
			wantStderr: []string{
				"未知帮助主题 unknown_topic",
				"未知命令 bogus_cmd",
				"pwd 不接受参数",
				"ls：未知选项 -z",
				"无效八进制权限 9999（须落在 0001..0777）",
				"sftp: 进度 [upload] 512/1024 字节",
				"当前环境未注入 LocalFS，无法列举本地目录",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			initLocal, _ := pathalg.ParseLocalDir("/work")
			var stdout, stderr bytes.Buffer
			err := sftpshell.Run(context.Background(), sftpshell.Config{
				Engine:          newFakeTransferClient(),
				TargetSpec:      "alice@example.com",
				Stdin:           strings.NewReader(script),
				Stdout:          &stdout,
				Stderr:          &stderr,
				InitialLocalDir: algebraic.Some(initLocal),
				ShowProgress:    true,
				Localizer:       tc.loc,
			})
			if err != nil {
				t.Fatalf("sftpshell.Run 失败: %v\nstderr=%s", err, stderr.String())
			}
			assertContainsAll(t, stdout.String(), tc.wantStdout)
			assertContainsAll(t, stderr.String(), tc.wantStderr)
		})
	}
}

func TestShellI18n_FormatCommandErrorBilingual(t *testing.T) {
	defer goleak.VerifyNone(t)
	cat := mustLoadCatalog(t)

	cases := []struct {
		name           string
		loc            *i18n.Localizer
		wantCanceled   string
		wantTimeout    string
		wantIsDirHint  string
		wantUnknown    string
		wantApproval   string
		wantApprovalTm string
	}{
		{
			name:           "english",
			loc:            cat.For(domi18n.LocaleEn),
			wantCanceled:   "command canceled (returned to prompt)",
			wantTimeout:    "command timed out (returned to prompt)",
			wantIsDirHint:  "(hint: use 'rmdir' for empty directories)",
			wantUnknown:    "CRITICAL OutcomeUnknown — DO NOT retry blindly:",
			wantApproval:   "usage: approval-required: sftpshell: invalid command syntax",
			wantApprovalTm: "approval required (policy gate, digest=sha256:abc)",
		},
		{
			name:           "chinese",
			loc:            cat.For(domi18n.LocaleZh),
			wantCanceled:   "当前命令已取消（已返回提示符）",
			wantTimeout:    "当前命令已超时（已返回提示符）",
			wantIsDirHint:  "（提示：删除空目录请使用 'rmdir'）",
			wantUnknown:    "严重：执行终态未知（OutcomeUnknown）— 严禁盲目重试：",
			wantApproval:   "用法：approval-required",
			wantApprovalTm: "需要人工审批（policy gate，摘要=sha256:abc）",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runFormatErrorMatrix(t, tc.loc, tc.wantCanceled, tc.wantTimeout, tc.wantIsDirHint, tc.wantUnknown, tc.wantApproval)
			gotApproval := tc.loc.T(i18n.KeySFTPMsgApprovalRequired,
				i18n.BoundStr("reason", "policy gate"),
				i18n.BoundStr("digest", "sha256:abc"),
			)
			if gotApproval != tc.wantApprovalTm {
				t.Fatalf("KeySFTPMsgApprovalRequired = %q, want %q", gotApproval, tc.wantApprovalTm)
			}
		})
	}
}

func runFormatErrorMatrix(t *testing.T, loc *i18n.Localizer, wantCanceled, wantTimeout, wantIsDirHint, wantUnknown, wantApproval string) {
	t.Helper()

	// 1. 测试 timeout、ErrRemoteIsDir、ErrOutcomeUnknown 与 ErrApprovalRequired。
	eng := newFakeTransferClient()
	eng.onUpload = func(ctx context.Context, req engine.SCPUploadRequest) (engine.SCPUploadResult, error) {
		switch {
		case strings.HasSuffix(req.RemoteDest.String(), "timeout.bin"):
			<-ctx.Done()
			return engine.SCPUploadResult{}, ctx.Err()
		case strings.HasSuffix(req.RemoteDest.String(), "unknown.bin"):
			return engine.SCPUploadResult{}, engine.ErrOutcomeUnknown
		case strings.HasSuffix(req.RemoteDest.String(), "approve.bin"):
			return engine.SCPUploadResult{}, i18n.WrapS(engine.ErrApprovalRequired, sftpshell.ErrSyntax, i18n.KeySFTPUsage, i18n.Str("usage", "approval-required"))
		default:
			return engine.SCPUploadResult{RemotePath: req.RemoteDest, FilesUploaded: 1, BytesTransferred: 1}, nil
		}
	}
	script := "put a.bin timeout.bin\nput a.bin unknown.bin\nput a.bin approve.bin\nrm sub\nquit\n"
	var stdout, stderr bytes.Buffer
	err := sftpshell.Run(context.Background(), sftpshell.Config{
		Engine:         eng,
		TargetSpec:     "alice@example.com",
		Stdin:          strings.NewReader(script),
		Stdout:         &stdout,
		Stderr:         &stderr,
		CommandTimeout: algebraic.Some(algebraic.FromStdDuration(15 * time.Millisecond)),
		Localizer:      loc,
	})
	if err != nil {
		t.Fatalf("Run 失败: %v\nstderr=%s", err, stderr.String())
	}
	assertContainsAll(t, stderr.String(), []string{wantTimeout, wantIsDirHint, wantUnknown, wantApproval})

	// 2. 测试单命令取消 ErrCommandCanceled 的双语提示。
	engCancel := newFakeTransferClient()
	started := make(chan struct{}, 1)
	engCancel.onUpload = func(ctx context.Context, _ engine.SCPUploadRequest) (engine.SCPUploadResult, error) {
		started <- struct{}{}
		<-ctx.Done()
		return engine.SCPUploadResult{}, ctx.Err()
	}
	intCh := make(chan struct{}, 1)
	pr, pw := io.Pipe()
	var out2, err2 bytes.Buffer
	var runErr error
	waitErr := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(_ context.Context) error {
			runErr = sftpshell.Run(context.Background(), sftpshell.Config{
				Engine:      engCancel,
				TargetSpec:  "alice@example.com",
				Stdin:       pr,
				Stdout:      &out2,
				Stderr:      &err2,
				InterruptCh: intCh,
				Localizer:   loc,
			})
			return nil
		}); gErr != nil {
			return gErr
		}
		_, _ = io.WriteString(pw, "put a.bin slow.bin\n")
		<-started
		intCh <- struct{}{}
		_, _ = io.WriteString(pw, "quit\n")
		_ = pw.Close()
		return nil
	})
	if waitErr != nil || runErr != nil {
		t.Fatalf("单命令取消场景失败: wait=%v run=%v", waitErr, runErr)
	}
	if !strings.Contains(err2.String(), wantCanceled) {
		t.Fatalf("取消输出缺少 %q\n实际 stderr:\n%s", wantCanceled, err2.String())
	}
}

func TestShellI18n_SentinelsAndInvalidLocalizerFailClosed(t *testing.T) {
	defer goleak.VerifyNone(t)
	cat := mustLoadCatalog(t)
	enLoc := cat.For(domi18n.LocaleEn)
	zhLoc := cat.For(domi18n.LocaleZh)

	sentinels := []struct {
		err error
		id  domi18n.MessageID
	}{
		{sftpshell.ErrNilContext, i18n.KeySFTPNilContext},
		{sftpshell.ErrInvalidConfig, i18n.KeySFTPInvalidConfig},
		{sftpshell.ErrNotInitialized, i18n.KeySFTPNotInitialized},
		{sftpshell.ErrCommandCanceled, i18n.KeySFTPCommandCanceled},
		{sftpshell.ErrSyntax, i18n.KeySFTPSyntax},
	}
	for _, tc := range sentinels {
		id, ok := domi18n.ErrorID(tc.err)
		if !ok || id != tc.id {
			t.Fatalf("ErrorID(%v) = (%q, %v), want %q", tc.err, id, ok, tc.id)
		}
		if enLoc.RenderError(tc.err) != tc.err.Error() {
			t.Fatalf("en RenderError(%v) = %q != Error() %q", tc.err, enLoc.RenderError(tc.err), tc.err.Error())
		}
		if zh := zhLoc.RenderError(tc.err); zh == "" || zh == tc.err.Error() {
			t.Fatalf("zh RenderError(%v) 未本地化: %q", tc.err, zh)
		}
	}

	// 显式传入无效 *i18n.Localizer 必须失败关闭返回 ErrInvalidConfig。
	var out, errBuf bytes.Buffer
	err := sftpshell.Run(context.Background(), sftpshell.Config{
		Engine:     newFakeTransferClient(),
		TargetSpec: "alice@example.com",
		Stdout:     &out,
		Stderr:     &errBuf,
		Localizer:  cat.For(domi18n.LocaleInvalid),
	})
	if !errors.Is(err, sftpshell.ErrInvalidConfig) {
		t.Fatalf("无效 Localizer 期望 ErrInvalidConfig，实际=%v", err)
	}
	if id, ok := domi18n.ErrorID(err); !ok || id != i18n.KeySFTPConfigInvalidField {
		t.Fatalf("无效 Localizer 期望 ErrorID=%q，实际=(%q, %v)", i18n.KeySFTPConfigInvalidField, id, ok)
	}
}
