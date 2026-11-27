package cli_test

import (
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/internal/entry/cli"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
)

func TestParseSSHArgs_ExtendedOpenSSHFlags(t *testing.T) {
	defer goleak.VerifyNone(t)

	parsed, err := cli.ParseSSHArgs([]string{
		"-L", "8080:127.0.0.1:80",
		"-R", "[::1]:9090:app.internal:9000",
		"-D", "1080",
		"-w", "0:1",
		"--tun-mode", "ethernet",
		"-MM",
		"-S", "/tmp/mux.sock",
		"-Nf",
		"--json",
		"--policy", "strict_operator",
		"ops@bastion.internal",
	})
	if err != nil {
		t.Fatalf("ParseSSHArgs 失败: %v", err)
	}
	if len(parsed.Forwards) != 4 || parsed.MasterCount != 2 || parsed.ControlSocket != "/tmp/mux.sock" {
		t.Fatalf("扩展标志解析失配: fwds=%d master=%d sock=%q", len(parsed.Forwards), parsed.MasterCount, parsed.ControlSocket)
	}
	if master := parsed.CLIOptions.Control().Master(); master != option.ControlMasterAsk {
		t.Fatalf("-MM 必须折叠为 ControlMaster=ask，实际=%v", master)
	}
	if !parsed.NoCommand || !parsed.Background || !parsed.JSON || parsed.Policy != engine.PolicyProfileStrictOperator {
		t.Fatalf("标志状态失配: N=%v f=%v json=%v policy=%v", parsed.NoCommand, parsed.Background, parsed.JSON, parsed.Policy)
	}

	muxParsed, err := cli.ParseSSHArgs([]string{"-O", "check", "-S", "/tmp/mux.sock", "web"})
	if err != nil || muxParsed.MuxAction != engine.MuxActionCheck {
		t.Fatalf("-O check 解析失败: action=%v err=%v", muxParsed.MuxAction, err)
	}

	stdioParsed, err := cli.ParseSSHArgs([]string{"-W", "10.0.0.5:443", "bastion"})
	if err != nil || !stdioParsed.StdioForward.IsSome() {
		t.Fatalf("-W 解析失败: fwd=%v err=%v", stdioParsed.StdioForward, err)
	}

	for _, bad := range [][]string{
		{"-O", "bogus", "host"},
		{"-W", "not-a-hostport", "host"},
		{"-L", "bad", "host"},
		{"-w", "bad:0", "host"},
		{"--tun-mode", "l4", "host"},
		{"--policy", "invalid", "host"},
		{"-f", "host", "echo", "hi"},
		{"-f", "host"},
		{"-f", "-O", "check", "host"},
	} {
		if _, err := cli.ParseSSHArgs(bad); !errors.Is(err, cli.ErrUsage) {
			t.Fatalf("非法参数 %v 应返回 ErrUsage，实际=%v", bad, err)
		}
	}
}

func TestApp_SSHExtendedModesAndMuxDaemonHook(t *testing.T) {
	defer goleak.VerifyNone(t)

	assertSSHJSONAndMuxControl(t)
	assertSSHDaemonAndNoCommand(t)
}

func assertSSHJSONAndMuxControl(t *testing.T) {
	t.Helper()
	// 1) --json 非交互执行返回规范 JSON/v2 ExecOutcomeView。
	h := newFullAppHarness(t, nil, nil)
	if code := h.app.Run(context.Background(), []string{"ssh", "--json", "web", "echo", "hi"}); code != 0 {
		t.Fatalf("ssh --json 失败: code=%d stderr=%q", code, h.stderr.String())
	}
	var outView clikit.ExecOutcomeView
	if err := jsonv2.Unmarshal(h.stdout.Bytes(), &outView); err != nil || !outView.OK || outView.Stdout != "ssh-ok\n" {
		t.Fatalf("ssh --json 输出异常: err=%v view=%+v raw=%q", err, outView, h.stdout.String())
	}

	// 2) -O check / forward / proxy 路由。
	hCheck := newFullAppHarness(t, nil, nil)
	if code := hCheck.app.Run(context.Background(), []string{"ssh", "-O", "check", "-S", "/tmp/m.sock", "--json", "web"}); code != 0 {
		t.Fatalf("ssh -O check 失败: code=%d stderr=%q", code, hCheck.stderr.String())
	}
	if !hCheck.eng.hasCall("ProbeMux") || !strings.Contains(hCheck.stdout.String(), `"alive":true`) {
		t.Fatalf("ProbeMux 未正确调用或 JSON 异常: calls=%v out=%q", hCheck.eng.calls, hCheck.stdout.String())
	}

	hFwd := newFullAppHarness(t, nil, nil)
	if code := hFwd.app.Run(context.Background(), []string{"ssh", "-O", "forward", "-L", "8080:127.0.0.1:80", "web"}); code != 0 {
		t.Fatalf("ssh -O forward 失败: code=%d stderr=%q", code, hFwd.stderr.String())
	}
	if !hFwd.eng.hasCall("ControlMux") || hFwd.eng.lastMuxReq.Action != engine.MuxActionForward {
		t.Fatalf("ControlMux 未收到 MuxActionForward: %+v", hFwd.eng.lastMuxReq)
	}

	hProxy := newFullAppHarness(t, nil, strings.NewReader("req"))
	if code := hProxy.app.Run(context.Background(), []string{"ssh", "-O", "proxy", "web"}); code != 0 || hProxy.stdout.String() != "proxy-stream" {
		t.Fatalf("ssh -O proxy 失败: code=%d out=%q", code, hProxy.stdout.String())
	}

	// 3) -W 严格 fail-closed 返回 ErrUnsupported (255)。
	hW := newFullAppHarness(t, nil, nil)
	if code := hW.app.Run(context.Background(), []string{"ssh", "-W", "10.0.0.5:443", "--json", "bastion"}); code != 255 {
		t.Fatalf("ssh -W 应 fail-closed 返回 255，实际=%d", code)
	}
	if !strings.Contains(hW.stdout.String(), `"error_code":"unsupported"`) {
		t.Fatalf("ssh -W JSON 应标明 unsupported: %q", hW.stdout.String())
	}
}

func assertSSHDaemonAndNoCommand(t *testing.T) {
	t.Helper()
	// 4) -f 路由至 RunMuxDaemon（未注入失败关闭，已注入透传强类型参数）。
	hNilDaemon := newFullAppHarness(t, nil, nil)
	if code := hNilDaemon.app.Run(context.Background(), []string{"ssh", "-f", "-N", "-L", "8080:db:5432", "web"}); code != 255 || !strings.Contains(hNilDaemon.stderr.String(), "RunMuxDaemon") {
		t.Fatalf("未注入 RunMuxDaemon 时 ssh -f 应返回 255 并说明原因，实际 code=%d stderr=%q", code, hNilDaemon.stderr.String())
	}
	var gotDaemonReq cli.MuxDaemonStartRequest
	hDaemon := newFullAppHarness(t, func(cfg *cli.AppConfig) {
		cfg.RunMuxDaemon = func(_ context.Context, req cli.MuxDaemonStartRequest) error {
			gotDaemonReq = req
			return nil
		}
	}, nil)
	if code := hDaemon.app.Run(context.Background(), []string{"--policy", "strict_operator", "ssh", "-f", "-N", "-L", "8080:db:5432", "-S", "/tmp/d.sock", "web"}); code != 0 {
		t.Fatalf("注入 RunMuxDaemon 时 ssh -f 应成功: code=%d stderr=%q", code, hDaemon.stderr.String())
	}
	if gotDaemonReq.TargetSpec != "web" || len(gotDaemonReq.Forwards) != 1 || gotDaemonReq.InitOptions.PolicyProfile != engine.PolicyProfileStrictOperator {
		t.Fatalf("RunMuxDaemon 请求字段不符: %+v", gotDaemonReq)
	}

	// 5) -N -M -L 前台隧道与主控在 ctx 取消后确定性退出且 0 协程泄漏。
	hKeep := newFullAppHarness(t, nil, nil)
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = hKeep.app.Run(cancelCtx, []string{"ssh", "-N", "-M", "-L", "8080:db:5432", "web"})
	hKeep2 := newFullAppHarness(t, nil, nil)
	runCtx, stopRun := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer stopRun()
	if code := hKeep2.app.Run(runCtx, []string{"ssh", "-N", "-M", "-L", "8080:db:5432", "web"}); code != 0 {
		t.Fatalf("ssh -N -M -L 在 ctx 取消时应正常退出 0: code=%d stderr=%q", code, hKeep2.stderr.String())
	}
	if !hKeep2.eng.hasCall("StartControlMaster") || !hKeep2.eng.hasCall("StartForward") {
		t.Fatalf("ssh -N -M -L 未启动控制主进程或转发: calls=%v", hKeep2.eng.calls)
	}
}

func TestApp_ExecSinglePrivilegedAndBatchStream(t *testing.T) {
	defer goleak.VerifyNone(t)

	// 1) 单目标 Exec + CommandPlan 选项 + --json。
	h := newFullAppHarness(t, nil, nil)
	code := h.app.Run(context.Background(), []string{
		"exec", "-p", "2222", "--workdir", "/srv/app", "--env", "MODE=prod",
		"--timeout", "30s", "--dialect", "posix", "--json", "web-1", "uname", "-a",
	})
	if code != 0 || !h.eng.hasCall("Exec") {
		t.Fatalf("单目标 exec 失败: code=%d stderr=%q", code, h.stderr.String())
	}
	if port, ok := h.eng.lastExecReq.CLIOptions.Port().Get(); !ok || port != 2222 {
		t.Fatalf("exec -p 未透传: port=%d ok=%v", port, ok)
	}

	// 2) 单目标提权 ExecPrivileged。
	hPriv := newFullAppHarness(t, nil, nil)
	code = hPriv.app.Run(context.Background(), []string{
		"exec", "--sudo", "--sudo-user", "root", "--password-ref", "vault/sudo_pw", "web-1", "id",
	})
	if code != 0 || !hPriv.eng.hasCall("ExecPrivileged") {
		t.Fatalf("exec --sudo 失败: code=%d stderr=%q", code, hPriv.stderr.String())
	}
	if hPriv.eng.lastPrivReq.Privilege.Method() != engine.PrivilegeMethodSudo {
		t.Fatalf("提权方式不符: %v", hPriv.eng.lastPrivReq.Privilege.Method())
	}

	// 3) 批量 exec --nodes + --stream（严格经真实 NodeStreamFactory 实时消费分块输出且 0 goroutine 泄漏）。
	hBatch := newFullAppHarness(t, nil, nil)
	hBatch.eng.batchExecFn = func(ctx context.Context, req engine.BatchExecRequest) (rep engine.BatchExecReport, err error) {
		if req.NodeStreamFactory == nil {
			t.Errorf("--stream 模式下必须注入 req.NodeStreamFactory")
			return rep, errors.New("missing NodeStreamFactory")
		}
		tr, _ := security.ParseTraceID("0123456789abcdef0123456789abcdef")
		op, _ := security.ParseOperationID("fedcba9876543210")
		nid, _ := inventory.ParseNodeID("web-1")
		nodeStream, sErr := req.NodeStreamFactory(nid, tr, op)
		if sErr != nil {
			return rep, sErr
		}
		defer nodeStream.Close()
		meta, _ := events.NewEventMeta(events.EventMetaSpec{
			TraceID: tr, OperationID: algebraic.Some(op), NodeID: algebraic.Some(nid), OccurredAt: time.Unix(1700000000, 0).UTC(), Seq: 1,
		})
		evOut, _ := events.NewOutputChunkEvent(events.OutputChunkSpec{
			Meta: meta, Stream: events.OutputStreamStdout, ChunkIndex: 0, Data: []byte("stream-line\n"),
		})
		evErr, _ := events.NewOutputChunkEvent(events.OutputChunkSpec{
			Meta: meta, Stream: events.OutputStreamStderr, ChunkIndex: 1, Data: []byte("warn-line\n"),
		})
		_ = nodeStream.Emit(ctx, evOut)
		_ = nodeStream.Emit(ctx, evErr)
		return rep, errors.New("stub-report")
	}
	_ = hBatch.app.Run(context.Background(), []string{
		"exec", "--nodes", "web-1", "--exclude-tags", "canary", "--concurrency", "4", "--fail-fast", "--stream", "--", "uptime",
	})
	if !hBatch.eng.hasCall("BatchExec") || !strings.Contains(hBatch.stdout.String(), "[web-1] stream-line\n") || !strings.Contains(hBatch.stderr.String(), "[web-1] warn-line\n") {
		t.Fatalf("批量流式输出未正确路由: stdout=%q stderr=%q", hBatch.stdout.String(), hBatch.stderr.String())
	}
}

func TestApp_TunnelAndMuxCommands(t *testing.T) {
	defer goleak.VerifyNone(t)

	h := newFullAppHarness(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if code := h.app.Run(ctx, []string{"tunnel", "-L", "8080:app:80", "-D", "1080", "-w", "0:1", "--tun-mode", "ethernet", "bastion"}); code != 0 {
		t.Fatalf("tunnel 多转发失败: code=%d stderr=%q", code, h.stderr.String())
	}
	if len(h.eng.lastFwdReqs) != 3 {
		t.Fatalf("期望启动 3 条转发，实际=%d", len(h.eng.lastFwdReqs))
	}

	// 验证 tunnel 显式子命令形式及 mux 各动作。
	hDyn := newFullAppHarness(t, nil, nil)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel2()
	if code := hDyn.app.Run(ctx2, []string{"forward", "dynamic", "bastion", "1080"}); code != 0 || len(hDyn.eng.lastFwdReqs) != 1 {
		t.Fatalf("forward dynamic 失败: code=%d fwds=%d", code, len(hDyn.eng.lastFwdReqs))
	}

	hMux := newFullAppHarness(t, nil, nil)
	if code := hMux.app.Run(context.Background(), []string{"mux", "status", "-S", "/tmp/m.sock", "--json", "web"}); code != 0 || !strings.Contains(hMux.stdout.String(), `"master_pid":4242`) {
		t.Fatalf("mux status --json 失败: code=%d out=%q err=%q", code, hMux.stdout.String(), hMux.stderr.String())
	}
	hMux.stdout.Reset()
	hMux.eng.probeMuxFn = func(context.Context, engine.MuxControlRequest) (engine.MuxControlResponse, error) {
		return mustDecodeJSON[engine.MuxControlResponse](`{"alive":false,"detail":"not running"}`), nil
	}
	if code := hMux.app.Run(context.Background(), []string{"mux", "check", "-S", "/tmp/m.sock", "--json", "web"}); code != 255 || !strings.Contains(hMux.stdout.String(), `"ok":false`) {
		t.Fatalf("dead mux check 应返回 255 且 ok=false: code=%d out=%q", code, hMux.stdout.String())
	}
	if code := hMux.app.Run(context.Background(), []string{"mux", "stop", "-S", "/tmp/m.sock", "web"}); code != 0 || hMux.eng.lastMuxReq.Action != engine.MuxActionStop {
		t.Fatalf("mux stop 失败: code=%d action=%v", code, hMux.eng.lastMuxReq.Action)
	}
	if code := hMux.app.Run(context.Background(), []string{"mux", "daemon", "web"}); code != 1 {
		t.Fatalf("未注入 RunMuxDaemon 时 mux daemon 应失败关闭返回 1，实际=%d", code)
	}
}

func TestApp_SCPAndSFTPCommands(t *testing.T) {
	defer goleak.VerifyNone(t)

	// 1) SCP 上传（OpenSSH -P/-r/-p + 选项 + --json）。
	hUp := newFullAppHarness(t, nil, nil)
	code := hUp.app.Run(context.Background(), []string{
		"scp", "-P", "2222", "-r", "-p", "--resume", "--no-clobber", "--json", "./pkg.tar.gz", "deploy@web:/tmp/pkg.tar.gz",
	})
	if code != 0 || !hUp.eng.hasCall("SCPUpload") {
		t.Fatalf("scp upload 失败: code=%d stderr=%q", code, hUp.stderr.String())
	}
	if !hUp.eng.lastUploadReq.Recursive || !hUp.eng.lastUploadReq.Resume || !hUp.eng.lastUploadReq.NoClobber || !strings.Contains(hUp.stdout.String(), `"direction":"upload"`) {
		t.Fatalf("scp upload 字段或 JSON 异常: req=%+v out=%q", hUp.eng.lastUploadReq, hUp.stdout.String())
	}

	// 2) SCP Windows 盘符路径不得被误判为远端主机。
	hWin := newFullAppHarness(t, nil, nil)
	if code := hWin.app.Run(context.Background(), []string{"scp", `C:\data\file.bin`, "web:/tmp/file.bin"}); code != 0 || !hWin.eng.hasCall("SCPUpload") {
		t.Fatalf("Windows 盘符路径应走 SCPUpload: code=%d stderr=%q", code, hWin.stderr.String())
	}

	// 3) SCP 下载结合 ResolveWorkDir 钩子自动推导本地文件名。
	hDown := newFullAppHarness(t, func(cfg *cli.AppConfig) {
		cfg.ResolveWorkDir = func() (pathalg.LocalDir, error) {
			return pathalg.ParseLocalDir("/tmp/workdir")
		}
	}, nil)
	if code := hDown.app.Run(context.Background(), []string{"scp", "--json", "web:/var/log/app.log", "."}); code != 0 || !hDown.eng.hasCall("SCPDownload") {
		t.Fatalf("scp download 失败: code=%d stderr=%q", code, hDown.stderr.String())
	}
	if hDown.eng.lastDownloadReq.LocalRoot.String() != "/tmp/workdir" || hDown.eng.lastDownloadReq.LocalDest.String() != "app.log" {
		t.Fatalf("scp download 目录/文件名推导失配: root=%s dest=%s", hDown.eng.lastDownloadReq.LocalRoot, hDown.eng.lastDownloadReq.LocalDest)
	}

	// 4) SCP 拒绝两端均为本地或两端均为远端。
	if code := hUp.app.Run(context.Background(), []string{"scp", "/tmp/a", "/tmp/b"}); code != 2 {
		t.Fatalf("本地到本地 scp 应返回退出码 2，实际=%d", code)
	}
	if code := hUp.app.Run(context.Background(), []string{"scp", "hostA:/tmp/x", "hostB:/tmp/y"}); code != 2 {
		t.Fatalf("远端到远端 scp 应返回退出码 2，实际=%d", code)
	}

	// 5) SFTP 交互子入口钩子（nil 失败关闭 vs 已注入转发）。
	assertSFTPInteractiveHook(t)

	// 6) SFTP 单步批处理子命令全覆盖。
	assertSFTPOperations(t)
}

func assertSFTPInteractiveHook(t *testing.T) {
	t.Helper()
	hSFTPNil := newFullAppHarness(t, nil, nil)
	if code := hSFTPNil.app.Run(context.Background(), []string{"sftp", "web"}); code != 1 {
		t.Fatalf("未注入 RunSFTPShell 时 sftp 交互应返回 1，实际=%d", code)
	}
	var gotSFTPReq cli.SFTPShellStartRequest
	hSFTP := newFullAppHarness(t, func(cfg *cli.AppConfig) {
		cfg.RunSFTPShell = func(_ context.Context, req cli.SFTPShellStartRequest) error {
			gotSFTPReq = req
			return nil
		}
	}, nil)
	if code := hSFTP.app.Run(context.Background(), []string{"sftp", "-P", "2200", "web:/srv"}); code != 0 {
		t.Fatalf("sftp 交互模式失败: code=%d stderr=%q", code, hSFTP.stderr.String())
	}
	if gotSFTPReq.TargetSpec != "web" || gotSFTPReq.InitialDir != "/srv" {
		t.Fatalf("SFTPShellStartRequest 失配: %+v", gotSFTPReq)
	}
}

func assertSFTPOperations(t *testing.T) {
	t.Helper()
	h := newFullAppHarness(t, func(cfg *cli.AppConfig) {
		cfg.ReadOperatorFile = func(_ context.Context, _ pathalg.LocalSourcePath, _ pathalg.SymlinkPolicy, _ int64) ([]byte, error) {
			return []byte("from-file"), nil
		}
	}, strings.NewReader("from-stdin"))

	cmds := [][]string{
		{"sftp", "ls", "--json", "web", "/etc"},
		{"sftp", "stat", "--json", "web", "/etc/hosts"},
		{"sftp", "cat", "--json", "web", "/etc/hosts"},
		{"sftp", "write", "--perm", "0640", "--json", "web", "/tmp/a.txt"},
		{"sftp", "write", "--file", "/tmp/local.txt", "--json", "web", "/tmp/b.txt"},
		{"sftp", "patch", "--old", "foo", "--new", "bar", "--all", "--json", "web", "/tmp/a.txt"},
		{"sftp", "mkdir", "--json", "web", "/tmp/newdir"},
		{"sftp", "mv", "--no-clobber", "--json", "web", "/tmp/a", "/tmp/b"},
		{"sftp", "chmod", "--json", "web", "0755", "/tmp/script.sh"},
		{"sftp", "realpath", "--json", "web", "/tmp/a"},
		{"sftp", "readlink", "--json", "web", "/tmp/link"},
		{"sftp", "rm", "--json", "web", "/tmp/a"},
		{"sftp", "rmdir", "--json", "web", "/tmp/newdir"},
		{"sftp", "recover", "--json", "web", "fedcba9876543210"},
		{"sftp", "recover", "--json"},
	}
	for _, args := range cmds {
		h.stdout.Reset()
		h.stderr.Reset()
		if code := h.app.Run(context.Background(), args); code != 0 {
			t.Fatalf("sftp 命令 %v 失败: code=%d stderr=%q", args, code, h.stderr.String())
		}
		var raw map[string]any
		if err := jsonv2.Unmarshal(h.stdout.Bytes(), &raw); err != nil {
			t.Fatalf("sftp 命令 %v 输出非合法 JSON/v2: err=%v out=%q", args, err, h.stdout.String())
		}
	}
	if string(h.eng.lastWriteReq.Content) != "from-file" {
		t.Fatalf("sftp write --file 未通过 ReadOperatorFile 读取载荷: got=%q", string(h.eng.lastWriteReq.Content))
	}
}
