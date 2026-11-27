package cmdssh_test

import (
	"bytes"
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
	"github.com/wentf9/xops-cli/internal/entry/cli/cmdssh"
)

type sshStub struct {
	mu           sync.Mutex
	lastExecReq  engine.ExecRequest
	lastBatchReq engine.BatchExecRequest
	lastFwdReqs  []engine.StartForwardRequest
	stopFwdErr   error
	batchExecFn  func(context.Context, engine.BatchExecRequest) (engine.BatchExecReport, error)
}

var (
	_ clikit.SSHClient        = (*sshStub)(nil)
	_ clikit.AutomationClient = (*sshStub)(nil)
)

func (s *sshStub) Close(_ context.Context) error { return nil }
func (s *sshStub) RunSSH(_ context.Context, _ engine.RunSSHRequest) (execution.ExecutionOutcome, error) {
	out, _ := execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	return out, nil
}
func (s *sshStub) ResolveTarget(_ context.Context, _ engine.ResolveTargetRequest) (res engine.ResolvedTarget, err error) {
	return res, nil
}
func (s *sshStub) Exec(_ context.Context, req engine.ExecRequest) (execution.ExecutionOutcome, error) {
	s.mu.Lock()
	s.lastExecReq = req
	s.mu.Unlock()
	out, _ := execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	return out, nil
}
func (s *sshStub) ExecPrivileged(_ context.Context, _ engine.PrivilegeExecRequest) (execution.ExecutionOutcome, error) {
	out, _ := execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	return out, nil
}
func (s *sshStub) ProbeShell(_ context.Context, _ engine.ProbeShellRequest) (res engine.ShellProbeResult, err error) {
	return res, nil
}
func (s *sshStub) StartForward(_ context.Context, req engine.StartForwardRequest) (info engine.ForwardInfo, err error) {
	s.mu.Lock()
	s.lastFwdReqs = append(s.lastFwdReqs, req)
	s.mu.Unlock()
	return info, nil
}
func (s *sshStub) InspectForward(_ context.Context, _ plan.ManagedHandle[plan.KindTunnel]) (st engine.ForwardStatus, err error) {
	return st, nil
}
func (s *sshStub) StopForward(_ context.Context, _ plan.ManagedHandle[plan.KindTunnel]) error {
	return s.stopFwdErr
}
func (s *sshStub) StartControlMaster(_ context.Context, _ engine.ControlMasterRequest) (info engine.ControlMasterInfo, err error) {
	return info, nil
}
func (s *sshStub) InspectControlMaster(_ context.Context, _ plan.ManagedHandle[plan.KindMux]) (st engine.ControlMasterStatus, err error) {
	return st, nil
}
func (s *sshStub) StopControlMaster(_ context.Context, _ plan.ManagedHandle[plan.KindMux]) error {
	return nil
}
func (s *sshStub) ProbeMux(_ context.Context, _ engine.MuxControlRequest) (resp engine.MuxControlResponse, err error) {
	return resp, nil
}
func (s *sshStub) ControlMux(_ context.Context, _ engine.MuxControlRequest) (resp engine.MuxControlResponse, err error) {
	return resp, nil
}
func (s *sshStub) RunMuxProxy(_ context.Context, _ engine.MuxControlRequest, _ io.ReadCloser, _ io.Writer) error {
	return nil
}
func (s *sshStub) NewOperationStream(_ context.Context, _ int) (*events.OperationStream, error) {
	return nil, errors.New("unexpected top-level stream")
}
func (s *sshStub) BatchExec(ctx context.Context, req engine.BatchExecRequest) (rep engine.BatchExecReport, err error) {
	s.mu.Lock()
	s.lastBatchReq = req
	s.mu.Unlock()
	if s.batchExecFn != nil {
		return s.batchExecFn(ctx, req)
	}
	return rep, nil
}
func (s *sshStub) RunPlaybook(_ context.Context, _ engine.PlaybookRequest) (res engine.PlaybookRunResult, err error) {
	return res, nil
}

func newSSHRuntime(stub *sshStub) (*clikit.Runtime, *bytes.Buffer, *bytes.Buffer) {
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
	return rt, &stdout, &stderr
}

func TestParseSSHArgs_ControlMasterFirstWins(t *testing.T) {
	defer goleak.VerifyNone(t)

	cases := []struct {
		name string
		args []string
		want option.ControlMasterMode
	}{
		{"single_M", []string{"-M", "web"}, option.ControlMasterYes},
		{"double_MM_cluster", []string{"-MM", "web"}, option.ControlMasterAsk},
		{"double_M_separate", []string{"-M", "-M", "web"}, option.ControlMasterAsk},
		{"option_before_MM_wins", []string{"-o", "ControlMaster=no", "-MM", "web"}, option.ControlMasterNo},
		{"MM_before_option_wins", []string{"-MM", "-o", "ControlMaster=no", "web"}, option.ControlMasterAsk},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := cmdssh.ParseSSHArgs(tc.args)
			if err != nil {
				t.Fatalf("ParseSSHArgs(%v) 失败: %v", tc.args, err)
			}
			if got := parsed.CLIOptions.Control().Master(); got != tc.want {
				t.Fatalf("ControlMaster=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestRunExec_NonPOSIXDialectsAndConcurrentBatchStreaming(t *testing.T) {
	defer goleak.VerifyNone(t)

	for _, tc := range []struct {
		name string
		args []string
		want execution.LaunchDialect
	}{
		{"powershell", []string{"--dialect", "powershell", "web", "Get-Date"}, execution.DialectPowerShell},
		{"cmd", []string{"--dialect", "cmd", "web", "dir"}, execution.DialectCmd},
		{"raw", []string{"--dialect", "raw", "web", "rawcmd"}, execution.DialectRaw},
		{"server", []string{"--interpreter", "server", "web", "cmd"}, execution.DialectUnknown},
		{"login_only", []string{"--login", "login", "web", "env"}, execution.DialectPOSIX},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := &sshStub{}
			rt, _, stderr := newSSHRuntime(stub)
			if code := cmdssh.RunExec(context.Background(), rt, tc.args); code != 0 {
				t.Fatalf("RunExec(%v) 失败: code=%d stderr=%q", tc.args, code, stderr.String())
			}
			cp, ok := stub.lastExecReq.CommandPlan.Get()
			if !ok || cp.Profile().Dialect() != tc.want {
				t.Fatalf("CommandPlan Dialect=%v ok=%v, want %v", cp.Profile().Dialect(), ok, tc.want)
			}
		})
	}

	// 验证 sh + login 非法组合在入口层即被拒绝并返回 JSON 错误信封。
	stubBad := &sshStub{}
	rtBad, outBad, _ := newSSHRuntime(stubBad)
	if code := cmdssh.RunExec(context.Background(), rtBad, []string{"--interpreter", "sh", "--login", "login", "--json", "web", "id"}); code != clikit.ExitUsage {
		t.Fatalf("sh+login 应返回 ExitUsage，实际=%d", code)
	}
	var env clikit.ErrorEnvelope
	if err := jsonv2.Unmarshal(outBad.Bytes(), &env); err != nil || env.OK || env.ErrorCode != "usage_error" {
		t.Fatalf("sh+login JSON 错误信封异常: err=%v env=%+v", err, env)
	}

	// 验证多节点并发 NodeStreamFactory 实时分块消费（-race 互斥安全 + 0 goroutine 泄漏）。
	stubBatch := &sshStub{batchExecFn: emitTwoNodesViaFactory}
	rtBatch, outBatch, errBatch := newSSHRuntime(stubBatch)
	_ = cmdssh.RunExec(context.Background(), rtBatch, []string{"--nodes", "web-1,web-2", "--stream", "--", "uptime"})
	if !strings.Contains(outBatch.String(), "[web-1] out-1\n") || !strings.Contains(outBatch.String(), "[web-2] out-2\n") {
		t.Fatalf("并发节点 stdout 流缺失: %q", outBatch.String())
	}
	if !strings.Contains(errBatch.String(), "[web-2] err-2\n") {
		t.Fatalf("并发节点 stderr 流缺失: %q", errBatch.String())
	}
}

func emitTwoNodesViaFactory(ctx context.Context, req engine.BatchExecRequest) (rep engine.BatchExecReport, err error) {
	if req.NodeStreamFactory == nil {
		return rep, errors.New("missing NodeStreamFactory")
	}
	tr, _ := security.ParseTraceID("0123456789abcdef0123456789abcdef")
	op, _ := security.ParseOperationID("fedcba9876543210")
	_ = conc.RunWait(ctx, func(wCtx context.Context, n *conc.Nursery) error {
		for _, pair := range [][3]string{{"web-1", "out-1\n", ""}, {"web-2", "out-2\n", "err-2\n"}} {
			p := pair
			_ = n.Go(func(c context.Context) error {
				nid, _ := inventory.ParseNodeID(p[0])
				st, sErr := req.NodeStreamFactory(nid, tr, op)
				if sErr != nil {
					return sErr
				}
				defer st.Close()
				meta, _ := events.NewEventMeta(events.EventMetaSpec{
					TraceID: tr, OperationID: algebraic.Some(op), NodeID: algebraic.Some(nid), OccurredAt: time.Unix(1700000000, 0).UTC(), Seq: 1,
				})
				ev1, _ := events.NewOutputChunkEvent(events.OutputChunkSpec{Meta: meta, Stream: events.OutputStreamStdout, ChunkIndex: 0, Data: []byte(p[1])})
				_ = st.Emit(c, ev1)
				if p[2] != "" {
					ev2, _ := events.NewOutputChunkEvent(events.OutputChunkSpec{Meta: meta, Stream: events.OutputStreamStderr, ChunkIndex: 1, Data: []byte(p[2])})
					_ = st.Emit(c, ev2)
				}
				return nil
			})
		}
		return nil
	})
	return rep, errors.New("stub-complete")
}

func TestRunSSH_TunnelPortToUnixAndJSONErrors(t *testing.T) {
	defer goleak.VerifyNone(t)

	// 1) 2 段 `8080:/var/run/app.sock` 端口至远端 Unix 套接字转发解析与单一合法 JSON 输出。
	stubFwd := &sshStub{}
	rtFwd, outFwd, errFwd := newSSHRuntime(stubFwd)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if code := cmdssh.RunTunnel(ctx, rtFwd, []string{"-L", "8080:/var/run/app.sock", "--json", "web"}); code != clikit.ExitOK {
		t.Fatalf("tunnel 2 段 port:unix_socket 应正常退出: code=%d stderr=%q", code, errFwd.String())
	}
	if len(stubFwd.lastFwdReqs) != 1 || stubFwd.lastFwdReqs[0].Spec.BindAddr() != "127.0.0.1:8080" || stubFwd.lastFwdReqs[0].Spec.TargetAddr() != "/var/run/app.sock" {
		t.Fatalf("2 段 port:unix_socket 解析失配: %+v", stubFwd.lastFwdReqs)
	}
	var active map[string]any
	if err := jsonv2.Unmarshal(outFwd.Bytes(), &active); err != nil {
		t.Fatalf("stdout 应保持单一合法 JSON 文档: err=%v raw=%q", err, outFwd.String())
	}

	// 2) tunnel / mux 解析错误遵循 --json 输出 ErrorEnvelope，并拒绝 -h<garbage>。
	for _, fn := range []func(*clikit.Runtime) int{
		func(rt *clikit.Runtime) int {
			return cmdssh.RunTunnel(context.Background(), rt, []string{"--bad", "--json", "web"})
		},
		func(rt *clikit.Runtime) int {
			return cmdssh.RunTunnel(context.Background(), rt, []string{"-hfoo", "--json", "web"})
		},
		func(rt *clikit.Runtime) int {
			return cmdssh.RunMux(context.Background(), rt, []string{"status", "--bad", "--json", "web"})
		},
	} {
		rt, stdout, _ := newSSHRuntime(&sshStub{})
		if c := fn(rt); c != clikit.ExitUsage {
			t.Fatalf("语法错误应返回 ExitUsage，实际=%d", c)
		}
		var env clikit.ErrorEnvelope
		if err := jsonv2.Unmarshal(stdout.Bytes(), &env); err != nil || env.OK || env.ErrorCode != "usage_error" {
			t.Fatalf("期望合法 JSON ErrorEnvelope: err=%v env=%+v raw=%q", err, env, stdout.String())
		}
	}
}
