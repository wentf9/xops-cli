package clikit_test

import (
	"bytes"
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
)

func TestParseForwardFlagSpec_TCPUnixIPv6DynamicAndTUN(t *testing.T) {
	defer goleak.VerifyNone(t)

	cases := []struct {
		name     string
		dir      engine.ForwardDirection
		raw      string
		wantBind string
		wantDst  string
		wantErr  bool
	}{
		{name: "local_port_only", dir: engine.ForwardLocal, raw: "8080:10.0.0.2:80", wantBind: "127.0.0.1:8080", wantDst: "10.0.0.2:80"},
		{name: "local_wildcard", dir: engine.ForwardLocal, raw: "*:8080:web.internal:443", wantBind: "0.0.0.0:8080", wantDst: "web.internal:443"},
		{name: "local_ipv6_brackets", dir: engine.ForwardLocal, raw: "[::1]:8080:[::1]:80", wantBind: "[::1]:8080", wantDst: "[::1]:80"},
		{name: "remote_port_zero", dir: engine.ForwardRemote, raw: "0:127.0.0.1:3000", wantBind: "127.0.0.1:0", wantDst: "127.0.0.1:3000"},
		{name: "local_unix_to_tcp", dir: engine.ForwardLocal, raw: "/tmp/local.sock:127.0.0.1:5432", wantBind: "/tmp/local.sock", wantDst: "127.0.0.1:5432"},
		{name: "local_tcp_to_unix", dir: engine.ForwardLocal, raw: "127.0.0.1:8080:/var/run/app.sock", wantBind: "127.0.0.1:8080", wantDst: "/var/run/app.sock"},
		{name: "local_port_to_unix", dir: engine.ForwardLocal, raw: "8080:/var/run/app.sock", wantBind: "127.0.0.1:8080", wantDst: "/var/run/app.sock"},
		{name: "remote_port_to_unix", dir: engine.ForwardRemote, raw: "9090:/tmp/svc.sock", wantBind: "127.0.0.1:9090", wantDst: "/tmp/svc.sock"},
		{name: "local_unix_to_unix", dir: engine.ForwardLocal, raw: "/tmp/a.sock:/var/run/b.sock", wantBind: "/tmp/a.sock", wantDst: "/var/run/b.sock"},
		{name: "dynamic_port_only", dir: engine.ForwardDynamic, raw: "1080", wantBind: "127.0.0.1:1080", wantDst: ""},
		{name: "dynamic_ipv6", dir: engine.ForwardDynamic, raw: "[::1]:1080", wantBind: "[::1]:1080", wantDst: ""},
		{name: "err_empty", dir: engine.ForwardLocal, raw: "  ", wantErr: true},
		{name: "err_bad_segments", dir: engine.ForwardLocal, raw: "1:2:3:4:5", wantErr: true},
		{name: "err_two_non_unix", dir: engine.ForwardLocal, raw: "8080:80", wantErr: true},
		{name: "err_zero_target_port", dir: engine.ForwardLocal, raw: "8080:127.0.0.1:0", wantErr: true},
		{name: "err_dynamic_too_many", dir: engine.ForwardDynamic, raw: "127.0.0.1:1080:extra", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertForwardFlagSpecCase(t, tc.dir, tc.raw, tc.wantBind, tc.wantDst, tc.wantErr)
		})
	}

	tunSpec, err := clikit.ParseTUNForwardSpec(engine.TUNModeEthernet, "2:any")
	if err != nil {
		t.Fatalf("ParseTUNForwardSpec 失败: %v", err)
	}
	if tunSpec.Direction() != engine.ForwardTUN {
		t.Fatalf("Direction=%v，期望 ForwardTUN", tunSpec.Direction())
	}
	if _, err := clikit.ParseTUNForwardSpec(engine.TUNModePointToPoint, "bad:0"); !errors.Is(err, clikit.ErrUsage) {
		t.Fatalf("非法 TUN 编号应返回 ErrUsage，实际=%v", err)
	}
}

func assertForwardFlagSpecCase(t *testing.T, dir engine.ForwardDirection, raw, wantBind, wantDst string, wantErr bool) {
	t.Helper()
	spec, err := clikit.ParseForwardFlagSpec(dir, raw)
	if wantErr {
		if err == nil {
			t.Fatalf("期望错误，实际 spec=%v", spec)
		}
		return
	}
	if err != nil {
		t.Fatalf("ParseForwardFlagSpec(%s, %q) 失败: %v", dir, raw, err)
	}
	if spec.BindAddr() != wantBind || spec.TargetAddr() != wantDst {
		t.Fatalf("got bind=%q dst=%q, want bind=%q dst=%q", spec.BindAddr(), spec.TargetAddr(), wantBind, wantDst)
	}
}

func TestParseGlobalPrefixAndPolicyValidation(t *testing.T) {
	defer goleak.VerifyNone(t)

	flags, rest, err := clikit.ParseGlobalPrefix([]string{"--json", "--policy", "strict_agent", "-F/tmp/ssh.cfg", "hosts", "list"})
	if err != nil {
		t.Fatalf("ParseGlobalPrefix 失败: %v", err)
	}
	if !flags.JSON || flags.Policy != engine.PolicyProfileStrictAgent || flags.ConfigFile != "/tmp/ssh.cfg" {
		t.Fatalf("全局标志解析异常: %+v", flags)
	}
	if len(rest) != 2 || rest[0] != "hosts" || rest[1] != "list" {
		t.Fatalf("剩余命令参数异常: %v", rest)
	}

	if _, _, err := clikit.ParseGlobalPrefix([]string{"--policy=nonexistent", "ssh", "web"}); !errors.Is(err, clikit.ErrUsage) {
		t.Fatalf("非法 --policy 应返回 ErrUsage，实际=%v", err)
	}
	if _, _, err := clikit.ParseGlobalPrefix([]string{"-F"}); !errors.Is(err, clikit.ErrUsage) {
		t.Fatalf("缺少 -F 参数应返回 ErrUsage，实际=%v", err)
	}
}

func TestJSONEnvelopeDeterministicAndErrorClassification(t *testing.T) {
	defer goleak.VerifyNone(t)

	var buf bytes.Buffer
	clikit.WriteJSONError(&buf, clikit.ExitGeneral, engine.ErrEngineHalted)
	var env clikit.ErrorEnvelope
	if err := jsonv2.Unmarshal(buf.Bytes(), &env); err != nil {
		t.Fatalf("ErrorEnvelope JSON/v2 反序列化失败: %v raw=%q", err, buf.String())
	}
	if env.OK || env.ExitCode != clikit.ExitGeneral || env.ErrorCode != "engine_halted" {
		t.Fatalf("ErrorEnvelope 字段异常: %+v", env)
	}

	// 验证 map 输出受 jsonv2.Deterministic(true) 约束键名按字典序确定性输出。
	buf.Reset()
	if err := clikit.WriteJSON(&buf, map[string]int{"z": 1, "a": 2, "m": 3}); err != nil {
		t.Fatalf("WriteJSON 失败: %v", err)
	}
	if got := strings.TrimSpace(buf.String()); got != `{"a":2,"m":3,"z":1}` {
		t.Fatalf("Deterministic JSON 顺序不符: %q", got)
	}

	codePairs := []struct {
		err  error
		want string
	}{
		{clikit.ErrUsage, "usage_error"},
		{clikit.ErrNotConfigured, "not_configured"},
		{engine.ErrAuthorizationDenied, "authorization_denied"},
		{engine.ErrVaultLocked, "vault_locked"},
		{engine.ErrRevisionConflict, "revision_conflict"},
		{engine.ErrNotFound, "not_found"},
		{engine.ErrAlreadyExists, "already_exists"},
		{engine.ErrLimitExceeded, "limit_exceeded"},
		{engine.ErrUnsupported, "unsupported"},
		{context.Canceled, "canceled"},
	}
	for _, cp := range codePairs {
		if got := clikit.ClassifyErrorCode(cp.err); got != cp.want {
			t.Fatalf("ClassifyErrorCode(%v)=%q, want %q", cp.err, got, cp.want)
		}
	}
}

func TestBuildExecOutcomeView_FailClosedAndDoNotRetry(t *testing.T) {
	defer goleak.VerifyNone(t)

	okZero, _ := execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	vHalted, code, _ := clikit.BuildExecOutcomeView(okZero, engine.ErrEngineHalted, "hi", "")
	if vHalted.OK || code != clikit.ExitSSHError || vHalted.ErrorCode != "engine_halted" {
		t.Fatalf("Completed(0)+ErrEngineHalted 必须 fail-closed: view=%+v code=%d", vHalted, code)
	}

	unknownOut, _ := execution.NewOutcomeUnknown(execution.ExecPhaseTransportLost, "eof", "lost")
	vUnk, codeUnk, _ := clikit.BuildExecOutcomeView(unknownOut, errors.New("broken"), "", "")
	if vUnk.OK || !vUnk.DoNotRetry || codeUnk != clikit.ExitSSHError {
		t.Fatalf("OutcomeUnknown 必须设置 do_not_retry=true 且非零退出: view=%+v code=%d", vUnk, codeUnk)
	}
}

func TestRuntime_WithEngineAndReadLocalInputFailClosed(t *testing.T) {
	defer goleak.VerifyNone(t)

	var stdout, stderr bytes.Buffer
	closeCalled := false
	rt := &clikit.Runtime{
		Stdin:           strings.NewReader("payload"),
		Stdout:          &stdout,
		Stderr:          &stderr,
		ShutdownTimeout: time.Second,
		EngineFactory: func(context.Context, clikit.EngineInitOptions) (clikit.EngineHandle, error) {
			return clikit.EngineHandle{
				Runner: nil,
				Close: func(context.Context) error {
					closeCalled = true
					return nil
				},
			}, nil
		},
	}
	code := rt.WithEngine(context.Background(), clikit.EngineInitOptions{}, clikit.ExitSSHError, false, func(clikit.SessionRunner) int {
		return clikit.ExitOK
	})
	if code != clikit.ExitGeneral || !closeCalled {
		t.Fatalf("nil Runner 必须返回 ExitGeneral 并调用 Close: code=%d closeCalled=%v", code, closeCalled)
	}

	// 验证未注入 ReadOperatorFile 钩子读取路径时失败关闭，读取 "-" 走 Stdin。
	data, src, err := rt.ReadLocalInput(context.Background(), "-", pathalg.SymlinkReject, 1024)
	if err != nil || string(data) != "payload" || src != "<stdin>" {
		t.Fatalf("stdin 读取异常: data=%q src=%q err=%v", string(data), src, err)
	}
	if _, _, err := rt.ReadLocalInput(context.Background(), "/tmp/a.yaml", pathalg.SymlinkReject, 1024); !errors.Is(err, clikit.ErrNotConfigured) {
		t.Fatalf("未注入 ReadOperatorFile 应返回 ErrNotConfigured，实际=%v", err)
	}
	if _, err := clikit.ReadBounded(strings.NewReader("123456"), 4); !errors.Is(err, engine.ErrLimitExceeded) {
		t.Fatalf("超出上限读取应返回 ErrLimitExceeded，实际=%v", err)
	}
}

func TestBuildLaunchProfile_MatrixAndValidation(t *testing.T) {
	defer goleak.VerifyNone(t)

	optEmpty, err := clikit.BuildOptionalLaunchProfile(algebraic.None[execution.LaunchDialect](), execution.InterpreterInvalid, execution.LoginModeUnset)
	if err != nil || optEmpty.IsSome() {
		t.Fatalf("全空参数应返回 None: opt=%v err=%v", optEmpty, err)
	}

	noneD := algebraic.None[execution.LaunchDialect]()
	someD := algebraic.Some[execution.LaunchDialect]
	validCases := []struct {
		name      string
		dialect   algebraic.Option[execution.LaunchDialect]
		interp    execution.Interpreter
		login     execution.LoginMode
		wantDial  execution.LaunchDialect
		wantInter execution.Interpreter
		wantLogin execution.LoginMode
	}{
		{"default", noneD, execution.InterpreterInvalid, execution.LoginModeUnset, execution.DialectUnknown, execution.InterpreterServer, execution.LoginModeInherit},
		{"powershell_only", someD(execution.DialectPowerShell), execution.InterpreterInvalid, execution.LoginModeUnset, execution.DialectPowerShell, execution.InterpreterPowerShell, execution.LoginModeDisabled},
		{"cmd_only", someD(execution.DialectCmd), execution.InterpreterInvalid, execution.LoginModeUnset, execution.DialectCmd, execution.InterpreterCmd, execution.LoginModeDisabled},
		{"raw_only", someD(execution.DialectRaw), execution.InterpreterInvalid, execution.LoginModeUnset, execution.DialectRaw, execution.InterpreterServer, execution.LoginModeInherit},
		{"server_interp", noneD, execution.InterpreterServer, execution.LoginModeUnset, execution.DialectUnknown, execution.InterpreterServer, execution.LoginModeInherit},
		{"pwsh_interp", noneD, execution.InterpreterPwsh, execution.LoginModeUnset, execution.DialectPowerShell, execution.InterpreterPwsh, execution.LoginModeDisabled},
		{"login_only", noneD, execution.InterpreterInvalid, execution.LoginModeLogin, execution.DialectPOSIX, execution.InterpreterBash, execution.LoginModeLogin},
		{"bash_login", someD(execution.DialectPOSIX), execution.InterpreterBash, execution.LoginModeLogin, execution.DialectPOSIX, execution.InterpreterBash, execution.LoginModeLogin},
	}
	for _, tc := range validCases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := clikit.BuildLaunchProfile(tc.dialect, tc.interp, tc.login)
			if err != nil {
				t.Fatalf("BuildLaunchProfile(%v,%v,%v) 失败: %v", tc.dialect, tc.interp, tc.login, err)
			}
			if p.Dialect() != tc.wantDial || p.Interpreter() != tc.wantInter || p.LoginMode() != tc.wantLogin {
				t.Fatalf("组合不符: got=(%v,%v,%v) want=(%v,%v,%v)",
					p.Dialect(), p.Interpreter(), p.LoginMode(), tc.wantDial, tc.wantInter, tc.wantLogin)
			}
		})
	}

	invalidCases := []struct {
		dialect algebraic.Option[execution.LaunchDialect]
		interp  execution.Interpreter
		login   execution.LoginMode
	}{
		{someD(execution.DialectPOSIX), execution.InterpreterSH, execution.LoginModeLogin},
		{someD(execution.DialectRaw), execution.InterpreterPwsh, execution.LoginModeUnset},
		{noneD, execution.InterpreterServer, execution.LoginModeDisabled},
		{someD(execution.DialectCmd), execution.InterpreterBash, execution.LoginModeUnset},
	}
	for _, bad := range invalidCases {
		if _, err := clikit.BuildLaunchProfile(bad.dialect, bad.interp, bad.login); !errors.Is(err, clikit.ErrUsage) {
			t.Fatalf("非法组合 %+v 应返回 ErrUsage，实际=%v", bad, err)
		}
	}
}

func TestParseOctalPermBounds(t *testing.T) {
	defer goleak.VerifyNone(t)

	for _, okPerm := range []string{"0001", "0644", "0755", "0777"} {
		if _, err := clikit.ParseOctalPerm("--perm", okPerm); err != nil {
			t.Fatalf("合法权限 %q 不应失败: %v", okPerm, err)
		}
	}
	for _, badPerm := range []string{"0", "0000", "01000", "04755", "07777", "999", ""} {
		if _, err := clikit.ParseOctalPerm("--perm", badPerm); !errors.Is(err, clikit.ErrUsage) {
			t.Fatalf("越界/非法权限 %q 应返回 ErrUsage，实际=%v", badPerm, err)
		}
	}
}

func TestParseLongFlagNameAndJSONPreservation(t *testing.T) {
	defer goleak.VerifyNone(t)

	if n, v, hasEq, isLong := clikit.ParseLongFlagName("--foo=bar"); !isLong || !hasEq || n != "foo" || v != "bar" {
		t.Fatalf("ParseLongFlagName(--foo=bar) 异常: %q %q %v %v", n, v, hasEq, isLong)
	}
	for _, nonLong := range []string{"foo", "foo=bar", "-f", "-", "--", "--=v"} {
		if _, _, _, isLong := clikit.ParseLongFlagName(nonLong); isLong {
			t.Fatalf("%q 不应被视为长选项", nonLong)
		}
	}
	if !clikit.HasJSONFlag([]string{"--json=false", "--json=true"}) || clikit.HasJSONFlag([]string{"--json", "--json=false"}) {
		t.Fatalf("HasJSONFlag 末次覆盖语义异常")
	}
	if clikit.HasJSONFlag([]string{"--", "--json"}) {
		t.Fatalf("HasJSONFlag 不得扫描 `--` 之后的参数")
	}
	cf, _, err := clikit.ParseGlobalPrefix([]string{"--json", "--policy", "invalid", "ssh", "web"})
	if !errors.Is(err, clikit.ErrUsage) || !cf.JSON {
		t.Fatalf("全局前缀报错时必须保留已解析的 --json 标志: cf=%+v err=%v", cf, err)
	}
}
