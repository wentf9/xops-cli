package execution

import (
	"bytes"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
)

// FuzzShellQuote 对 POSIX、PowerShell 与 cmd 引用/编码器执行模糊测试，验证无 panic 且控制/NUL 绝不逃逸。
func FuzzShellQuote(f *testing.F) {
	f.Add("")
	f.Add("hello world")
	f.Add("it's a $HOME `test` $(id)")
	f.Add("line1\nline2")
	f.Add("nul\x00byte")
	f.Add("bidi\u202ereverse")
	f.Add("smart\u2019quote")
	f.Add("cmd%PATH%&whoami")

	f.Fuzz(func(t *testing.T, input string) {
		assertShellQuoteInvariants(t, input)
	})
}

func assertShellQuoteInvariants(t *testing.T, input string) {
	t.Helper()
	if q, err := QuotePOSIX(input); err == nil {
		if len(q) < 2 || q[0] != '\'' || q[len(q)-1] != '\'' || strings.IndexByte(q, 0) >= 0 {
			t.Fatalf("QuotePOSIX 输出不变量被破坏: %q", q)
		}
	}
	if q, err := QuotePowerShell(input); err == nil {
		if len(q) < 2 || q[0] != '\'' || q[len(q)-1] != '\'' {
			t.Fatalf("QuotePowerShell 输出未以单引号包裹: %q", q)
		}
	}
	assertCmdQuoteAndPSBase64Invariants(t, input)
}

func assertCmdQuoteAndPSBase64Invariants(t *testing.T, input string) {
	t.Helper()
	if q, err := QuoteCmdArg(input); err == nil {
		if strings.ContainsAny(input, "\"%!^&|<>()\r\n\x00") {
			t.Fatalf("QuoteCmdArg 放行了危险元字符: %q", input)
		}
		if strings.ContainsAny(input, " \t,;=") && (len(q) < 2 || q[0] != '"' || q[len(q)-1] != '"' || strings.HasSuffix(input, `\`)) {
			t.Fatalf("QuoteCmdArg 未正确引号包裹或放行尾部反斜杠: in=%q out=%q", input, q)
		}
	}
	if enc, err := EncodePowerShellUTF16LEBase64(input); err == nil && enc == "" {
		t.Fatal("EncodePowerShellUTF16LEBase64 成功时不得返回空串")
	}
}

// FuzzCommandPlan 对 CommandPlan 构造、渲染、摘要确定性、脱敏与 JSON/v2 往返执行模糊测试。
func FuzzCommandPlan(f *testing.F) {
	f.Add("uname -a", "/tmp", "APP_ENV", "prod", uint8(1), uint8(2), uint8(1))
	f.Add("echo 'hi' && pwd", "/var/log", "TOKEN", "secret123", uint8(1), uint8(3), uint8(2))
	f.Add("Get-Process", "/srv", "KEY", "val", uint8(2), uint8(6), uint8(1))
	f.Add("password=mysecretval echo ok", "", "DB_PASS", "p@ss", uint8(4), uint8(1), uint8(3))

	f.Fuzz(func(t *testing.T, cmd, wdRaw, envKey, envVal string, dRaw, iRaw, lRaw uint8) {
		plan, err := buildFuzzCommandPlan(cmd, wdRaw, envKey, envVal, dRaw, iRaw, lRaw)
		if err != nil {
			return
		}
		assertFuzzCommandPlanInvariants(t, plan)
	})
}

func buildFuzzCommandPlan(cmd, wdRaw, envKey, envVal string, dRaw, iRaw, lRaw uint8) (CommandPlan, error) {
	dialect := LaunchDialect(dRaw % 5)
	dOpt := algebraic.None[LaunchDialect]()
	if dialect != DialectUnknown {
		dOpt = algebraic.Some(dialect)
	}
	prof, err := NewLaunchProfile(LaunchProfileSpec{Dialect: dOpt, Interpreter: Interpreter(iRaw % 8), Login: LoginMode(lRaw % 4)})
	if err != nil {
		return CommandPlan{}, err
	}
	wdOpt := algebraic.None[pathalg.RemotePath]()
	if wdRaw != "" {
		wd, err := pathalg.ParseRemotePath(wdRaw)
		if err != nil {
			return CommandPlan{}, err
		}
		wdOpt = algebraic.Some(wd)
	}
	var envMap map[string]string
	if envKey != "" {
		envMap = map[string]string{envKey: envVal}
	}
	kind := PlanKindCommand
	if dRaw&0x80 != 0 {
		kind = PlanKindScript
	}
	return NewCommandPlan(CommandPlanSpec{
		Kind: kind, Profile: prof, Command: cmd, WorkDir: wdOpt, Env: envMap,
	})
}

func assertFuzzCommandPlanInvariants(t *testing.T, plan CommandPlan) {
	t.Helper()
	if _, err := plan.RenderCommand(); err != nil {
		t.Fatalf("已构造有效 CommandPlan 渲染失败: %v", err)
	}
	_, hasStdin := plan.StdinPayload()
	if hasStdin != (plan.Kind() == PlanKindScript) {
		t.Fatalf("StdinPayload 标志与 PlanKind 不一致: kind=%s hasStdin=%v", plan.Kind(), hasStdin)
	}
	d1, err := plan.Digest()
	if err != nil || !d1.IsValid() {
		t.Fatalf("有效 CommandPlan Digest 失败: %v", err)
	}
	raw, err := plan.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON 失败: %v", err)
	}
	var roundTripped CommandPlan
	if err := jsonv2.Unmarshal(raw, &roundTripped); err != nil || !roundTripped.Equal(plan) {
		t.Fatalf("CommandPlan 往返失败: err=%v", err)
	}
	if d2, err := roundTripped.Digest(); err != nil || !d1.Equal(d2) {
		t.Fatalf("CommandPlan 往返摘要漂移: %s vs %s", d1, d2)
	}
	_ = plan.RedactedSummary()
}

// FuzzExecutionOutcomeJSON 对多态 ExecutionOutcome JSON 解码与 CanRetry 不变量执行模糊测试。
func FuzzExecutionOutcomeJSON(f *testing.F) {
	f.Add(`{"kind":"not_started","start_phase":"dial","code":"e1","reason":"refused"}`)
	f.Add(`{"kind":"completed","exit_status":{"kind":"code","code":0}}`)
	f.Add(`{"kind":"completed","exit_status":{"kind":"signal","signal":"KILL","core_dumped":true}}`)
	f.Add(`{"kind":"completed","exit_status":{"kind":"unknown","reason":"eof"},"truncated":true}`)
	f.Add(`{"kind":"unknown","exec_phase":"timed_out","reason":"deadline"}`)
	f.Add(`null`)
	f.Add(`{}`)

	f.Fuzz(func(t *testing.T, data string) {
		dec, err := UnmarshalOutcomeFrom(jsontext.NewDecoder(strings.NewReader(data)))
		if err != nil {
			return
		}
		if dec == nil || !dec.IsValid() {
			t.Fatal("成功解码的 ExecutionOutcome 必须非 nil 且有效")
		}
		_, isNotStarted := dec.(*OutcomeNotStarted)
		if dec.CanRetry() != isNotStarted || CanRetryOutcome(dec) != isNotStarted {
			t.Fatalf("CanRetry 不变量被破坏: type=%T canRetry=%v", dec, dec.CanRetry())
		}
		var buf bytes.Buffer
		if err := MarshalOutcomeTo(jsontext.NewEncoder(&buf), dec); err != nil {
			t.Fatalf("重编码失败: %v", err)
		}
		dec2, err := UnmarshalOutcomeFrom(jsontext.NewDecoder(&buf))
		if err != nil || !EqualOutcome(dec, dec2) {
			t.Fatalf("ExecutionOutcome 二次往返失败: err=%v", err)
		}
	})
}
