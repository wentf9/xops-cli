package execution_test

import (
	"bytes"
	"encoding"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
)

// TestExternalInterfaceContracts 在外部包编译期锁定 execution 包所有导出类型的编解码与封闭接口契约。
func TestExternalInterfaceContracts(t *testing.T) {
	var (
		ld execution.LaunchDialect
		in execution.Interpreter
		lm execution.LoginMode
		lp execution.LaunchProfile
		pk execution.PlanKind
		cp execution.CommandPlan
		sp execution.StartPhase
		ep execution.ExecPhase
		ek execution.ExitStatusKind
		ec execution.ExitCode
		es execution.ExitSignal
		eu execution.ExitUnknown
		ok execution.OutcomeKind
		on execution.OutcomeNotStarted
		oc execution.OutcomeCompleted
		ou execution.OutcomeUnknown
	)
	var (
		_ encoding.TextAppender      = ld
		_ encoding.TextMarshaler     = ld
		_ encoding.TextUnmarshaler   = &ld
		_ encoding.TextAppender      = in
		_ encoding.TextMarshaler     = in
		_ encoding.TextUnmarshaler   = &in
		_ encoding.TextAppender      = lm
		_ encoding.TextMarshaler     = lm
		_ encoding.TextUnmarshaler   = &lm
		_ encoding.TextAppender      = pk
		_ encoding.TextMarshaler     = pk
		_ encoding.TextUnmarshaler   = &pk
		_ encoding.TextAppender      = sp
		_ encoding.TextMarshaler     = sp
		_ encoding.TextUnmarshaler   = &sp
		_ encoding.TextAppender      = ep
		_ encoding.TextMarshaler     = ep
		_ encoding.TextUnmarshaler   = &ep
		_ encoding.TextAppender      = ek
		_ encoding.TextMarshaler     = ek
		_ encoding.TextUnmarshaler   = &ek
		_ encoding.TextAppender      = ok
		_ encoding.TextMarshaler     = ok
		_ encoding.TextUnmarshaler   = &ok
		_ jsonv2.MarshalerTo         = lp
		_ jsonv2.UnmarshalerFrom     = &lp
		_ jsonv2.MarshalerTo         = cp
		_ jsonv2.UnmarshalerFrom     = &cp
		_ execution.ExitStatus       = &ec
		_ execution.ExitStatus       = &es
		_ execution.ExitStatus       = &eu
		_ jsonv2.MarshalerTo         = ec
		_ jsonv2.MarshalerTo         = es
		_ jsonv2.MarshalerTo         = eu
		_ execution.ExecutionOutcome = &on
		_ execution.ExecutionOutcome = &oc
		_ execution.ExecutionOutcome = &ou
		_ jsonv2.MarshalerTo         = on
		_ jsonv2.MarshalerTo         = oc
		_ jsonv2.MarshalerTo         = ou
	)
}

// TestExternalExecutionContract 验证外部包经导出构造器与穷尽 switch 消费 execution 全量契约。
func TestExternalExecutionContract(t *testing.T) {
	prof, err := execution.POSIXLaunchProfile(execution.InterpreterSH, execution.LoginModeDisabled)
	if err != nil {
		t.Fatalf("POSIXLaunchProfile 失败: %v", err)
	}
	plan, err := execution.NewCommandPlan(execution.CommandPlanSpec{
		Kind:    execution.PlanKindCommand,
		Profile: prof,
		Command: "uname -a",
	})
	if err != nil {
		t.Fatalf("NewCommandPlan 失败: %v", err)
	}
	digest, err := plan.Digest()
	if err != nil || !digest.IsValid() {
		t.Fatalf("CommandPlan.Digest 失败: err=%v digest=%s", err, digest)
	}

	outcome, err := execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	if err != nil {
		t.Fatalf("NewOutcomeCompleted 失败: %v", err)
	}
	var buf bytes.Buffer
	if err := execution.MarshalOutcomeTo(jsontext.NewEncoder(&buf), outcome); err != nil {
		t.Fatalf("MarshalOutcomeTo 失败: %v", err)
	}
	decoded, err := execution.UnmarshalOutcomeFrom(jsontext.NewDecoder(&buf))
	if err != nil {
		t.Fatalf("UnmarshalOutcomeFrom 失败: %v", err)
	}
	switch v := decoded.(type) {
	case *execution.OutcomeNotStarted:
		t.Fatalf("非预期 NotStarted: %s", v.Reason())
	case *execution.OutcomeCompleted:
		if !v.Succeeded() || v.CanRetry() {
			t.Fatal("Completed(0) 必须成功且不可重试")
		}
	case *execution.OutcomeUnknown:
		t.Fatalf("非预期 Unknown: %s", v.Reason())
	default:
		t.Fatal("未知 ExecutionOutcome 变体")
	}

	// 验证外部包无法将无效 Option[LaunchDialect] 注入 LaunchProfile
	if _, err := execution.NewLaunchProfile(execution.LaunchProfileSpec{
		Dialect:     algebraic.Some(execution.DialectUnknown),
		Interpreter: execution.InterpreterServer,
		Login:       execution.LoginModeInherit,
	}); err == nil {
		t.Fatal("显式 Some(DialectUnknown) 必须被拒绝")
	}
}
