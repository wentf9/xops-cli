package playbook_test

import (
	"encoding"
	jsonv2 "encoding/json/v2"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/playbook"
)

// TestExternalInterfaceContracts 在外部包编译期锁定 playbook 包所有导出类型的编解码与封闭和类型契约。
func TestExternalInterfaceContracts(t *testing.T) {
	var (
		pbID  playbook.PlaybookID
		stID  playbook.StepID
		onErr playbook.OnErrorPolicy
		mode  playbook.FileMode
		kind  playbook.StepActionKind
		stSt  playbook.StepStatus
		ndSt  playbook.NodeStatus
		sel   playbook.TargetSelector
		step  playbook.Step
		pb    playbook.Playbook
		sh    playbook.StepShell
		sc    playbook.StepScript
		cp    playbook.StepCopy
		tpl   playbook.StepTemplate
		ens   playbook.StepEnsure
		rec   playbook.StepExecutionRecord
		nr    playbook.NodeReport
		pr    playbook.PlaybookReport
	)
	var (
		_ encoding.TextAppender    = pbID
		_ encoding.TextMarshaler   = pbID
		_ encoding.TextUnmarshaler = &pbID
		_ encoding.TextAppender    = stID
		_ encoding.TextMarshaler   = stID
		_ encoding.TextUnmarshaler = &stID
		_ encoding.TextAppender    = onErr
		_ encoding.TextMarshaler   = onErr
		_ encoding.TextUnmarshaler = &onErr
		_ encoding.TextAppender    = mode
		_ encoding.TextMarshaler   = mode
		_ encoding.TextUnmarshaler = &mode
		_ encoding.TextAppender    = kind
		_ encoding.TextMarshaler   = kind
		_ encoding.TextUnmarshaler = &kind
		_ encoding.TextAppender    = stSt
		_ encoding.TextMarshaler   = stSt
		_ encoding.TextUnmarshaler = &stSt
		_ encoding.TextAppender    = ndSt
		_ encoding.TextMarshaler   = ndSt
		_ encoding.TextUnmarshaler = &ndSt

		_ jsonv2.MarshalerTo     = sel
		_ jsonv2.UnmarshalerFrom = &sel
		_ jsonv2.MarshalerTo     = step
		_ jsonv2.UnmarshalerFrom = &step
		_ jsonv2.MarshalerTo     = pb
		_ jsonv2.UnmarshalerFrom = &pb
		_ jsonv2.MarshalerTo     = sh
		_ jsonv2.MarshalerTo     = sc
		_ jsonv2.MarshalerTo     = cp
		_ jsonv2.MarshalerTo     = tpl
		_ jsonv2.MarshalerTo     = ens
		_ jsonv2.MarshalerTo     = rec
		_ jsonv2.UnmarshalerFrom = &rec
		_ jsonv2.MarshalerTo     = nr
		_ jsonv2.UnmarshalerFrom = &nr
		_ jsonv2.MarshalerTo     = pr
		_ jsonv2.UnmarshalerFrom = &pr

		_ playbook.StepAction = (*playbook.StepShell)(nil)
		_ playbook.StepAction = (*playbook.StepScript)(nil)
		_ playbook.StepAction = (*playbook.StepCopy)(nil)
		_ playbook.StepAction = (*playbook.StepTemplate)(nil)
		_ playbook.StepAction = (*playbook.StepEnsure)(nil)
	)
}

func classifyAction(a playbook.StepAction) string {
	switch v := a.(type) {
	case *playbook.StepShell:
		return "shell:" + v.Command()
	case *playbook.StepScript:
		return "script:" + v.Source().String()
	case *playbook.StepCopy:
		return "copy:" + v.Dest().String()
	case *playbook.StepTemplate:
		return "template:" + v.Dest().String()
	case *playbook.StepEnsure:
		return "ensure:" + v.Check().Kind().String() + "->" + v.Action().Kind().String()
	default:
		return "invalid"
	}
}

func mustExt[T any](v T, err error) func(*testing.T) T {
	return func(t *testing.T) T {
		t.Helper()
		if err != nil {
			t.Fatalf("构造外部测试夹具失败: %v", err)
		}
		return v
	}
}

func TestExternalPlaybookContractAndExhaustiveSwitch(t *testing.T) {
	pbID := mustExt(playbook.ParsePlaybookID("ext-deploy"))(t)
	stepID := mustExt(playbook.ParseStepID("ensure-conf"))(t)
	check := mustExt(playbook.NewStepShell(playbook.StepShellSpec{Command: "test -f /etc/app.conf"}))(t)
	src := mustExt(pathalg.ParseLocalSourcePath("conf/app.conf"))(t)
	dst := mustExt(pathalg.ParseRemotePath("/etc/app.conf"))(t)
	act := mustExt(playbook.NewStepCopy(playbook.StepCopySpec{Source: src, SymlinkPolicy: pathalg.SymlinkReject, Dest: dst, Atomic: true}))(t)
	ens := mustExt(playbook.NewStepEnsure(playbook.StepEnsureSpec{Check: check, Action: act, MaxRetries: 1}))(t)
	if got := classifyAction(ens); got != "ensure:shell->copy" {
		t.Fatalf("穷尽分类结果异常: %q", got)
	}
	st := mustExt(playbook.NewStep(playbook.StepSpec{ID: stepID, Name: "ensure", Action: ens}))(t)
	sel := mustExt(playbook.NewTargetSelector(playbook.TargetSelectorSpec{All: true}))(t)
	pb := mustExt(playbook.NewPlaybook(playbook.PlaybookSpec{
		Version: playbook.VersionV2, ID: pbID, Name: "Ext Test", OnError: playbook.OnErrorFailFast, Target: sel, Steps: algebraic.NewNonEmpty(st),
	}))(t)
	raw := mustExt(pb.CanonicalJSON())(t)
	var rt playbook.Playbook
	if err := jsonv2.Unmarshal(raw, &rt); err != nil || !pb.Equal(rt) {
		t.Fatalf("外部包 JSON 往返失败: err=%v", err)
	}
	nodeID := mustExt(inventory.ParseNodeID("web-01"))(t)
	rec := mustExt(playbook.NewStepExecutionRecord(playbook.StepExecutionRecordSpec{NodeID: nodeID, StepID: stepID, Status: playbook.StepStatusChanged}))(t)
	rep, err := playbook.FoldPlaybookReport(rt, []playbook.StepExecutionRecord{rec})
	if err != nil || rep.Status() != playbook.NodeStatusChanged {
		t.Fatalf("外部包 FoldPlaybookReport 失败: err=%v status=%v", err, rep.Status())
	}
	rawRep := mustExt(rep.CanonicalJSON())(t)
	var rtRep playbook.PlaybookReport
	if err := jsonv2.Unmarshal(rawRep, &rtRep); err != nil || !rtRep.Equal(rep) {
		t.Fatalf("外部包 PlaybookReport JSON 往返失败: err=%v", err)
	}
}
