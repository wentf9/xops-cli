package playbook

import (
	"bytes"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
)

func mustPlaybookID(t *testing.T, raw string) PlaybookID {
	t.Helper()
	id, err := ParsePlaybookID(raw)
	if err != nil {
		t.Fatalf("ParsePlaybookID(%q) 意外失败: %v", raw, err)
	}
	return id
}

func mustStepID(t *testing.T, raw string) StepID {
	t.Helper()
	id, err := ParseStepID(raw)
	if err != nil {
		t.Fatalf("ParseStepID(%q) 意外失败: %v", raw, err)
	}
	return id
}

func mustNodeID(t *testing.T, raw string) inventory.NodeID {
	t.Helper()
	id, err := inventory.ParseNodeID(raw)
	if err != nil {
		t.Fatalf("ParseNodeID(%q) 意外失败: %v", raw, err)
	}
	return id
}

func mustTag(t *testing.T, raw string) inventory.Tag {
	t.Helper()
	tag, err := inventory.ParseTag(raw)
	if err != nil {
		t.Fatalf("ParseTag(%q) 意外失败: %v", raw, err)
	}
	return tag
}

func mustLocalSource(t *testing.T, raw string) pathalg.LocalSourcePath {
	t.Helper()
	p, err := pathalg.ParseLocalSourcePath(raw)
	if err != nil {
		t.Fatalf("ParseLocalSourcePath(%q) 意外失败: %v", raw, err)
	}
	return p
}

func mustRemotePath(t *testing.T, raw string) pathalg.RemotePath {
	t.Helper()
	p, err := pathalg.ParseRemotePath(raw)
	if err != nil {
		t.Fatalf("ParseRemotePath(%q) 意外失败: %v", raw, err)
	}
	return p
}

func mustDuration(d time.Duration) algebraic.Duration {
	return algebraic.FromStdDuration(d)
}

func mustFullPlaybook(t *testing.T) Playbook {
	t.Helper()
	prof, err := execution.POSIXLaunchProfile(execution.InterpreterSH, execution.LoginModeDisabled)
	if err != nil {
		t.Fatalf("POSIXLaunchProfile 失败: %v", err)
	}
	mode644, err := ParseFileMode("0644")
	if err != nil {
		t.Fatalf("ParseFileMode 失败: %v", err)
	}
	sh, err := NewStepShell(StepShellSpec{
		Command: "uname -a",
		Profile: algebraic.Some(prof),
		WorkDir: algebraic.Some(mustRemotePath(t, "/opt/app")),
		Env:     map[string]string{"APP_ENV": "prod", "A_FLAG": "1"},
		Timeout: algebraic.Some(mustDuration(15 * time.Second)),
	})
	if err != nil {
		t.Fatalf("NewStepShell 失败: %v", err)
	}
	sc, err := NewStepScript(StepScriptSpec{
		Source:        mustLocalSource(t, "scripts/deploy.sh"),
		SymlinkPolicy: pathalg.SymlinkReject,
		Args:          []string{"--check", "v2"},
		Profile:       algebraic.Some(prof),
		Env:           map[string]string{"MODE": "fast"},
	})
	if err != nil {
		t.Fatalf("NewStepScript 失败: %v", err)
	}
	cp, err := NewStepCopy(StepCopySpec{
		Source:        mustLocalSource(t, "files/app.conf"),
		SymlinkPolicy: pathalg.SymlinkFollowOperatorSource,
		Dest:          mustRemotePath(t, "/etc/app/app.conf"),
		Mode:          algebraic.Some(mode644),
		Overwrite:     true,
		Atomic:        true,
	})
	if err != nil {
		t.Fatalf("NewStepCopy 失败: %v", err)
	}
	tpl, err := NewStepTemplate(StepTemplateSpec{
		Source:        mustLocalSource(t, "templates/nginx.tmpl"),
		SymlinkPolicy: pathalg.SymlinkReject,
		Dest:          mustRemotePath(t, "/etc/nginx/site.conf"),
		Vars:          map[string]string{"app.port": "8080", "app-name": "web"},
		Mode:          algebraic.Some(mode644),
		Overwrite:     true,
		Atomic:        true,
	})
	if err != nil {
		t.Fatalf("NewStepTemplate 失败: %v", err)
	}
	ens, err := NewStepEnsure(StepEnsureSpec{
		Check:      sh,
		Action:     cp,
		MaxRetries: 3,
	})
	if err != nil {
		t.Fatalf("NewStepEnsure 失败: %v", err)
	}
	s1, err := NewStep(StepSpec{ID: mustStepID(t, "s1-shell"), Name: "探针命令", Action: sh})
	if err != nil {
		t.Fatalf("NewStep s1 失败: %v", err)
	}
	s2, err := NewStep(StepSpec{ID: mustStepID(t, "s2-script"), Name: "脚本部署", Action: sc, OnError: algebraic.Some(OnErrorContinue), WhenTags: []inventory.Tag{mustTag(t, "web")}})
	if err != nil {
		t.Fatalf("NewStep s2 失败: %v", err)
	}
	s3, err := NewStep(StepSpec{ID: mustStepID(t, "s3-copy"), Action: cp})
	if err != nil {
		t.Fatalf("NewStep s3 失败: %v", err)
	}
	s4, err := NewStep(StepSpec{ID: mustStepID(t, "s4-tpl"), Action: tpl})
	if err != nil {
		t.Fatalf("NewStep s4 失败: %v", err)
	}
	s5, err := NewStep(StepSpec{ID: mustStepID(t, "s5-ensure"), Name: "幂等配置", Action: ens})
	if err != nil {
		t.Fatalf("NewStep s5 失败: %v", err)
	}
	steps, err := algebraic.NonEmptyFromSlice([]Step{s1, s2, s3, s4, s5})
	if err != nil {
		t.Fatalf("NonEmptyFromSlice 失败: %v", err)
	}
	target, err := NewTargetSelector(TargetSelectorSpec{
		Tags:         []inventory.Tag{mustTag(t, "prod"), mustTag(t, "web")},
		ExcludeNodes: []inventory.NodeID{mustNodeID(t, "canary-1")},
	})
	if err != nil {
		t.Fatalf("NewTargetSelector 失败: %v", err)
	}
	pb, err := NewPlaybook(PlaybookSpec{
		Version:     VersionV2,
		ID:          mustPlaybookID(t, "deploy-v2"),
		Name:        "生产发布 v2",
		Description: "纯函数 AST 快照测试",
		OnError:     OnErrorFailFast,
		Target:      target,
		Vars:        map[string]string{"release.ver": "2.3.3", "env": "prod"},
		Steps:       steps,
	})
	if err != nil {
		t.Fatalf("NewPlaybook 失败: %v", err)
	}
	return pb
}

func TestFileModeValidation(t *testing.T) {
	var zeroMode FileMode
	if zeroMode.IsValid() || !zeroMode.IsZero() || zeroMode.String() != "" {
		t.Fatalf("零值 FileMode 必须失败关闭")
	}
	if _, err := zeroMode.MarshalText(); !errors.Is(err, ErrInvalidFileMode) {
		t.Fatalf("零值 FileMode.MarshalText 期望 ErrInvalidFileMode，实际 %v", err)
	}
	m0, err := NewFileMode(0)
	if err != nil || !m0.IsValid() || m0.String() != "0000" {
		t.Fatalf("0000 权限应合法: m0=%v err=%v", m0, err)
	}
	mMax, err := ParseFileMode("7777")
	if err != nil || mMax.Bits() != 0o7777 || mMax.String() != "7777" {
		t.Fatalf("7777 权限应合法: %v %v", mMax, err)
	}
	for _, bad := range []string{"", "64", "00644", "0888", "064\u202e4", "abc"} {
		if _, err := ParseFileMode(bad); !errors.Is(err, ErrInvalidFileMode) {
			t.Fatalf("ParseFileMode(%q) 应失败关闭: %v", bad, err)
		}
	}
	if _, err := NewFileMode(0o10000); !errors.Is(err, ErrInvalidFileMode) {
		t.Fatalf("超出 07777 的 FileMode 应拒绝: %v", err)
	}
}

func TestTargetSelectorMatchingAndConflicts(t *testing.T) {
	var zeroSel TargetSelector
	if zeroSel.IsValid() || !zeroSel.IsZero() || zeroSel.Matches(mustNodeID(t, "n1"), nil) {
		t.Fatalf("零值 TargetSelector 必须失败关闭")
	}
	n1, n2, n3 := mustNodeID(t, "node-b"), mustNodeID(t, "node-a"), mustNodeID(t, "node-c")
	tWeb, tDB, tCanary := mustTag(t, "web"), mustTag(t, "db"), mustTag(t, "canary")
	sel, err := NewTargetSelector(TargetSelectorSpec{
		Nodes:        []inventory.NodeID{n1, n2, n1},
		Tags:         []inventory.Tag{tWeb, tWeb},
		ExcludeNodes: []inventory.NodeID{n3},
		ExcludeTags:  []inventory.Tag{tCanary},
	})
	if err != nil {
		t.Fatalf("NewTargetSelector 失败: %v", err)
	}
	if len(sel.Nodes()) != 2 || !sel.Nodes()[0].Equal(n2) {
		t.Fatalf("节点列表未排序去重: %v", sel.Nodes())
	}
	if !sel.Matches(n1, nil) || !sel.Matches(mustNodeID(t, "other"), []inventory.Tag{tWeb}) {
		t.Fatalf("应命中节点或正向标签")
	}
	if sel.Matches(n1, []inventory.Tag{tCanary}) || sel.Matches(n3, []inventory.Tag{tWeb}) || sel.Matches(mustNodeID(t, "other"), []inventory.Tag{tDB}) {
		t.Fatalf("排除规则必须严格优先于包含规则")
	}
	for _, badSpec := range []TargetSelectorSpec{
		{},
		{Nodes: []inventory.NodeID{n1}, ExcludeNodes: []inventory.NodeID{n1}},
		{Tags: []inventory.Tag{tWeb}, ExcludeTags: []inventory.Tag{tWeb}},
	} {
		if _, err := NewTargetSelector(badSpec); !errors.Is(err, ErrInvalidTargetSelector) {
			t.Fatalf("非法选择器应拒绝: %+v err=%v", badSpec, err)
		}
	}
}

func TestStepEnsureAntiNesting(t *testing.T) {
	sh, _ := NewStepShell(StepShellSpec{Command: "echo ok"})
	cp, _ := NewStepCopy(StepCopySpec{Source: mustLocalSource(t, "a.txt"), SymlinkPolicy: pathalg.SymlinkReject, Dest: mustRemotePath(t, "/tmp/a.txt")})
	tpl, _ := NewStepTemplate(StepTemplateSpec{Source: mustLocalSource(t, "a.tmpl"), SymlinkPolicy: pathalg.SymlinkReject, Dest: mustRemotePath(t, "/tmp/b.txt")})
	ens, err := NewStepEnsure(StepEnsureSpec{Check: sh, Action: cp, MaxRetries: 2})
	if err != nil {
		t.Fatalf("NewStepEnsure 失败: %v", err)
	}
	if _, err := NewStepEnsure(StepEnsureSpec{Check: sh, Action: ens}); !errors.Is(err, ErrNestedEnsureForbidden) {
		t.Fatalf("Action 嵌套 StepEnsure 必须返回 ErrNestedEnsureForbidden，实际 %v", err)
	}
	if _, err := NewStepEnsure(StepEnsureSpec{Check: ens, Action: cp}); !errors.Is(err, ErrNestedEnsureForbidden) {
		t.Fatalf("Check 嵌套 StepEnsure 必须返回 ErrNestedEnsureForbidden，实际 %v", err)
	}
	if _, err := NewStepEnsure(StepEnsureSpec{Check: cp, Action: sh}); !errors.Is(err, ErrInvalidEnsureCheck) {
		t.Fatalf("Check 使用 StepCopy 必须返回 ErrInvalidEnsureCheck，实际 %v", err)
	}
	if _, err := NewStepEnsure(StepEnsureSpec{Check: tpl, Action: sh}); !errors.Is(err, ErrInvalidEnsureCheck) {
		t.Fatalf("Check 使用 StepTemplate 必须返回 ErrInvalidEnsureCheck，实际 %v", err)
	}
	if _, err := NewStepEnsure(StepEnsureSpec{Check: sh, Action: cp, MaxRetries: MaxEnsureRetries + 1}); !errors.Is(err, ErrInvalidStepAction) {
		t.Fatalf("MaxRetries 超限必须拒绝: %v", err)
	}
}

func TestStepActionValidationAndTypedNilSafety(t *testing.T) {
	srvProf := execution.DefaultServerLaunchProfile()
	if _, err := NewStepScript(StepScriptSpec{Source: mustLocalSource(t, "run.sh"), SymlinkPolicy: pathalg.SymlinkReject, Profile: algebraic.Some(srvProf)}); !errors.Is(err, ErrInvalidStepAction) {
		t.Fatalf("StepScript 使用 InterpreterServer 必须拒绝: %v", err)
	}
	if _, err := NewStepShell(StepShellSpec{Command: "ls \u202e/tmp"}); !errors.Is(err, ErrInvalidStepAction) {
		t.Fatalf("含 Bidi 字符的命令必须拒绝: %v", err)
	}
	if _, err := NewStepShell(StepShellSpec{Command: "ls", Env: map[string]string{"1BAD": "x"}}); !errors.Is(err, ErrInvalidStepAction) {
		t.Fatalf("非法环境变量键必须拒绝: %v", err)
	}
	var (
		nilSh *StepShell
		nilSc *StepScript
		nilCp *StepCopy
		nilTp *StepTemplate
		nilEn *StepEnsure
	)
	if nilSh.IsValid() || nilSh.Command() != "" || nilSh.Kind() != StepActionKindInvalid {
		t.Fatalf("typed-nil *StepShell 应安全返回零值")
	}
	if nilSc.IsValid() || nilSc.Args() != nil || nilCp.IsValid() || nilCp.Overwrite() || nilTp.IsValid() || nilTp.Vars() != nil {
		t.Fatalf("typed-nil Script/Copy/Template 应安全返回零值")
	}
	if nilEn.IsValid() || nilEn.Check() != nil || nilEn.Action() != nil || nilEn.MaxRetries() != 0 {
		t.Fatalf("typed-nil *StepEnsure 应安全返回零值")
	}
}

func TestStepExplicitProfileDelegatesCommandPlanInvariants(t *testing.T) {
	// 1. server + DialectUnknown/Raw 携带 WorkDir/Env 必须经 execution.NewCommandPlan 拒绝
	srvProf := execution.DefaultServerLaunchProfile()
	if _, err := NewStepShell(StepShellSpec{Command: "id", Profile: algebraic.Some(srvProf), WorkDir: algebraic.Some(mustRemotePath(t, "/tmp"))}); !errors.Is(err, ErrInvalidStepAction) {
		t.Fatalf("server+unknown 方言携带 WorkDir 必须拒绝: %v", err)
	}
	// 2. cmd 方言含 %VAR% 展开符的 Env 必须拒绝
	cmdProf, err := execution.NewLaunchProfile(execution.LaunchProfileSpec{
		Dialect: algebraic.Some(execution.DialectCmd), Interpreter: execution.InterpreterCmd, Login: execution.LoginModeInherit,
	})
	if err != nil {
		t.Fatalf("构造 cmd LaunchProfile 失败: %v", err)
	}
	if _, err := NewStepShell(StepShellSpec{Command: "echo hi", Profile: algebraic.Some(cmdProf), Env: map[string]string{"A": "%PATH%"}}); !errors.Is(err, ErrInvalidStepAction) {
		t.Fatalf("cmd 方言 Env 含 %%VAR%% 必须拒绝: %v", err)
	}
	// 3. PowerShell 方言弯单引号与超长 -EncodedCommand 必须拒绝
	psProf, err := execution.NewLaunchProfile(execution.LaunchProfileSpec{
		Dialect: algebraic.Some(execution.DialectPowerShell), Interpreter: execution.InterpreterPwsh, Login: execution.LoginModeDisabled,
	})
	if err != nil {
		t.Fatalf("构造 PowerShell LaunchProfile 失败: %v", err)
	}
	if _, err := NewStepShell(StepShellSpec{Command: "Get-Date", Profile: algebraic.Some(psProf), Env: map[string]string{"K": "bad\u2019quote"}}); !errors.Is(err, ErrInvalidStepAction) {
		t.Fatalf("PowerShell Env 含弯单引号必须拒绝: %v", err)
	}
	if _, err := NewStepShell(StepShellSpec{Command: strings.Repeat("a", 20000), Profile: algebraic.Some(psProf)}); !errors.Is(err, ErrInvalidStepAction) {
		t.Fatalf("超出 Windows 命令行上限的 PowerShell 命令必须拒绝: %v", err)
	}
	if _, err := NewStepScript(StepScriptSpec{Source: mustLocalSource(t, "run.ps1"), SymlinkPolicy: pathalg.SymlinkReject, Profile: algebraic.Some(psProf), Args: []string{"arg\u2018quote"}}); !errors.Is(err, ErrInvalidStepAction) {
		t.Fatalf("PowerShell Script 参数含弯单引号必须拒绝: %v", err)
	}
}

func TestPlaybookVersionAndStepLookup(t *testing.T) {
	pb := mustFullPlaybook(t)
	if !pb.IsValid() || pb.Version() != VersionV2 || !pb.Digest().IsValid() {
		t.Fatalf("有效 Playbook 元数据非法")
	}
	if v, ok := pb.VarValue("release.ver"); !ok || v != "2.3.3" {
		t.Fatalf("VarValue 查找失败: %q %v", v, ok)
	}
	if _, ok := pb.VarValue("missing"); ok {
		t.Fatalf("不存在的变量应返回 false")
	}
	s2, idx, ok := pb.StepByID(mustStepID(t, "s2-script"))
	if !ok || idx != 1 || pb.EffectiveOnError(s2) != OnErrorContinue {
		t.Fatalf("StepByID 或 EffectiveOnError 错误: idx=%d ok=%v eff=%v", idx, ok, pb.EffectiveOnError(s2))
	}
	for _, badVer := range []uint32{0, 1, 3} {
		if _, err := NewPlaybook(PlaybookSpec{
			Version: badVer, ID: pb.ID(), Name: pb.Name(), OnError: OnErrorFailFast, Target: pb.Target(), Steps: pb.Steps(),
		}); !errors.Is(err, ErrUnsupportedVersion) {
			t.Fatalf("version=%d 必须返回 ErrUnsupportedVersion，实际 %v", badVer, err)
		}
	}
	dupSteps, _ := algebraic.NonEmptyFromSlice([]Step{pb.StepSlice()[0], pb.StepSlice()[0]})
	if _, err := NewPlaybook(PlaybookSpec{
		Version: VersionV2, ID: pb.ID(), Name: pb.Name(), OnError: OnErrorFailFast, Target: pb.Target(), Steps: dupSteps,
	}); !errors.Is(err, ErrDuplicateStepID) {
		t.Fatalf("重复 StepID 必须返回 ErrDuplicateStepID，实际 %v", err)
	}
}

func TestPlaybookCanonicalJSONAndStrictReject(t *testing.T) {
	pb := mustFullPlaybook(t)
	raw1, err := pb.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON 失败: %v", err)
	}
	raw2, err := pb.CanonicalJSON()
	if err != nil || !bytes.Equal(raw1, raw2) {
		t.Fatalf("CanonicalJSON 必须字节级确定")
	}
	var decoded Playbook
	if err := jsonv2.Unmarshal(raw1, &decoded); err != nil || !pb.Equal(decoded) || !pb.Digest().Equal(decoded.Digest()) {
		t.Fatalf("Playbook JSON 往返不等: %v", err)
	}
	tampered := strings.Replace(string(raw1), pb.Digest().String(), "sha256:"+strings.Repeat("0", 64), 1)
	var badPB Playbook
	if err := jsonv2.Unmarshal([]byte(tampered), &badPB); !errors.Is(err, ErrTamperedDigest) {
		t.Fatalf("篡改 digest 必须返回 ErrTamperedDigest，实际 %v", err)
	}
	badPlaybooks := []string{
		`null`,
		`{}`,
		`{"version":1,"id":"p","name":"n","on_error":"fail_fast","target":{"all":true},"steps":[{"id":"s","action":{"kind":"shell","command":"ls"}}]}`,
		`{"version":2,"id":"p","name":"n","on_error":"fail_fast","target":{"all":true},"extra_field":1,"steps":[{"id":"s","action":{"kind":"shell","command":"ls"}}]}`,
		`{"version":2,"id":"p","name":"n","on_error":"fail_fast","target":{"all":true},"steps":[{"id":"s","action":{"kind":"shell","command":"ls","dest":"/tmp/x"}}]}`,
		`{"version":2,"id":"p","name":"n","on_error":"fail_fast","target":{"all":true},"steps":[{"id":"s","action":{"kind":"shell","command":"ls","overwrite":false}}]}`,
		`{"version":2,"id":"p","name":"n","on_error":"fail_fast","target":{"all":true},"steps":[{"id":"s","action":{"kind":"shell","command":"ls","vars":{}}}]}`,
		`{"version":2,"id":"p","name":"n","on_error":"fail_fast","target":{"all":true},"steps":[{"id":"s","action":{"kind":"copy","source":"a","dest":"/tmp/a","args":[]}}]}`,
		`{"version":2,"id":"p","name":"n","on_error":"fail_fast","target":{"all":true},"steps":[{"id":"s","action":{"kind":"ensure","check":null,"action":{"kind":"shell","command":"ls"}}}]}`,
		`{"version":2,"id":"p","name":"n","on_error":"fail_fast","target":{"all":true},"steps":[{"id":"s","action":{"kind":"ensure","check":{"kind":"shell","command":"ls"},"action":{"kind":"ensure","check":{"kind":"shell","command":"ls"},"action":{"kind":"shell","command":"ls"}}}}]}`,
	}
	for i, js := range badPlaybooks {
		var dst Playbook
		if err := jsonv2.Unmarshal([]byte(js), &dst); err == nil || dst.IsValid() {
			t.Fatalf("badPlaybooks[%d] 应反序列化失败且保持零值: %s", i, js)
		}
	}
	var zeroPB Playbook
	if _, err := jsonv2.Marshal(zeroPB); err == nil {
		t.Fatalf("零值 Playbook 编码必须失败")
	}
	var buf bytes.Buffer
	if err := MarshalStepActionTo(jsontext.NewEncoder(&buf), pb.StepSlice()[4].Action()); err != nil {
		t.Fatalf("MarshalStepActionTo 失败: %v", err)
	}
	gotAction, err := UnmarshalStepActionFrom(jsontext.NewDecoder(bytes.NewReader(buf.Bytes())))
	if err != nil || !EqualStepAction(gotAction, pb.StepSlice()[4].Action()) {
		t.Fatalf("UnmarshalStepActionFrom 往返失败: err=%v", err)
	}
}

func mustTestStepRec(t *testing.T, n inventory.NodeID, s StepID, st StepStatus, out algebraic.Option[execution.ExecutionOutcome], ms int64) StepExecutionRecord {
	t.Helper()
	r, err := NewStepExecutionRecord(StepExecutionRecordSpec{NodeID: n, StepID: s, Status: st, Outcome: out, Duration: mustDuration(time.Duration(ms) * time.Millisecond)})
	if err != nil {
		t.Fatalf("NewStepExecutionRecord 失败: %v", err)
	}
	return r
}

func TestStepExecutionRecordOutcomeConsistency(t *testing.T) {
	nA, s1 := mustNodeID(t, "node-a"), mustStepID(t, "s1-shell")
	outFail, _ := execution.NewOutcomeCompleted(execution.NewExitCode(2), false)
	outNotStarted, _ := execution.NewOutcomeNotStarted(execution.StartPhaseDial, "E_DIAL", "conn refused")
	outUnknown, _ := execution.NewOutcomeUnknown(execution.ExecPhaseTransportLost, "E_LOST", "eof mid-exec")

	for _, badStatus := range []StepStatus{StepStatusSucceeded, StepStatusChanged, StepStatusSkipped, StepStatusFailed, StepStatusAborted} {
		if _, err := NewStepExecutionRecord(StepExecutionRecordSpec{
			NodeID: nA, StepID: s1, Status: badStatus, Outcome: algebraic.Some[execution.ExecutionOutcome](outUnknown), Duration: mustDuration(time.Second),
		}); !errors.Is(err, ErrOutcomeStatusMismatch) {
			t.Fatalf("OutcomeUnknown 搭配 %s 必须返回 ErrOutcomeStatusMismatch，实际 %v", badStatus, err)
		}
	}
	for _, out := range []execution.ExecutionOutcome{outNotStarted, outFail} {
		if _, err := NewStepExecutionRecord(StepExecutionRecordSpec{
			NodeID: nA, StepID: s1, Status: StepStatusSucceeded, Outcome: algebraic.Some(out),
		}); !errors.Is(err, ErrOutcomeStatusMismatch) {
			t.Fatalf("非成功 Outcome 搭配 Succeeded 必须拒绝: %v", err)
		}
	}
	// 确定失败的 OutcomeCompleted 不得伪装为 StepStatusOutcomeUnknown
	if _, err := NewStepExecutionRecord(StepExecutionRecordSpec{
		NodeID: nA, StepID: s1, Status: StepStatusOutcomeUnknown, Outcome: algebraic.Some[execution.ExecutionOutcome](outFail),
	}); !errors.Is(err, ErrOutcomeStatusMismatch) {
		t.Fatalf("非零退出码 OutcomeCompleted 搭配 outcome_unknown 必须拒绝: %v", err)
	}
	// CJK（3 字节）与 Emoji（4 字节）超长消息截断必须保持合法 UTF-8 且可通过 json/v2 CanonicalJSON 编码
	pb := mustFullPlaybook(t)
	for _, longMsg := range []string{strings.Repeat("中", 500), "x" + strings.Repeat("🚀", 300)} {
		rec, err := NewStepExecutionRecord(StepExecutionRecordSpec{
			NodeID: nA, StepID: s1, Status: StepStatusFailed, Outcome: algebraic.Some[execution.ExecutionOutcome](outFail), Message: longMsg,
		})
		if err != nil || !utf8.ValidString(rec.Message()) || len(rec.Message()) > maxMessageBytes {
			t.Fatalf("UTF-8 截断不变量违背: err=%v len=%d valid=%v", err, len(rec.Message()), utf8.ValidString(rec.Message()))
		}
		rep, err := FoldPlaybookReport(pb, []StepExecutionRecord{rec})
		if err != nil {
			t.Fatalf("FoldPlaybookReport 失败: %v", err)
		}
		if _, err := rep.CanonicalJSON(); err != nil {
			t.Fatalf("含截断多字节消息的 PlaybookReport.CanonicalJSON 编码失败: %v", err)
		}
	}
}

func TestFoldPlaybookReportOrderIndependence(t *testing.T) {
	pb := mustFullPlaybook(t)
	s1, s2, s3 := mustStepID(t, "s1-shell"), mustStepID(t, "s2-script"), mustStepID(t, "s3-copy")
	nA, nB, nC := mustNodeID(t, "node-a"), mustNodeID(t, "node-b"), mustNodeID(t, "node-c")
	outOK, _ := execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	outFail, _ := execution.NewOutcomeCompleted(execution.NewExitCode(2), false)
	outUnknown, _ := execution.NewOutcomeUnknown(execution.ExecPhaseTransportLost, "E_LOST", "eof mid-exec")

	rA1 := mustTestStepRec(t, nA, s1, StepStatusSucceeded, algebraic.Some[execution.ExecutionOutcome](outOK), 100)
	rA2 := mustTestStepRec(t, nA, s2, StepStatusChanged, algebraic.Some[execution.ExecutionOutcome](outOK), 200)
	rA3 := mustTestStepRec(t, nA, s3, StepStatusSkipped, algebraic.None[execution.ExecutionOutcome](), 0)
	rB1 := mustTestStepRec(t, nB, s1, StepStatusFailed, algebraic.Some[execution.ExecutionOutcome](outFail), 50)
	rB2 := mustTestStepRec(t, nB, s2, StepStatusAborted, algebraic.None[execution.ExecutionOutcome](), 0)
	rC1 := mustTestStepRec(t, nC, s1, StepStatusOutcomeUnknown, algebraic.Some[execution.ExecutionOutcome](outUnknown), 300)

	rep1, err1 := FoldPlaybookReport(pb, []StepExecutionRecord{rA1, rA2, rA3, rB1, rB2, rC1})
	rep2, err2 := FoldPlaybookReport(pb, []StepExecutionRecord{rC1, rB2, rA3, rA1, rB1, rA2})
	rep3, err3 := FoldPlaybookReport(pb, []StepExecutionRecord{rB1, rA2, rC1, rA3, rB2, rA1})
	if err1 != nil || err2 != nil || err3 != nil || !rep1.Equal(rep2) || !rep1.Equal(rep3) {
		t.Fatalf("不同输入排列的 FoldPlaybookReport 结果必须一致: %v %v %v", err1, err2, err3)
	}
	j1, err := rep1.CanonicalJSON()
	j2, err2 := rep2.CanonicalJSON()
	if err != nil || err2 != nil || !bytes.Equal(j1, j2) {
		t.Fatalf("不同输入排列的 CanonicalJSON 必须字节级相等")
	}
	if rep1.Status() != NodeStatusOutcomeUnknown || !rep1.HasUnknownOutcome() {
		t.Fatalf("含 OutcomeUnknown 的报表总状态必须为 outcome_unknown，实际 %s", rep1.Status())
	}
	nodes := rep1.Nodes()
	if len(nodes) != 3 || !nodes[0].NodeID().Equal(nA) || !nodes[1].NodeID().Equal(nB) || !nodes[2].NodeID().Equal(nC) {
		t.Fatalf("节点未按 NodeID 升序排列: %v", nodes)
	}
	if nodes[0].Status() != NodeStatusChanged || nodes[1].Status() != NodeStatusFailed || nodes[2].Status() != NodeStatusOutcomeUnknown {
		t.Fatalf("节点折叠状态异常: %v %v %v", nodes[0].Status(), nodes[1].Status(), nodes[2].Status())
	}
	aSteps := nodes[0].Steps()
	if !aSteps[0].StepID().Equal(s1) || !aSteps[1].StepID().Equal(s2) || !aSteps[2].StepID().Equal(s3) {
		t.Fatalf("节点内步骤未按 Playbook 声明顺序排列")
	}
}

func TestJoinNodeStatusLatticeLawsAndInvalidFolds(t *testing.T) {
	allStatuses := []NodeStatus{NodeStatusSucceeded, NodeStatusChanged, NodeStatusAborted, NodeStatusFailed, NodeStatusOutcomeUnknown}
	for _, a := range allStatuses {
		if JoinNodeStatus(a, a) != a || JoinNodeStatus(NodeStatusInvalid, a) != NodeStatusInvalid {
			t.Fatalf("JoinNodeStatus 幂等律或零值失败关闭违背: %v", a)
		}
		for _, b := range allStatuses {
			if JoinNodeStatus(a, b) != JoinNodeStatus(b, a) {
				t.Fatalf("JoinNodeStatus 交换律违背: %v %v", a, b)
			}
			assertNodeStatusAssociative(t, a, b, allStatuses)
		}
	}
	pb := mustFullPlaybook(t)
	rA1 := mustTestStepRec(t, mustNodeID(t, "node-a"), mustStepID(t, "s1-shell"), StepStatusSucceeded, algebraic.None[execution.ExecutionOutcome](), 10)
	unknownRec := mustTestStepRec(t, mustNodeID(t, "node-a"), mustStepID(t, "not-in-pb"), StepStatusSucceeded, algebraic.None[execution.ExecutionOutcome](), 10)
	if _, err := FoldPlaybookReport(pb, nil); !errors.Is(err, ErrEmptyReport) {
		t.Fatalf("空记录应返回 ErrEmptyReport: %v", err)
	}
	if _, err := FoldPlaybookReport(Playbook{}, []StepExecutionRecord{rA1}); !errors.Is(err, ErrInvalidPlaybook) {
		t.Fatalf("无效 Playbook 应返回 ErrInvalidPlaybook: %v", err)
	}
	if _, err := FoldPlaybookReport(pb, []StepExecutionRecord{rA1, rA1}); !errors.Is(err, ErrDuplicateStepRecord) {
		t.Fatalf("重复 (node, step) 应返回 ErrDuplicateStepRecord: %v", err)
	}
	if _, err := FoldPlaybookReport(pb, []StepExecutionRecord{unknownRec}); !errors.Is(err, ErrUnknownStepID) {
		t.Fatalf("未知 StepID 应返回 ErrUnknownStepID: %v", err)
	}
}

func TestStepScriptDelegationAndReportJSONRoundTrip(t *testing.T) {
	psProf, err := execution.NewLaunchProfile(execution.LaunchProfileSpec{
		Dialect: algebraic.Some(execution.DialectPowerShell), Interpreter: execution.InterpreterPwsh, Login: execution.LoginModeDisabled,
	})
	if err != nil {
		t.Fatalf("NewLaunchProfile(pwsh) 失败: %v", err)
	}
	if _, err := NewStepScript(StepScriptSpec{
		Source: mustLocalSource(t, "scripts/deploy.ps1"), SymlinkPolicy: pathalg.SymlinkReject,
		Args: []string{"ok-arg", "v2"}, Profile: algebraic.Some(psProf),
	}); err != nil {
		t.Fatalf("合法 PowerShell 参数化脚本应通过校验: %v", err)
	}
	if _, err := NewStepScript(StepScriptSpec{
		Source: mustLocalSource(t, "scripts/deploy.ps1"), SymlinkPolicy: pathalg.SymlinkReject,
		Args: []string{"bad\u2019quote"}, Profile: algebraic.Some(psProf),
	}); !errors.Is(err, ErrInvalidStepAction) {
		t.Fatalf("含 PowerShell 弯引号的脚本参数期望 ErrInvalidStepAction，实际=%v", err)
	}

	pb := mustFullPlaybook(t)
	s1, s2 := mustStepID(t, "s1-shell"), mustStepID(t, "s2-script")
	nA, nB := mustNodeID(t, "node-a"), mustNodeID(t, "node-b")
	outOK, _ := execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	outUnknown, _ := execution.NewOutcomeUnknown(execution.ExecPhaseTransportLost, "E_LOST", "eof")
	rA1 := mustTestStepRec(t, nA, s1, StepStatusSucceeded, algebraic.Some[execution.ExecutionOutcome](outOK), 100)
	rA2 := mustTestStepRec(t, nA, s2, StepStatusChanged, algebraic.Some[execution.ExecutionOutcome](outOK), 200)
	rB1 := mustTestStepRec(t, nB, s1, StepStatusOutcomeUnknown, algebraic.Some[execution.ExecutionOutcome](outUnknown), 300)

	rep, err := FoldPlaybookReport(pb, []StepExecutionRecord{rA1, rA2, rB1})
	if err != nil {
		t.Fatalf("FoldPlaybookReport 失败: %v", err)
	}
	// StepExecutionRecord / NodeReport / PlaybookReport 确定性 JSON 往返
	rawRec, err := jsonv2.Marshal(rB1, jsonv2.Deterministic(true))
	if err != nil {
		t.Fatalf("Marshal StepExecutionRecord 失败: %v", err)
	}
	var rtRec StepExecutionRecord
	if err := jsonv2.Unmarshal(rawRec, &rtRec); err != nil || !rtRec.Equal(rB1) {
		t.Fatalf("StepExecutionRecord JSON 往返失败: err=%v", err)
	}
	rawNR, err := jsonv2.Marshal(rep.Nodes()[0], jsonv2.Deterministic(true))
	if err != nil {
		t.Fatalf("Marshal NodeReport 失败: %v", err)
	}
	var rtNR NodeReport
	if err := jsonv2.Unmarshal(rawNR, &rtNR); err != nil || !rtNR.Equal(rep.Nodes()[0]) {
		t.Fatalf("NodeReport JSON 往返失败: err=%v", err)
	}
	rawRep, err := rep.CanonicalJSON()
	if err != nil {
		t.Fatalf("PlaybookReport.CanonicalJSON 失败: %v", err)
	}
	var rtRep PlaybookReport
	if err := jsonv2.Unmarshal(rawRep, &rtRep); err != nil || !rtRep.Equal(rep) {
		t.Fatalf("PlaybookReport JSON 往返失败: err=%v", err)
	}
	assertReportUnmarshalRejectsTampering(t, string(rawRec), string(rawNR), string(rawRep))
}

func assertReportUnmarshalRejectsTampering(t *testing.T, rawRec, rawNR, rawRep string) {
	t.Helper()
	var rec StepExecutionRecord
	for _, bad := range []string{
		`null`,
		strings.Replace(rawRec, `"outcome_unknown"`, `"succeeded"`, 1),
		strings.TrimSuffix(rawRec, "}") + `,"extra":1}`,
	} {
		if err := jsonv2.Unmarshal([]byte(bad), &rec); err == nil || rec.IsValid() {
			t.Fatalf("恶意 StepExecutionRecord JSON %s 必须拒绝", bad)
		}
	}
	var nr NodeReport
	for _, bad := range []string{
		`null`,
		strings.Replace(rawNR, `"status":"changed"`, `"status":"succeeded"`, 1),
		strings.Replace(rawNR, `"total_duration":"300ms"`, `"total_duration":"100ms"`, 1),
		strings.TrimSuffix(rawNR, "}") + `,"extra":1}`,
	} {
		if err := jsonv2.Unmarshal([]byte(bad), &nr); err == nil || nr.IsValid() {
			t.Fatalf("恶意 NodeReport JSON %s 必须拒绝", bad)
		}
	}
	var pr PlaybookReport
	for _, bad := range []string{
		`null`,
		strings.Replace(rawRep, `"status":"outcome_unknown"`, `"status":"failed"`, 1),
		strings.Replace(rawRep, `"step_counts":{"succeeded":1`, `"step_counts":{"succeeded":9`, 1),
		strings.Replace(rawRep, `"has_unknown_outcome":true}`, `"has_unknown_outcome":false}`, 1),
		strings.TrimSuffix(rawRep, "}") + `,"extra":1}`,
	} {
		if err := jsonv2.Unmarshal([]byte(bad), &pr); err == nil || pr.IsValid() {
			t.Fatalf("恶意 PlaybookReport JSON %s 必须拒绝", bad)
		}
	}
}

func assertNodeStatusAssociative(t *testing.T, a, b NodeStatus, all []NodeStatus) {
	t.Helper()
	for _, c := range all {
		if JoinNodeStatus(JoinNodeStatus(a, b), c) != JoinNodeStatus(a, JoinNodeStatus(b, c)) {
			t.Fatalf("JoinNodeStatus 结合律违背: %v %v %v", a, b, c)
		}
	}
}
