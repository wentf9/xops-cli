package playbook

import (
	"bytes"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"testing"
)

func FuzzPlaybookJSON(f *testing.F) {
	f.Add([]byte(`{"version":2,"id":"p1","name":"demo","on_error":"fail_fast","target":{"all":true},"steps":[{"id":"s1","action":{"kind":"shell","command":"echo hi"}}]}`))
	f.Add([]byte(`{"version":1,"id":"p1","name":"demo","on_error":"fail_fast","target":{"all":true},"steps":[{"id":"s1","action":{"kind":"shell","command":"echo hi"}}]}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"version":2,"id":"p1","name":"demo","on_error":"abort","target":{"all":true},"steps":[{"id":"s1","action":{"kind":"ensure","check":{"kind":"shell","command":"ls"},"action":{"kind":"ensure","check":{"kind":"shell","command":"ls"},"action":{"kind":"shell","command":"ls"}}}}]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		verifyFuzzPlaybook(t, data)
	})
}

func verifyFuzzPlaybook(t *testing.T, data []byte) {
	t.Helper()
	// 1. 直接验证 UnmarshalJSONFrom 失败时必须将接收者重置为零值无效
	var streamed Playbook
	if err := streamed.UnmarshalJSONFrom(jsontext.NewDecoder(bytes.NewReader(data))); err != nil && streamed.IsValid() {
		t.Fatalf("UnmarshalJSONFrom 失败后 Playbook 必须保持零值无效")
	}
	// 2. 验证完整顶层 JSON（无尾随非法 token）解码成功后满足全部不变量且往返相等
	var pb Playbook
	if err := jsonv2.Unmarshal(data, &pb); err != nil {
		return
	}
	if !pb.IsValid() || pb.Version() != VersionV2 || !pb.Digest().IsValid() {
		t.Fatalf("反序列化成功的 Playbook 必须满足全部不变量")
	}
	raw, err := pb.CanonicalJSON()
	if err != nil {
		t.Fatalf("有效 Playbook.CanonicalJSON 失败: %v", err)
	}
	var rt Playbook
	if err := jsonv2.Unmarshal(raw, &rt); err != nil {
		t.Fatalf("CanonicalJSON 往返解码失败: %v", err)
	}
	if !pb.Equal(rt) || !pb.Digest().Equal(rt.Digest()) {
		t.Fatalf("Playbook JSON 往返摘要或内容不一致")
	}
}

func FuzzStepActionJSON(f *testing.F) {
	f.Add([]byte(`{"kind":"shell","command":"id"}`))
	f.Add([]byte(`{"kind":"script","source":"run.sh","symlink_policy":"reject"}`))
	f.Add([]byte(`{"kind":"copy","source":"a.txt","dest":"/tmp/a.txt","mode":"0644","atomic":true}`))
	f.Add([]byte(`{"kind":"template","source":"a.tmpl","dest":"/tmp/b.txt","vars":{"k":"v"}}`))
	f.Add([]byte(`{"kind":"ensure","check":{"kind":"shell","command":"test -f /x"},"action":{"kind":"shell","command":"touch /x"},"max_retries":2}`))
	f.Add([]byte(`null`))

	f.Fuzz(func(t *testing.T, data []byte) {
		verifyFuzzStepAction(t, data)
	})
}

func verifyFuzzStepAction(t *testing.T, data []byte) {
	t.Helper()
	act, err := UnmarshalStepActionFrom(jsontext.NewDecoder(bytes.NewReader(data)))
	if err != nil {
		if act != nil && act.IsValid() {
			t.Fatalf("失败时不应返回有效 StepAction")
		}
		return
	}
	if act == nil || !act.IsValid() {
		t.Fatalf("成功解码的 StepAction 必须有效")
	}
	if ens, ok := act.(*StepEnsure); ok && (ens.Action().Kind() == StepActionKindEnsure || ens.Check().Kind() == StepActionKindEnsure) {
		t.Fatalf("反序列化绝不得产生嵌套 StepEnsure")
	}
	var buf bytes.Buffer
	if err := MarshalStepActionTo(jsontext.NewEncoder(&buf), act); err != nil {
		t.Fatalf("有效 StepAction 编码失败: %v", err)
	}
	rt, err := UnmarshalStepActionFrom(jsontext.NewDecoder(bytes.NewReader(buf.Bytes())))
	if err != nil || !EqualStepAction(act, rt) {
		t.Fatalf("StepAction 往返不一致: err=%v", err)
	}
}

func FuzzTargetSelectorAndFileMode(f *testing.F) {
	f.Add("0644", `{"all":true}`)
	f.Add("755", `{"nodes":["n1"],"exclude_nodes":["n2"]}`)
	f.Add("07777", `{"tags":["prod"],"exclude_tags":["canary"]}`)
	f.Add("0888", `{"nodes":["n1"],"exclude_nodes":["n1"]}`)

	f.Fuzz(func(t *testing.T, modeRaw, selJSON string) {
		verifyFuzzFileMode(t, modeRaw)
		verifyFuzzTargetSelector(t, selJSON)
	})
}

func verifyFuzzFileMode(t *testing.T, modeRaw string) {
	t.Helper()
	m, err := ParseFileMode(modeRaw)
	if err != nil {
		return
	}
	if !m.IsValid() || m.Bits() > maxFileMode {
		t.Fatalf("合法 FileMode 越界: %v", m)
	}
	txt, err := m.MarshalText()
	if err != nil {
		t.Fatalf("有效 FileMode.MarshalText 失败: %v", err)
	}
	var rt FileMode
	if err := rt.UnmarshalText(txt); err != nil || !m.Equal(rt) {
		t.Fatalf("FileMode 往返不一致: %v", err)
	}
}

func verifyFuzzTargetSelector(t *testing.T, selJSON string) {
	t.Helper()
	var sel TargetSelector
	if err := jsonv2.Unmarshal([]byte(selJSON), &sel); err != nil {
		return
	}
	if !sel.IsValid() {
		t.Fatalf("反序列化成功的 TargetSelector 必须有效")
	}
	raw, err := jsonv2.Marshal(sel, jsonv2.Deterministic(true))
	if err != nil {
		t.Fatalf("有效 TargetSelector 编码失败: %v", err)
	}
	var rt TargetSelector
	if err := jsonv2.Unmarshal(raw, &rt); err != nil || !sel.Equal(rt) {
		t.Fatalf("TargetSelector 往返不一致: %v", err)
	}
}
