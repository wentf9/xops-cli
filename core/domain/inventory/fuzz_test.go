package inventory

import (
	"bytes"
	"encoding/json/jsontext"
	"strings"
	"testing"
)

// FuzzAuthMethodJSON 对多态 AuthMethod JSON/v2 解码、嵌套深度与二次往返执行模糊测试。
func FuzzAuthMethodJSON(f *testing.F) {
	f.Add(`{"kind":"password","password_ref":"local/pw1"}`)
	f.Add(`{"kind":"agent"}`)
	f.Add(`{"kind":"private_key","key_paths":["~/.ssh/id_ed25519"]}`)
	f.Add(`{"kind":"keyboard_interactive","rules":[{"kind":"login_password","prompt_pattern":"^Password:"}]}`)
	f.Add(`{"kind":"composite","methods":[{"kind":"agent"},{"kind":"password","password_ref":"local/p"}]}`)
	f.Add(`null`)
	f.Add(`{}`)

	f.Fuzz(func(t *testing.T, data string) {
		m, err := UnmarshalAuthMethodFrom(jsontext.NewDecoder(strings.NewReader(data)))
		if err != nil {
			return
		}
		if m == nil || !m.IsValid() {
			t.Fatal("成功解码的 AuthMethod 必须非 nil 且有效")
		}
		var buf bytes.Buffer
		if err := MarshalAuthMethodTo(jsontext.NewEncoder(&buf), m); err != nil {
			t.Fatalf("重编码 AuthMethod 失败: %v", err)
		}
		m2, err := UnmarshalAuthMethodFrom(jsontext.NewDecoder(&buf))
		if err != nil || !EqualAuthMethod(m, m2) {
			t.Fatalf("AuthMethod 二次往返不一致: err=%v", err)
		}
		var can1, can2 bytes.Buffer
		if err := WriteAuthMethodCanonical(&can1, m); err != nil {
			t.Fatalf("WriteAuthMethodCanonical(m) 失败: %v", err)
		}
		if err := WriteAuthMethodCanonical(&can2, m2); err != nil || !bytes.Equal(can1.Bytes(), can2.Bytes()) {
			t.Fatalf("AuthMethod 规范编码漂移: err=%v", err)
		}
	})
}

// FuzzParseKeyFingerprintAndID 对指纹与节点标识符解析执行模糊测试。
func FuzzParseKeyFingerprintAndID(f *testing.F) {
	f.Add("web-01")
	f.Add("openssh:bastion")
	f.Add("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	f.Add("SHA256:bad=pad")
	f.Add("bad\u202eident")

	f.Fuzz(func(t *testing.T, raw string) {
		if id, err := ParseNodeID(raw); err == nil {
			if !id.IsValid() || strings.ContainsAny(id.String(), "@:/\\") {
				t.Fatalf("ParseNodeID 放行了非法标识: %q", id.String())
			}
		}
		if fp, err := ParseKeyFingerprint(raw); err == nil {
			if !fp.IsValid() {
				t.Fatal("有效 KeyFingerprint 必须 IsValid()==true")
			}
			fp2, err := ParseKeyFingerprint(fp.String())
			if err != nil || !fp.Equal(fp2) {
				t.Fatalf("KeyFingerprint 往返失败: %v", err)
			}
		}
	})
}
