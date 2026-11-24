package plan

import (
	jsonv2 "encoding/json/v2"
	"testing"
)

// FuzzParseDigestsAndHandleID 对摘要与句柄标识解析器执行模糊测试，验证合法输入严格双射往返且无 panic。
func FuzzParseDigestsAndHandleID(f *testing.F) {
	f.Add("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("sha256:UPPERCASE")
	f.Add("handle-01")
	f.Add("bad:colon")
	f.Add("")

	f.Fuzz(func(t *testing.T, raw string) {
		assertDigestAndHandleIDRoundTrip(t, raw)
	})
}

func assertDigestAndHandleIDRoundTrip(t *testing.T, raw string) {
	t.Helper()
	if hd, err := ParseHopDigest(raw); err == nil {
		if hd2, err := ParseHopDigest(hd.String()); err != nil || !hd.Equal(hd2) {
			t.Fatalf("HopDigest 往返失败: %v", err)
		}
	}
	if pd, err := ParsePlanDigest(raw); err == nil {
		if pd2, err := ParsePlanDigest(pd.String()); err != nil || !pd.Equal(pd2) {
			t.Fatalf("PlanDigest 往返失败: %v", err)
		}
	}
	if hi, err := ParseHandleID(raw); err == nil {
		if hi2, err := ParseHandleID(hi.String()); err != nil || !hi.Equal(hi2) {
			t.Fatalf("HandleID 往返失败: %v", err)
		}
	}
}

// FuzzSealedConnectionPlanJSON 对 SealedConnectionPlan JSON 解码与防篡改重算执行模糊测试。
func FuzzSealedConnectionPlanJSON(f *testing.F) {
	f.Add(`null`)
	f.Add(`{}`)
	f.Add(`{"hops":[]}`)
	f.Add(`{"hops":[null]}`)

	f.Fuzz(func(t *testing.T, data string) {
		var p SealedConnectionPlan
		if err := jsonv2.Unmarshal([]byte(data), &p); err != nil {
			if p.IsValid() {
				t.Fatal("解码失败后 SealedConnectionPlan 必须保持零值无效")
			}
			return
		}
		if !p.IsValid() {
			t.Fatal("解码成功但 SealedConnectionPlan 无效")
		}
		raw, err := p.CanonicalJSON()
		if err != nil {
			t.Fatalf("重编码 CanonicalJSON 失败: %v", err)
		}
		var p2 SealedConnectionPlan
		if err := jsonv2.Unmarshal(raw, &p2); err != nil || !p2.Equal(p) {
			t.Fatalf("SealedConnectionPlan 二次往返失败: err=%v", err)
		}
	})
}
