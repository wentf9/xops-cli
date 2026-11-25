package ports

import (
	jsonv2 "encoding/json/v2"
	"testing"
)

func assertOutOfRangeEnum[T interface {
	IsValid() bool
	String() string
	AppendText([]byte) ([]byte, error)
	MarshalText() ([]byte, error)
}](t *testing.T, name string, vals ...T) {
	t.Helper()
	for _, v := range vals {
		if v.IsValid() || v.String() != "invalid" {
			t.Fatalf("%s 越界值须返回 invalid: valid=%v str=%q", name, v.IsValid(), v.String())
		}
		if _, err := v.AppendText(nil); err == nil {
			t.Fatalf("%s 越界值 AppendText 必须失败关闭", name)
		}
		if _, err := v.MarshalText(); err == nil {
			t.Fatalf("%s 越界值 MarshalText 必须失败关闭", name)
		}
		if _, err := jsonv2.Marshal(v); err == nil {
			t.Fatalf("%s 越界值 jsonv2.Marshal 必须失败关闭", name)
		}
	}
}

// TestOutOfRangeEnumsFailClosedWithoutPanic 通过白盒测试构造越界底层枚举值（99/255），
// 验证全部 7 个端口枚举的 String/AppendText/MarshalText/JSON 编码零 panic 且严格失败关闭。
func TestOutOfRangeEnumsFailClosedWithoutPanic(t *testing.T) {
	assertOutOfRangeEnum(t, "LockMode", LockMode(99), LockMode(255))
	assertOutOfRangeEnum(t, "HostTrustStatus", HostTrustStatus(99), HostTrustStatus(255))
	assertOutOfRangeEnum(t, "ForwardDirection", ForwardDirection(99), ForwardDirection(255))
	assertOutOfRangeEnum(t, "MuxControlAction", MuxControlAction(99), MuxControlAction(255))
	assertOutOfRangeEnum(t, "RemoteFileType", RemoteFileType(99), RemoteFileType(255))
	assertOutOfRangeEnum(t, "AuditPhase", AuditPhase(99), AuditPhase(255))
	assertOutOfRangeEnum(t, "AuditOutcome", AuditOutcome(99), AuditOutcome(255))
}
