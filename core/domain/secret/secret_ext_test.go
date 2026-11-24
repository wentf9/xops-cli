package secret_test

import (
	jsonv2 "encoding/json/v2"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/secret"
)

// TestExternalNonWhitelistSecretBoxContract 验证外部非明文白名单包（例如 core/ports/tck、internal/host/sys）
// 可在零 //nolint: 与零明文消费的前提下，合法调用 WithBytes、Equal、IsValid、IsWiped 与 Len。
func TestExternalNonWhitelistSecretBoxContract(t *testing.T) {
	err := secret.WithBytes([]byte("tck-secret-value"), func(box1 *secret.SecretBox) error {
		if !box1.IsValid() || box1.IsWiped() || box1.Len() != len("tck-secret-value") {
			t.Fatalf("外置包借用 SecretBox 状态异常: valid=%v wiped=%v len=%d", box1.IsValid(), box1.IsWiped(), box1.Len())
		}
		return assertExternalEqualPairs(t, box1)
	})
	if err != nil {
		t.Fatalf("外置包调用 WithBytes 失败: %v", err)
	}

	var zeroBox secret.SecretBox
	if zeroBox.IsValid() || zeroBox.Equal(&zeroBox) {
		t.Fatal("外置包零值 SecretBox 必须失败关闭")
	}
}

func assertExternalEqualPairs(t *testing.T, box1 *secret.SecretBox) error {
	t.Helper()
	if err := secret.WithBytes([]byte("tck-secret-value"), func(box2 *secret.SecretBox) error {
		if !box1.Equal(box2) {
			t.Fatal("外置包调用常量时间 Equal 比对相同机密应返回 true")
		}
		return nil
	}); err != nil {
		return err
	}
	return secret.WithBytes([]byte("tck-secret-other"), func(box3 *secret.SecretBox) error {
		if box1.Equal(box3) {
			t.Fatal("外置包调用常量时间 Equal 比对不同机密应返回 false")
		}
		return nil
	})
}

// TestExternalRefJSONv2Contract 验证外部包可经导出构造器与 JSON/v2 确定性往返使用 secret.Ref。
func TestExternalRefJSONv2Contract(t *testing.T) {
	ref, err := secret.NewRef("local-offline", "item-01")
	if err != nil {
		t.Fatalf("NewRef 失败: %v", err)
	}
	rawJSON, err := jsonv2.Marshal(ref, jsonv2.Deterministic(true))
	if err != nil || string(rawJSON) != `"local-offline/item-01"` {
		t.Fatalf("外置包 Marshal(Ref) = (%s, %v)", rawJSON, err)
	}
	var decoded secret.Ref
	if err := jsonv2.Unmarshal(rawJSON, &decoded); err != nil || !decoded.Equal(ref) {
		t.Fatalf("外置包 Unmarshal(Ref) = (%+v, %v)", decoded, err)
	}
}

// TestExternalNonEmptyForEachInBorrowedScope 跨包验证 algebraic.NonEmpty.ForEach 的 //xops:syncclosure 事实：
// 允许在 secret.WithBytes 的 //xops:borrowed 作用域内安全捕获借用句柄 box，0 xopsvet 违例。
func TestExternalNonEmptyForEachInBorrowedScope(t *testing.T) {
	items := algebraic.NewNonEmpty("a", "bb", "ccc")
	total := 0
	err := secret.WithBytes([]byte("pw"), func(box *secret.SecretBox) error {
		return items.ForEach(func(item string) error {
			total += len(item) + box.Len()
			return nil
		})
	})
	if err != nil || total != 12 {
		t.Fatalf("ForEach 跨包同步闭包验证失败: total=%d err=%v", total, err)
	}
}
