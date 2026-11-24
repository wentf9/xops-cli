package algebraic_test

import (
	jsonv2 "encoding/json/v2"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
)

// TestExternalOpaqueDTOContract 验证外部包以 //xops:opaque 契约组合使用 algebraic 原语与 JSON/v2 DTO。
func TestExternalOpaqueDTOContract(t *testing.T) {
	//xops:dto
	type sampleConfigDTO struct {
		Timeout algebraic.Duration                   `json:"timeout"`
		Retry   algebraic.Option[algebraic.Duration] `json:"retry,omitzero"`
		Hops    algebraic.NonEmpty[string]           `json:"hops"`
		User    algebraic.FirstWins[string]          `json:"user,omitzero"`
	}

	cfg := sampleConfigDTO{
		Timeout: algebraic.FromStdDuration(15 * time.Second),
		Retry:   algebraic.Some(algebraic.ZeroDuration()),
		Hops:    algebraic.NewNonEmpty("bastion-1", "bastion-2"),
		User:    algebraic.UnsetFirstWins[string](),
	}

	raw, err := jsonv2.Marshal(cfg, jsonv2.Deterministic(true))
	if err != nil {
		t.Fatalf("外置包 Marshal DTO 失败: %v", err)
	}
	want := `{"timeout":"15s","retry":"0s","hops":["bastion-1","bastion-2"]}`
	if string(raw) != want {
		t.Fatalf("外置包 Marshal DTO = %s, 期望 %s", raw, want)
	}

	var decoded sampleConfigDTO
	if err := jsonv2.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("外置包 Unmarshal DTO 失败: %v", err)
	}
	if !decoded.Timeout.Equal(cfg.Timeout) ||
		!algebraic.EqualOption(decoded.Retry, cfg.Retry) ||
		!algebraic.EqualNonEmpty(decoded.Hops, cfg.Hops) ||
		!decoded.User.IsUnset() {
		t.Fatalf("外置包 DTO 往返不一致: %+v", decoded)
	}
}
