package i18n_test

import (
	jsonv2 "encoding/json/v2"
	"errors"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/domain/i18n"
)

func TestPublicAPIBlackBox(t *testing.T) {
	loc, err := i18n.ParseLocale("zh-CN")
	if err != nil || loc != i18n.LocaleZh || loc.Next() != i18n.LocaleEn {
		t.Fatalf("ParseLocale 公开契约异常: loc=%v err=%v", loc, err)
	}
	if got := i18n.ResolveLocale("", "C", "zh_CN.UTF-8"); got != i18n.LocaleEn {
		t.Fatalf("ResolveLocale POSIX C 阻断异常: got=%v", got)
	}

	msg := i18n.NewMessage(
		i18n.KeyLocaleInvalidValue,
		i18n.Str("value", "xx"),
		i18n.Dur("timeout", 3*time.Second),
	)
	if !msg.IsValid() || msg.Canonical() != "i18n: invalid locale xx" {
		t.Fatalf("NewMessage 公开契约异常: valid=%v canonical=%q", msg.IsValid(), msg.Canonical())
	}
	raw, err := jsonv2.Marshal(msg, jsonv2.Deterministic(true))
	var round i18n.Message
	if err != nil || jsonv2.Unmarshal(raw, &round) != nil || !round.Equal(msg) {
		t.Fatalf("Message 外置 JSON 往返异常: raw=%s err=%v", raw, err)
	}

	wrapped := i18n.WrapSentinel(
		i18n.Sentinel(i18n.KeyCommonPermissionDeny),
		i18n.EF(i18n.ErrInvalidLocale, i18n.KeyLocaleInvalidValue, i18n.BoundStr("value", "bad\xff")),
		i18n.ErrInvalidLocale,
	)
	if !errors.Is(wrapped, i18n.ErrInvalidLocale) {
		t.Fatal("WrapSentinel 外置 errors.Is 链路断裂")
	}
	if id, ok := i18n.ErrorID(wrapped); !ok || id != i18n.KeyCommonPermissionDeny {
		t.Fatalf("ErrorID 外置契约异常: (%q, %v)", id, ok)
	}
	view, ok := i18n.InspectNode(wrapped)
	if !ok || len(view.SuppressedSentinels) != 1 || !errors.Is(view.SuppressedSentinels[0], i18n.ErrInvalidLocale) || len(i18n.UnwrapDirect(wrapped)) != 2 {
		t.Fatalf("InspectNode/UnwrapDirect 外置契约异常: ok=%v view=%+v", ok, view)
	}
	if got := i18n.CanonicalError(wrapped); got != wrapped.Error() {
		t.Fatalf("CanonicalError 与 Error() 不一致: %q vs %q", got, wrapped.Error())
	}
	customRendered := i18n.RenderErrorChain(wrapped, i18n.ErrorRenderHooks{
		JoinCausal: func(head, tail string) string { return head + " | " + tail },
	})
	if customRendered != "permission denied | i18n: invalid locale bad\uFFFD" {
		t.Fatalf("RenderErrorChain 外置契约异常: got=%q", customRendered)
	}
	if got := i18n.BoundDisplayText("ab中文", 5); got != "ab中" {
		t.Fatalf("BoundDisplayText 外置契约异常: got=%q", got)
	}
}

func TestDynamicDetailPrimitivesBlackBox(t *testing.T) {
	wd := i18n.WrapSentinelDetail(i18n.Sentinel(i18n.KeyCommonPermissionDeny), i18n.ErrInvalidLocale, "peer-denied", i18n.ErrInvalidLocale)
	if !errors.Is(wd, i18n.ErrInvalidLocale) || wd.Error() != "permission denied: peer-denied" {
		t.Fatalf("WrapSentinelDetail 外置契约异常: err=%q", wd.Error())
	}
	if dyn := i18n.DynamicDetailError("raw remote err"); dyn.Error() != "raw remote err" {
		t.Fatalf("DynamicDetailError 外置契约异常: err=%q", dyn.Error())
	}
}
