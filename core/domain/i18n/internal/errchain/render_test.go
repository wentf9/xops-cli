package errchain_test

import (
	"errors"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/i18n/internal/errchain"
)

type fakeNode struct {
	sentinel   error
	msg        string
	hasMsg     bool
	cause      error
	suppressed []error
	isSentinel bool
}

func (f *fakeNode) Error() string { return "DO_NOT_CALL_ERROR" }

func (f *fakeNode) Unwrap() []error {
	return errchain.FilterNonNil([]error{f.sentinel, f.cause})
}

func fakeOps() errchain.Ops[string] {
	return errchain.Ops[string]{
		Inspect: func(err error) (errchain.NodeView[string], bool, bool) {
			n, ok := any(err).(*fakeNode)
			if !ok {
				return errchain.NodeView[string]{}, false, false
			}
			if n == nil || (!n.hasMsg && n.sentinel == nil && n.cause == nil) {
				return errchain.NodeView[string]{}, true, false
			}
			return errchain.NodeView[string]{
				Sentinel:            n.sentinel,
				Message:             n.msg,
				HasMessage:          n.hasMsg,
				Cause:               n.cause,
				SuppressedSentinels: n.suppressed,
				IsSentinel:          n.isSentinel,
			}, true, true
		},
		CanonicalMessage: func(m string) string { return m },
	}
}

func TestErrchainRulesM1ToM6(t *testing.T) {
	ops := fakeOps()
	src := &fakeNode{msg: "src sentinel", hasMsg: true, isSentinel: true}
	facade := &fakeNode{msg: "facade sentinel", hasMsg: true, isSentinel: true}
	leaf := errors.New("leaf detail")

	// M1 + M2: 门面替换同义源哨兵并折叠裸源哨兵。
	wrapped := &fakeNode{sentinel: facade, cause: src, suppressed: []error{src}}
	if got := errchain.Render(wrapped, ops); got != "facade sentinel" {
		t.Fatalf("M1+M2 折叠异常: got=%q", got)
	}

	// M3 + M4: errors.Join 兄弟分支抑制集隔离且上下文段永不被吞噬。
	joined := errors.Join(
		&fakeNode{sentinel: facade, cause: src, suppressed: []error{src}},
		src,
		&fakeNode{msg: "ctx", hasMsg: true, cause: leaf},
	)
	want := "facade sentinel\nsrc sentinel\nctx: leaf detail"
	if got := errchain.Render(joined, ops); got != want {
		t.Fatalf("M3+M4 折叠异常:\n got=%q\nwant=%q", got, want)
	}

	// M6: 自环在预算内确定性终止且绝不调用 .Error()。
	cyc := &fakeNode{msg: "loop", hasMsg: true}
	cyc.cause = cyc
	if got := errchain.Render(cyc, ops); got != "loop" {
		t.Fatalf("M6 自环折叠异常: got=%q", got)
	}

	// UnwrapDirect 与 FilterNonNil。
	if got := errchain.UnwrapDirect(wrapped); len(got) != 2 {
		t.Fatalf("UnwrapDirect 长度异常: %d", len(got))
	}
	if errchain.FilterNonNil([]error{nil, nil}) != nil {
		t.Fatal("FilterNonNil 全 nil 应返回 nil")
	}
}
