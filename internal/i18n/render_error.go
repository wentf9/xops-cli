package i18n

import (
	"context"
	"errors"
	"fmt"

	"github.com/wentf9/xops-cli/core/conc"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

// RenderError 将任意 Go error 链按当前语种递归展开并结构化折叠渲染：
//   - 零值或 nil *Localizer 严格回退 err.Error()；nil error 返回空串；
//   - 直接委托至 domi18n.RenderErrorChain，与 domi18n.CanonicalError 共享唯一折叠代数与深度/环路保护；
//   - 多段错误链连接符严格取自 YAML 词条 common.error_join，源码零中文/全角标点字面量；
//   - 仅对精确匹配叶子文本（CORE-2）的 context.* 与全部 core/conc 哨兵执行本地化并受 SuppressedSentinels 精准过滤；
//   - 对直接 *conc.PanicError：typed-nil 或零值 panic 遵循 SuppressedSentinels 抑制，携带非空值的 panic 永不抑制并有界渲染。
func (l *Localizer) RenderError(err error) string {
	if err == nil {
		return ""
	}
	if !l.IsValid() {
		return err.Error()
	}
	return domi18n.RenderErrorChain(err, domi18n.ErrorRenderHooks{
		RenderMessage:      l.Render,
		JoinCausal:         l.joinCausalSegments,
		RenderUnstructured: l.renderUnstructuredNode,
	})
}

func (l *Localizer) joinCausalSegments(head, tail string) string {
	return l.T(domi18n.KeyCommonErrorJoin, domi18n.BoundStr("head", head), domi18n.BoundStr("tail", tail))
}

func (l *Localizer) renderUnstructuredNode(err error, children []error) (string, error, bool) {
	if text, bareTarget, ok := l.renderDirectPanicError(err, children); ok {
		return text, bareTarget, true
	}
	if len(children) == 0 {
		return l.renderMappedLeafSentinel(err)
	}
	return "", nil, false
}

func (l *Localizer) renderDirectPanicError(err error, children []error) (string, error, bool) {
	pe, ok := errors.AsType[*conc.PanicError](err)
	if !ok || childrenHavePanicError(children) {
		return "", nil, false
	}
	if pe == nil || pe.Value() == nil {
		return l.T(KeyConcTaskPanicked), conc.ErrTaskPanicked, true
	}
	return l.T(KeyConcPanic, domi18n.BoundStr("value", fmt.Sprint(pe.Value()))), nil, true
}

func childrenHavePanicError(children []error) bool {
	for _, child := range children {
		if _, ok := errors.AsType[*conc.PanicError](child); ok {
			return true
		}
	}
	return false
}

// renderMappedLeafSentinel 对纯叶子非结构化错误执行精确文本匹配（CORE-2），
// 防止携带自定义上下文文本且实现 Is(target) 的错误被误覆写或误吞噬。
func (l *Localizer) renderMappedLeafSentinel(err error) (string, error, bool) {
	switch {
	case isExactLeafSentinel(err, context.Canceled):
		return l.T(KeyStdContextCanceled), context.Canceled, true
	case isExactLeafSentinel(err, context.DeadlineExceeded):
		return l.T(KeyStdDeadlineExceeded), context.DeadlineExceeded, true
	case isExactLeafSentinel(err, conc.ErrNurseryNotInitialized):
		return l.T(KeyConcNurseryNotInitialized), conc.ErrNurseryNotInitialized, true
	case isExactLeafSentinel(err, conc.ErrNurseryClosed):
		return l.T(KeyConcNurseryClosed), conc.ErrNurseryClosed, true
	case isExactLeafSentinel(err, conc.ErrNilTask):
		return l.T(KeyConcNilTask), conc.ErrNilTask, true
	case isExactLeafSentinel(err, conc.ErrTaskPanicked):
		return l.T(KeyConcTaskPanicked), conc.ErrTaskPanicked, true
	case isExactLeafSentinel(err, conc.ErrMutexNotInitialized):
		return l.T(KeyConcMutexNotInitialized), conc.ErrMutexNotInitialized, true
	case isExactLeafSentinel(err, conc.ErrNilContext):
		return l.T(KeyConcNilContext), conc.ErrNilContext, true
	default:
		return "", nil, false
	}
}

func isExactLeafSentinel(err, target error) bool {
	return err != nil && target != nil && errors.Is(err, target) && err.Error() == target.Error()
}
