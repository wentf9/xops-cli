package i18n

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/wentf9/xops-cli/core/conc"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

const maxErrorRenderDepth = 64

// RenderError 将任意 Go error 链按当前语种递归展开并结构化去重渲染：
//   - 零值或 nil *Localizer 严格回退 err.Error()；nil error 返回空串；
//   - 通过 domi18n.InspectNode 与 UnwrapDirect 逐层无穿透检查（零 errorlint 告警且无需任何行内 lint 豁免注释）；
//   - 多段错误链连接符严格取自 YAML 词条 common.error_join，源码零中文/全角标点字面量；
//   - 尊重 WrapSentinel 标记的 SuppressInnerID 跳过紧邻同义内层哨兵，并在扁平因果段上折叠相邻完全重复段；
//   - 递归展开 errors.Join 多错误树，映射 context.Canceled/DeadlineExceeded、全部 conc.Err* 及 *conc.PanicError，
//     并原样保留底层 OS 或第三方技术错误叶子详情。
func (l *Localizer) RenderError(err error) string {
	if err == nil {
		return ""
	}
	if !l.IsValid() {
		return err.Error()
	}
	return l.renderErrorBranch(err, false, 0)
}

func (l *Localizer) renderErrorBranch(err error, suppressSentinel bool, depth int) string {
	segments := l.collectCausalSegments(err, suppressSentinel, depth, nil)
	segments = collapseAdjacentDuplicates(segments)
	if len(segments) == 0 {
		if suppressSentinel {
			return ""
		}
		return err.Error()
	}
	return l.joinSegments(segments)
}

func (l *Localizer) collectCausalSegments(err error, suppressSentinel bool, depth int, acc []string) []string {
	if err == nil {
		return acc
	}
	if depth >= maxErrorRenderDepth {
		if raw := err.Error(); raw != "" {
			return append(acc, raw)
		}
		return acc
	}
	if view, ok := domi18n.InspectNode(err); ok {
		return l.collectStructuredNode(err, view, suppressSentinel, depth, acc)
	}
	return l.collectUnstructuredNode(err, suppressSentinel, depth, acc)
}

func (l *Localizer) collectStructuredNode(orig error, view domi18n.ErrorNode, suppressSentinel bool, depth int, acc []string) []string {
	before := len(acc)
	if head := l.renderStructuredHead(view, suppressSentinel, depth); head != "" {
		acc = append(acc, head)
	}
	if view.Cause != nil {
		nextSuppress := view.SuppressInnerID || (suppressSentinel && isPureSentinelWrapper(view))
		acc = l.collectCausalSegments(view.Cause, nextSuppress, depth+1, acc)
	}
	if len(acc) == before && !suppressSentinel && !view.IsSentinel && orig != nil {
		if raw := orig.Error(); raw != "" {
			acc = append(acc, raw)
		}
	}
	return acc
}

func (l *Localizer) renderStructuredHead(view domi18n.ErrorNode, suppressSentinel bool, depth int) string {
	if suppressSentinel && (view.IsSentinel || isPureSentinelWrapper(view)) {
		return ""
	}
	if view.Message.IsValid() {
		return l.Render(view.Message)
	}
	if view.Sentinel != nil {
		return l.renderErrorBranch(view.Sentinel, false, depth+1)
	}
	return ""
}

func isPureSentinelWrapper(view domi18n.ErrorNode) bool {
	return !view.Message.IsValid() && view.Sentinel != nil
}

func (l *Localizer) collectUnstructuredNode(err error, suppressSentinel bool, depth int, acc []string) []string {
	children := domi18n.UnwrapDirect(err)
	if rendered, ok := l.renderDirectPanicError(err, children); ok {
		return appendNonEmpty(acc, rendered)
	}
	if len(children) > 0 && matchesJoinedErrorText(err, children) {
		if len(children) == 1 {
			return l.collectCausalSegments(children[0], suppressSentinel, depth+1, acc)
		}
		return appendNonEmpty(acc, l.renderJoinedErrors(children, suppressSentinel, depth))
	}
	if len(children) == 0 {
		if rendered, ok := l.renderMappedLeafSentinel(err); ok {
			if suppressSentinel {
				return acc
			}
			return appendNonEmpty(acc, rendered)
		}
	}
	return appendNonEmpty(acc, err.Error())
}

func (l *Localizer) renderJoinedErrors(children []error, suppressSentinel bool, depth int) string {
	parts := make([]string, 0, len(children))
	for _, child := range children {
		if rendered := l.renderErrorBranch(child, suppressSentinel, depth+1); rendered != "" {
			parts = append(parts, rendered)
		}
	}
	return strings.Join(parts, "\n")
}

func (l *Localizer) renderDirectPanicError(err error, children []error) (string, bool) {
	pe, ok := errors.AsType[*conc.PanicError](err)
	if !ok || childrenHavePanicError(children) {
		return "", false
	}
	if pe == nil || pe.Value() == nil {
		return l.T(KeyConcTaskPanicked), true
	}
	valText := boundDisplayText(fmt.Sprint(pe.Value()), domi18n.MaxParamStringBytes)
	return l.T(KeyConcPanic, domi18n.Str("value", valText)), true
}

func childrenHavePanicError(children []error) bool {
	for _, child := range children {
		if _, ok := errors.AsType[*conc.PanicError](child); ok {
			return true
		}
	}
	return false
}

func (l *Localizer) renderMappedLeafSentinel(err error) (string, bool) {
	switch {
	case errors.Is(err, context.Canceled):
		return l.T(KeyStdContextCanceled), true
	case errors.Is(err, context.DeadlineExceeded):
		return l.T(KeyStdDeadlineExceeded), true
	case errors.Is(err, conc.ErrNurseryNotInitialized):
		return l.T(KeyConcNurseryNotInitialized), true
	case errors.Is(err, conc.ErrNurseryClosed):
		return l.T(KeyConcNurseryClosed), true
	case errors.Is(err, conc.ErrNilTask):
		return l.T(KeyConcNilTask), true
	case errors.Is(err, conc.ErrTaskPanicked):
		return l.T(KeyConcTaskPanicked), true
	case errors.Is(err, conc.ErrMutexNotInitialized):
		return l.T(KeyConcMutexNotInitialized), true
	case errors.Is(err, conc.ErrNilContext):
		return l.T(KeyConcNilContext), true
	default:
		return "", false
	}
}

func (l *Localizer) joinSegments(segments []string) string {
	if len(segments) == 0 {
		return ""
	}
	out := segments[0]
	for _, seg := range segments[1:] {
		out = l.joinTwoSegments(out, seg)
	}
	return out
}

func (l *Localizer) joinTwoSegments(head, tail string) string {
	if head == "" {
		return tail
	}
	if tail == "" || tail == head {
		return head
	}
	tmpl, ok := l.lookupTemplate(domi18n.KeyCommonErrorJoin, false, 0)
	if !ok || tmpl == "" {
		tmpl = domi18n.CanonicalFallback(domi18n.KeyCommonErrorJoin)
	}
	return domi18n.FormatTemplate(tmpl, func(key string) (string, bool) {
		switch key {
		case "head":
			return head, true
		case "tail":
			return tail, true
		default:
			return "", false
		}
	})
}

func appendNonEmpty(acc []string, s string) []string {
	if s == "" {
		return acc
	}
	return append(acc, s)
}

func collapseAdjacentDuplicates(segments []string) []string {
	if len(segments) <= 1 {
		return segments
	}
	out := make([]string, 0, len(segments))
	for _, seg := range segments {
		if seg == "" {
			continue
		}
		if len(out) > 0 && out[len(out)-1] == seg {
			continue
		}
		out = append(out, seg)
	}
	return out
}

// matchesJoinedErrorText 判断 err 是否为纯 errors.Join 风格多错误容器（无额外前缀文案），
// 避免调用 errors.Join 触发 failclosed/error_swallow 检查。
func matchesJoinedErrorText(err error, children []error) bool {
	if len(children) == 0 {
		return false
	}
	var b strings.Builder
	for i, child := range children {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(child.Error())
	}
	return err.Error() == b.String()
}
