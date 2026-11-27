package secretfact

import (
	"go/types"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
)

const (
	eventsPkgPath         = vetutil.ModulePrefix + "/core/events"
	auditPkgPath          = vetutil.ModulePrefix + "/internal/host/audit"
	portsPkgPath          = vetutil.ModulePrefix + "/core/ports"
	coreDomainI18nPkgPath = vetutil.ModulePrefix + "/core/domain/i18n"
	internalI18nPkgPath   = vetutil.ModulePrefix + "/internal/i18n"
)

// SinkKind 标识机密（SecretBox 或明文）严禁流入的公共高危汇点类别（供 secretbox 与 secrettaint 共享）。
type SinkKind uint8

const (
	SinkNone SinkKind = iota
	SinkLog
	SinkError
	SinkSerialize
	SinkEventAudit
)

// Label 返回用于诊断消息的中文汇点分类名称。
func (k SinkKind) Label() string {
	switch k {
	case SinkLog:
		return "日志"
	case SinkError:
		return "错误格式化"
	case SinkSerialize:
		return "序列化"
	case SinkEventAudit:
		return "事件/审计"
	default:
		return ""
	}
}

// ClassifyCommonSink 对日志、错误格式化、序列化与事件/审计公共汇点进行统一分类。
func ClassifyCommonSink(obj types.Object) SinkKind {
	pkgPath := vetutil.ObjectPkgPath(obj)
	if pkgPath == "" {
		return SinkNone
	}
	if kind := classifyLogOrErrorSink(pkgPath, obj.Name()); kind != SinkNone {
		return kind
	}
	if kind := classifySerializeSink(pkgPath, obj.Name()); kind != SinkNone {
		return kind
	}
	return classifyEventAuditSink(pkgPath, obj)
}

func classifyLogOrErrorSink(pkgPath, name string) SinkKind {
	switch pkgPath {
	case "log/slog":
		return SinkLog
	case "log":
		if hasAnyPrefix(name, "Print", "Fatal", "Panic", "Output") {
			return SinkLog
		}
	case "errors":
		if name == "New" {
			return SinkError
		}
	case "fmt":
		if name == "Errorf" || hasAnyPrefix(name, "Print", "Fprint", "Sprint", "Append") {
			return SinkError
		}
	case coreDomainI18nPkgPath:
		if slices.Contains([]string{
			"Str", "BoundStr", "BoundDisplayText", "Int", "Int64", "Uint64", "Float", "Bool", "Dur", "DurNanos", "Msg",
			"NewMessage", "NewMessageWithFallback", "NewPluralMessage", "NewPluralMessageWithFallback",
			"Sentinel", "SentinelWithFallback", "NewErrorWithFallback", "E", "EF", "Wrap", "WrapS", "WrapSentinel",
			"WrapSentinelDetail", "DynamicDetailError",
			"CanonicalError", "RenderErrorChain", "FormatTemplate",
		}, name) {
			return SinkError
		}
	case internalI18nPkgPath:
		if slices.Contains([]string{
			"Str", "BoundStr", "Int", "Int64", "Uint64", "Float", "Bool", "Dur", "DurNanos", "Msg",
			"NewMessage", "NewPluralMessage",
			"Sentinel", "E", "EF", "Wrap", "WrapS",
			"T", "TPlural", "Render", "RenderError",
		}, name) {
			return SinkError
		}
	}
	return SinkNone
}

func classifySerializeSink(pkgPath, name string) SinkKind {
	switch pkgPath {
	case "encoding/json", "encoding/xml", "encoding/gob", "encoding/csv":
		if isMarshalOrEncodeSymbol(name) {
			return SinkSerialize
		}
	case "encoding/json/v2":
		if slices.Contains([]string{"Marshal", "MarshalWrite", "MarshalEncode"}, name) {
			return SinkSerialize
		}
	case "encoding/json/jsontext":
		if name == "WriteValue" || name == "WriteToken" {
			return SinkSerialize
		}
	}
	if isYAMLPackage(pkgPath) && isMarshalOrEncodeSymbol(name) {
		return SinkSerialize
	}
	return SinkNone
}

func classifyEventAuditSink(pkgPath string, obj types.Object) SinkKind {
	if pkgPath == eventsPkgPath || strings.HasPrefix(pkgPath, eventsPkgPath+"/") ||
		pkgPath == auditPkgPath || strings.HasPrefix(pkgPath, auditPkgPath+"/") {
		return SinkEventAudit
	}
	if pkgPath != portsPkgPath {
		return SinkNone
	}
	fn, _ := obj.(*types.Func)
	named, ok := RecvNamedType(fn)
	if !ok {
		return SinkNone
	}
	if named.Obj().Name() == "AuditSink" || (named.Obj().Name() == "InteractionPort" && fn.Name() != "PromptSecret") {
		return SinkEventAudit
	}
	return SinkNone
}

func isMarshalOrEncodeSymbol(name string) bool {
	return slices.Contains([]string{"Marshal", "MarshalIndent", "Encode", "Write", "WriteAll"}, name)
}

func isYAMLPackage(pkgPath string) bool {
	return pkgPath == "yaml" || strings.HasSuffix(pkgPath, "/yaml") ||
		strings.HasSuffix(pkgPath, "/yaml.v2") || strings.HasSuffix(pkgPath, "/yaml.v3") ||
		strings.HasSuffix(pkgPath, "/yaml/v3") || strings.HasSuffix(pkgPath, "/yaml/v4") ||
		strings.HasSuffix(pkgPath, "/go-yaml")
}

func hasAnyPrefix(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
