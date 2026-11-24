package secrettaint

import (
	"go/ast"
	"go/types"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
)

const (
	secretPkgPath    = vetutil.ModulePrefix + "/core/domain/secret"
	eventsPkgPath    = vetutil.ModulePrefix + "/core/events"
	auditPkgPath     = vetutil.ModulePrefix + "/internal/host/audit"
	portsPkgPath     = vetutil.ModulePrefix + "/core/ports"
	secretBoxName    = "SecretBox"
	sshCryptoPkgPath = "golang.org/x/crypto/ssh"
)

type sinkKind uint8

const (
	sinkNone sinkKind = iota
	sinkLog
	sinkError
	sinkSerialize
	sinkEventAudit
)

func (k sinkKind) label() string {
	switch k {
	case sinkLog:
		return "日志"
	case sinkError:
		return "错误格式化"
	case sinkSerialize:
		return "序列化"
	case sinkEventAudit:
		return "事件/审计"
	default:
		return ""
	}
}

func isSecretBoxType(t types.Type) bool {
	return vetutil.TypeContainsNamed(t, secretPkgPath, secretBoxName)
}

func classifyRule1SinkCall(info *types.Info, call *ast.CallExpr) sinkKind {
	obj := vetutil.ResolveCalledObject(info, call)
	if obj == nil {
		return sinkNone
	}
	if isFmtSprintFunc(obj) {
		return sinkError
	}
	return classifyCommonSink(obj)
}

func classifyRule2SinkCall(info *types.Info, call *ast.CallExpr) sinkKind {
	obj := vetutil.ResolveCalledObject(info, call)
	if obj == nil {
		return sinkNone
	}
	return classifyCommonSink(obj)
}

func isFmtSprintFunc(obj types.Object) bool {
	return vetutil.IsPkgSymbol(obj, "fmt", "Sprint", "Sprintf", "Sprintln")
}

func classifyCommonSink(obj types.Object) sinkKind {
	pkgPath := vetutil.ObjectPkgPath(obj)
	if pkgPath == "" {
		return sinkNone
	}
	if kind := classifyLogOrErrorSink(pkgPath, obj); kind != sinkNone {
		return kind
	}
	if kind := classifySerializeSink(pkgPath, obj); kind != sinkNone {
		return kind
	}
	return classifyEventAuditSink(pkgPath, obj)
}

func classifyLogOrErrorSink(pkgPath string, obj types.Object) sinkKind {
	switch pkgPath {
	case "log/slog":
		return sinkLog
	case "log":
		if hasAnyPrefix(obj.Name(), "Print", "Fatal", "Panic", "Output") {
			return sinkLog
		}
	case "errors":
		if obj.Name() == "New" {
			return sinkError
		}
	case "fmt":
		if obj.Name() == "Errorf" || hasAnyPrefix(obj.Name(), "Print", "Fprint") {
			return sinkError
		}
	}
	return sinkNone
}

func classifySerializeSink(pkgPath string, obj types.Object) sinkKind {
	switch pkgPath {
	case "encoding/json", "encoding/xml", "encoding/gob", "encoding/csv":
		if isMarshalOrEncodeSymbol(obj.Name()) {
			return sinkSerialize
		}
	case "encoding/json/v2":
		if obj.Name() == "Marshal" || obj.Name() == "MarshalWrite" || obj.Name() == "MarshalEncode" {
			return sinkSerialize
		}
	case "encoding/json/jsontext":
		if obj.Name() == "WriteValue" || obj.Name() == "WriteToken" {
			return sinkSerialize
		}
	}
	if isYAMLPackage(pkgPath) && isMarshalOrEncodeSymbol(obj.Name()) {
		return sinkSerialize
	}
	return sinkNone
}

func classifyEventAuditSink(pkgPath string, obj types.Object) sinkKind {
	switch pkgPath {
	case eventsPkgPath, auditPkgPath:
		return sinkEventAudit
	case portsPkgPath:
		return classifyPortsSink(obj)
	}
	return sinkNone
}

func classifyPortsSink(obj types.Object) sinkKind {
	fn, ok := obj.(*types.Func)
	if !ok || fn == nil {
		return sinkNone
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return sinkNone
	}
	named, ok := vetutil.UnwrapNamedType(sig.Recv().Type())
	if !ok {
		return sinkNone
	}
	switch named.Obj().Name() {
	case "AuditSink":
		return sinkEventAudit
	case "InteractionPort":
		if fn.Name() != "PromptSecret" {
			return sinkEventAudit
		}
	}
	return sinkNone
}

func isMarshalOrEncodeSymbol(name string) bool {
	return name == "Marshal" || name == "MarshalIndent" || name == "Encode" || name == "Write" || name == "WriteAll"
}

func isYAMLPackage(pkgPath string) bool {
	return pkgPath == "yaml" ||
		strings.HasSuffix(pkgPath, "/yaml") ||
		strings.HasSuffix(pkgPath, "/yaml.v2") ||
		strings.HasSuffix(pkgPath, "/yaml.v3")
}

func isExemptBuiltinCall(info *types.Info, call *ast.CallExpr) bool {
	id, ok := ast.Unparen(call.Fun).(*ast.Ident)
	if !ok {
		return false
	}
	b, ok := info.Uses[id].(*types.Builtin)
	if !ok || b == nil {
		return false
	}
	switch b.Name() {
	case "len", "cap", "clear":
		return true
	default:
		return false
	}
}

func isExemptPredicateCall(info *types.Info, call *ast.CallExpr) bool {
	obj := vetutil.ResolveCalledObject(info, call)
	if obj == nil {
		return false
	}
	pkgPath := vetutil.ObjectPkgPath(obj)
	name := obj.Name()
	switch pkgPath {
	case "bytes":
		return name == "Equal" || name == "Compare" || name == "Contains" ||
			hasAnyPrefix(name, "HasPrefix", "HasSuffix", "Index", "Count")
	case "strings":
		return name == "EqualFold" || name == "Compare" || name == "Contains" ||
			hasAnyPrefix(name, "HasPrefix", "HasSuffix", "Index", "Count")
	case "crypto/subtle":
		return name == "ConstantTimeCompare" || name == "ConstantTimeByteEq"
	case "unicode/utf8":
		return name == "Valid" || name == "ValidString"
	default:
		return false
	}
}

func isTaintPropagatingCall(info *types.Info, call *ast.CallExpr) bool {
	obj := vetutil.ResolveCalledObject(info, call)
	if obj == nil {
		return false
	}
	pkgPath := vetutil.ObjectPkgPath(obj)
	name := obj.Name()
	switch pkgPath {
	case "bytes":
		return isBytesTaintPropagator(name)
	case "strings":
		return isStringsTaintPropagator(name)
	case "slices":
		return name == "Clone" || name == "Concat" || name == "Repeat"
	case "fmt":
		return name == "Sprint" || name == "Sprintf" || name == "Sprintln" ||
			name == "Append" || name == "Appendf" || name == "Appendln"
	case "io":
		return name == "ReadAll"
	case "strconv", "encoding/base64", "encoding/hex":
		return true
	default:
		return false
	}
}

func isBytesTaintPropagator(name string) bool {
	switch name {
	case "Clone", "String", "Bytes", "Repeat", "Join",
		"NewBuffer", "NewBufferString", "NewReader",
		"ReadBytes", "ReadString", "Next":
		return true
	default:
		return hasAnyPrefix(name, "Trim", "ToLower", "ToUpper", "Replace")
	}
}

func isStringsTaintPropagator(name string) bool {
	switch name {
	case "Clone", "String", "Repeat", "Join", "NewReader":
		return true
	default:
		return hasAnyPrefix(name, "Trim", "ToLower", "ToUpper", "Replace")
	}
}

func isBufferOrBuilderWriteMethod(info *types.Info, call *ast.CallExpr) bool {
	return isBytesOrStringsMethod(info, call, []string{"Buffer", "Builder"}, "Write", "WriteString", "WriteByte", "WriteRune")
}

func isBufferOrReaderWriteToMethod(info *types.Info, call *ast.CallExpr) bool {
	return isBytesOrStringsMethod(info, call, []string{"Buffer", "Reader"}, "WriteTo")
}

func isBufferOrReaderReadIntoMethod(info *types.Info, call *ast.CallExpr) bool {
	return isBytesOrStringsMethod(info, call, []string{"Buffer", "Reader"}, "Read", "ReadAt")
}

func isBufferReadFromMethod(info *types.Info, call *ast.CallExpr) bool {
	return isBytesOrStringsMethod(info, call, []string{"Buffer"}, "ReadFrom")
}

func isIOCopyCall(info *types.Info, call *ast.CallExpr) bool {
	obj := vetutil.ResolveCalledObject(info, call)
	return vetutil.IsPkgSymbol(obj, "io", "Copy", "CopyN", "CopyBuffer")
}

// isIOCopyBufferCall 判断调用是否为 io.CopyBuffer，用于额外追踪其第三参数临时缓冲切片的污点流与逃逸。
func isIOCopyBufferCall(info *types.Info, call *ast.CallExpr) bool {
	obj := vetutil.ResolveCalledObject(info, call)
	return vetutil.IsPkgSymbol(obj, "io", "CopyBuffer")
}

func isBytesOrStringsMethod(info *types.Info, call *ast.CallExpr, recvTypes []string, methodNames ...string) bool {
	obj := vetutil.ResolveCalledObject(info, call)
	fn, ok := obj.(*types.Func)
	if !ok || fn == nil {
		return false
	}
	pkgPath := vetutil.ObjectPkgPath(fn)
	if (pkgPath != "bytes" && pkgPath != "strings") || !slices.Contains(methodNames, fn.Name()) {
		return false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return false
	}
	named, ok := vetutil.UnwrapNamedType(sig.Recv().Type())
	return ok && slices.Contains(recvTypes, named.Obj().Name())
}

func isFmtAppendCall(info *types.Info, call *ast.CallExpr) bool {
	obj := vetutil.ResolveCalledObject(info, call)
	return vetutil.IsPkgSymbol(obj, "fmt", "Append", "Appendf", "Appendln")
}

func isAllowedAuthOrCryptoConsumer(info *types.Info, call *ast.CallExpr) bool {
	obj := vetutil.ResolveCalledObject(info, call)
	if obj == nil {
		return false
	}
	return vetutil.ObjectPkgPath(obj) == sshCryptoPkgPath
}

func hasAnyPrefix(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
