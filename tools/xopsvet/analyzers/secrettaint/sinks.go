package secrettaint

import (
	"go/types"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/secretfact"
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetssa"
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/ssa"
)

const (
	slotRecv    = -1
	slotAllArgs = -2
)

// writeToDstSpec 统一描述「将源操作数明文写入显式目标操作数」的受控操作槽位映射（消除重复规则表）。
func writeToDstSpec(fn *types.Func) (srcSlot, dstSlot int, ok bool) {
	if fn == nil {
		return 0, 0, false
	}
	switch {
	case isBytesOrStringsRecvMethod(fn, []string{"Buffer", "Builder"}, "Write", "WriteString", "WriteByte", "WriteRune"),
		isBytesOrStringsRecvMethod(fn, []string{"Buffer"}, "ReadFrom"):
		return slotAllArgs, slotRecv, true
	case isBytesOrStringsRecvMethod(fn, []string{"Buffer", "Reader"}, "Read", "ReadAt"):
		return slotRecv, 0, true
	case isIOCopyFunc(fn), vetutil.IsPkgSymbol(fn, "encoding/hex", "Encode", "Decode"), vetutil.IsPkgSymbol(fn, "encoding/base64", "Encode", "Decode"):
		return 1, 0, true
	case vetutil.IsPkgSymbol(fn, "crypto/subtle", "ConstantTimeCopy"):
		return 2, 1, true
	default:
		return 0, 0, false
	}
}

// writeToDstCallTaint 判定调用是否属于写入显式目标的受控操作并返回源操作数的最紧作用域。
func (ts *taintScope) writeToDstCallTaint(rc vetssa.ResolvedCall) (vetssa.ScopeRange, bool) {
	srcSlot, _, ok := writeToDstSpec(rc.FuncObj)
	if !ok {
		return vetssa.ScopeRange{}, false
	}
	switch srcSlot {
	case slotAllArgs:
		return vetssa.CombinedScope(ts.tainted, rc.UserArgs...)
	case slotRecv:
		if rc.Recv == nil {
			return vetssa.ScopeRange{}, false
		}
		sc, hit := ts.tainted[rc.Recv]
		return sc, hit
	default:
		if len(rc.UserArgs) <= srcSlot {
			return vetssa.ScopeRange{}, false
		}
		sc, hit := ts.tainted[rc.UserArgs[srcSlot]]
		return sc, hit
	}
}

func writeToDstTargets(rc vetssa.ResolvedCall) []ssa.Value {
	_, dstSlot, ok := writeToDstSpec(rc.FuncObj)
	if !ok {
		return nil
	}
	if dstSlot == slotRecv && rc.Recv != nil {
		return []ssa.Value{rc.Recv}
	}
	if dstSlot >= 0 && len(rc.UserArgs) > dstSlot {
		return []ssa.Value{rc.UserArgs[dstSlot]}
	}
	return nil
}

// isSafePredicate 放行仅返回布尔/整型且绝不泄密的纯谓词函数。
func isSafePredicate(fn *types.Func) bool {
	if fn == nil {
		return false
	}
	pkgPath, name := vetutil.ObjectPkgPath(fn), fn.Name()
	switch pkgPath {
	case "bytes":
		return slices.Contains([]string{"Equal", "Compare", "Contains"}, name) || hasAnyPrefix(name, "HasPrefix", "HasSuffix", "Index", "LastIndex", "Count")
	case "strings":
		return slices.Contains([]string{"EqualFold", "Compare", "Contains"}, name) || hasAnyPrefix(name, "HasPrefix", "HasSuffix", "Index", "LastIndex", "Count")
	case "crypto/subtle":
		return slices.Contains([]string{"ConstantTimeCompare", "ConstantTimeByteEq", "ConstantTimeEq"}, name)
	case "unicode/utf8":
		return slices.Contains([]string{"Valid", "ValidString", "RuneCount", "RuneCountInString"}, name)
	default:
		return false
	}
}

// isTaintPreservingTransform 放行局部变换与 KDF/PEM 派生函数（返回值保持污点并受零逃逸约束）。
func isTaintPreservingTransform(fn *types.Func) bool {
	if fn == nil {
		return false
	}
	pkgPath, name := vetutil.ObjectPkgPath(fn), fn.Name()
	switch pkgPath {
	case "bytes":
		return slices.Contains([]string{"Clone", "String", "Bytes", "Repeat", "Join", "NewBuffer", "NewBufferString", "NewReader", "ReadBytes", "ReadString", "Next", "Lines"}, name) ||
			hasAnyPrefix(name, "Trim", "ToLower", "ToUpper", "Replace", "Split", "Cut", "Fields")
	case "strings":
		return slices.Contains([]string{"Clone", "String", "Repeat", "Join", "NewReader", "Lines"}, name) ||
			hasAnyPrefix(name, "Trim", "ToLower", "ToUpper", "Replace", "Split", "Cut", "Fields")
	case "slices":
		return slices.Contains([]string{"Clone", "Concat", "Repeat", "All", "Values", "Backward", "Chunk"}, name)
	case "fmt":
		return slices.Contains([]string{"Sprint", "Sprintf", "Sprintln"}, name)
	case "io":
		return name == "ReadAll"
	case "strconv":
		return true
	case "encoding/base64", "encoding/hex":
		return slices.Contains([]string{"EncodeToString", "AppendEncode", "DecodeString", "AppendDecode"}, name)
	case "golang.org/x/crypto/argon2":
		return name == "IDKey" || name == "Key"
	case "crypto/pbkdf2", "golang.org/x/crypto/scrypt":
		return name == "Key"
	case "crypto/hkdf":
		return slices.Contains([]string{"Extract", "Expand", "Key"}, name)
	case "encoding/pem":
		return name == "Decode"
	case "crypto/x509":
		return name == "DecryptPEMBlock"
	default:
		return false
	}
}

// isExactCryptoSanitizer 实施精确符号级密码学净化消费器白名单（CRIT-4B + 评审 #12）。
func isExactCryptoSanitizer(rc vetssa.ResolvedCall) bool {
	fn := rc.FuncObj
	if fn == nil {
		return false
	}
	pkgPath, name := vetutil.ObjectPkgPath(fn), fn.Name()
	switch pkgPath {
	case "crypto/sha256":
		return slices.Contains([]string{"Sum256", "Sum224", "New", "New224"}, name)
	case "crypto/sha512":
		return slices.Contains([]string{"Sum512", "Sum384", "Sum512_224", "Sum512_256", "New", "New384", "New512_224", "New512_256"}, name)
	case "crypto/hmac":
		return name == "New"
	case "golang.org/x/crypto/chacha20poly1305":
		return name == "New" || name == "NewX"
	case "crypto/aes":
		return name == "NewCipher"
	case "crypto/cipher":
		if slices.Contains([]string{"NewGCM", "NewGCMWithNonceSize", "NewGCMWithTagSize"}, name) {
			return true
		}
		named, ok := secretfact.RecvNamedType(fn)
		return name == "Seal" && ok && vetutil.IsPkgSymbol(named.Obj(), "crypto/cipher", "AEAD")
	case sshCryptoPkgPath:
		return slices.Contains([]string{"Password", "ParsePrivateKey", "ParsePrivateKeyWithPassphrase"}, name)
	default:
		return name == "Write" && rc.Recv != nil && tracesOnlyToStdlibHashCtor(rc.Recv, make(map[ssa.Value]bool))
	}
}

// tracesOnlyToStdlibHashCtor 严格追溯 Write 接收者是否仅源自标准库 crypto/{sha256,sha512,hmac}.New*。
func tracesOnlyToStdlibHashCtor(v ssa.Value, seen map[ssa.Value]bool) bool {
	v = vetssa.UnwrapInterface(v)
	if v == nil || seen[v] {
		return false
	}
	seen[v] = true
	switch val := v.(type) {
	case *ssa.Call:
		obj := vetssa.OriginFuncObj(val.Call.StaticCallee())
		return vetutil.IsPkgSymbol(obj, "crypto/sha256", "New", "New224") ||
			vetutil.IsPkgSymbol(obj, "crypto/sha512", "New", "New384", "New512_224", "New512_256") ||
			vetutil.IsPkgSymbol(obj, "crypto/hmac", "New")
	case *ssa.Phi:
		return len(val.Edges) > 0 && !slices.ContainsFunc(val.Edges, func(e ssa.Value) bool { return !tracesOnlyToStdlibHashCtor(e, seen) })
	default:
		return false
	}
}

func isBufferOrReaderWriteToFunc(fn *types.Func) bool {
	return isBytesOrStringsRecvMethod(fn, []string{"Buffer", "Reader"}, "WriteTo")
}

func isBytesOrStringsRecvMethod(fn *types.Func, recvTypes []string, methodNames ...string) bool {
	pkgPath := vetutil.ObjectPkgPath(fn)
	if (pkgPath != "bytes" && pkgPath != "strings") || !slices.Contains(methodNames, fn.Name()) {
		return false
	}
	named, ok := secretfact.RecvNamedType(fn)
	return ok && slices.Contains(recvTypes, named.Obj().Name())
}

func isIOCopyFunc(fn *types.Func) bool {
	return vetutil.IsPkgSymbol(fn, "io", "Copy", "CopyN", "CopyBuffer")
}

func isIOCopyBufferFunc(fn *types.Func) bool { return vetutil.IsPkgSymbol(fn, "io", "CopyBuffer") }

func isFmtAppendFunc(fn *types.Func) bool {
	return vetutil.IsPkgSymbol(fn, "fmt", "Append", "Appendf", "Appendln")
}

func hasAnyPrefix(s string, prefixes ...string) bool {
	return slices.ContainsFunc(prefixes, func(p string) bool { return strings.HasPrefix(s, p) })
}
