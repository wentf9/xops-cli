package secrettaint

import (
	"go/token"
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

func (ts *taintScope) writeToDstCallTaint(rc vetssa.ResolvedCall) (vetssa.ScopeRange, bool) {
	srcSlot, _, ok := writeToDstSpec(rc.FuncObj)
	if !ok {
		return vetssa.ScopeRange{}, false
	}
	switch {
	case srcSlot == slotAllArgs:
		return vetssa.CombinedScope(ts.tainted, rc.UserArgs...)
	case srcSlot == slotRecv:
		sc, hit := ts.tainted[rc.Recv]
		return sc, rc.Recv != nil && hit
	case len(rc.UserArgs) > srcSlot:
		sc, hit := ts.tainted[rc.UserArgs[srcSlot]]
		return sc, hit
	default:
		return vetssa.ScopeRange{}, false
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

// isSafePredicate 放行无用户回调的纯谓词与 runtime.KeepAlive（ST-9 / ST-12）。
func isSafePredicate(fn *types.Func) bool {
	if fn == nil || strings.HasSuffix(fn.Name(), "Func") || strings.HasSuffix(fn.Name(), "FuncSeq") {
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
	case "runtime":
		return name == "KeepAlive"
	default:
		return false
	}
}

// isTaintPreservingTransform 放行无用户回调的局部变换、UTF-16 转换及 KDF/PEM 派生函数（ST-4 / ST-9 / ST-12）。
func isTaintPreservingTransform(fn *types.Func) bool {
	if fn == nil || strings.HasSuffix(fn.Name(), "Func") || strings.HasSuffix(fn.Name(), "FuncSeq") {
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
	case "maps":
		return slices.Contains([]string{"All", "Keys", "Values"}, name)
	case "io":
		return name == "ReadAll"
	case "strconv":
		return !strings.HasPrefix(name, "Append")
	case "encoding/base64", "encoding/hex":
		return name == "EncodeToString" || name == "DecodeString"
	case "golang.org/x/sys/windows":
		return name == "UTF16FromString" || name == "UTF16PtrFromString"
	default:
		return vetutil.IsPkgSymbol(fn, "unicode/utf16", "Encode") ||
			vetutil.IsPkgSymbol(fn, "encoding/pem", "Decode") ||
			vetutil.IsPkgSymbol(fn, "crypto/x509", "DecryptPEMBlock") ||
			vetutil.IsPkgSymbol(fn, "golang.org/x/crypto/argon2", "IDKey", "Key") ||
			vetutil.IsPkgSymbol(fn, "crypto/pbkdf2", "Key") ||
			vetutil.IsPkgSymbol(fn, "golang.org/x/crypto/scrypt", "Key") ||
			vetutil.IsPkgSymbol(fn, "crypto/hkdf", "Extract", "Expand", "Key")
	}
}

func isAppendToDstFunc(fn *types.Func) bool {
	if fn == nil {
		return false
	}
	switch vetutil.ObjectPkgPath(fn) {
	case "fmt":
		return slices.Contains([]string{"Append", "Appendf", "Appendln"}, fn.Name())
	case "strconv":
		return strings.HasPrefix(fn.Name(), "Append")
	case "encoding/base64", "encoding/hex":
		return fn.Name() == "AppendEncode" || fn.Name() == "AppendDecode"
	default:
		return false
	}
}

func isFmtSprintFunc(fn *types.Func) bool {
	return vetutil.IsPkgSymbol(fn, "fmt", "Sprint", "Sprintf", "Sprintln")
}

func (ts *taintScope) allFmtArgsSafe(args []ssa.Value) bool {
	for _, arg := range args {
		if varElems := vetssa.ExtractVarargsElements(arg); len(varElems) > 0 {
			if !ts.allFmtArgsSafe(varElems) {
				return false
			}
			continue
		}
		if _, tainted := ts.tainted[arg]; tainted && !isSafeFmtValueType(concreteFmtArgType(arg)) {
			return false
		}
	}
	return true
}

// concreteFmtArgType 仅剥离接口装箱（MakeInterface/ChangeInterface），保留 ChangeType 构造的命名类型（ST-13）。
func concreteFmtArgType(v ssa.Value) types.Type {
	for v != nil {
		if mi, ok := v.(*ssa.MakeInterface); ok {
			v = mi.X
		} else if ci, ok := v.(*ssa.ChangeInterface); ok {
			v = ci.X
		} else {
			return v.Type()
		}
	}
	return nil
}

func isSafeFmtValueType(t types.Type) bool {
	if t == nil {
		return false
	}
	switch u := types.Unalias(t).(type) {
	case *types.Basic:
		return true
	case *types.Slice:
		b, ok := types.Unalias(u.Elem()).(*types.Basic)
		return ok && (b.Kind() == types.Byte || b.Kind() == types.Uint8 || b.Kind() == types.Rune)
	default:
		return false
	}
}

// isExactCryptoSanitizer 实施精确符号级密码学净化消费器白名单（含 AEAD.Seal 与 hmac.New 源头验证，ST-5/ST-16）。
func (ts *taintScope) isExactCryptoSanitizer(rc vetssa.ResolvedCall, inSc vetssa.ScopeRange) bool {
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
		return name == "New" && len(rc.UserArgs) >= 1 && tracesOnlyToStdlibHashFuncVal(rc.UserArgs[0])
	case "golang.org/x/crypto/chacha20poly1305":
		return name == "New" || name == "NewX"
	case "crypto/aes":
		return name == "NewCipher"
	case "crypto/cipher":
		if slices.Contains([]string{"NewGCM", "NewGCMWithNonceSize", "NewGCMWithTagSize"}, name) {
			return true
		}
		named, ok := secretfact.RecvNamedType(fn)
		return name == "Seal" && ok && vetutil.IsPkgSymbol(named.Obj(), "crypto/cipher", "AEAD") && ts.isSafeAEADSeal(rc, inSc)
	case sshCryptoPkgPath:
		return slices.Contains([]string{"Password", "ParsePrivateKey", "ParsePrivateKeyWithPassphrase"}, name)
	default:
		return name == "Write" && rc.Recv != nil && tracesOnlyToStdlibCtor(rc.Recv, isStdlibHashCtor, map[ssa.Value]bool{})
	}
}

func (ts *taintScope) isSafeAEADSeal(rc vetssa.ResolvedCall, inSc vetssa.ScopeRange) bool {
	if rc.Recv == nil || len(rc.UserArgs) < 1 || !tracesOnlyToStdlibCtor(rc.Recv, isStdlibAEADCtor, map[ssa.Value]bool{}) {
		return false
	}
	dst := rc.UserArgs[0]
	_, dstTainted := ts.tainted[dst]
	return !dstTainted && (vetssa.IsNilConst(dst) || vetssa.IsAllowedSliceWriteDst(dst, inSc, ts.callerParams))
}

func isStdlibAEADCtor(obj *types.Func) bool {
	return vetutil.IsPkgSymbol(obj, "crypto/cipher", "NewGCM", "NewGCMWithNonceSize", "NewGCMWithTagSize") ||
		vetutil.IsPkgSymbol(obj, "golang.org/x/crypto/chacha20poly1305", "New", "NewX")
}

func isStdlibHashCtor(obj *types.Func) bool {
	return vetutil.IsPkgSymbol(obj, "crypto/sha256", "New", "New224") ||
		vetutil.IsPkgSymbol(obj, "crypto/sha512", "New", "New384", "New512_224", "New512_256") ||
		vetutil.IsPkgSymbol(obj, "crypto/hmac", "New")
}

// tracesOnlyToStdlibCtor 统一沿 Extract/Phi/FreeVar/Alloc/UnOp 追溯接收者是否全部源于标准库构造器。
func tracesOnlyToStdlibCtor(v ssa.Value, match func(*types.Func) bool, seen map[ssa.Value]bool) bool {
	v = vetssa.UnwrapInterface(v)
	if v == nil || seen[v] {
		return false
	}
	seen[v] = true
	switch val := v.(type) {
	case *ssa.Extract:
		return val.Index == 0 && tracesOnlyToStdlibCtor(val.Tuple, match, seen)
	case *ssa.Call:
		return match(vetssa.OriginFuncObj(val.Call.StaticCallee()))
	case *ssa.Phi:
		return len(val.Edges) > 0 && !slices.ContainsFunc(val.Edges, func(e ssa.Value) bool { return !tracesOnlyToStdlibCtor(e, match, seen) })
	case *ssa.FreeVar:
		origins := vetssa.TraceFreeVarOrigins(val)
		return len(origins) > 0 && !slices.ContainsFunc(origins, func(o ssa.Value) bool { return !tracesOnlyToStdlibCtor(o, match, seen) })
	case *ssa.Alloc:
		vals, ok := vetssa.LoadedCellValues(val)
		return ok && !slices.ContainsFunc(vals, func(sv ssa.Value) bool { return !tracesOnlyToStdlibCtor(sv, match, seen) })
	case *ssa.UnOp:
		return val.Op == token.MUL && tracesOnlyToStdlibCtor(val.X, match, seen)
	default:
		return false
	}
}

func tracesOnlyToStdlibHashFuncVal(v ssa.Value) bool {
	targets, allKnown := vetssa.ResolveFuncValues(v)
	return allKnown && len(targets) > 0 && !slices.ContainsFunc(targets, func(tgt ssa.Value) bool {
		fn, ok := tgt.(*ssa.Function)
		obj := vetssa.OriginFuncObj(fn)
		return !ok || (!vetutil.IsPkgSymbol(obj, "crypto/sha256", "New", "New224") && !vetutil.IsPkgSymbol(obj, "crypto/sha512", "New", "New384", "New512_224", "New512_256"))
	})
}

func isBufferOrReaderWriteToFunc(fn *types.Func) bool {
	return isBytesOrStringsRecvMethod(fn, []string{"Buffer", "Reader"}, "WriteTo")
}

func isBytesOrStringsRecvMethod(fn *types.Func, recvTypes []string, methodNames ...string) bool {
	pkgPath := vetutil.ObjectPkgPath(fn)
	named, ok := secretfact.RecvNamedType(fn)
	return (pkgPath == "bytes" || pkgPath == "strings") && slices.Contains(methodNames, fn.Name()) && ok && slices.Contains(recvTypes, named.Obj().Name())
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
