package vetutil

import (
	"cmp"
	"go/ast"
	"go/token"
	"go/types"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/tools/go/analysis"
)

// Diag 表示一条待确定性排序（与可选按行去重）的静态分析诊断。
type Diag struct {
	Pos, End token.Pos
	Msg      string
}

type diagLineKey struct {
	file string
	line int
}

// ReportSortedDedup 按 (Pos, End, Msg) 确定性排序并去重后上报诊断；dedupByLine 为 true 时同行仅留首条。
func ReportSortedDedup(pass *analysis.Pass, diags []Diag, dedupByLine bool) {
	if pass == nil || len(diags) == 0 {
		return
	}
	slices.SortFunc(diags, func(a, b Diag) int {
		if c := cmp.Compare(a.Pos, b.Pos); c != 0 {
			return c
		}
		if c := cmp.Compare(a.End, b.End); c != 0 {
			return c
		}
		return strings.Compare(a.Msg, b.Msg)
	})
	seenLines := make(map[diagLineKey]bool)
	for i, d := range diags {
		if !d.Pos.IsValid() || (i > 0 && d == diags[i-1]) || (dedupByLine && isDuplicateDiagLine(pass.Fset, d.Pos, seenLines)) {
			continue
		}
		pass.Report(analysis.Diagnostic{Pos: d.Pos, End: d.End, Message: d.Msg})
	}
}

func isDuplicateDiagLine(fset *token.FileSet, pos token.Pos, seen map[diagLineKey]bool) bool {
	if fset == nil {
		return false
	}
	p := fset.Position(pos)
	lk := diagLineKey{file: p.Filename, line: p.Line}
	if seen[lk] {
		return true
	}
	seen[lk] = true
	return false
}

// ForEachTypeSpec 顺序遍历当前包全部文件的顶层 type 声明（含 GenDecl 以读取块级注释指令）。
func ForEachTypeSpec(pass *analysis.Pass, fn func(*ast.File, *ast.GenDecl, *ast.TypeSpec)) {
	for _, file := range pass.Files {
		for _, decl := range file.Decls {
			if gen, ok := decl.(*ast.GenDecl); ok && gen.Tok == token.TYPE {
				visitTypeSpecs(file, gen, fn)
			}
		}
	}
}

func visitTypeSpecs(file *ast.File, gen *ast.GenDecl, fn func(*ast.File, *ast.GenDecl, *ast.TypeSpec)) {
	for _, spec := range gen.Specs {
		if ts, ok := spec.(*ast.TypeSpec); ok {
			fn(file, gen, ts)
		}
	}
}

// ForEachPkgVarSpec 顺序遍历当前包全部文件的顶层 var 声明（skipTests 为 true 时跳过 *_test.go）。
func ForEachPkgVarSpec(pass *analysis.Pass, skipTests bool, fn func(*ast.GenDecl, *ast.ValueSpec)) {
	for _, file := range pass.Files {
		if skipTests && IsTestFile(pass, file) {
			continue
		}
		for _, decl := range file.Decls {
			if gen, ok := decl.(*ast.GenDecl); ok && gen.Tok == token.VAR {
				visitValueSpecs(gen, fn)
			}
		}
	}
}

func visitValueSpecs(gen *ast.GenDecl, fn func(*ast.GenDecl, *ast.ValueSpec)) {
	for _, spec := range gen.Specs {
		if vs, ok := spec.(*ast.ValueSpec); ok {
			fn(gen, vs)
		}
	}
}

// IdentSliceToExprs 将标识符切片转换为通用表达式切片，供赋左值对辅助函数复用。
func IdentSliceToExprs(ids []*ast.Ident) []ast.Expr {
	out := make([]ast.Expr, len(ids))
	for i, id := range ids {
		out[i] = id
	}
	return out
}

// SplitIdentTokens 将 Go 标识符按蛇形下划线、驼峰大小写及数字↔字母边界拆分为小写词元序列。
func SplitIdentTokens(name string) []string {
	var tokens []string
	for part := range strings.SplitSeq(name, "_") {
		if part != "" {
			tokens = append(tokens, splitCamelWord(part)...)
		}
	}
	return tokens
}

func splitCamelWord(word string) []string {
	runes := []rune(word)
	var out []string
	start := 0
	for i := 1; i < len(runes); i++ {
		if isIdentBoundary(runes, i) {
			out = append(out, strings.ToLower(string(runes[start:i])))
			start = i
		}
	}
	if start < len(runes) {
		out = append(out, strings.ToLower(string(runes[start:])))
	}
	return out
}

func isIdentBoundary(runes []rune, i int) bool {
	prev, cur := runes[i-1], runes[i]
	return unicode.IsDigit(prev) != unicode.IsDigit(cur) ||
		(unicode.IsLower(prev) && unicode.IsUpper(cur)) ||
		(i+1 < len(runes) && unicode.IsUpper(prev) && unicode.IsUpper(cur) && unicode.IsLower(runes[i+1]))
}

// IsNegationToken 判断词元是否为前置否定修饰词（供 sumexhaust 与 failclosed 共享极性判定）。
func IsNegationToken(tok string) bool {
	return slices.Contains([]string{"not", "no", "never", "without", "non"}, tok)
}

// HasPrecedingNegation 判断词元序列中索引 idx 紧邻的前一词元是否为否定修饰词。
func HasPrecedingNegation(tokens []string, idx int) bool {
	return idx > 0 && IsNegationToken(tokens[idx-1])
}

// SerialTagFlags 记录结构体或单字段上非 "-" 序列化标签的存在情况。
type SerialTagFlags struct{ HasJSON, HasYAML bool }

// Any 返回是否存在任意非 "-" 的 JSON 或 YAML 序列化标签。
func (f SerialTagFlags) Any() bool { return f.HasJSON || f.HasYAML }

// ParseStructFieldTag 解析 AST 结构体字段的反引号/双引号标签。
func ParseStructFieldTag(f *ast.Field) (reflect.StructTag, bool, error) {
	if f == nil || f.Tag == nil {
		return "", false, nil
	}
	raw, err := strconv.Unquote(f.Tag.Value)
	if err != nil {
		return "", false, err
	}
	return reflect.StructTag(raw), true, nil
}

// StructSerialTags 扫描结构体字段，返回非 "-" 的 json/yaml 序列化标签（单字段畸形 tag 容错续扫）。
func StructSerialTags(st *ast.StructType) (SerialTagFlags, error) {
	var flags SerialTagFlags
	if st == nil || st.Fields == nil {
		return flags, nil
	}
	var firstErr error
	for _, f := range st.Fields.List {
		tag, hasTag, err := ParseStructFieldTag(f)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if hasTag {
			addSerialTag(tag, &flags)
		}
	}
	if flags.Any() {
		return flags, nil
	}
	return flags, firstErr
}

func addSerialTag(tag reflect.StructTag, flags *SerialTagFlags) {
	if v, ok := tag.Lookup("json"); ok && v != "-" {
		flags.HasJSON = true
	}
	if v, ok := tag.Lookup("yaml"); ok && v != "-" {
		flags.HasYAML = true
	}
}

// IsTagSkippedForFormat 按 JSON / YAML 真实编码语义判定字段是否被 "-" 忽略（YAML 绝不认 json:"-"）。
func IsTagSkippedForFormat(tag reflect.StructTag, checkJSON, checkYAML bool) bool {
	jv, hasJ := tag.Lookup("json")
	yv, hasY := tag.Lookup("yaml")
	jSkip, ySkip := hasJ && jv == "-", hasY && yv == "-"
	switch {
	case checkJSON && checkYAML:
		return jSkip && ySkip
	case checkYAML:
		return ySkip
	default:
		return jSkip && (!hasY || ySkip)
	}
}

// IsCompileTimePureExpr 判定表达式是否为无运行期副作用的纯常量、字面量、零值转换或纯 new(...)。
func IsCompileTimePureExpr(info *types.Info, expr ast.Expr) bool {
	if info == nil || expr == nil {
		return false
	}
	switch e := ast.Unparen(expr).(type) {
	case *ast.BasicLit:
		return true
	case *ast.Ident:
		return isPureConstOrNilIdent(info, e)
	case *ast.CompositeLit:
		return isPureCompositeLit(info, e)
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			lit, ok := ast.Unparen(e.X).(*ast.CompositeLit)
			return ok && isPureCompositeLit(info, lit)
		}
		return (e.Op == token.ADD || e.Op == token.SUB || e.Op == token.NOT || e.Op == token.XOR) && IsCompileTimePureExpr(info, e.X)
	case *ast.CallExpr:
		return isPureConvOrNewExpr(info, e)
	default:
		return false
	}
}

func isPureConstOrNilIdent(info *types.Info, id *ast.Ident) bool {
	if id.Name == "nil" {
		return true
	}
	if tv, ok := info.Types[id]; ok && tv.Value != nil {
		return true
	}
	obj := info.Uses[id]
	_, isC := obj.(*types.Const)
	_, isN := obj.(*types.Nil)
	return isC || isN
}

func isPureCompositeLit(info *types.Info, lit *ast.CompositeLit) bool {
	t := info.TypeOf(lit)
	isStruct := false
	if t != nil {
		_, isStruct = types.Unalias(t).Underlying().(*types.Struct)
	}
	for _, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if (!isStruct && !IsCompileTimePureExpr(info, kv.Key)) || !IsCompileTimePureExpr(info, kv.Value) {
				return false
			}
		} else if !IsCompileTimePureExpr(info, elt) {
			return false
		}
	}
	return true
}

func isPureConvOrNewExpr(info *types.Info, call *ast.CallExpr) bool {
	if len(call.Args) != 1 || call.Ellipsis.IsValid() {
		return false
	}
	if id, ok := ast.Unparen(call.Fun).(*ast.Ident); ok && id.Name == "new" {
		if b, isB := info.Uses[id].(*types.Builtin); isB && b.Name() == "new" {
			argTV, ok := info.Types[call.Args[0]]
			return (ok && argTV.IsType()) || IsCompileTimePureExpr(info, call.Args[0])
		}
	}
	tv, ok := info.Types[call.Fun]
	return ok && tv.IsType() && IsCompileTimePureExpr(info, call.Args[0])
}
