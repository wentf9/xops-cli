package vetutil

import (
	"go/ast"
	"go/token"
	"strings"
)

// DirectiveKind 表示 XOps v2 代码中支持的 //xops:* 注释指令类型。
type DirectiveKind uint8

const (
	// DirectiveUnknown 表示未识别或非指令文本。
	DirectiveUnknown DirectiveKind = iota
	// DirectiveOpaque 表示 //xops:opaque（禁止包外字面量构造的不透明类型）。
	DirectiveOpaque
	// DirectiveFailClosed 表示 //xops:failclosed（零值即拒绝/无效的安全类型）。
	DirectiveFailClosed
	// DirectiveCanonicalHash 表示 //xops:canonicalhash（需经 WriteCanonical 覆盖全字段的结构体）。
	DirectiveCanonicalHash
	// DirectiveHashExclude 表示 //xops:hash-exclude:<reason>（显式豁免规范摘要的字段）。
	DirectiveHashExclude
	// DirectiveBorrowed 表示 //xops:borrowed（禁止逃逸当前同步闭包的作用域借用形参）。
	DirectiveBorrowed
	// DirectiveSyncClosure 表示 //xops:syncclosure（保证同步执行且不逃逸闭包实参的高阶函数）。
	DirectiveSyncClosure
	// DirectiveSecretUse 表示 //xops:secretuse（明文机密借用回调函数）。
	DirectiveSecretUse
	// DirectiveDTO 表示 //xops:dto（显式声明为序列化 DTO 的结构体，禁裸用 time.Duration）。
	DirectiveDTO
	// DirectiveBuildVar 表示 //xops:buildvar（仅限 cmd/xops package main 的链接期只读构建元信息变量）。
	DirectiveBuildVar
)

// Directive 表示一条从注释中解析出的 //xops:* 指令。
type Directive struct {
	Kind DirectiveKind // 指令类型
	Arg  string        // 附带参数（对 hash-exclude 保存已去空白的排除理由）
	Pos  token.Pos     // 指令所属注释的源码位置
	Raw  string        // 原始单行注释内容
}

// ParseCommentLines 将单条 AST 注释拆分为去除注释定界符与前导空白的文本行。
func ParseCommentLines(c *ast.Comment) []string {
	if c == nil {
		return nil
	}
	if strings.HasPrefix(c.Text, "//") {
		line := strings.TrimSpace(strings.TrimPrefix(c.Text, "//"))
		return []string{line}
	}
	body := strings.TrimPrefix(c.Text, "/*")
	body = strings.TrimSuffix(body, "*/")
	rawLines := strings.Split(body, "\n")
	lines := make([]string, 0, len(rawLines))
	for _, raw := range rawLines {
		trimmed := strings.TrimSpace(raw)
		if after, ok := strings.CutPrefix(trimmed, "*"); ok {
			trimmed = strings.TrimSpace(after)
		}
		// 块注释内的 /* //xops:... */ 与 /* xops:... */ 等价；// 行注释分支已提前返回，故 // //xops:... 仍视为普通注释。
		if strings.HasPrefix(trimmed, "//xops:") {
			trimmed = strings.TrimPrefix(trimmed, "//")
		}
		lines = append(lines, trimmed)
	}
	return lines
}

// ParseLineDirective 解析单行已剥离注释定界符的文本，提取 //xops:* 指令。
func ParseLineDirective(line string, pos token.Pos) (Directive, bool) {
	trimmed := strings.TrimSpace(line)
	rest, ok := strings.CutPrefix(trimmed, "xops:")
	if !ok {
		return Directive{}, false
	}
	if arg, hasColon := strings.CutPrefix(rest, "hash-exclude:"); hasColon {
		return Directive{
			Kind: DirectiveHashExclude,
			Arg:  strings.TrimSpace(arg),
			Pos:  pos,
			Raw:  line,
		}, true
	}
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return Directive{}, false
	}
	kind := matchDirectiveToken(fields[0])
	if kind == DirectiveUnknown {
		return Directive{}, false
	}
	return Directive{
		Kind: kind,
		Pos:  pos,
		Raw:  line,
	}, true
}

func matchDirectiveToken(tok string) DirectiveKind {
	switch tok {
	case "opaque":
		return DirectiveOpaque
	case "failclosed":
		return DirectiveFailClosed
	case "canonicalhash":
		return DirectiveCanonicalHash
	case "hash-exclude":
		return DirectiveHashExclude
	case "borrowed":
		return DirectiveBorrowed
	case "syncclosure":
		return DirectiveSyncClosure
	case "secretuse":
		return DirectiveSecretUse
	case "dto":
		return DirectiveDTO
	case "buildvar":
		return DirectiveBuildVar
	default:
		return DirectiveUnknown
	}
}

// ParseCommentGroup 从注释组中解析出全部 //xops:* 指令。
func ParseCommentGroup(cg *ast.CommentGroup) []Directive {
	if cg == nil {
		return nil
	}
	var out []Directive
	for _, c := range cg.List {
		for _, line := range ParseCommentLines(c) {
			if dir, ok := ParseLineDirective(line, c.Pos()); ok {
				out = append(out, dir)
			}
		}
	}
	return out
}

// FindDirective 在注释组中查找首个指定类型的 //xops:* 指令并返回。
func FindDirective(cg *ast.CommentGroup, kind DirectiveKind) (Directive, bool) {
	for _, dir := range ParseCommentGroup(cg) {
		if dir.Kind == kind {
			return dir, true
		}
	}
	return Directive{}, false
}

// HasDirective 判断注释组中是否包含指定类型的 //xops:* 指令。
func HasDirective(cg *ast.CommentGroup, kind DirectiveKind) bool {
	_, ok := FindDirective(cg, kind)
	return ok
}

// TypeSpecHasDirective 判断类型声明 ts（含其所属单声明 GenDecl 文档注释与行尾注释）
// 是否包含指定类型的 //xops:* 指令。当 GenDecl 包含多个 TypeSpec 时不继承 gen.Doc，
// 避免块级 type (...) 头部注释误串扰到后续成员类型。
func TypeSpecHasDirective(gen *ast.GenDecl, ts *ast.TypeSpec, kind DirectiveKind) bool {
	if ts == nil {
		return false
	}
	if HasDirective(ts.Doc, kind) || HasDirective(ts.Comment, kind) {
		return true
	}
	return gen != nil && len(gen.Specs) == 1 && HasDirective(gen.Doc, kind)
}

// FieldHasDirective 判断字段或形参声明 f（含文档注释与行尾注释）是否包含指定类型的 //xops:* 指令。
func FieldHasDirective(f *ast.Field, kind DirectiveKind) bool {
	if f == nil {
		return false
	}
	return HasDirective(f.Doc, kind) || HasDirective(f.Comment, kind)
}

// FuncDeclHasDirective 判断函数或方法声明 fn 的文档注释中是否包含指定类型的 //xops:* 指令。
func FuncDeclHasDirective(fn *ast.FuncDecl, kind DirectiveKind) bool {
	if fn == nil {
		return false
	}
	return HasDirective(fn.Doc, kind)
}

// ParamFieldHasDirective 判断函数形参列表 fl 中第 idx 个字段是否带有指定 //xops:* 指令。
// 由于 go/parser 不会将函数参数列表内的注释挂载到 ast.Field.Doc/Comment，
// 本函数结合文件注释列表 comments 与源码行号，支持参数上方独立行注释、行尾注释及前置块注释。
func ParamFieldHasDirective(
	fset *token.FileSet,
	comments []*ast.CommentGroup,
	fl *ast.FieldList,
	idx int,
	kind DirectiveKind,
) bool {
	if fl == nil || idx < 0 || idx >= len(fl.List) {
		return false
	}
	f := fl.List[idx]
	if FieldHasDirective(f, kind) {
		return true
	}
	if fset == nil || len(comments) == 0 {
		return false
	}
	return paramCommentsHaveDirective(fset, comments, fl, idx, kind)
}

type paramCommentWindow struct {
	prevEnd      token.Pos
	nextPos      token.Pos
	prevEndLine  int
	startLine    int
	endLine      int
	sameLinePrev bool
	sameLineNext bool
}

func paramCommentsHaveDirective(
	fset *token.FileSet,
	comments []*ast.CommentGroup,
	fl *ast.FieldList,
	idx int,
	kind DirectiveKind,
) bool {
	f := fl.List[idx]
	prevEnd := fl.Opening
	if idx > 0 {
		prevEnd = fl.List[idx-1].End()
	}
	nextPos := fl.Closing
	hasNextField := idx+1 < len(fl.List)
	if hasNextField {
		nextPos = fl.List[idx+1].Pos()
	}
	prevEndLine := fset.Position(prevEnd).Line
	startLine := fset.Position(f.Pos()).Line
	endLine := fset.Position(f.End()).Line
	win := paramCommentWindow{
		prevEnd:      prevEnd,
		nextPos:      nextPos,
		prevEndLine:  prevEndLine,
		startLine:    startLine,
		endLine:      endLine,
		sameLinePrev: idx > 0 && prevEndLine == startLine,
		sameLineNext: hasNextField && fset.Position(nextPos).Line == endLine,
	}
	for _, cg := range comments {
		if HasDirective(cg, kind) && matchesParamComment(fset, cg, f, win) {
			return true
		}
	}
	return false
}

func matchesParamComment(fset *token.FileSet, cg *ast.CommentGroup, f *ast.Field, w paramCommentWindow) bool {
	if cg.Pos() > w.prevEnd && cg.End() < f.Pos() && fset.Position(cg.Pos()).Line > w.prevEndLine {
		return true
	}
	if isBlockCommentGroup(cg) && cg.Pos() >= w.prevEnd && cg.End() <= f.Pos() && fset.Position(cg.End()).Line == w.startLine {
		// 同行前导块注释（如 s S, /* //xops:borrowed */ other）距当前形参更近，防止误归属于前参尾注释。
		return !w.sameLinePrev || (f.Pos()-cg.End()) < (cg.Pos()-w.prevEnd)
	}
	if cg.Pos() >= f.End() && cg.End() <= w.nextPos && fset.Position(cg.Pos()).Line == w.endLine {
		// 同行尾随块注释（如 s S /* //xops:borrowed */, other）位于逗号前，距当前形参尾部更近。
		return !w.sameLineNext || (isBlockCommentGroup(cg) && (cg.Pos()-f.End()) < (w.nextPos-cg.End()))
	}
	return false
}

func isBlockCommentGroup(cg *ast.CommentGroup) bool {
	return len(cg.List) > 0 && strings.HasPrefix(cg.List[0].Text, "/*")
}

// HasNolintComment 判断单条 AST 注释是否为 golangci-lint 的 //nolint 指令。
// 仅在去除注释定界符后的行首满足 "nolint" 且后续为行尾、冒号或空白时返回 true，
// 以避免对说明性中文注释中的 "//nolint:" 字样产生自检误报。
func HasNolintComment(c *ast.Comment) bool {
	for _, line := range ParseCommentLines(c) {
		rest, ok := strings.CutPrefix(line, "nolint")
		if !ok {
			continue
		}
		if rest == "" || rest[0] == ':' || rest[0] == ' ' || rest[0] == '\t' {
			return true
		}
	}
	return false
}
