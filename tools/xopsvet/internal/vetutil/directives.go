package vetutil

import (
	"go/ast"
	"go/token"
	"strings"
)

// DirectiveKind 表示 XOps v2 代码中支持的 //xops:* 注释指令类型。
type DirectiveKind uint8

const (
	DirectiveUnknown DirectiveKind = iota
	DirectiveOpaque
	DirectiveFailClosed
	DirectiveCanonicalHash
	DirectiveHashExclude
	DirectiveBorrowed
	DirectiveSyncClosure
	DirectiveSecretUse
	DirectiveDTO
	DirectiveBuildVar
)

// Directive 表示一条从注释中解析出的 //xops:* 指令。
type Directive struct {
	Kind DirectiveKind
	Arg  string
	Pos  token.Pos
	Raw  string
}

// ParseCommentLines 将单条 AST 注释拆分为去除注释定界符与前导空白的文本行。
func ParseCommentLines(c *ast.Comment) []string {
	if c == nil {
		return nil
	}
	if strings.HasPrefix(c.Text, "//") {
		return []string{strings.TrimSpace(strings.TrimPrefix(c.Text, "//"))}
	}
	body := strings.TrimSuffix(strings.TrimPrefix(c.Text, "/*"), "*/")
	var lines []string
	for raw := range strings.SplitSeq(body, "\n") {
		t := strings.TrimSpace(raw)
		if after, ok := strings.CutPrefix(t, "*"); ok {
			t = strings.TrimSpace(after)
		}
		if strings.HasPrefix(t, "//xops:") {
			t = strings.TrimPrefix(t, "//")
		}
		lines = append(lines, t)
	}
	return lines
}

// ParseLineDirective 解析单行已剥离注释定界符的文本，提取 //xops:* 指令。
func ParseLineDirective(line string, pos token.Pos) (Directive, bool) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(line), "xops:")
	if !ok {
		return Directive{}, false
	}
	if arg, ok := strings.CutPrefix(rest, "hash-exclude:"); ok {
		return Directive{Kind: DirectiveHashExclude, Arg: strings.TrimSpace(arg), Pos: pos, Raw: line}, true
	}
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return Directive{}, false
	}
	kind := matchDirectiveToken(fields[0])
	return Directive{Kind: kind, Pos: pos, Raw: line}, kind != DirectiveUnknown
}

func matchDirectiveToken(tok string) DirectiveKind {
	return map[string]DirectiveKind{
		"opaque":        DirectiveOpaque,
		"failclosed":    DirectiveFailClosed,
		"canonicalhash": DirectiveCanonicalHash,
		"hash-exclude":  DirectiveHashExclude,
		"borrowed":      DirectiveBorrowed,
		"syncclosure":   DirectiveSyncClosure,
		"secretuse":     DirectiveSecretUse,
		"dto":           DirectiveDTO,
		"buildvar":      DirectiveBuildVar,
	}[tok]
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

// TypeSpecHasDirective 判断类型声明 ts（含单声明 GenDecl 文档注释与行尾注释）是否包含指定指令。
func TypeSpecHasDirective(gen *ast.GenDecl, ts *ast.TypeSpec, kind DirectiveKind) bool {
	return ts != nil && (HasDirective(ts.Doc, kind) || HasDirective(ts.Comment, kind) ||
		(gen != nil && len(gen.Specs) == 1 && HasDirective(gen.Doc, kind)))
}

// FieldHasDirective 判断字段或形参声明 f 是否包含指定 //xops:* 指令。
func FieldHasDirective(f *ast.Field, kind DirectiveKind) bool {
	return f != nil && (HasDirective(f.Doc, kind) || HasDirective(f.Comment, kind))
}

// FuncDeclHasDirective 判断函数或方法声明 fn 的文档注释中是否包含指定指令。
func FuncDeclHasDirective(fn *ast.FuncDecl, kind DirectiveKind) bool {
	return fn != nil && HasDirective(fn.Doc, kind)
}

// ParamFieldHasDirective 结合文件注释列表与源码行号判断形参列表第 idx 个字段是否带指定指令。
func ParamFieldHasDirective(fset *token.FileSet, comments []*ast.CommentGroup, fl *ast.FieldList, idx int, kind DirectiveKind) bool {
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
	prevEnd, nextPos                token.Pos
	prevEndLine, startLine, endLine int
	sameLinePrev, sameLineNext      bool
}

func paramCommentsHaveDirective(fset *token.FileSet, comments []*ast.CommentGroup, fl *ast.FieldList, idx int, kind DirectiveKind) bool {
	f, prevEnd, nextPos, hasNext := fl.List[idx], fl.Opening, fl.Closing, idx+1 < len(fl.List)
	if idx > 0 {
		prevEnd = fl.List[idx-1].End()
	}
	if hasNext {
		nextPos = fl.List[idx+1].Pos()
	}
	prevLine, startLine, endLine := fset.Position(prevEnd).Line, fset.Position(f.Pos()).Line, fset.Position(f.End()).Line
	win := paramCommentWindow{
		prevEnd: prevEnd, nextPos: nextPos, prevEndLine: prevLine, startLine: startLine, endLine: endLine,
		sameLinePrev: idx > 0 && prevLine == startLine, sameLineNext: hasNext && fset.Position(nextPos).Line == endLine,
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
	isBlock := len(cg.List) > 0 && strings.HasPrefix(cg.List[0].Text, "/*")
	if isBlock && cg.Pos() >= w.prevEnd && cg.End() <= f.Pos() && fset.Position(cg.End()).Line == w.startLine {
		return !w.sameLinePrev || (f.Pos()-cg.End()) < (cg.Pos()-w.prevEnd)
	}
	return cg.Pos() >= f.End() && cg.End() <= w.nextPos && fset.Position(cg.Pos()).Line == w.endLine &&
		(!w.sameLineNext || (isBlock && (cg.Pos()-f.End()) < (w.nextPos-cg.End())))
}

// HasNolintComment 精确判断单条 AST 注释是否为 golangci-lint 的 //nolint 指令（不误伤中文说明）。
func HasNolintComment(c *ast.Comment) bool {
	for _, line := range ParseCommentLines(c) {
		if rest, ok := strings.CutPrefix(line, "nolint"); ok &&
			(rest == "" || rest[0] == ':' || rest[0] == ' ' || rest[0] == '\t') {
			return true
		}
	}
	return false
}
