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
