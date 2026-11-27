package i18nguard

import (
	"go/ast"
	"go/token"
	"strconv"
	"unicode"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

// checkCJKLiterals 执行规则 3：禁止生产源码中的 STRING 与 CHAR 字面量出现汉字或全角中文标点。
func checkCJKLiterals(pass *analysis.Pass) {
	vetutil.InspectorOf(pass).Preorder([]ast.Node{(*ast.BasicLit)(nil)}, func(n ast.Node) {
		lit, ok := n.(*ast.BasicLit)
		if !ok || (lit.Kind != token.STRING && lit.Kind != token.CHAR) || vetutil.IsPosInTestFile(pass, lit.Pos()) {
			return
		}
		checkCJKLit(pass, lit)
	})
}

func checkCJKLit(pass *analysis.Pass, lit *ast.BasicLit) {
	decoded := lit.Value
	if unquoted, err := strconv.Unquote(lit.Value); err == nil {
		decoded = unquoted
	}
	if containsForbiddenCJKRune(decoded) {
		pass.ReportRangef(lit, "i18nguard: 禁止在生产源码中硬编码中文/CJK 字符或全角标点字面量，请迁入词库并通过 MessageID 引用")
	}
}

func containsForbiddenCJKRune(s string) bool {
	for _, r := range s {
		if isForbiddenCJKRune(r) {
			return true
		}
	}
	return false
}

func isForbiddenCJKRune(r rune) bool {
	return unicode.Is(unicode.Han, r) ||
		(r >= 0x3000 && r <= 0x303F) ||
		(r >= 0xFF00 && r <= 0xFFEF)
}
