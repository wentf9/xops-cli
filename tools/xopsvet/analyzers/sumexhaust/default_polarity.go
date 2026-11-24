package sumexhaust

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"slices"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
)

// isPermissiveIdentName 基于前置紧邻否定修饰判定标识符是否表达放行（fail-open）语义。
func isPermissiveIdentName(name string) bool {
	return hasUnnegatedPermissive(vetutil.SplitIdentTokens(name))
}

// isFailClosedIdentName 与 isPermissiveIdentName 严格保持逻辑对偶：
// 必须不含未否定放行词元，且包含显式拒绝词元或「前置否定词 + 放行词」紧邻组合。
func isFailClosedIdentName(name string) bool {
	tokens := vetutil.SplitIdentTokens(name)
	if hasUnnegatedPermissive(tokens) {
		return false
	}
	for i, tok := range tokens {
		if isFailClosedToken(tok) || (isPermissiveToken(tok) && vetutil.HasPrecedingNegation(tokens, i)) {
			return true
		}
	}
	return false
}

func hasUnnegatedPermissive(tokens []string) bool {
	for i, tok := range tokens {
		if isPermissiveToken(tok) && !vetutil.HasPrecedingNegation(tokens, i) {
			return true
		}
	}
	return false
}

func isPermissiveToken(tok string) bool {
	return slices.Contains([]string{"allow", "allowed", "permit", "permitted", "grant", "granted", "approve", "approved"}, tok)
}

func isFailClosedToken(tok string) bool {
	return slices.Contains([]string{
		"deny", "denied", "reject", "rejected", "invalid", "unknown",
		"fail", "failed", "err", "error", "forbid", "forbidden", "closed", "disabled",
		"disallow", "disallowed", "block", "blocked", "halt", "halted",
		"revoke", "revoked", "unset", "refuse", "refused",
		"unapproved", "unauthorized", "unpermitted",
	}, tok)
}

func rightmostIdent(expr ast.Expr) *ast.Ident {
	switch e := unwrapExprChain(expr).(type) {
	case *ast.Ident:
		return e
	case *ast.SelectorExpr:
		return e.Sel
	default:
		return nil
	}
}

func unwrapExprChain(expr ast.Expr) ast.Expr {
	for cur := ast.Unparen(expr); cur != nil; {
		switch e := cur.(type) {
		case *ast.UnaryExpr:
			if e.Op != token.AND {
				return cur
			}
			cur = ast.Unparen(e.X)
		case *ast.CompositeLit:
			if e.Type == nil {
				return cur
			}
			cur = ast.Unparen(e.Type)
		case *ast.CallExpr:
			cur = ast.Unparen(e.Fun)
		case *ast.IndexExpr:
			cur = ast.Unparen(e.X)
		case *ast.IndexListExpr:
			cur = ast.Unparen(e.X)
		default:
			return cur
		}
	}
	return nil
}

func unwrapSingleTypeConversion(info *types.Info, expr ast.Expr) (ast.Expr, bool) {
	if info == nil || expr == nil {
		return nil, false
	}
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || len(call.Args) != 1 || call.Ellipsis.IsValid() || !isTypeExpr(info, call.Fun) {
		return nil, false
	}
	return call.Args[0], true
}

func isTypeExpr(info *types.Info, expr ast.Expr) bool {
	if info == nil || expr == nil {
		return false
	}
	if tv, ok := info.Types[expr]; ok && tv.IsType() {
		return true
	}
	tv, ok := info.Types[ast.Unparen(expr)]
	return ok && tv.IsType()
}

func isBoolConstExpr(info *types.Info, expr ast.Expr, want bool) bool {
	if info == nil || expr == nil {
		return false
	}
	if tv, ok := info.Types[expr]; ok && tv.Value != nil && tv.Value.Kind() == constant.Bool {
		return constant.BoolVal(tv.Value) == want
	}
	id, ok := ast.Unparen(expr).(*ast.Ident)
	if !ok {
		return false
	}
	c, ok := info.Uses[id].(*types.Const)
	return ok && c.Val() != nil && c.Val().Kind() == constant.Bool && constant.BoolVal(c.Val()) == want
}

// isNilIdent 循环剥离括号与单参类型转换，判定表达式是否指向内置 nil（覆盖 error(nil) 与 (*T)(nil)）。
func isNilIdent(info *types.Info, expr ast.Expr) bool {
	cur := ast.Unparen(expr)
	for {
		arg, ok := unwrapSingleTypeConversion(info, cur)
		if !ok {
			break
		}
		cur = ast.Unparen(arg)
	}
	id, ok := cur.(*ast.Ident)
	if !ok {
		return false
	}
	if info != nil {
		if obj := info.Uses[id]; obj != nil {
			_, isNil := obj.(*types.Nil)
			return isNil
		}
	}
	return id.Name == "nil"
}
