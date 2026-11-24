package linearlease

import (
	"go/ast"
	"go/token"
	"go/types"
)

// exprTaintedClosure 判断表达式是否指向捕获了 //xops:borrowed 变量的闭包
// （含类型断言、索引/切片派生与单参类型转换）。
func (s *closureState) exprTaintedClosure(expr ast.Expr) (taintedClosureInfo, bool) {
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		v, ok := s.pass.TypesInfo.Uses[e].(*types.Var)
		if !ok || v == nil {
			return taintedClosureInfo{}, false
		}
		info, exists := s.taintedClosures[v]
		return info, exists
	case *ast.FuncLit:
		if capScope := s.capturedBorrowedScope(e); capScope != nil {
			return taintedClosureInfo{lit: e, ownerScope: capScope}, true
		}
		return taintedClosureInfo{}, false
	case *ast.TypeAssertExpr:
		return s.exprTaintedClosure(e.X)
	case *ast.IndexExpr:
		return s.exprTaintedClosure(e.X)
	case *ast.SliceExpr:
		return s.exprTaintedClosure(e.X)
	case *ast.StarExpr:
		return s.exprTaintedClosure(e.X)
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			return s.exprTaintedClosure(e.X)
		}
		return taintedClosureInfo{}, false
	case *ast.CallExpr:
		return s.conversionTaintedClosure(e)
	default:
		return taintedClosureInfo{}, false
	}
}

func (s *closureState) conversionTaintedClosure(call *ast.CallExpr) (taintedClosureInfo, bool) {
	if len(call.Args) != 1 {
		return taintedClosureInfo{}, false
	}
	tv, ok := s.pass.TypesInfo.Types[call.Fun]
	if !ok || !tv.IsType() {
		return taintedClosureInfo{}, false
	}
	return s.exprTaintedClosure(call.Args[0])
}

func (s *closureState) exprBorrowedScope(expr ast.Expr) (*types.Scope, bool) {
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		v, ok := s.pass.TypesInfo.Uses[e].(*types.Var)
		if !ok || v == nil {
			return nil, false
		}
		sc, exists := s.borrowed[v]
		return sc, exists
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			return s.exprBorrowedScope(e.X)
		}
		return nil, false
	case *ast.StarExpr:
		return s.exprBorrowedScope(e.X)
	case *ast.TypeAssertExpr:
		return s.exprBorrowedScope(e.X)
	case *ast.SliceExpr:
		return s.exprBorrowedScope(e.X)
	case *ast.IndexExpr:
		if isBasicScalarType(s.pass.TypesInfo.TypeOf(e)) {
			return nil, false
		}
		return s.exprBorrowedScope(e.X)
	case *ast.CallExpr:
		return s.conversionBorrowedScope(e)
	default:
		return nil, false
	}
}

func (s *closureState) conversionBorrowedScope(call *ast.CallExpr) (*types.Scope, bool) {
	if len(call.Args) != 1 {
		return nil, false
	}
	tv, ok := s.pass.TypesInfo.Types[call.Fun]
	if !ok || !tv.IsType() {
		return nil, false
	}
	return s.exprBorrowedScope(call.Args[0])
}

func rangeKeyType(t types.Type) types.Type {
	if t == nil {
		return nil
	}
	switch u := types.Unalias(t).Underlying().(type) {
	case *types.Map:
		return u.Key()
	case *types.Chan:
		return u.Elem()
	case *types.Slice, *types.Array:
		return types.Typ[types.Int]
	case *types.Basic:
		if u.Info()&types.IsString != 0 {
			return types.Typ[types.Int]
		}
		return nil
	default:
		return nil
	}
}

func rangeElemType(t types.Type) types.Type {
	if t == nil {
		return nil
	}
	switch u := types.Unalias(t).Underlying().(type) {
	case *types.Slice:
		return u.Elem()
	case *types.Array:
		return u.Elem()
	case *types.Map:
		return u.Elem()
	case *types.Chan:
		return u.Elem()
	case *types.Basic:
		if u.Info()&types.IsString != 0 {
			return types.Typ[types.Rune]
		}
		return nil
	default:
		return nil
	}
}

func isDeclaredWithinScope(v *types.Var, ownerScope *types.Scope) bool {
	if v == nil || ownerScope == nil || v.IsField() {
		return false
	}
	for cur := v.Parent(); cur != nil; cur = cur.Parent() {
		if cur == ownerScope {
			return true
		}
	}
	return false
}

func (s *closureState) reportEscape(rng ast.Node, msg string) {
	if rng == nil || s.reported[rng.Pos()] {
		return
	}
	s.reported[rng.Pos()] = true
	s.pass.ReportRangef(rng, "%s", msg)
}
