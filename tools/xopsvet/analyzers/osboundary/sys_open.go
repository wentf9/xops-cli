package osboundary

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

const sysUnixPkgPath = "golang.org/x/sys/unix"

// collectAllowedSysUnixOpenPositions 在 LayerHostSys 生产源码中收集唯一合法的直接 unix.Open 调用点位置：
//   - 仅限非外置测试的 LayerHostSys 生产文件；
//   - 必须为直接调用 golang.org/x/sys/unix.Open（拒绝函数值赋值、unix.Openat、os.Open/OpenFile/NewFile）；
//   - arg 0 必须为精确编译期常量 "/dev/net/tun" 或 "/dev/tty"；
//   - arg 1 必须为编译期整数常量，且强制置位 unix.O_CLOEXEC、严格不含 unix.O_CREAT。
func collectAllowedSysUnixOpenPositions(pass *analysis.Pass, allowOSFS, allowSys bool) map[token.Pos]bool {
	if allowOSFS || !allowSys || pass.TypesInfo == nil {
		return nil
	}
	allowed := make(map[token.Pos]bool)
	vetutil.InspectorOf(pass).Preorder([]ast.Node{(*ast.CallExpr)(nil)}, func(n ast.Node) {
		call, ok := n.(*ast.CallExpr)
		if !ok || vetutil.IsPosInTestFile(pass, call.Pos()) {
			return
		}
		if openPos, ok := allowedSysUnixOpenCallPos(pass, call); ok {
			allowed[openPos] = true
		}
	})
	return allowed
}

func allowedSysUnixOpenCallPos(pass *analysis.Pass, call *ast.CallExpr) (token.Pos, bool) {
	if call == nil || call.Ellipsis.IsValid() || len(call.Args) < 2 {
		return token.NoPos, false
	}
	openIdent, openObj := directUnixOpenIdent(pass, call.Fun)
	if openIdent == nil || openObj == nil {
		return token.NoPos, false
	}
	if !isAllowedSysDevicePathConst(pass, call.Args[0]) {
		return token.NoPos, false
	}
	if !isSafeSysUnixOpenFlags(pass, openObj.Pkg(), call.Args[1]) {
		return token.NoPos, false
	}
	return openIdent.Pos(), true
}

func directUnixOpenIdent(pass *analysis.Pass, fun ast.Expr) (*ast.Ident, *types.Func) {
	var id *ast.Ident
	switch f := ast.Unparen(fun).(type) {
	case *ast.SelectorExpr:
		if pass.TypesInfo.Selections[f] != nil {
			return nil, nil
		}
		id = f.Sel
	case *ast.Ident:
		id = f
	default:
		return nil, nil
	}
	fn, ok := pass.TypesInfo.Uses[id].(*types.Func)
	if !ok || !vetutil.IsPkgSymbol(fn, sysUnixPkgPath, "Open") {
		return nil, nil
	}
	return id, fn
}

func isAllowedSysDevicePathConst(pass *analysis.Pass, arg ast.Expr) bool {
	tv, ok := pass.TypesInfo.Types[arg]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
		return false
	}
	s := constant.StringVal(tv.Value)
	return s == "/dev/net/tun" || s == "/dev/tty"
}

func isSafeSysUnixOpenFlags(pass *analysis.Pass, unixPkg *types.Package, arg ast.Expr) bool {
	if unixPkg == nil || unixPkg.Scope() == nil {
		return false
	}
	cloexecMask, okClo := lookupUint64Const(unixPkg, "O_CLOEXEC")
	creatMask, okCre := lookupUint64Const(unixPkg, "O_CREAT")
	if !okClo || !okCre || cloexecMask == 0 || creatMask == 0 {
		return false
	}
	tv, ok := pass.TypesInfo.Types[arg]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.Int {
		return false
	}
	flags, ok := constant.Uint64Val(tv.Value)
	return ok && (flags&cloexecMask == cloexecMask) && (flags&creatMask == 0)
}

func lookupUint64Const(pkg *types.Package, name string) (uint64, bool) {
	c, ok := pkg.Scope().Lookup(name).(*types.Const)
	if !ok || c == nil || c.Val() == nil || c.Val().Kind() != constant.Int {
		return 0, false
	}
	return constant.Uint64Val(c.Val())
}
