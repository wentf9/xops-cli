package winsec

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// TestWinsecProduction_NoPathBasedNamedSecurityInfo verifies on every OS
// (including Linux CI) that core/winsec production code uses handle-based
// GetSecurityInfo / SetSecurityInfo exclusively and never calls path-based
// GetNamedSecurityInfo or SetNamedSecurityInfo.
func TestWinsecProduction_NoPathBasedNamedSecurityInfo(t *testing.T) {
	t.Parallel()

	fset := token.NewFileSet()
	var sawGetSecurityInfo, sawSetSecurityInfo bool

	for _, filename := range []string{"eval.go", "windows.go", "handle_windows.go"} {
		file, err := parser.ParseFile(fset, filename, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", filename, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch sel.Sel.Name {
			case "GetNamedSecurityInfo", "SetNamedSecurityInfo":
				pos := fset.Position(sel.Pos())
				t.Errorf("%s:%d calls forbidden path-based %s; use handle-based GetSecurityInfo/SetSecurityInfo",
					filename, pos.Line, sel.Sel.Name)
			case "GetSecurityInfo":
				sawGetSecurityInfo = true
			case "SetSecurityInfo":
				sawSetSecurityInfo = true
			}
			return true
		})
	}

	if !sawGetSecurityInfo || !sawSetSecurityInfo {
		t.Fatalf("expected handle-based GetSecurityInfo (%v) and SetSecurityInfo (%v) in core/winsec",
			sawGetSecurityInfo, sawSetSecurityInfo)
	}
}
