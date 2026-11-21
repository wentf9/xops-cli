//go:build p7repro

package cmd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"testing"
)

type p7SftpPendingCleanupReport struct {
	hasWithPendingNode  bool
	hasDiscardPending   bool
	preparesWithoutLeak bool
	preparePos          token.Position
	discardedCreatedPos token.Position
}

func inspectSftpPendingCleanup(fset *token.FileSet, file *ast.File) p7SftpPendingCleanupReport {
	var r p7SftpPendingCleanupReport
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			r.inspectCall(fset, node)
		case *ast.AssignStmt:
			r.inspectAssign(fset, node)
		}
		return true
	})
	return r
}

func (r *p7SftpPendingCleanupReport) inspectCall(fset *token.FileSet, call *ast.CallExpr) {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		if fn.Name == "discardPendingNode" {
			r.hasDiscardPending = true
		}
	case *ast.SelectorExpr:
		switch fn.Sel.Name {
		case "WithPendingNode":
			r.hasWithPendingNode = true
		case "DiscardPendingNode":
			r.hasDiscardPending = true
		case "resolveNode", "prepareNode", "PrepareNodeContext":
			r.preparesWithoutLeak = true
			r.preparePos = fset.Position(call.Pos())
		}
	}
}

func (r *p7SftpPendingCleanupReport) inspectAssign(fset *token.FileSet, stmt *ast.AssignStmt) {
	if len(stmt.Rhs) != 1 || len(stmt.Lhs) < 2 {
		return
	}
	call, ok := stmt.Rhs[0].(*ast.CallExpr)
	if !ok {
		return
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || (sel.Sel.Name != "resolveNode" && sel.Sel.Name != "prepareNode") {
		return
	}
	if ident, ok := stmt.Lhs[1].(*ast.Ident); ok && ident.Name == "_" {
		r.discardedCreatedPos = fset.Position(ident.Pos())
	}
}

// TestP7Repro_MED2_SftpRunContextDiscardsPendingNodeOnFailure reproduces MED-2:
// cmd/sftp.go (*SftpOptions).RunContext prepares a pending node via resolveNode,
// throws away the created return value with "_", and never discards the pending
// node (neither via discardPendingNode/DiscardPendingNode nor via a scoped
// WithPendingNode lease) when connect/setup fails.
func TestP7Repro_MED2_SftpRunContextDiscardsPendingNodeOnFailure(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to locate test file path")
	}
	sftpGoPath := filepath.Join(filepath.Dir(thisFile), "sftp.go")

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, sftpGoPath, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", sftpGoPath, err)
	}

	report := inspectSftpPendingCleanup(fset, file)
	if report.hasWithPendingNode || !report.preparesWithoutLeak {
		return
	}
	if report.discardedCreatedPos.IsValid() {
		t.Errorf("%s:%d: (*SftpOptions).RunContext discards the created flag from resolveNode/prepareNode ('_'), making pending cleanup impossible",
			filepath.Base(report.discardedCreatedPos.Filename), report.discardedCreatedPos.Line)
	}
	if !report.hasDiscardPending {
		t.Fatalf("%s:%d: prepares pending node without any discardPendingNode/DiscardPendingNode or WithPendingNode cleanup on connect failure",
			filepath.Base(report.preparePos.Filename), report.preparePos.Line)
	}
}
