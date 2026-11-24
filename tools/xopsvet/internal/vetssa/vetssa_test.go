package vetssa_test

import (
	"go/token"
	"go/types"
	"testing"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetssa"
)

func TestIsRuntimeSecretDoAndStdlibSyncIter(t *testing.T) {
	rtSecretPkg := types.NewPackage("runtime/secret", "secret")
	doFn := types.NewFunc(token.NoPos, rtSecretPkg, "Do", types.NewSignatureType(nil, nil, nil, nil, nil, false))
	if !vetssa.IsRuntimeSecretDo(doFn) {
		t.Fatal("expected runtime/secret.Do to be recognized as sync closure")
	}

	otherPkg := types.NewPackage("example.com/secret", "secret")
	otherDo := types.NewFunc(token.NoPos, otherPkg, "Do", types.NewSignatureType(nil, nil, nil, nil, nil, false))
	if vetssa.IsRuntimeSecretDo(otherDo) {
		t.Fatal("unexpected match for non-stdlib secret.Do")
	}

	slicesPkg := types.NewPackage("slices", "slices")
	valFn := types.NewFunc(token.NoPos, slicesPkg, "Values", types.NewSignatureType(nil, nil, nil, nil, nil, false))
	if !vetssa.IsStdlibSyncIter(valFn) {
		t.Fatal("expected slices.Values to be recognized as stdlib sync iterator")
	}

	bytesPkg := types.NewPackage("bytes", "bytes")
	splitSeq := types.NewFunc(token.NoPos, bytesPkg, "SplitSeq", types.NewSignatureType(nil, nil, nil, nil, nil, false))
	if !vetssa.IsStdlibSyncIter(splitSeq) {
		t.Fatal("expected bytes.SplitSeq to be recognized as stdlib sync iterator")
	}
	fieldsFuncSeq := types.NewFunc(token.NoPos, bytesPkg, "FieldsFuncSeq", types.NewSignatureType(nil, nil, nil, nil, nil, false))
	if vetssa.IsStdlibSyncIter(fieldsFuncSeq) {
		t.Fatal("bytes.FieldsFuncSeq passes runes to user callback and must not be blindly whitelisted")
	}
}

func TestAuditTrackerTopLevelAndDepthExceeded(t *testing.T) {
	tr := vetssa.NewAuditTracker()
	if _, _, st := tr.Enter(nil, nil, nil, 0, 8); st != vetssa.EnterSkip {
		t.Fatalf("expected EnterSkip for nil fn, got %v", st)
	}
	if (vetssa.ScopeRange{Start: 10, End: 5}).Valid() {
		t.Fatal("expected inverted ScopeRange to be invalid")
	}
	k1 := vetssa.MakeAuditKey(nil, map[int]bool{0: true}, nil, true)
	if k1.Fn != nil {
		t.Fatal("expected zero key for nil fn")
	}
}
