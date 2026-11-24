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
}
