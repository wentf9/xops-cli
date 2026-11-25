package vetssa_test

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"testing"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetssa"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
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
	if _, _, st := tr.Enter(nil, nil, nil, nil, 0, 8); st != vetssa.EnterSkip {
		t.Fatalf("expected EnterSkip for nil fn, got %v", st)
	}
	if (vetssa.ScopeRange{Start: 10, End: 5}).Valid() {
		t.Fatal("expected inverted ScopeRange to be invalid")
	}
	k1 := vetssa.MakeAuditKey(nil, map[int]bool{0: true}, nil, nil, true)
	if k1.Fn != nil {
		t.Fatal("expected zero key for nil fn")
	}
	sSecret := vetssa.ScopeRange{Start: 10, End: 50, SecretOnly: true}
	sPlain := vetssa.ScopeRange{Start: 5, End: 60, SecretOnly: false}
	if got := vetssa.TightenScope(sSecret, sPlain); got.SecretOnly || got.Start != 10 || got.End != 50 {
		t.Fatalf("TightenScope(secret, non-secret) = %+v, want [10,50] SecretOnly=false", got)
	}
	if got := vetssa.TightenScope(sSecret, vetssa.ScopeRange{Start: 12, End: 40, SecretOnly: true}); !got.SecretOnly || got.Start != 12 || got.End != 40 {
		t.Fatalf("TightenScope(secret, secret) = %+v, want [12,40] SecretOnly=true", got)
	}
	// 不相交区间交集必须收敛至吸收底元，再次与任意有效区间求交不得震荡弹回。
	disjoint := vetssa.TightenScope(vetssa.ScopeRange{Start: 10, End: 20, SecretOnly: true}, vetssa.ScopeRange{Start: 30, End: 40, SecretOnly: true})
	if disjoint.Valid() || disjoint.SecretOnly {
		t.Fatalf("disjoint TightenScope = %+v, want invalid absorbing bottom", disjoint)
	}
	if again := vetssa.TightenScope(disjoint, vetssa.ScopeRange{Start: 10, End: 20, SecretOnly: true}); again != disjoint {
		t.Fatalf("absorbing bottom oscillated: got %+v, want %+v", again, disjoint)
	}
	if !vetssa.IsPlainSecretParamType(types.NewSlice(types.Typ[types.Byte])) || !vetssa.IsPlainSecretParamType(types.Typ[types.String]) {
		t.Fatal("expected []byte and string to be plain secret param types")
	}
	if vetssa.IsPlainSecretParamType(types.NewPointer(types.NewStruct(nil, nil))) {
		t.Fatal("expected *struct{} not to be a plain secret param type")
	}
}

func buildTestSSAPkg(t *testing.T, src string) *ssa.Package {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "sample.go", src, 0)
	if err != nil {
		t.Fatalf("parse sample failed: %v", err)
	}
	conf := types.Config{Importer: importer.Default()}
	pkg, _, err := ssautil.BuildPackage(&conf, fset, types.NewPackage("example.com/sample", "sample"), []*ast.File{file}, ssa.SanityCheckFunctions)
	if err != nil {
		t.Fatalf("build ssa failed: %v", err)
	}
	return pkg
}

func findInnermostIndexAddrSlice(fn *ssa.Function) ssa.Value {
	var found ssa.Value
	var walk func(*ssa.Function)
	walk = func(cur *ssa.Function) {
		for _, anon := range cur.AnonFuncs {
			walk(anon)
		}
		if found != nil {
			return
		}
		vetssa.ForEachInst(cur, func(inst ssa.Instruction) {
			if st, ok := inst.(*ssa.Store); ok {
				if ia, isIA := st.Addr.(*ssa.IndexAddr); isIA {
					found = ia.X
				}
			}
		})
	}
	walk(fn)
	return found
}

func findNamedLocalAlloc(fn *ssa.Function, name string) *ssa.Alloc {
	var found *ssa.Alloc
	vetssa.ForEachInst(fn, func(inst ssa.Instruction) {
		if a, ok := inst.(*ssa.Alloc); ok && a.Comment == name {
			found = a
		}
	})
	return found
}

func TestWriteTargetRootsMultiLevelClosures(t *testing.T) {
	const src = `package sample

var globalSlice []string
var escapedPtr *[]string

func sink(p *[]string) { escapedPtr = p }
func run(fn func())    { fn() }

func okTwoLevel() {
	answers := make([]string, 2)
	run(func() {
		run(func() {
			answers[0] = "ok"
		})
	})
}

func okThreeLevel() {
	answers := make([]string, 2)
	run(func() {
		run(func() {
			run(func() {
				answers[0] = "ok"
			})
		})
	})
}

func badTwoLevelMutateOuter() {
	answers := make([]string, 2)
	run(func() {
		run(func() {
			answers = globalSlice
			answers[0] = "bad"
		})
	})
}

func badTwoLevelEscapeCall() {
	answers := make([]string, 2)
	run(func() {
		run(func() {
			sink(&answers)
			answers[0] = "bad"
		})
	})
}

func badTwoLevelEscapePtrStore() {
	answers := make([]string, 2)
	run(func() {
		run(func() {
			escapedPtr = &answers
			answers[0] = "bad"
		})
	})
}
`
	pkg := buildTestSSAPkg(t, src)
	for _, tc := range []struct {
		name    string
		wantOK  bool
		wantOwn bool
	}{
		{"okTwoLevel", true, true},
		{"okThreeLevel", true, true},
		{"badTwoLevelMutateOuter", true, false},
		{"badTwoLevelEscapeCall", false, false},
		{"badTwoLevelEscapePtrStore", false, false},
	} {
		fn := pkg.Func(tc.name)
		if fn == nil {
			t.Fatalf("missing func %s", tc.name)
		}
		sliceVal := findInnermostIndexAddrSlice(fn)
		if sliceVal == nil {
			t.Fatalf("%s: missing IndexAddr store", tc.name)
		}
		_, ok := vetssa.WriteTargetRoots(sliceVal, true)
		if ok != tc.wantOK {
			t.Errorf("%s: WriteTargetRoots ok=%v, want %v", tc.name, ok, tc.wantOK)
		}
		own := vetssa.AllRootsOwnedInScope(sliceVal, vetssa.ScopeRangeOfFunc(fn), nil)
		if own != tc.wantOwn {
			t.Errorf("%s: AllRootsOwnedInScope=%v, want %v", tc.name, own, tc.wantOwn)
		}
	}
}

func TestLoadedCellValuesMultiLevelClosures(t *testing.T) {
	const src = `package sample

var sinkVal any

func run(fn func()) { fn() }
func sinkPtr(p *[]byte) { sinkVal = p }

func okTwoLevelReadOnly() {
	cell := make([]byte, 4)
	run(func() {
		run(func() {
			_ = len(cell)
		})
	})
}

func okThreeLevelReadOnly() {
	cell := make([]byte, 4)
	run(func() {
		run(func() {
			run(func() {
				_ = len(cell)
			})
		})
	})
}

func badTwoLevelStoreNonNil() {
	cell := make([]byte, 4)
	run(func() {
		run(func() {
			cell = make([]byte, 8)
			_ = len(cell)
		})
	})
}

func badTwoLevelStoreNil() {
	cell := make([]byte, 4)
	run(func() {
		run(func() {
			cell = nil
			_ = len(cell)
		})
	})
}

func badTwoLevelEscapeAddr() {
	cell := make([]byte, 4)
	run(func() {
		run(func() {
			sinkPtr(&cell)
			_ = len(cell)
		})
	})
}
`
	pkg := buildTestSSAPkg(t, src)
	for _, tc := range []struct {
		name   string
		wantOK bool
	}{
		{"okTwoLevelReadOnly", true},
		{"okThreeLevelReadOnly", true},
		{"badTwoLevelStoreNonNil", false},
		{"badTwoLevelStoreNil", false},
		{"badTwoLevelEscapeAddr", false},
	} {
		fn := pkg.Func(tc.name)
		if fn == nil {
			t.Fatalf("missing func %s", tc.name)
		}
		alloc := findNamedLocalAlloc(fn, "cell")
		if alloc == nil {
			t.Fatalf("%s: missing cell alloc", tc.name)
		}
		vals, ok := vetssa.LoadedCellValues(alloc)
		if ok != tc.wantOK {
			t.Errorf("%s: LoadedCellValues ok=%v (vals=%d), want %v", tc.name, ok, len(vals), tc.wantOK)
		}
	}
}

func TestCollectKIAnswersAuditRootsDirectOwnership(t *testing.T) {
	const src = `package sample

func run(fn func()) { fn() }

func okHolderArrayBacking() {
	var holder struct{ buf [1]string }
	answers := holder.buf[:]
	run(func() {
		run(func() {
			answers[0] = "ok"
		})
	})
}

func badMiddleClosureAlloc() {
	run(func() {
		leaked := make([]string, 1)
		run(func() {
			leaked[0] = "bad"
		})
	})
}

func badOuterIndirectAlias() {
	var outer []string
	run(func() {
		outer = make([]string, 1)
		answers := outer
		run(func() {
			answers[0] = "bad"
		})
	})
}
`
	pkg := buildTestSSAPkg(t, src)

	okFn := pkg.Func("okHolderArrayBacking")
	okSlice := findInnermostIndexAddrSlice(okFn)
	okRoots, ok := vetssa.CollectKIAnswersAuditRoots(okSlice, okFn, vetssa.ScopeRangeOfFunc(okFn))
	if !ok || len(okRoots) < 2 {
		t.Fatalf("okHolderArrayBacking: CollectKIAnswersAuditRoots=(len=%d, ok=%v), want ok=true with both holder and answers", len(okRoots), ok)
	}
	hasHolder := false
	for _, r := range okRoots {
		if a, isAlloc := r.(*ssa.Alloc); isAlloc && a.Comment == "holder" {
			hasHolder = true
		}
	}
	if !hasHolder {
		t.Fatalf("okHolderArrayBacking: expected holder *ssa.Alloc in audit roots, got %v", okRoots)
	}

	midFn := pkg.Func("badMiddleClosureAlloc")
	if _, ok := vetssa.CollectKIAnswersAuditRoots(findInnermostIndexAddrSlice(midFn), midFn, vetssa.ScopeRangeOfFunc(midFn)); ok {
		t.Fatal("badMiddleClosureAlloc: expected CollectKIAnswersAuditRoots to reject nested-closure slice")
	}

	outerFn := pkg.Func("badOuterIndirectAlias")
	if outerFn == nil || len(outerFn.AnonFuncs) == 0 {
		t.Fatal("badOuterIndirectAlias: missing inner closure")
	}
	kiSimFn := outerFn.AnonFuncs[0]
	if _, ok := vetssa.CollectKIAnswersAuditRoots(findInnermostIndexAddrSlice(kiSimFn), kiSimFn, vetssa.ScopeRangeOfFunc(kiSimFn)); ok {
		t.Fatal("badOuterIndirectAlias: expected CollectKIAnswersAuditRoots to reject indirect outer-container alias")
	}
}

func TestRunScopedFixpointReRunsOnInPlaceTighten(t *testing.T) {
	const src = `package sample

func target(x string) string {
	y := x
	return y
}
`
	pkg := buildTestSSAPkg(t, src)
	fn := pkg.Func("target")
	if fn == nil || len(fn.Params) != 1 {
		t.Fatal("missing target function")
	}
	param := fn.Params[0]
	scoped := map[ssa.Value]vetssa.ScopeRange{
		param: {Start: 10, End: 100, SecretOnly: true},
	}
	nestedCalls := 0
	propCalls := 0
	vetssa.RunScopedFixpoint(fn, scoped, nil, func(_ ssa.Instruction) bool {
		propCalls++
		return false
	}, func(_ ssa.Instruction) {
		nestedCalls++
		if scoped[param].SecretOnly {
			// 原地收紧 SecretOnly: true -> false 且不新增 map 键，RunScopedFixpoint 必须触发再收敛。
			vetssa.MarkValueScope(scoped, param, vetssa.ScopeRange{Start: 10, End: 100, SecretOnly: false})
		}
	})
	if scoped[param].SecretOnly {
		t.Fatal("expected param ScopeRange.SecretOnly to be tightened to false")
	}
	if propCalls <= 1 || nestedCalls < 2 {
		t.Fatalf("expected RunScopedFixpoint to re-run after in-place tighten, got propCalls=%d nestedCalls=%d", propCalls, nestedCalls)
	}
}

func TestResolveDirectStdlibIterCallbackWithBotScope(t *testing.T) {
	const src = `package sample

import "slices"

func run(xs []string) {
	it := slices.Values(xs)
	it(func(s string) bool {
		_ = s
		return true
	})
}
`
	pkg := buildTestSSAPkg(t, src)
	fn := pkg.Func("run")
	if fn == nil {
		t.Fatal("missing run function")
	}
	var iterCall ssa.CallInstruction
	vetssa.ForEachInst(fn, func(inst ssa.Instruction) {
		if ci, ok := inst.(ssa.CallInstruction); ok && ci.Common() != nil && vetssa.IsIterSeqSignature(ci.Common().Value.Type()) {
			iterCall = ci
		}
	})
	if iterCall == nil {
		t.Fatal("missing direct iter.Seq call")
	}
	bot := vetssa.TightenScope(vetssa.ScopeRange{Start: 10, End: 20}, vetssa.ScopeRange{Start: 30, End: 40})
	if bot.Valid() {
		t.Fatalf("expected disjoint meet to produce invalid absorbing bottom, got %+v", bot)
	}
	rc := vetssa.ResolveCall(nil, iterCall)
	targets, sc, ok := vetssa.ResolveDirectStdlibIterCallback(nil, rc, map[ssa.Value]vetssa.ScopeRange{
		rc.Common.Value: bot,
	})
	if !ok || len(targets) != 1 || sc != bot {
		t.Fatalf("ResolveDirectStdlibIterCallback with Bot = (len=%d, sc=%+v, ok=%v), want (1, %+v, true)", len(targets), sc, ok, bot)
	}
}
