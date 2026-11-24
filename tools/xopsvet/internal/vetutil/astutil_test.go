package vetutil

import (
	"go/types"
	"reflect"
	"testing"
)

func TestSplitIdentTokensWithDigits(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"V2Allow", []string{"v", "2", "allow"}},
		{"Allow2", []string{"allow", "2"}},
		{"HTTP2Server", []string{"http", "2", "server"}},
		{"ErrNotAllowed", []string{"err", "not", "allowed"}},
		{"not_valid", []string{"not", "valid"}},
	}
	for _, tc := range cases {
		got := SplitIdentTokens(tc.in)
		if !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("SplitIdentTokens(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestContainsValueTypeSkipsInterfaceMethodsAndSignatures(t *testing.T) {
	secretPkg := types.NewPackage(ModulePrefix+"/core/domain/secret", "secret")
	boxName := types.NewTypeName(0, secretPkg, "SecretBox", nil)
	boxNamed := types.NewNamed(boxName, types.NewStruct(nil, nil), nil)
	boxPtr := types.NewPointer(boxNamed)

	// 构造模拟 ports.SecretVault 接口：方法签名接收 *secret.SecretBox，但不持有 SecretBox 值。
	portsPkg := types.NewPackage(ModulePrefix+"/core/ports", "ports")
	putParams := types.NewTuple(types.NewVar(0, portsPkg, "box", boxPtr))
	putSig := types.NewSignatureType(nil, nil, nil, putParams, nil, false)
	putMethod := types.NewFunc(0, portsPkg, "PutAndVerify", putSig)
	vaultIface := types.NewInterfaceType([]*types.Func{putMethod}, nil).Complete()
	vaultName := types.NewTypeName(0, portsPkg, "SecretVault", nil)
	vaultNamed := types.NewNamed(vaultName, vaultIface, nil)

	// RotateRequest{Vault ports.SecretVault} 绝不可被 ContainsValueType 误判为持有 SecretBox（CRIT-3）。
	reqStruct := types.NewStruct([]*types.Var{
		types.NewField(0, portsPkg, "Vault", vaultNamed, false),
	}, nil)

	if ContainsValueNamed(vaultNamed, secretPkg.Path(), "SecretBox") {
		t.Fatal("ContainsValueNamed must NOT descend into interface methods (ports.SecretVault)")
	}
	if ContainsValueNamed(reqStruct, secretPkg.Path(), "SecretBox") {
		t.Fatal("ContainsValueNamed must NOT report struct holding ports.SecretVault")
	}
	if !TypeContainsNamed(vaultNamed, secretPkg.Path(), "SecretBox") {
		t.Fatal("TypeContainsNamed should still see method signature references")
	}

	// 匿名结构体嵌入 *SecretBox 必须被 ContainsValueType 命中（CRIT-2）。
	anonEmbed := types.NewStruct([]*types.Var{
		types.NewField(0, portsPkg, "SecretBox", boxPtr, true),
	}, nil)
	if !ContainsValueNamed(anonEmbed, secretPkg.Path(), "SecretBox") {
		t.Fatal("ContainsValueNamed must catch anonymous struct embedding *SecretBox")
	}

	// *types.Union 约束中含 SecretBox 必须被 TypeContains 与 ContainsValueType 共同命中（N3）。
	union := types.NewUnion([]*types.Term{types.NewTerm(false, boxPtr), types.NewTerm(false, types.Typ[types.Int])})
	if !TypeContainsNamed(union, secretPkg.Path(), "SecretBox") {
		t.Fatal("TypeContainsNamed must traverse *types.Union")
	}
	if !ContainsValueNamed(union, secretPkg.Path(), "SecretBox") {
		t.Fatal("ContainsValueNamed must traverse *types.Union")
	}
}
