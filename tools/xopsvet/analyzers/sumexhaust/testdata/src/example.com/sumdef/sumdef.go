package sumdef

// Test value-receiver, pointer-receiver, mixin, alias, generic, and //xops:failclosed.

type AuthMethod interface {
	sealedAuth()
}

type AuthPassword struct{}

func (AuthPassword) sealedAuth() {}

type AuthKey struct{}

func (*AuthKey) sealedAuth() {}

type AuthPasswordAlias = AuthPassword

type Capability interface {
	sealedCapability()
}

type sealedCapMarker struct{}

func (sealedCapMarker) sealedCapability() {}

type CapInspect struct{ sealedCapMarker }
type CapExecute struct{ sealedCapMarker }

type GenSealed[T any] interface {
	sealedGen()
}

type GenBox[T any] struct{ V T }

func (*GenBox[T]) sealedGen() {}

type GenOther[T any] struct{}

func (*GenOther[T]) sealedGen() {}

//xops:failclosed
type StepAction interface { // want StepAction:"failclosedsum"
	sealedStep()
}

type StepShell struct{}

func (*StepShell) sealedStep() {}

type StepScript struct{}

func (*StepScript) sealedStep() {}

func checkSamePkgValid(a AuthMethod) string {
	switch a.(type) {
	case AuthPasswordAlias, *AuthPassword, *AuthKey:
		return "ok"
	default:
		return "unknown"
	}
}

func checkMissingPtrForValueRecv(a AuthMethod) string {
	switch a.(type) { // want "sumexhaust: 对封闭接口 AuthMethod 的 type switch 缺少变体: \\*AuthPassword"
	case AuthPassword, *AuthKey:
		return "missing ptr"
	default:
		return "unknown"
	}
}

func checkAntiBypass(a AuthMethod) string {
	switch a.(type) { // want "sumexhaust: 对封闭接口 AuthMethod 的 type switch 缺少变体: \\*AuthKey, AuthPassword, \\*AuthPassword"
	case any, nil:
		return "bypass"
	default:
		return "unknown"
	}
}

func checkCapabilityMixinIgnored(c Capability) bool {
	switch c.(type) {
	case CapInspect, *CapInspect, CapExecute, *CapExecute:
		return true
	default:
		return false
	}
}

func checkGenericSealed(g GenSealed[int]) int {
	switch v := g.(type) {
	case *GenBox[int]:
		return v.V
	case *GenOther[int]:
		return 0
	default:
		return -1
	}
}

func checkGenericMissing(g GenSealed[int]) int {
	switch v := g.(type) { // want "sumexhaust: 对封闭接口 GenSealed\\[int\\] 的 type switch 缺少变体: \\*GenOther\\[int\\]"
	case *GenBox[int]:
		return v.V
	default:
		return -1
	}
}
