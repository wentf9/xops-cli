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

// Challenge 1: 非空超集/等价接口不可绕过穷尽检查，但严格子集子接口仍允许。
type RichSealed interface {
	sealedRich()
	Tag() string
}

type RichA struct{}

func (RichA) sealedRich() {}
func (RichA) Tag() string { return "A" }

type RichB struct{}

func (RichB) sealedRich() {}
func (RichB) Tag() string { return "B" }

func checkSamePkgSealedSubIfaceBypass(r RichSealed) string {
	switch r.(type) { // want "sumexhaust: 对封闭接口 RichSealed 的 type switch 缺少变体: RichA, \\*RichA, RichB, \\*RichB"
	case interface{ sealedRich() }:
		return "bypass"
	default:
		return "none"
	}
}

type Outcome interface {
	sealedOutcome()
}

type RetryableOutcome interface {
	isRetryable()
}

type OutcomeTimeout struct{}

func (*OutcomeTimeout) sealedOutcome() {}
func (*OutcomeTimeout) isRetryable()   {}

type OutcomeOK struct{}

func (*OutcomeOK) sealedOutcome() {}

func checkStrictSubsetSubInterfaceAllowed(o Outcome) string {
	switch o.(type) {
	case RetryableOutcome, *OutcomeOK:
		return "ok"
	default:
		return "none"
	}
}

// Challenge 6: 多类型参数泛型变体实现单类型参数泛型封闭接口。
type GenMultiBox[T any] interface {
	sealedGenMulti()
}

type SingleParam[T any] struct{ V T }

func (*SingleParam[T]) sealedGenMulti() {}

type MultiParam[A, B any] struct {
	First  A
	Second B
}

func (*MultiParam[A, B]) sealedGenMulti() {}

type MultiVal[A, B any] struct {
	First  A
	Second B
}

func (MultiVal[A, B]) sealedGenMulti() {}

func checkMultiArityValid(g GenMultiBox[int]) int {
	switch g.(type) {
	case *SingleParam[int], *MultiParam[int, string], MultiVal[int, bool], *MultiVal[int, bool]:
		return 1
	default:
		return 0
	}
}

func checkMultiArityMissing(g GenMultiBox[int]) int {
	switch g.(type) { // want "sumexhaust: 对封闭接口 GenMultiBox\\[int\\] 的 type switch 缺少变体: \\*MultiParam\\[A, B any\\], \\*MultiVal\\[A, B any\\]"
	case *SingleParam[int], MultiVal[int, bool]:
		return 1
	default:
		return 0
	}
}
