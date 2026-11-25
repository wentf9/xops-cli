package windows

type LazyProc struct{}

func (*LazyProc) Call(a ...uintptr) (uintptr, uintptr, error) {
	return 0, 0, nil
}
