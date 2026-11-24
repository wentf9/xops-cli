package conc

type Handle struct{ id int }

func Spawn(fn func()) {
	go fn()
}

//xops:borrowed
func WithHandle(fn func(h *Handle)) { // want WithHandle:"syncclosure,borrowed"
	h := &Handle{id: 1}
	fn(h)
}

var leaked *Handle

func badGoCapture() {
	WithHandle(func(h *Handle) {
		go func() { // want "禁止在 go 语句中调用捕获了 //xops:borrowed 变量的闭包"
			_ = h.id
		}()
	})
}

func badDirectEscape(
	//xops:borrowed
	h *Handle,
) {
	leaked = h // want "禁止将 //xops:borrowed 借用变量逃逸"
}
