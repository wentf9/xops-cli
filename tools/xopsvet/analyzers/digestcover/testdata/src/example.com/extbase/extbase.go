package extbase

import "io"

type ExtBase struct {
	Public string
	secret int
}

func (e ExtBase) WriteCanonical(w io.Writer) {
	_, _ = io.WriteString(w, e.Public)
	_ = byte(e.secret)
}
