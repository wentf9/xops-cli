package opaquedef

//xops:opaque
type Token struct { // want Token:"opaque"
	id string
}

//xops:opaque
type Box[T any] struct { // want Box:"opaque"
	val T
}

//xops:opaque
type OpID string // want OpID:"opaque"

func NewToken() Token {
	return Token{id: "ok"}
}

func NewOpID() OpID {
	return OpID("op-1")
}
