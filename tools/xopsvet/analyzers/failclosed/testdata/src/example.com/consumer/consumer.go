package consumer

import "example.com/opaquedef"

type TokenAlias = opaquedef.Token

type Holder struct {
	T opaquedef.Token
}

func validUses(existing opaquedef.OpID) {
	t := opaquedef.NewToken()
	_ = t
	_ = new(opaquedef.NewToken())
	_ = new(*opaquedef.Token)
	_ = opaquedef.OpID(existing)
	var zeroDecl opaquedef.Token
	_ = zeroDecl
}

func badConstructions() {
	_ = opaquedef.Token{} // want "failclosed: 禁止在包外通过字面量构造 //xops:opaque 类型 Token，请调用导出构造器"
	_ = &opaquedef.Token{} // want "failclosed: 禁止在包外通过字面量构造 //xops:opaque 类型 Token，请调用导出构造器"
	_ = TokenAlias{} // want "failclosed: 禁止在包外通过字面量构造 //xops:opaque 类型 Token，请调用导出构造器"
	_ = opaquedef.Box[int]{} // want "failclosed: 禁止在包外通过字面量构造 //xops:opaque 类型 Box，请调用导出构造器"
	_ = []opaquedef.Token{{}} // want "failclosed: 禁止在包外通过字面量构造 //xops:opaque 类型 Token，请调用导出构造器"
	_ = []*opaquedef.Token{{}} // want "failclosed: 禁止在包外通过字面量构造 //xops:opaque 类型 Token，请调用导出构造器"
	_ = map[string]opaquedef.Token{"k": {}} // want "failclosed: 禁止在包外通过字面量构造 //xops:opaque 类型 Token，请调用导出构造器"
	_ = Holder{T: opaquedef.Token{}} // want "failclosed: 禁止在包外通过字面量构造 //xops:opaque 类型 Token，请调用导出构造器"
	_ = new(opaquedef.Token) // want "failclosed: 禁止在包外通过 new\\(Token\\) 构造 //xops:opaque 类型，请调用导出构造器"
	_ = opaquedef.OpID("raw") // want "failclosed: 禁止在包外通过类型转换构造 //xops:opaque 类型 OpID，请调用导出构造器"
}
