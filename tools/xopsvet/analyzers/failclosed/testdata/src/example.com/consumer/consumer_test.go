package consumer_test

import "example.com/opaquedef"

func externalBlackboxTestBanned() {
	_ = opaquedef.Token{} // want "failclosed: 禁止在包外通过字面量构造 //xops:opaque 类型 Token，请调用导出构造器"
}
