package consumer

import "example.com/opaquedef"

// BadImplicitOpaqueConst 验证未导出标量 //xops:opaque 经隐式无类型常量赋值绕过构造器必须拦截（M7）。
func BadImplicitOpaqueConst() opaquedef.OpID {
	var id opaquedef.OpID = "raw-implicit" // want "禁止在包外通过无类型常量隐式构造 //xops:opaque 类型 OpID"
	return id
}
