package badnet

import "net"

// ExportedDialerHolder 导出 net.Dialer 字段被转入接口时，因调用方可绕过受控封装必须拦截（B-2/AB-3）。
type ExportedDialerHolder struct {
	Dialer net.Dialer
}

func (ExportedDialerHolder) Touch() {}

type touchable interface{ Touch() }

func BadExportedNetFieldInInterface() touchable {
	var h ExportedDialerHolder
	return h // want "禁止将 net\\.Dialer/net\\.ListenConfig 经接口或泛型实参擦除"
}
