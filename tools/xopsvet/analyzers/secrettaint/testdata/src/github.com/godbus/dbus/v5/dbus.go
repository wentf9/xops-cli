package dbus

import "context"

type Flags byte
type ObjectPath string
type Variant struct{}
type Call struct{ Err error }

type BusObject interface {
	Call(method string, flags Flags, args ...any) *Call
	CallWithContext(ctx context.Context, method string, flags Flags, args ...any) *Call
}

type Object struct{}

func (*Object) Call(method string, flags Flags, args ...any) *Call { return &Call{} }
func (*Object) CallWithContext(ctx context.Context, method string, flags Flags, args ...any) *Call {
	return &Call{}
}
