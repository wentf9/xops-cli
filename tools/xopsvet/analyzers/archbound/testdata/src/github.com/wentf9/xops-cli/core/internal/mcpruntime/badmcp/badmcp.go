package badmcp

import "github.com/wentf9/xops-cli/core/ports"

type Ok struct {
	Root ports.ScopedRootFS
}

type BadHolder struct {
	Read ports.OperatorReadFS // want "core/internal/mcpruntime 物理禁止引用 ports.OperatorReadFS"
}

type AliasFS = ports.OperatorReadFS // want "core/internal/mcpruntime 物理禁止引用 ports.OperatorReadFS"

func BadParam(fs ports.OperatorReadFS) { // want "core/internal/mcpruntime 物理禁止引用 ports.OperatorReadFS"
	_ = fs
}

func BadAssert(v any) {
	_ = v.(ports.OperatorReadFS) // want "core/internal/mcpruntime 物理禁止引用 ports.OperatorReadFS"
}

func BadInferred(fn func() ports.OperatorReadFS) { // want "core/internal/mcpruntime 物理禁止引用 ports.OperatorReadFS"
	x := fn() // want "core/internal/mcpruntime 物理禁止引用 ports.OperatorReadFS"
	_ = x
	_ = fn().WithOperatorRead("x") // want "core/internal/mcpruntime 物理禁止引用 ports.OperatorReadFS"
}
