package badnet

import (
	"context"
	"net"
	"time"
)

type wrapDialer struct {
	net.Dialer // want "禁止在命名或匿名结构体中嵌入 net.Dialer"
}

type wrapListenConfig struct {
	net.ListenConfig // want "禁止在命名或匿名结构体中嵌入 net.ListenConfig"
}

// H2b 同构换壳克隆必须被防线 3 拦截。
type myDialer net.Dialer // want "禁止通过定义类型同构克隆 net 包结构体 myDialer"

type anyDialer interface {
	Dial(network, address string) (net.Conn, error)
}

func stealGeneric[T any](v T) {
	_ = v
}

func defense1BannedPkgSymbols() {
	_, _ = net.Dial("unix", "/tmp/a.sock")                     // want "禁止使用 net.Dial"
	_, _ = net.DialUnix("unix", nil, nil)                      // want "禁止使用 net.DialUnix"
	_, _ = net.Listen("unix", "/tmp/a.sock")                   // want "禁止使用 net.Listen"
	_, _ = net.ListenPacket("unixgram", "/tmp/a.sock")         // want "禁止使用 net.ListenPacket"
	_, _ = net.DialTimeout("unix", "/tmp/a.sock", time.Second) // want "禁止使用 net.DialTimeout"
	_, _ = net.ListenTCP("tcp", nil)                           // want "禁止使用 net.ListenTCP"
	_ = net.DefaultResolver                                    // want "禁止使用 net.DefaultResolver"
	var _ net.KeepAliveConfig                                  // want "禁止使用 net.KeepAliveConfig"
	var tc *net.TCPConn                                        // want "禁止使用 net.TCPConn"
	_ = tc.Close()                                             // want "禁止调用 net.TCPConn.Close"
}

func defense2ControlledNetworkArgs(ctx context.Context, dynNet string) {
	var d net.Dialer
	_, _ = d.Dial("tcp", "unix")                     // want "禁止调用 net.Dialer.Dial"
	_, _ = d.DialContext(ctx, "tcp", "127.0.0.1:80") // want "禁止调用 net.Dialer.DialContext"
	_, _ = d.DialUnix(ctx, "tcp", nil, nil)          // want "network 参数必须为对应编译期常量"
	_, _ = d.DialUnix(ctx, dynNet, nil, nil)         // want "network 参数必须为对应编译期常量"

	var lc net.ListenConfig
	_, _ = lc.Listen(ctx, "tcp", "127.0.0.1:0")       // want "network 参数必须为对应编译期常量"
	_, _ = lc.ListenPacket(ctx, "udp", "127.0.0.1:0") // want "network 参数必须为对应编译期常量"
	_, _ = net.ListenUnix("unixgram", nil)            // want "network 参数必须为对应编译期常量"
	_, _ = net.ListenUnixgram("unix", nil)            // want "network 参数必须为对应编译期常量"
	_, _ = net.ResolveUnixAddr(dynNet, "/tmp/x.sock") // want "network 参数必须为对应编译期常量"

	listenFn := net.ListenUnix // want "禁止将 net.ListenUnix 用作函数值、方法值或方法表达式"
	_, _ = listenFn("unix", nil)
	dialUnixFn := d.DialUnix // want "禁止将 net.DialUnix 用作函数值、方法值或方法表达式"
	_, _ = dialUnixFn(ctx, "unix", nil, nil)
	_, _ = (*net.Dialer).DialUnix(&d, ctx, "unix", nil, nil) // want "禁止将 net.DialUnix 用作函数值、方法值或方法表达式"
}

func defense3ErasureAnonEmbedAndCompositeLits(ctx context.Context) {
	// CRIT-2: 匿名结构体嵌入 + 接口擦除 + any 泛型擦除必须全部拦截。
	var iface anyDialer = &struct{ net.Dialer }{} // want "禁止在命名或匿名结构体中嵌入 net.Dialer"
	_, _ = iface.Dial("tcp", "1.1.1.1:80")
	var d anyDialer = &net.Dialer{} // want "禁止将 net.Dialer/net.ListenConfig 经接口或泛型实参擦除"
	_, _ = d.Dial("tcp", "1.1.1.1:80")
	stealGeneric(&net.Dialer{}) // want "禁止将 net.Dialer/net.ListenConfig 经接口或泛型实参擦除"

	var raw net.Dialer
	_ = raw.DialTCP                 // want "禁止调用 net.Dialer.DialTCP"
	_ = raw.DialUDP                 // want "禁止调用 net.Dialer.DialUDP"
	_ = raw.DialIP                  // want "禁止调用 net.Dialer.DialIP"
	_ = raw.MultipathTCP()          // want "禁止调用 net.Dialer.MultipathTCP"
	raw.SetMultipathTCP(true)       // want "禁止调用 net.Dialer.SetMultipathTCP"
	raw.DualStack = true            // want "禁止访问受禁 net 结构体字段 DualStack"
	raw.FallbackDelay = time.Second // want "禁止访问受禁 net 结构体字段 FallbackDelay"
	raw.KeepAlive = time.Second     // want "禁止访问受禁 net 结构体字段 KeepAlive"
	_ = raw.KeepAliveConfig         // want "禁止访问受禁 net 结构体字段 KeepAliveConfig"
	raw.Resolver = nil              // want "禁止访问受禁 net 结构体字段 Resolver"

	var lc net.ListenConfig
	_ = lc.MultipathTCP()      // want "禁止调用 net.ListenConfig.MultipathTCP"
	lc.SetMultipathTCP(true)   // want "禁止调用 net.ListenConfig.SetMultipathTCP"
	lc.KeepAlive = time.Second // want "禁止访问受禁 net 结构体字段 KeepAlive"
	_ = lc.KeepAliveConfig     // want "禁止访问受禁 net 结构体字段 KeepAliveConfig"

	var w wrapDialer
	_ = w.DialTCP                                    // want "禁止调用 net.Dialer.DialTCP"
	w.KeepAlive = time.Second                        // want "禁止访问受禁 net 结构体字段 KeepAlive"
	_, _ = w.DialContext(ctx, "tcp", "127.0.0.1:80") // want "禁止调用 net.Dialer.DialContext"

	var wlc wrapListenConfig
	wlc.KeepAlive = time.Second // want "禁止访问受禁 net 结构体字段 KeepAlive"
	wlc.SetMultipathTCP(true)   // want "禁止调用 net.ListenConfig.SetMultipathTCP"

	// 显式与省略类型复合字面量校验。
	_ = net.Dialer{DualStack: true}                                // want "禁止在 net.Dialer 字面量中初始化受禁字段"
	_ = []net.Dialer{{DualStack: true}}                            // want "禁止在 net.Dialer 字面量中初始化受禁字段"
	_ = []*net.Dialer{{KeepAlive: time.Second}}                    // want "禁止在 net.Dialer 字面量中初始化受禁字段"
	_ = map[string]net.ListenConfig{"a": {KeepAlive: time.Second}} // want "禁止在 net.ListenConfig 字面量中初始化受禁字段"
}
