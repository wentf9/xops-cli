package badnet

import (
	"context"
	"net"
	"time"
)

type wrapDialer struct {
	net.Dialer
}

type wrapListenConfig struct {
	net.ListenConfig
}

func defense1BannedPkgSymbols() {
	_, _ = net.Dial("unix", "/tmp/a.sock") // want "禁止使用 net.Dial"
	_, _ = net.ListenTCP("tcp", nil)       // want "禁止使用 net.ListenTCP"
	_ = net.DefaultResolver                // want "禁止使用 net.DefaultResolver"
	var _ net.KeepAliveConfig              // want "禁止使用 net.KeepAliveConfig"
	var tc *net.TCPConn                    // want "禁止使用 net.TCPConn"
	_ = tc.Close()                         // want "禁止调用 net.TCPConn.Close"
}

func defense2ControlledNetworkArgs(ctx context.Context, dynNet string) {
	_, _ = net.Listen("tcp", "127.0.0.1:0")                         // want "network 参数必须为编译期常量 unix/unixpacket/unixgram"
	_, _ = net.ListenPacket("udp", "127.0.0.1:0")                   // want "network 参数必须为编译期常量 unix/unixpacket/unixgram"
	_, _ = net.DialTimeout("tcp", "127.0.0.1:80", time.Second)      // want "network 参数必须为编译期常量 unix/unixpacket/unixgram"
	_, _ = net.Listen(dynNet, "/tmp/dyn.sock")                      // want "network 参数必须为编译期常量 unix/unixpacket/unixgram"

	var d net.Dialer
	_, _ = d.Dial("tcp", "unix")                                    // want "network 参数必须为编译期常量 unix/unixpacket/unixgram"
	_, _ = d.DialContext(ctx, "tcp", "127.0.0.1:80")                // want "network 参数必须为编译期常量 unix/unixpacket/unixgram"

	var lc net.ListenConfig
	_, _ = lc.Listen(ctx, "tcp", "127.0.0.1:0")                     // want "network 参数必须为编译期常量 unix/unixpacket/unixgram"
	_, _ = lc.ListenPacket(ctx, "udp", "127.0.0.1:0")               // want "network 参数必须为编译期常量 unix/unixpacket/unixgram"

	listenFn := net.Listen                                          // want "禁止将 net.Listen 用作函数值、方法值或方法表达式"
	_, _ = listenFn("unix", "/tmp/fn.sock")
	dialCtxFn := d.DialContext                                      // want "禁止将 net.DialContext 用作函数值、方法值或方法表达式"
	_, _ = dialCtxFn(ctx, "unix", "/tmp/m.sock")
	_, _ = (*net.Dialer).Dial(&d, "unix", "/tmp/mexpr.sock")        // want "禁止将 net.Dial 用作函数值、方法值或方法表达式"
}

func defense3MembersEmbeddingAndCompositeLits(ctx context.Context) {
	var d net.Dialer
	_ = d.DialTCP                                                   // want "禁止调用 net.Dialer.DialTCP"
	_ = d.DialUDP                                                   // want "禁止调用 net.Dialer.DialUDP"
	_ = d.DialIP                                                    // want "禁止调用 net.Dialer.DialIP"
	_ = d.MultipathTCP()                                            // want "禁止调用 net.Dialer.MultipathTCP"
	d.SetMultipathTCP(true)                                         // want "禁止调用 net.Dialer.SetMultipathTCP"
	d.DualStack = true                                              // want "禁止访问受禁 net 结构体字段 DualStack"
	d.FallbackDelay = time.Second                                   // want "禁止访问受禁 net 结构体字段 FallbackDelay"
	d.KeepAlive = time.Second                                       // want "禁止访问受禁 net 结构体字段 KeepAlive"
	_ = d.KeepAliveConfig                                           // want "禁止访问受禁 net 结构体字段 KeepAliveConfig"
	d.Resolver = nil                                                // want "禁止访问受禁 net 结构体字段 Resolver"

	var lc net.ListenConfig
	_ = lc.MultipathTCP()                                           // want "禁止调用 net.ListenConfig.MultipathTCP"
	lc.SetMultipathTCP(true)                                        // want "禁止调用 net.ListenConfig.SetMultipathTCP"
	lc.KeepAlive = time.Second                                      // want "禁止访问受禁 net 结构体字段 KeepAlive"
	_ = lc.KeepAliveConfig                                          // want "禁止访问受禁 net 结构体字段 KeepAliveConfig"

	// 穿透嵌入结构体绕过验证。
	var w wrapDialer
	_ = w.DialTCP                                                   // want "禁止调用 net.Dialer.DialTCP"
	w.KeepAlive = time.Second                                       // want "禁止访问受禁 net 结构体字段 KeepAlive"
	w.DualStack = true                                              // want "禁止访问受禁 net 结构体字段 DualStack"
	w.SetMultipathTCP(true)                                         // want "禁止调用 net.Dialer.SetMultipathTCP"
	_, _ = w.Dial("tcp", "unix")                                    // want "network 参数必须为编译期常量 unix/unixpacket/unixgram"
	_, _ = w.DialContext(ctx, "tcp", "127.0.0.1:80")                // want "network 参数必须为编译期常量 unix/unixpacket/unixgram"

	var wlc wrapListenConfig
	wlc.KeepAlive = time.Second                                     // want "禁止访问受禁 net 结构体字段 KeepAlive"
	wlc.SetMultipathTCP(true)                                       // want "禁止调用 net.ListenConfig.SetMultipathTCP"

	// 显式与省略类型复合字面量校验。
	_ = net.Dialer{DualStack: true}                                 // want "禁止在 net.Dialer 字面量中初始化受禁字段"
	_ = []net.Dialer{{DualStack: true}}                             // want "禁止在 net.Dialer 字面量中初始化受禁字段"
	_ = []*net.Dialer{{KeepAlive: time.Second}}                     // want "禁止在 net.Dialer 字面量中初始化受禁字段"
	_ = map[string]net.ListenConfig{"a": {KeepAlive: time.Second}}  // want "禁止在 net.ListenConfig 字面量中初始化受禁字段"
}
