package badnet

import . "net"

func dotImportBypassAttempts() {
	_, _ = Dial("unix", "/tmp/dot.sock") // want "禁止使用 net.Dial"
	_, _ = Listen("tcp", "127.0.0.1:0")  // want "禁止使用 net.Listen"
	_, _ = ListenUnix("unixgram", nil)   // want "network 参数必须为对应编译期常量"
	fn := ListenUnix                     // want "禁止将 net.ListenUnix 用作函数值、方法值或方法表达式"
	_, _ = fn("unix", nil)
}
