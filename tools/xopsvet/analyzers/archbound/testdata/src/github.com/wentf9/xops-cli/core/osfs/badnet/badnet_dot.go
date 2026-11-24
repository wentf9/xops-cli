package badnet

import . "net"

func dotImportBypassAttempts() {
	_, _ = Dial("unix", "/tmp/dot.sock") // want "禁止使用 net.Dial"
	_, _ = Listen("tcp", "127.0.0.1:0")  // want "network 参数必须为编译期常量 unix/unixpacket/unixgram"
	fn := Listen                         // want "禁止将 net.Listen 用作函数值、方法值或方法表达式"
	_, _ = fn("unix", "/tmp/dotfn.sock")
}
