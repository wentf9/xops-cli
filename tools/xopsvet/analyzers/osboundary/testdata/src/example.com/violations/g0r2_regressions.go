package violations

import (
	"context"
	"net"
	"path/filepath"

	"github.com/wentf9/xops-cli/core/domain/pathalg"
)

type copyTask struct {
	Remote   pathalg.RemotePath
	LocalDir string
}

// OkStructLocalFieldNotTainted 验证 RemotePath 不污染同结构体内的本地字段（B-6）。
func OkStructLocalFieldNotTainted(rp pathalg.RemotePath, local string) string {
	task := copyTask{Remote: rp, LocalDir: local}
	return filepath.Join(task.LocalDir, "file.txt")
}

// BadStructNestedAndMapRemotePath 验证嵌套字段、map 与闭包字段投影传播 RemotePath 必须拦截（H4）。
func BadStructNestedAndMapRemotePath(rp pathalg.RemotePath, local string) {
	type inner struct{ Raw string }
	type outer struct{ In inner }
	task := copyTask{Remote: rp, LocalDir: local}
	_ = filepath.Join(task.Remote.String(), "a") // want "禁止对 RemotePath 调用 path/filepath\\.\\*"

	o := outer{In: inner{Raw: rp.String()}}
	_ = filepath.Clean(o.In.Raw) // want "禁止对 RemotePath 调用 path/filepath\\.\\*"

	m := map[string]string{"k": rp.String()}
	_ = filepath.Base(m["k"]) // want "禁止对 RemotePath 调用 path/filepath\\.\\*"

	fn := func() {
		_ = filepath.Dir(o.In.Raw) // want "禁止对 RemotePath 调用 path/filepath\\.\\*"
	}
	fn()
}

type narrowListenerConfig interface {
	Listen(ctx context.Context, network, address string) (net.Listener, error)
}

// BadPhiAndNarrowInterfaceUnixListen 验证 Phi 函数/网络名与窄接口 ListenConfig 创建 AF_UNIX 必须拦截（H5）。
func BadPhiAndNarrowInterfaceUnixListen(cond bool, addr string) {
	netName := "unix"
	if cond {
		netName = "unixpacket"
	}
	fn := net.Listen
	_, _ = fn(netName, addr) // want "白名单包 core/osfs 之外禁止直接创建 Unix Domain Socket 监听"

	var lc narrowListenerConfig = &net.ListenConfig{}
	_, _ = lc.Listen(context.Background(), "unix", addr) // want "白名单包 core/osfs 之外禁止直接创建 Unix Domain Socket 监听"
}
