package violations

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/wentf9/xops-cli/core/domain/pathalg"
)

func allowedPrimitives() {
	_ = os.Stdin
	_ = os.ErrNotExist
	_ = syscall.SIGINT
	_, _ = net.Listen("tcp", "127.0.0.1:0")
	_ = filepath.Join("/tmp", "local")
}

func bannedFileAndSocket(r *os.Root) { // want "core/osfs 之外禁止直接调用裸 OS"
	_, _ = os.Open("a")                            // want "core/osfs 之外禁止直接调用裸 OS"
	_ = os.WriteFile("a", nil, 0o600)              // want "core/osfs 之外禁止直接调用裸 OS"
	_, _ = os.OpenRoot("/tmp")                     // want "core/osfs 之外禁止直接调用裸 OS"
	_, _ = r.Open("b")                             // want "core/osfs 之外禁止调用 os.Root 方法"
	_, _ = syscall.Open("a", 0, 0)                 // want "core/osfs 之外禁止直接调用裸 OS"
	_, _ = net.ListenUnix("unix", &net.UnixAddr{}) // want "core/osfs 之外禁止直接调用裸 OS"
	_, _ = net.Listen("unix", "/tmp/x.sock")       // want "core/osfs 之外禁止直接创建 Unix Domain Socket 监听"
}

func bannedEnvAndExec(ctx context.Context) {
	_ = os.Getenv("SECRET")            // want "internal/host/sys 之外禁止直接调用环境变量或进程执行 API"
	_, _ = os.LookupEnv("SECRET")      // want "internal/host/sys 之外禁止直接调用环境变量或进程执行 API"
	_ = exec.Command("sh", "-c", "id") // want "internal/host/sys 之外禁止直接调用环境变量或进程执行 API"
	_ = exec.CommandContext(ctx, "sh") // want "internal/host/sys 之外禁止直接调用环境变量或进程执行 API"
	_, _ = syscall.Getenv("SECRET")    // want "internal/host/sys 之外禁止直接调用环境变量或进程执行 API"

	var lc net.ListenConfig
	_, _ = lc.Listen(ctx, "tcp", "127.0.0.1:0")
	_, _ = lc.Listen(ctx, "unix", "/tmp/lc.sock")          // want "core/osfs 之外禁止直接创建 Unix Domain Socket 监听"
	_, _ = lc.ListenPacket(ctx, "unixgram", "/tmp/l.sock") // want "core/osfs 之外禁止直接创建 Unix Domain Socket 监听"

	// v2.3.3: 方法表达式 $thunk 与方法值 $bound 均按精确参数槽位拦截
	listenExpr := (*net.ListenConfig).Listen
	_, _ = listenExpr(&lc, ctx, "unix", "/tmp/thunk.sock") // want "core/osfs 之外禁止直接创建 Unix Domain Socket 监听"
	listenBound := lc.ListenPacket
	_, _ = listenBound(ctx, "unixgram", "/tmp/bound.sock") // want "core/osfs 之外禁止直接创建 Unix Domain Socket 监听"
}

type CopyTask struct {
	LocalDir   string
	RemoteDest pathalg.RemotePath
}

func (CopyTask) LocalFile() string { return "a.txt" }

func copyTaskBoundary(task CopyTask) {
	_ = filepath.Join(task.LocalDir, "b")
	_ = filepath.Clean(task.LocalFile())

	positional := CopyTask{"/tmp/local", task.RemoteDest}
	_ = filepath.Join(positional.LocalDir, "c")

	// v2.3.3 B6c: 字段敏感验证——局部结构体字符串字段赋值也不相互污染
	pair := struct {
		Local  string
		Remote string
	}{
		Local:  "/tmp/local",
		Remote: task.RemoteDest.String(),
	}
	_ = filepath.Clean(pair.Local)
	_ = filepath.Clean(pair.Remote) // want "禁止对 RemotePath 调用 path/filepath"

	_ = filepath.Join(task.RemoteDest.String(), "b")    // want "禁止对 RemotePath 调用 path/filepath"
	_ = filepath.Join(fmt.Sprint(task.RemoteDest), "b") // want "禁止对 RemotePath 调用 path/filepath"
}

func remotePathBoundary(rp pathalg.RemotePath) string {
	ok := path.Join(rp.String(), "sub")
	_ = ok

	_ = filepath.Join(rp.String(), "sub") // want "禁止对 RemotePath 调用 path/filepath"
	s1 := rp.String()
	s2 := s1 + "/conf"
	s3 := fmt.Sprintf("%s/app", s2)
	_ = filepath.Clean(s3) // want "禁止对 RemotePath 调用 path/filepath"

	// v2.3.3 M2: 多返回值 path.Split、iter.Seq 与嵌套闭包仅精确报 1 次
	dir, file := path.Split(rp.String())
	_ = filepath.Join(dir, "d") // want "禁止对 RemotePath 调用 path/filepath"
	_ = filepath.Clean(file)    // want "禁止对 RemotePath 调用 path/filepath"

	for seg := range strings.SplitSeq(rp.String(), "/") {
		_ = filepath.Clean(seg) // want "禁止对 RemotePath 调用 path/filepath"
	}

	func() {
		func() {
			_ = filepath.Join(rp.String(), "nested") // want "禁止对 RemotePath 调用 path/filepath"
		}()
	}()

	for _, item := range []string{rp.String()} {
		_ = filepath.Join(item, "range") // want "禁止对 RemotePath 调用 path/filepath"
	}
	return s3
}
