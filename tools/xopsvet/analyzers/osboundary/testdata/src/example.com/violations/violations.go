package violations

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
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
	_, _ = os.Open("a")                              // want "core/osfs 之外禁止直接调用裸 OS"
	_ = os.WriteFile("a", nil, 0o600)                // want "core/osfs 之外禁止直接调用裸 OS"
	_, _ = os.OpenRoot("/tmp")                       // want "core/osfs 之外禁止直接调用裸 OS"
	_, _ = r.Open("b")                               // want "core/osfs 之外禁止调用 os.Root 方法"
	_ = syscall.Flock(0, syscall.LOCK_EX)            // want "core/osfs 之外禁止直接调用裸 OS"
	_, _ = net.ListenUnix("unix", &net.UnixAddr{})   // want "core/osfs 之外禁止直接调用裸 OS"
	_, _ = net.Listen("unix", "/tmp/x.sock")         // want "core/osfs 之外禁止直接创建 Unix Domain Socket 监听"
}

func bannedEnvAndExec(ctx context.Context) {
	_ = os.Getenv("SECRET")             // want "internal/host/sys 之外禁止直接调用环境变量或进程执行 API"
	_, _ = os.LookupEnv("SECRET")       // want "internal/host/sys 之外禁止直接调用环境变量或进程执行 API"
	_ = exec.Command("sh", "-c", "id")  // want "internal/host/sys 之外禁止直接调用环境变量或进程执行 API"
	_ = exec.CommandContext(ctx, "sh")  // want "internal/host/sys 之外禁止直接调用环境变量或进程执行 API"
	_, _ = syscall.Getenv("SECRET")     // want "internal/host/sys 之外禁止直接调用环境变量或进程执行 API"
}

func remotePathBoundary(rp pathalg.RemotePath) string {
	ok := path.Join(rp.String(), "sub")
	_ = ok

	_ = filepath.Join(rp.String(), "sub") // want "禁止对 RemotePath 调用 path/filepath"
	s1 := rp.String()
	s2 := s1 + "/conf"
	s3 := fmt.Sprintf("%s/app", s2)
	_ = filepath.Clean(s3) // want "禁止对 RemotePath 调用 path/filepath"
	return s3
}
