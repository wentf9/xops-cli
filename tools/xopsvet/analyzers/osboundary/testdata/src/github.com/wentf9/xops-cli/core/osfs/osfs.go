package osfs

import (
	"net"
	"os"
	"os/exec"
	"syscall"
)

func OpenSafeRoot(dir string) (*os.Root, error) {
	return os.OpenRoot(dir)
}

func UseAllowedOSFS(r *os.Root, sock string) error {
	f, err := r.Open("data.txt")
	if err == nil {
		_ = f.Close()
	}
	_, _ = syscall.Open("data.txt", 0, 0)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err == nil {
		_ = ln.Close()
	}
	ln2, err := net.Listen("unix", sock)
	if err == nil {
		_ = ln2.Close()
	}
	return nil
}

func DisallowedEnvExecInOSFS() {
	_ = os.Getenv("HOME")     // want "internal/host/sys 之外禁止直接调用环境变量或进程执行 API"
	_ = exec.Command("false") // want "internal/host/sys 之外禁止直接调用环境变量或进程执行 API"
}
