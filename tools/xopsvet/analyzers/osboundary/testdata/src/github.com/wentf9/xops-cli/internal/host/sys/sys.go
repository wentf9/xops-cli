package sys

import (
	"context"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
	"golang.org/x/sys/windows"
)

func AllowedEnvAndExec(ctx context.Context) error {
	_ = os.Getenv("PATH")
	_, _ = os.LookupEnv("HOME")
	_ = os.Setenv("K", "V")
	_ = os.Unsetenv("K")
	_ = os.Environ()
	_ = os.ExpandEnv("$HOME")
	_ = syscall.Environ()
	_ = exec.Command("echo", "hi")
	_ = exec.CommandContext(ctx, "echo", "hi")
	_, _ = exec.LookPath("sh")
	return nil
}

func AllowedNarrowDeviceOpen() {
	_, _ = unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	_, _ = unix.Open("/dev/tty", unix.O_RDWR|unix.O_CLOEXEC, 0)
}

func DisallowedFileAndDeviceOpen(dynPath string, dynFlags int) {
	_, _ = os.ReadFile("/etc/hosts") // want "core/osfs 之外禁止直接调用裸 OS"
	_, _ = unix.Open("/etc/passwd", unix.O_RDONLY|unix.O_CLOEXEC, 0)         // want "core/osfs 之外禁止直接调用裸 OS"
	_, _ = unix.Open(dynPath, unix.O_RDWR|unix.O_CLOEXEC, 0)                 // want "core/osfs 之外禁止直接调用裸 OS"
	_, _ = unix.Open("/dev/net/tun", unix.O_RDWR, 0)                         // want "core/osfs 之外禁止直接调用裸 OS"
	_, _ = unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC|unix.O_CREAT, 0) // want "core/osfs 之外禁止直接调用裸 OS"
	_, _ = unix.Open("/dev/tty", dynFlags, 0)                                // want "core/osfs 之外禁止直接调用裸 OS"
	fn := unix.Open                                                          // want "core/osfs 之外禁止直接调用裸 OS"
	_, _ = fn("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	_, _ = unix.Openat(0, "/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)     // want "core/osfs 之外禁止直接调用裸 OS"
	var st unix.Stat_t
	_ = unix.Fstat(0, &st) // want "core/osfs 之外禁止直接调用裸 OS"
	_ = os.NewFile(0, "tun") // want "core/osfs 之外禁止直接调用裸 OS"
	_, _ = windows.CreateFile(nil, 0, 0, nil, windows.OPEN_EXISTING, 0, 0) // want "core/osfs 之外禁止直接调用裸 OS"
	_, _ = windows.GetSecurityInfo(0, windows.SE_KERNEL_OBJECT, 0)         // want "core/osfs 之外禁止直接调用裸 OS"
}
