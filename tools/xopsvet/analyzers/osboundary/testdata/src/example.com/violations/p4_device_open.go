package violations

import "golang.org/x/sys/unix"

func badNonSysUnixDeviceOpen() {
	_, _ = unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0) // want "core/osfs 之外禁止直接调用裸 OS"
	_, _ = unix.Open("/dev/tty", unix.O_RDWR|unix.O_CLOEXEC, 0)     // want "core/osfs 之外禁止直接调用裸 OS"
}
