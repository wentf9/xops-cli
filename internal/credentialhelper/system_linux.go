//go:build linux

package credentialhelper

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/wentf9/xops-cli/pkg/credential"
)

func resolveDefaultSystemHelper() (string, error) {
	if p, err := exec.LookPath(DefaultSystemHelperCommand); err == nil {
		return p, nil
	}
	// 在没有预安装外部 helper 且处于 headless 环境时报错
	if err := checkPlatformSystemAvailability(); err != nil {
		return "", err
	}
	return DefaultSystemHelperCommand, nil
}

func checkPlatformSystemAvailability() error {
	// Linux Secret Service 强依赖桌面 D-Bus 会话
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" && os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		return fmt.Errorf("%w: system credential store unavailable in headless environment without D-Bus session", credential.ErrCredentialStoreUnavailable)
	}
	return nil
}
