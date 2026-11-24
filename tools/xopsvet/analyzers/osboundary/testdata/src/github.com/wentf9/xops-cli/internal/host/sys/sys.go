package sys

import (
	"context"
	"os"
	"os/exec"
	"syscall"
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

func DisallowedFileInSys() {
	_, _ = os.ReadFile("/etc/hosts") // want "core/osfs 之外禁止直接调用裸 OS"
}
