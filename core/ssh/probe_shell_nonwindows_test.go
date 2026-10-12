//go:build !windows

package ssh

import "os/exec"

func configureProbeShellCommand(_ *exec.Cmd, _ string, _ LaunchDialect, _ string) {}
