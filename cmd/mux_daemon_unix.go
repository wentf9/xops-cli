//go:build !windows

package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
)

func startMuxDaemonCommand(exe string, spec MuxDaemonSpec, devNull *os.File) (*exec.Cmd, error) {
	return startMuxDaemonCommandWithPrefix(exe, []string{"ssh"}, spec, devNull)
}

func startMuxDaemonCommandWithPrefix(exe string, prefixArgs []string, spec MuxDaemonSpec, devNull *os.File) (*exec.Cmd, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(spec)
	if err != nil {
		return nil, fmt.Errorf("marshal mux daemon spec failed: %w", err)
	}
	if len(payload) > maxMuxDaemonSpecBytes {
		return nil, fmt.Errorf("mux daemon spec exceeds %d byte limit", maxMuxDaemonSpecBytes)
	}
	r, w, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("create mux daemon spec pipe failed: %w", err)
	}
	args := make([]string, 0, len(prefixArgs)+2)
	args = append(args, prefixArgs...)
	args = append(args, "--"+muxDaemonSpecFDFlag, "3")
	cmd := exec.Command(exe, args...)
	cmd.Env = append(os.Environ(), sshMuxDaemonEnv+"=true", sshBackgroundChildEnv+"=true")
	cmd.Stdin = devNull
	cmd.Stdout = devNull
	cmd.Stderr = devNull
	cmd.ExtraFiles = []*os.File{r}
	if err := startDaemonProcess(cmd); err != nil {
		_ = r.Close()
		_ = w.Close()
		return nil, err
	}
	_ = r.Close()
	go func() {
		defer func() { _ = w.Close() }()
		_, _ = w.Write(payload)
	}()
	return cmd, nil
}

func readMuxDaemonSpecFromFD(fd int) (MuxDaemonSpec, error) {
	if fd != 3 {
		return MuxDaemonSpec{}, fmt.Errorf("invalid mux daemon spec descriptor %d", fd)
	}
	f := os.NewFile(uintptr(fd), "mux-daemon-spec")
	if f == nil {
		return MuxDaemonSpec{}, fmt.Errorf("open mux daemon spec descriptor %d failed", fd)
	}
	defer func() { _ = f.Close() }()
	return readMuxDaemonSpec(f)
}
