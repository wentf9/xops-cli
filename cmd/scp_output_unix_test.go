//go:build linux || darwin

package cmd

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSCPProgressProbePreservesPipeFlags(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer closeSCPTestResource(t, reader)
	defer closeSCPTestResource(t, writer)
	raw, err := writer.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	flags := func() int {
		t.Helper()
		var value int
		var readErr error
		if err := raw.Control(func(fd uintptr) { value, readErr = unix.FcntlInt(fd, unix.F_GETFL, 0) }); err != nil {
			t.Fatal(err)
		}
		if readErr != nil {
			t.Fatal(readErr)
		}
		return value
	}
	before := flags()
	if before&unix.O_NONBLOCK == 0 {
		t.Fatal("Go pipe fixture is blocking")
	}
	stdout, stderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = writer, writer
	defer func() { os.Stdout, os.Stderr = stdout, stderr }()
	if NewScpOptions().progressEnabled() {
		t.Fatal("pipe reported as a progress terminal")
	}
	if flags() != before {
		t.Fatal("terminal detection changed borrowed pipe flags")
	}
}
