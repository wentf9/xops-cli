//go:build integration && linux && amd64

package kdfhelper

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

func TestKDFProcessWorker(t *testing.T) {
	mode := os.Args[len(os.Args)-1]
	if !strings.HasPrefix(mode, "worker-") {
		return
	}
	switch mode {
	case "worker-valid":
		os.Exit(ServeFiles(os.Stdin, os.Stdout))
	case "worker-stall":
		time.Sleep(10 * time.Second)
		os.Exit(1)
	case "worker-memory":
		// Wait for the runner to install the private cgroup before allocation.
		request, err := io.ReadAll(io.LimitReader(os.Stdin, MaxRequestBytes+1))
		clear(request)
		if err != nil {
			os.Exit(1)
		}
		b := make([]byte, 256*1024*1024)
		for i := 0; i < len(b); i += 4096 {
			b[i] = 0x42
		}
		runtime.KeepAlive(b)
		os.Exit(1)
	}
	b, err := io.ReadAll(io.LimitReader(os.Stdin, MaxRequestBytes+1))
	if err != nil {
		os.Exit(1)
	}
	clear(b)
	response, err := (Response{Status: Success, Key: bytes.Repeat([]byte{0x42}, 32)}).MarshalBinary()
	if err != nil {
		os.Exit(1)
	}
	switch mode {
	case "worker-extra":
		response = append(response, response...)
	case "worker-stderr":
		if _, err := os.Stderr.Write(bytes.Repeat([]byte("sensitive-diagnostic"), 512)); err != nil {
			os.Exit(1)
		}
	}
	if _, err := os.Stdout.Write(response); err != nil {
		os.Exit(1)
	}
	clear(response)
	if mode == "worker-badexit" {
		os.Exit(2)
	}
	os.Exit(0)
}

func TestRunnerNativeAndFailureBoundaries(t *testing.T) {
	v := fixtures(t)
	var salt [16]byte
	copy(salt[:], v["salt"])
	req := Request{Salt: salt, Password: v["password"]}
	for _, tc := range []struct {
		name    string
		timeout time.Duration
		valid   bool
	}{
		{"valid", 5 * time.Second, true}, {"extra", 5 * time.Second, false}, {"badexit", 5 * time.Second, false}, {"stderr", 5 * time.Second, false}, {"stall", 100 * time.Millisecond, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Runner{Timeout: tc.timeout}
			key, err := r.run(t.Context(), req, os.Args[0], []string{"-test.run=^TestKDFProcessWorker$", "--", "worker-" + tc.name})
			defer clear(key)
			if tc.valid {
				if err != nil || !bytes.Equal(key, v["password_key"]) {
					t.Fatalf("native KDF vector: %v", err)
				}
				return
			}
			if err == nil || key != nil {
				t.Fatal("accepted failed process output")
			}
			if strings.Contains(err.Error(), "sensitive-diagnostic") {
				t.Fatal("stderr leaked")
			}
			if tc.name == "stall" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("timeout cause: %v", err)
			}
		})
	}
}

func TestRunnerRejectsFakeCgroup(t *testing.T) {
	path := t.TempDir()
	if _, err := createLimit(path); !errors.Is(err, ErrResource) {
		t.Fatalf("ordinary directory accepted as kernel limit: %v", err)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("fake cgroup files created")
	}
}

func TestRunnerDelegatedMemoryLimit(t *testing.T) {
	uid := os.Geteuid()
	parent := fmt.Sprintf("/sys/fs/cgroup/user.slice/user-%d.slice/user@%d.service", uid, uid)
	if err := unix.Access(parent, unix.W_OK); err != nil {
		t.Skip("no delegated per-user cgroup")
	}
	probe, err := createLimit(parent)
	if err != nil {
		t.Skipf("memory controller not delegated: %v", err)
	}
	if err := removeLimit(probe); err != nil {
		t.Fatal(err)
	}
	v := fixtures(t)
	var salt [16]byte
	copy(salt[:], v["salt"])
	r := Runner{Timeout: 5 * time.Second, CgroupParent: parent}
	req := Request{Salt: salt, Password: v["password"]}
	executable, args := os.Args[0], []string{"-test.run=^TestKDFProcessWorker$", "--", "worker-valid"}
	if cli := os.Getenv("XOPS_TEST_CLI_PATH"); cli != "" {
		executable, args = cli, []string{PrivateArgument}
	}
	key, err := r.run(t.Context(), req, executable, args)
	defer clear(key)
	if errors.Is(err, os.ErrPermission) {
		t.Skipf("test process is outside delegated subtree: %v", err)
	}
	if err != nil || !bytes.Equal(key, v["password_key"]) {
		t.Fatalf("bounded native KDF: %v", err)
	}
	key, err = r.run(t.Context(), req, os.Args[0], []string{"-test.run=^TestKDFProcessWorker$", "--", "worker-memory"})
	clear(key)
	if !errors.Is(err, ErrResource) {
		t.Fatalf("cgroup OOM not classified: %v", err)
	}
	entries, err := filepath.Glob(filepath.Join(parent, "xops-kdf-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("private cgroup not cleaned up")
	}
}
