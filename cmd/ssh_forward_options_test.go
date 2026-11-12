package cmd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/concurrent"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/internal/sshenv"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/models"
	cryptoSSH "golang.org/x/crypto/ssh"
)

// -----------------------------------------------------------------------------
// Matrix 1: CLI Flag Registration & Ordering Semantics
// -----------------------------------------------------------------------------

func TestSSHForward_DuplicateStdioForward(t *testing.T) {
	opts := NewSshOptions()
	cmd := newCmdSshWithOptions(opts)
	err := cmd.ParseFlags([]string{"-W", "host1:80", "-W", "host2:80"})
	if err == nil {
		t.Fatal("expected error on duplicate -W flag, got nil")
	}
	if !strings.Contains(err.Error(), "cannot be specified multiple times") {
		t.Fatalf("expected error mentioning 'cannot be specified multiple times', got: %v", err)
	}
}

func TestSSHForward_TunnelOrdering(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantDev     string
		wantSpec    string
		wantMode    ssh.TunnelMode
		wantDevNorm string
		wantOptMode string
	}{
		{
			name:        "-w 0:1 defaults to point-to-point",
			args:        []string{"-w", "0:1"},
			wantDev:     "0:1",
			wantSpec:    "0:1",
			wantMode:    ssh.TunnelModePointToPoint,
			wantDevNorm: "0:1",
			wantOptMode: string(ssh.TunnelModePointToPoint),
		},
		{
			name:        "-w 0 normalizes to 0:any",
			args:        []string{"-w", "0"},
			wantDev:     "0",
			wantSpec:    "0:any",
			wantMode:    ssh.TunnelModePointToPoint,
			wantDevNorm: "0:any",
			wantOptMode: string(ssh.TunnelModePointToPoint),
		},
		{
			name:        "-o Tunnel=ethernet preceding -w 0:0 yields ethernet",
			args:        []string{"-o", "Tunnel=ethernet", "-w", "0:0"},
			wantDev:     "0:0",
			wantSpec:    "0:0",
			wantMode:    ssh.TunnelModeEthernet,
			wantDevNorm: "0:0",
			wantOptMode: string(ssh.TunnelModeEthernet),
		},
		{
			name:        "-w 0:0 preceding -o Tunnel=ethernet stays point-to-point (locked by -w)",
			args:        []string{"-w", "0:0", "-o", "Tunnel=ethernet"},
			wantDev:     "0:0",
			wantSpec:    "0:0",
			wantMode:    ssh.TunnelModePointToPoint,
			wantDevNorm: "0:0",
			wantOptMode: string(ssh.TunnelModePointToPoint),
		},
		{
			name:        "-o 'Tunnel ethernet' whitespace syntax preceding -w any",
			args:        []string{"-o", "Tunnel ethernet", "-w", "any"},
			wantDev:     "any",
			wantSpec:    "any:any",
			wantMode:    ssh.TunnelModeEthernet,
			wantDevNorm: "any:any",
			wantOptMode: string(ssh.TunnelModeEthernet),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := NewSshOptions()
			cmd := newCmdSshWithOptions(opts)
			if err := cmd.ParseFlags(tc.args); err != nil {
				t.Fatalf("ParseFlags(%v) failed: %v", tc.args, err)
			}
			if opts.TunnelDevice != tc.wantDev {
				t.Fatalf("opts.TunnelDevice = %q, want %q", opts.TunnelDevice, tc.wantDev)
			}

			sessionOpts, err := opts.toSessionControlOptions()
			if err != nil {
				t.Fatalf("toSessionControlOptions failed: %v", err)
			}
			if sessionOpts.Options == nil {
				t.Fatal("sessionOpts.Options is nil")
			}
			if devSpec, ok := sessionOpts.Options.TunnelDevice(); !ok || devSpec.String() != tc.wantDevNorm {
				t.Fatalf("sessionOpts TunnelDevice = %q (ok=%v), want %q", devSpec.String(), ok, tc.wantDevNorm)
			}
			if mode := sessionOpts.Options.Tunnel(); mode != tc.wantOptMode {
				t.Fatalf("sessionOpts Tunnel = %q, want %q", mode, tc.wantOptMode)
			}

			fwdCfg, err := opts.resolveSessionForwardConfig()
			if err != nil {
				t.Fatalf("resolveSessionForwardConfig failed: %v", err)
			}
			if !fwdCfg.hasTunnelDevice {
				t.Fatal("fwdCfg.hasTunnelDevice is false")
			}
			if fwdCfg.tunnelMode != tc.wantMode {
				t.Fatalf("fwdCfg.tunnelMode = %q, want %q", fwdCfg.tunnelMode, tc.wantMode)
			}
			if fwdCfg.tunnelDevice.String() != tc.wantSpec {
				t.Fatalf("fwdCfg.tunnelDevice = %q, want %q", fwdCfg.tunnelDevice.String(), tc.wantSpec)
			}
		})
	}
}

func TestSSHForward_TTYOrderingAndPrecedence(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantMode ssh.RequestTTYMode
	}{
		{
			name:     "-T yields RequestTTYNo",
			args:     []string{"-T"},
			wantMode: ssh.RequestTTYNo,
		},
		{
			name:     "-t yields RequestTTYYes",
			args:     []string{"-t"},
			wantMode: ssh.RequestTTYYes,
		},
		{
			name:     "-tt yields RequestTTYForce",
			args:     []string{"-tt"},
			wantMode: ssh.RequestTTYForce,
		},
		{
			name:     "-t -t yields RequestTTYForce",
			args:     []string{"-t", "-t"},
			wantMode: ssh.RequestTTYForce,
		},
		{
			name:     "-t -T yields RequestTTYNo",
			args:     []string{"-t", "-T"},
			wantMode: ssh.RequestTTYNo,
		},
		{
			name:     "-tT combined yields RequestTTYNo",
			args:     []string{"-tT"},
			wantMode: ssh.RequestTTYNo,
		},
		{
			name:     "-T -t yields RequestTTYYes",
			args:     []string{"-T", "-t"},
			wantMode: ssh.RequestTTYYes,
		},
		{
			name:     "-Tt combined yields RequestTTYYes",
			args:     []string{"-Tt"},
			wantMode: ssh.RequestTTYYes,
		},
		{
			name:     "-T -tt yields RequestTTYForce",
			args:     []string{"-T", "-tt"},
			wantMode: ssh.RequestTTYForce,
		},
		{
			name:     "-Ttt combined yields RequestTTYForce",
			args:     []string{"-Ttt"},
			wantMode: ssh.RequestTTYForce,
		},
		{
			name:     "-o RequestTTY=force without -t/-T yields RequestTTYForce",
			args:     []string{"-o", "RequestTTY=force"},
			wantMode: ssh.RequestTTYForce,
		},
		{
			name:     "-T -o RequestTTY=force: -T wins",
			args:     []string{"-T", "-o", "RequestTTY=force"},
			wantMode: ssh.RequestTTYNo,
		},
		{
			name:     "-o RequestTTY=force -T: -T wins",
			args:     []string{"-o", "RequestTTY=force", "-T"},
			wantMode: ssh.RequestTTYNo,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := NewSshOptions()
			cmd := newCmdSshWithOptions(opts)
			if err := cmd.ParseFlags(tc.args); err != nil {
				t.Fatalf("ParseFlags(%v) failed: %v", tc.args, err)
			}
			if got := opts.effectiveRequestTTY(); got != tc.wantMode {
				t.Fatalf("effectiveRequestTTY() = %q, want %q", got, tc.wantMode)
			}
		})
	}
}

func TestSSHForward_ExplicitTTYPrecedenceOverOption(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		wantMode ssh.RequestTTYMode
	}{
		{
			name:     "-o RequestTTY=force -T yields RequestTTYNo",
			args:     []string{"-o", "RequestTTY=force", "-T"},
			wantMode: ssh.RequestTTYNo,
		},
		{
			name:     "-T -o RequestTTY=force yields RequestTTYNo",
			args:     []string{"-T", "-o", "RequestTTY=force"},
			wantMode: ssh.RequestTTYNo,
		},
		{
			name:     "-o RequestTTY=no -tt yields RequestTTYForce",
			args:     []string{"-o", "RequestTTY=no", "-tt"},
			wantMode: ssh.RequestTTYForce,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := NewSshOptions()
			cmd := newCmdSshWithOptions(opts)
			if err := cmd.ParseFlags(tc.args); err != nil {
				t.Fatalf("ParseFlags(%v) failed: %v", tc.args, err)
			}
			if got := opts.effectiveRequestTTY(); got != tc.wantMode {
				t.Fatalf("effectiveRequestTTY() = %q, want %q", got, tc.wantMode)
			}
		})
	}
}

func TestSSHForward_DynamicForwardAccumulation(t *testing.T) {
	t.Run("CLI flags accumulate and keep last in DynamicForward", func(t *testing.T) {
		opts := NewSshOptions()
		cmd := newCmdSshWithOptions(opts)
		if err := cmd.ParseFlags([]string{"-D", "1080", "-D", "127.0.0.1:1081"}); err != nil {
			t.Fatalf("ParseFlags failed: %v", err)
		}

		if !slices.Equal(opts.DynamicForwards, []string{"1080", "127.0.0.1:1081"}) {
			t.Fatalf("opts.DynamicForwards = %v, want [1080, 127.0.0.1:1081]", opts.DynamicForwards)
		}
		if opts.DynamicForward != "127.0.0.1:1081" {
			t.Fatalf("opts.DynamicForward = %q, want '127.0.0.1:1081'", opts.DynamicForward)
		}

		cfg, err := opts.resolveSessionForwardConfig()
		if err != nil {
			t.Fatalf("resolveSessionForwardConfig failed: %v", err)
		}
		if len(cfg.dynamicForwards) != 2 {
			t.Fatalf("len(cfg.dynamicForwards) = %d, want 2", len(cfg.dynamicForwards))
		}
		net0, addr0 := cfg.dynamicForwards[0].LocalListenAddress(cfg.gatewayPorts)
		if net0 != "tcp" || addr0 != "127.0.0.1:1080" {
			t.Fatalf("dynamic forward 0 = %s, %s, want tcp, 127.0.0.1:1080", net0, addr0)
		}
		net1, addr1 := cfg.dynamicForwards[1].LocalListenAddress(cfg.gatewayPorts)
		if net1 != "tcp" || addr1 != "127.0.0.1:1081" {
			t.Fatalf("dynamic forward 1 = %s, %s, want tcp, 127.0.0.1:1081", net1, addr1)
		}
	})

	t.Run("programmatic SshOptions with DynamicForward resolves", func(t *testing.T) {
		progOpts := &SshOptions{
			DynamicForward: "1080",
		}
		cfg, err := progOpts.resolveSessionForwardConfig()
		if err != nil {
			t.Fatalf("resolveSessionForwardConfig failed: %v", err)
		}
		if len(cfg.dynamicForwards) != 1 {
			t.Fatalf("len(cfg.dynamicForwards) = %d, want 1", len(cfg.dynamicForwards))
		}
		net0, addr0 := cfg.dynamicForwards[0].LocalListenAddress(cfg.gatewayPorts)
		if net0 != "tcp" || addr0 != "127.0.0.1:1080" {
			t.Fatalf("dynamic forward 0 = %s, %s, want tcp, 127.0.0.1:1080", net0, addr0)
		}
	})
}

func TestSSHForward_ApplyGeneralOptions_WhitespaceSyntax(t *testing.T) {
	opts := NewSshOptions()
	optionStrings := []string{
		"Port 2222",
		"User alice",
		"IdentityFile /tmp/id_test",
		"ProxyJump bastion.example.com",
	}

	if err := ApplyGeneralOptions(opts, optionStrings, nil); err != nil {
		t.Fatalf("ApplyGeneralOptions failed: %v", err)
	}

	if opts.Port != 2222 {
		t.Fatalf("opts.Port = %d, want 2222", opts.Port)
	}
	if opts.User != "alice" {
		t.Fatalf("opts.User = %q, want 'alice'", opts.User)
	}
	if opts.IdentityFile != "/tmp/id_test" {
		t.Fatalf("opts.IdentityFile = %q, want '/tmp/id_test'", opts.IdentityFile)
	}
	if opts.JumpHost != "bastion.example.com" {
		t.Fatalf("opts.JumpHost = %q, want 'bastion.example.com'", opts.JumpHost)
	}
}

// -----------------------------------------------------------------------------
// Matrix 2: -W Validation, Implied Options, Overrides, and Piped Stdin Safety
// -----------------------------------------------------------------------------

func TestSSHStdioForward_ValidationRejections(t *testing.T) {
	t.Run("invalid -W syntax", func(t *testing.T) {
		invalidTargets := []string{"bad", ":80", "host:99999"}
		for _, target := range invalidTargets {
			opts := NewSshOptions()
			opts.StdioForward = target
			if err := opts.validateForwardAndSessionFlags(); err == nil {
				t.Fatalf("expected error for StdioForward=%q, got nil", target)
			}
		}
	})

	t.Run("remote command conflict with -W", func(t *testing.T) {
		opts := NewSshOptions()
		opts.StdioForward = "host:80"
		opts.Command = "remote-cmd"
		err := opts.validateForwardAndSessionFlags()
		if err == nil {
			t.Fatal("expected error combining StdioForward and Command, got nil")
		}
		if !strings.Contains(err.Error(), i18n.T("ssh_err_stdio_forward_with_cmd")) {
			t.Fatalf("expected error %q, got %q", i18n.T("ssh_err_stdio_forward_with_cmd"), err.Error())
		}
	})

	t.Run("background execution -f with -W", func(t *testing.T) {
		opts := NewSshOptions()
		opts.StdioForward = "host:80"
		opts.BgRun = true
		err := opts.validateForwardAndSessionFlags()
		if err == nil {
			t.Fatal("expected error combining StdioForward and BgRun, got nil")
		}
		if !strings.Contains(err.Error(), i18n.T("ssh_err_stdio_forward_with_bg")) {
			t.Fatalf("expected error %q, got %q", i18n.T("ssh_err_stdio_forward_with_bg"), err.Error())
		}

		// Also check with -N
		optsWithN := NewSshOptions()
		optsWithN.StdioForward = "host:80"
		optsWithN.BgRun = true
		optsWithN.NoCmd = true
		errN := optsWithN.validateForwardAndSessionFlags()
		if errN == nil {
			t.Fatal("expected error combining StdioForward, BgRun and NoCmd, got nil")
		}
		if !strings.Contains(errN.Error(), i18n.T("ssh_err_stdio_forward_with_bg")) {
			t.Fatalf("expected error %q, got %q", i18n.T("ssh_err_stdio_forward_with_bg"), errN.Error())
		}
	})

	t.Run("sudo conflict with -W", func(t *testing.T) {
		opts := NewSshOptions()
		opts.StdioForward = "host:80"
		opts.Sudo = true
		err := opts.validateForwardAndSessionFlags()
		if err == nil {
			t.Fatal("expected error combining StdioForward and Sudo, got nil")
		}
		if !strings.Contains(err.Error(), i18n.T("ssh_err_stdio_forward_with_sudo")) {
			t.Fatalf("expected error %q, got %q", i18n.T("ssh_err_stdio_forward_with_sudo"), err.Error())
		}
	})

	t.Run("explicit execution flag --no-login with -W", func(t *testing.T) {
		opts := NewSshOptions()
		cmd := newCmdSshWithOptions(opts)
		if err := cmd.ParseFlags([]string{"--no-login", "-W", "host:80", "target"}); err != nil {
			t.Fatalf("ParseFlags failed: %v", err)
		}
		if err := opts.Complete(cmd, []string{"target"}); err != nil {
			t.Fatalf("Complete failed: %v", err)
		}
		err := opts.Validate()
		if err == nil {
			t.Fatal("expected error combining --no-login and -W, got nil")
		}
		if !strings.Contains(err.Error(), "explicit execution cannot be combined with -W / --stdio-forward") {
			t.Fatalf("expected error mentioning explicit execution and -W, got: %v", err)
		}
	})
}

func TestSSHForward_ValidateRejectsInvalidForwards(t *testing.T) {
	t.Run("invalid -L argument", func(t *testing.T) {
		opts := NewSshOptions()
		cmd := newCmdSshWithOptions(opts)
		if err := cmd.Flags().Parse([]string{"-L", "invalid", "target"}); err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		if err := opts.Complete(cmd, cmd.Flags().Args()); err != nil {
			t.Fatalf("Complete failed: %v", err)
		}
		err := opts.Validate()
		if err == nil {
			t.Fatal("expected error for -L invalid, got nil")
		}
	})

	t.Run("invalid -R argument", func(t *testing.T) {
		opts := NewSshOptions()
		cmd := newCmdSshWithOptions(opts)
		if err := cmd.Flags().Parse([]string{"-R", "invalid", "target"}); err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		if err := opts.Complete(cmd, cmd.Flags().Args()); err != nil {
			t.Fatalf("Complete failed: %v", err)
		}
		err := opts.Validate()
		if err == nil {
			t.Fatal("expected error for -R invalid, got nil")
		}
	})

	t.Run("invalid -D argument", func(t *testing.T) {
		opts := NewSshOptions()
		cmd := newCmdSshWithOptions(opts)
		if err := cmd.Flags().Parse([]string{"-D", "invalid", "target"}); err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		if err := opts.Complete(cmd, cmd.Flags().Args()); err != nil {
			t.Fatalf("Complete failed: %v", err)
		}
		err := opts.Validate()
		if err == nil {
			t.Fatal("expected error for -D invalid, got nil")
		}
	})

	t.Run("-O proxy with -L invalid and -W exits with 255", func(t *testing.T) {
		opts := NewSshOptions()
		cmd := newCmdSshWithOptions(opts)
		if err := cmd.Flags().Parse([]string{"-O", "proxy", "-L", "invalid", "-W", "127.0.0.1:22", "target"}); err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		if err := opts.Complete(cmd, cmd.Flags().Args()); err != nil {
			t.Fatalf("Complete failed: %v", err)
		}
		err := opts.Validate()
		if err == nil {
			t.Fatal("expected error for -O proxy -L invalid, got nil")
		}
		code, ok := ExitCodeFromError(err)
		if !ok || code != 255 {
			t.Fatalf("expected ExitCode 255, got code=%d ok=%v err=%v", code, ok, err)
		}
	})
}

func TestSSHStdioForward_MuxCommandConflict(t *testing.T) {
	rejectedCmds := []string{"check", "exit", "stop", "forward", "cancel"}
	for _, cmdName := range rejectedCmds {
		t.Run(cmdName, func(t *testing.T) {
			opts := NewSshOptions()
			cmd := newCmdSshWithOptions(opts)
			args := []string{"-O", cmdName, "-W", "127.0.0.1:80", "target"}
			if err := cmd.ParseFlags(args); err != nil {
				t.Fatalf("ParseFlags failed: %v", err)
			}
			if err := opts.Complete(cmd, []string{"target"}); err != nil {
				t.Fatalf("Complete failed: %v", err)
			}
			err := opts.Validate()
			if err == nil {
				t.Fatalf("expected Validate to fail for -O %s -W", cmdName)
			}
			var ctlErr *ControlExitError
			if !errors.As(err, &ctlErr) {
				t.Fatalf("expected *ControlExitError, got %T: %v", err, err)
			}
			if ctlErr.Code != 255 {
				t.Fatalf("expected exit code 255, got %d", ctlErr.Code)
			}
			expectedMsg := i18n.T("ssh_err_stdio_forward_with_mux_cmd")
			if !strings.Contains(err.Error(), expectedMsg) {
				t.Fatalf("expected error containing %q, got %q", expectedMsg, err.Error())
			}
		})
	}

	t.Run("proxy allowed with -W", func(t *testing.T) {
		opts := NewSshOptions()
		cmd := newCmdSshWithOptions(opts)
		args := []string{"-O", "proxy", "-W", "127.0.0.1:80", "target"}
		if err := cmd.ParseFlags(args); err != nil {
			t.Fatalf("ParseFlags failed: %v", err)
		}
		if err := opts.Complete(cmd, []string{"target"}); err != nil {
			t.Fatalf("Complete failed: %v", err)
		}
		if err := opts.Validate(); err != nil {
			t.Fatalf("expected -O proxy -W with target to pass Validate, got: %v", err)
		}
	})
}

func TestSSHStdioForward_PipedStdinSafety(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = r.Close()
		_ = w.Close()
	}()

	oldStdin := os.Stdin
	os.Stdin = r
	defer func() {
		os.Stdin = oldStdin
	}()

	opts := NewSshOptions()
	cmd := newCmdSshWithOptions(opts)
	if err := cmd.ParseFlags([]string{"-W", "127.0.0.1:80", "myhost"}); err != nil {
		t.Fatalf("ParseFlags failed: %v", err)
	}
	if err := opts.Complete(cmd, []string{"myhost"}); err != nil {
		t.Fatalf("Complete failed: %v", err)
	}

	if opts.stdinScript {
		t.Fatal("opts.stdinScript must remain false when -W is active, even if os.Stdin is a pipe")
	}

	if err := opts.Validate(); err != nil {
		t.Fatalf("Validate failed on piped stdin with -W: %v", err)
	}
}

func testStdioForwardBaseline(t *testing.T) {
	opts := NewSshOptions()
	opts.StdioForward = "127.0.0.1:80"
	opts.LocalForwards = []string{"8080:127.0.0.1:80"}
	opts.RemoteForwards = []string{"9090:127.0.0.1:90"}
	opts.DynamicForward = "1080"
	opts.TunnelDevice = "0:1"

	cfg, err := opts.resolveSessionForwardConfig()
	if err != nil {
		t.Fatalf("resolveSessionForwardConfig failed: %v", err)
	}
	if !cfg.clearAllForwardings {
		t.Fatal("expected clearAllForwardings == true by default with -W")
	}
	if !cfg.exitOnForwardFailure {
		t.Fatal("expected exitOnForwardFailure == true by default with -W")
	}
	if len(cfg.localForwards) != 0 || len(cfg.remoteForwards) != 0 || len(cfg.dynamicForwards) != 0 || cfg.hasTunnelDevice {
		t.Fatalf("expected all forwardings cleared with ClearAllForwardings, got %+v", cfg)
	}
	if ttyMode := opts.effectiveRequestTTY(); ttyMode != ssh.RequestTTYNo {
		t.Fatalf("effectiveRequestTTY() = %q, want RequestTTYNo", ttyMode)
	}
}

func testStdioForwardClearAllOverride(t *testing.T) {
	opts := NewSshOptions()
	opts.StdioForward = "127.0.0.1:80"
	opts.LocalForwards = []string{"8080:127.0.0.1:80"}
	opts.RemoteForwards = []string{"9090:127.0.0.1:90"}
	opts.DynamicForward = "1080"
	opts.TunnelDevice = "0:1"
	opts.control.Options = []string{"ClearAllForwardings=no"}

	cfg, err := opts.resolveSessionForwardConfig()
	if err != nil {
		t.Fatalf("resolveSessionForwardConfig failed: %v", err)
	}
	if cfg.clearAllForwardings {
		t.Fatal("expected clearAllForwardings == false after explicit override")
	}
	if len(cfg.localForwards) != 1 {
		t.Fatalf("len(cfg.localForwards) = %d, want 1", len(cfg.localForwards))
	}
	if len(cfg.remoteForwards) != 1 {
		t.Fatalf("len(cfg.remoteForwards) = %d, want 1", len(cfg.remoteForwards))
	}
	if len(cfg.dynamicForwards) != 1 {
		t.Fatalf("len(cfg.dynamicForwards) = %d, want 1", len(cfg.dynamicForwards))
	}
	if !cfg.hasTunnelDevice {
		t.Fatal("expected hasTunnelDevice == true after explicit override")
	}
}

func testStdioForwardExitOnFailureOverride(t *testing.T) {
	opts := NewSshOptions()
	opts.StdioForward = "127.0.0.1:80"
	opts.control.Options = []string{"ExitOnForwardFailure=no"}

	cfg, err := opts.resolveSessionForwardConfig()
	if err != nil {
		t.Fatalf("resolveSessionForwardConfig failed: %v", err)
	}
	if cfg.exitOnForwardFailure {
		t.Fatal("expected exitOnForwardFailure == false after explicit override")
	}
}

func testStdioForwardTierConfigOverride(t *testing.T) {
	cfgModel := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	cfgModel.Hosts.Set("host1", models.Host{Address: "127.0.0.1", Port: 22})
	cfgModel.Identities.Set("id1", models.Identity{User: "alice", AuthType: "auto"})
	cfgModel.Nodes.Set("testnode", models.Node{
		HostRef:     "host1",
		IdentityRef: "id1",
		SSHOptions: ssh.MustOptions(
			ssh.OptionClearAllForwardings, "no",
			ssh.OptionExitOnForwardFailure, "no",
		),
	})
	provider, err := config.NewProvider(cfgModel)
	if err != nil {
		t.Fatalf("config.NewProvider failed: %v", err)
	}

	opts := NewSshOptions()
	opts.StdioForward = "127.0.0.1:80"
	opts.LocalForwards = []string{"8080:127.0.0.1:80"}

	_, err = opts.resolveAndCacheSessionOptions(provider, "testnode")
	if err != nil {
		t.Fatalf("resolveAndCacheSessionOptions failed: %v", err)
	}

	cfg, err := opts.resolveSessionForwardConfig()
	if err != nil {
		t.Fatalf("resolveSessionForwardConfig failed: %v", err)
	}
	if cfg.clearAllForwardings {
		t.Fatal("expected clearAllForwardings == false from Tier 2 node config")
	}
	if cfg.exitOnForwardFailure {
		t.Fatal("expected exitOnForwardFailure == false from Tier 2 node config")
	}
	if len(cfg.localForwards) != 1 {
		t.Fatalf("expected 1 local forward, got %d", len(cfg.localForwards))
	}
}

func TestSSHStdioForward_ImpliedOptionsAndOverrides(t *testing.T) {
	t.Run("baseline -W implies ClearAllForwardings, ExitOnForwardFailure, RequestTTYNo", testStdioForwardBaseline)
	t.Run("override ClearAllForwardings with -o ClearAllForwardings=no", testStdioForwardClearAllOverride)
	t.Run("override ExitOnForwardFailure with -o ExitOnForwardFailure=no", testStdioForwardExitOnFailureOverride)
	t.Run("Tier 2/3 configuration overrides implied options", testStdioForwardTierConfigOverride)
}

// -----------------------------------------------------------------------------
// Matrix 3: End-to-End In-Process Session & Tunnel Tests
// -----------------------------------------------------------------------------

type fakeTunnelDevice struct {
	name      string
	mode      ssh.TunnelMode
	readCh    chan []byte
	writtenCh chan []byte
	closeOnce sync.Once
	closeCh   chan struct{}
	closed    atomic.Bool
}

func newFakeTunnelDevice(name string, mode ssh.TunnelMode) *fakeTunnelDevice {
	return &fakeTunnelDevice{
		name:      name,
		mode:      mode,
		readCh:    make(chan []byte, 10),
		writtenCh: make(chan []byte, 10),
		closeCh:   make(chan struct{}),
	}
}

func (d *fakeTunnelDevice) Name() string         { return d.name }
func (d *fakeTunnelDevice) Mode() ssh.TunnelMode { return d.mode }

func (d *fakeTunnelDevice) ReadPacket(buf []byte) ([]byte, error) {
	select {
	case pkt, ok := <-d.readCh:
		if !ok {
			return nil, os.ErrClosed
		}
		n := copy(buf, pkt)
		return buf[:n], nil
	case <-d.closeCh:
		return nil, os.ErrClosed
	}
}

func (d *fakeTunnelDevice) WritePacket(pkt []byte) error {
	if d.closed.Load() {
		return os.ErrClosed
	}
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	select {
	case d.writtenCh <- cp:
		return nil
	case <-d.closeCh:
		return os.ErrClosed
	}
}

func (d *fakeTunnelDevice) Close() error {
	d.closeOnce.Do(func() {
		d.closed.Store(true)
		close(d.closeCh)
	})
	return nil
}

type fakeTunnelOpener struct {
	mu         sync.Mutex
	openedMode ssh.TunnelMode
	openedUnit int
	device     *fakeTunnelDevice
}

func (o *fakeTunnelOpener) OpenTunnelDevice(mode ssh.TunnelMode, localUnit int) (ssh.TunnelDevice, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.openedMode = mode
	o.openedUnit = localUnit
	return o.device, nil
}

func startTunnelEchoServer(t *testing.T, listener net.Listener, serverConfig *cryptoSSH.ServerConfig) <-chan struct{} {
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer closeTunnelTestResource(t, conn)

		server, channels, requests, hErr := cryptoSSH.NewServerConn(conn, serverConfig)
		if hErr != nil {
			t.Error(hErr)
			return
		}
		defer closeTunnelTestResource(t, server)
		var workers sync.WaitGroup
		defer workers.Wait()
		workers.Go(func() { cryptoSSH.DiscardRequests(requests) })

		for newChan := range channels {
			if newChan.ChannelType() != "tun@openssh.com" {
				_ = newChan.Reject(cryptoSSH.UnknownChannelType, "unsupported")
				continue
			}
			ch, reqs, aErr := newChan.Accept()
			if aErr != nil {
				t.Error(aErr)
				return
			}
			workers.Go(func() { cryptoSSH.DiscardRequests(reqs) })
			workers.Go(func() { pumpEchoTunnelFrames(t, ch) })
		}
	}()
	return serverDone
}

func pumpEchoTunnelFrames(t *testing.T, ch cryptoSSH.Channel) {
	defer closeTunnelTestResource(t, ch)
	buf := make([]byte, 32768)
	for {
		n, err := ch.Read(buf)
		if err != nil {
			return
		}
		if n < 24 || binary.BigEndian.Uint32(buf[0:4]) != 2 {
			t.Errorf("unexpected tunnel frame: n=%d", n)
			return
		}
		if _, err := ch.Write(buf[:n]); err != nil {
			return
		}
	}
}

func TestSSHTunnel_TunnelDeviceForward(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cryptoSSH.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := &cryptoSSH.ServerConfig{NoClientAuth: true}
	serverConfig.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	serverDone := startTunnelEchoServer(t, listener, serverConfig)
	t.Cleanup(func() {
		cancel()
		closeTunnelTestResource(t, listener)
		<-serverDone
	})

	fakeDev := newFakeTunnelDevice("tun0", ssh.TunnelModePointToPoint)
	fakeOpener := &fakeTunnelOpener{device: fakeDev}

	env := sshenv.Discover()
	env.TunnelOpener = fakeOpener

	addr := listener.Addr().(*net.TCPAddr)
	connector := ssh.NewConnector(tunnelTestProvider{&ssh.ClientConfig{
		NodeID: "test", Address: "127.0.0.1", Port: addr.Port,
		User: "test", AuthType: "password", Password: "test",
	}}, ssh.WithEnvironment(env))
	connector.AcceptNewHostKey.Store(true)
	t.Cleanup(func() {
		_ = connector.CloseAll()
	})

	client, err := connector.Connect(ctx, "test")
	if err != nil {
		t.Fatalf("connector.Connect failed: %v", err)
	}

	opts := NewSshOptions()
	opts.TunnelDevice = "0:1"

	group, err := opts.startTunnels(ctx, cancel, client)
	if err != nil {
		t.Fatalf("startTunnels failed: %v", err)
	}

	fakeOpener.mu.Lock()
	openedMode := fakeOpener.openedMode
	openedUnit := fakeOpener.openedUnit
	fakeOpener.mu.Unlock()

	if openedMode != ssh.TunnelModePointToPoint {
		t.Fatalf("openedMode = %q, want PointToPoint", openedMode)
	}
	if openedUnit != 0 {
		t.Fatalf("openedUnit = %d, want 0", openedUnit)
	}

	testPacket := []byte{
		0x45, 0x00, 0x00, 0x14, 0x01, 0x02, 0x03, 0x04,
		0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
		0x0d, 0x0e, 0x0f, 0x10,
	}

	select {
	case fakeDev.readCh <- testPacket:
	case <-time.After(time.Second):
		t.Fatal("timed out enqueuing test packet to fake device")
	}

	select {
	case echoed := <-fakeDev.writtenCh:
		if !bytes.Equal(echoed, testPacket) {
			t.Fatalf("echoed packet = %x, want %x", echoed, testPacket)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for echoed packet from tunnel device")
	}

	if err := group.Close(); err != nil {
		t.Fatalf("group.Close failed: %v", err)
	}

	if !fakeDev.closed.Load() {
		t.Fatal("expected fake tunnel device to be closed when group.Close() ran")
	}
}

func TestSSHTunnel_ExitOnForwardFailure(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	t.Run("ExitOnForwardFailure=no logs warning and continues", func(t *testing.T) {
		client, _ := newTunnelTestClient(t)
		errLines := captureSSHTunnelErrors(t)

		opts := NewSshOptions()
		opts.RemoteForwards = []string{"0:127.0.0.1:20173"}
		opts.control.Options = []string{"ExitOnForwardFailure=no"}

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		group, err := opts.startTunnels(ctx, cancel, client)
		if err != nil {
			t.Fatalf("startTunnels failed: %v", err)
		}
		defer func() {
			if group != nil {
				_ = group.Close()
			}
		}()

		if ctx.Err() != nil {
			t.Fatalf("expected context to remain active, got: %v", ctx.Err())
		}

		select {
		case line := <-errLines:
			if !strings.Contains(line, "warning: setup remote forward failed:") {
				t.Fatalf("expected warning line on stderr, got: %q", line)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for warning message on stderr")
		}
	})

	t.Run("ExitOnForwardFailure=yes fails startTunnels", func(t *testing.T) {
		client, _ := newTunnelTestClient(t)

		opts := NewSshOptions()
		opts.StdioForward = "127.0.0.1:80"
		opts.RemoteForwards = []string{"0:127.0.0.1:20173"}
		opts.control.Options = []string{"ClearAllForwardings=no"} // ExitOnForwardFailure defaults to true

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		group, err := opts.startTunnels(ctx, cancel, client)
		if err == nil {
			if group != nil {
				_ = group.Close()
			}
			t.Fatal("expected startTunnels to fail on rejected RemoteForward, got nil")
		}
	})
}

func startDirectTCPIPServer(t *testing.T, listener net.Listener, serverConfig *cryptoSSH.ServerConfig, binaryInput, binaryOutput []byte, serverErrCh chan error) <-chan struct{} {
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer closeTunnelTestResource(t, conn)

		server, channels, requests, hErr := cryptoSSH.NewServerConn(conn, serverConfig)
		if hErr != nil {
			serverErrCh <- hErr
			return
		}
		defer closeTunnelTestResource(t, server)
		var workers sync.WaitGroup
		defer workers.Wait()
		workers.Go(func() { cryptoSSH.DiscardRequests(requests) })

		for newChan := range channels {
			if newChan.ChannelType() != "direct-tcpip" {
				_ = newChan.Reject(cryptoSSH.UnknownChannelType, "unsupported")
				continue
			}

			ch, reqs, aErr := newChan.Accept()
			if aErr != nil {
				serverErrCh <- aErr
				return
			}
			workers.Go(func() { cryptoSSH.DiscardRequests(reqs) })

			workers.Go(func() {
				defer closeTunnelTestResource(t, ch)
				var received bytes.Buffer
				buf := make([]byte, 1024)
				for {
					n, rErr := ch.Read(buf)
					if n > 0 {
						received.Write(buf[:n])
					}
					if rErr != nil {
						if !errors.Is(rErr, io.EOF) {
							serverErrCh <- fmt.Errorf("server read error: %w", rErr)
						}
						break
					}
				}

				if !bytes.Equal(received.Bytes(), binaryInput) {
					serverErrCh <- fmt.Errorf("server received %v, want %v", received.Bytes(), binaryInput)
					return
				}

				if _, wErr := ch.Write(binaryOutput); wErr != nil {
					serverErrCh <- fmt.Errorf("server write error: %w", wErr)
					return
				}
			})
		}
	}()
	return serverDone
}

func TestSSHStdioForward_BinaryStreamPurity(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cryptoSSH.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := &cryptoSSH.ServerConfig{NoClientAuth: true}
	serverConfig.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	binaryInput := []byte{0x00, 0xff, 0xfe, 0x01, 0x00, 0x7f, 0x80, 0xaa}
	binaryOutput := []byte{0xaa, 0x55, 0x00, 0xff, 0x42, 0x13, 0x37}

	serverErrCh := make(chan error, 1)
	serverDone := startDirectTCPIPServer(t, listener, serverConfig, binaryInput, binaryOutput, serverErrCh)
	t.Cleanup(func() {
		cancel()
		closeTunnelTestResource(t, listener)
		<-serverDone
	})

	addr := listener.Addr().(*net.TCPAddr)
	connector := ssh.NewConnector(tunnelTestProvider{&ssh.ClientConfig{
		NodeID: "test", Address: "127.0.0.1", Port: addr.Port,
		User: "test", AuthType: "password", Password: "test",
	}}, ssh.WithEnvironment(sshenv.Discover()))
	connector.AcceptNewHostKey.Store(true)
	t.Cleanup(func() {
		_ = connector.CloseAll()
	})

	client, err := connector.Connect(ctx, "test")
	if err != nil {
		t.Fatalf("connector.Connect failed: %v", err)
	}

	t.Setenv("XOPS_CLI_SSH_FROM_TUI", "true")

	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	oldStdin := os.Stdin
	oldStdout := os.Stdout
	os.Stdin = stdinR
	os.Stdout = stdoutW
	t.Cleanup(func() {
		os.Stdin = oldStdin
		os.Stdout = oldStdout
	})

	go func() {
		defer closeTunnelTestResource(t, stdinW)
		_, _ = stdinW.Write(binaryInput)
	}()

	opts := NewSshOptions()
	opts.StdioForward = "127.0.0.1:8080"
	repo := setupTestRepository(t)

	tunnels, err := opts.startTunnels(ctx, cancel, client)
	if err != nil {
		t.Fatalf("startTunnels failed: %v", err)
	}
	defer func() {
		if tunnels != nil {
			_ = tunnels.Close()
		}
	}()

	sessionErr := opts.runConnectedSession(ctx, connector, client, repo, "test", tunnels, false)
	if sessionErr != nil {
		t.Fatalf("runConnectedSession failed: %v", sessionErr)
	}

	closeTunnelTestResource(t, stdoutW)

	var stdoutBytes []byte
	stdoutBuf := make([]byte, 1024)
	for {
		n, rErr := stdoutR.Read(stdoutBuf)
		if n > 0 {
			stdoutBytes = append(stdoutBytes, stdoutBuf[:n]...)
		}
		if rErr != nil {
			break
		}
	}
	closeTunnelTestResource(t, stdoutR)
	closeTunnelTestResource(t, stdinR)

	select {
	case sErr := <-serverErrCh:
		t.Fatalf("server error: %v", sErr)
	default:
	}

	if !bytes.Equal(stdoutBytes, binaryOutput) {
		t.Fatalf("stdout bytes = %v, want exact %v (zero extra characters or banner allowed)", stdoutBytes, binaryOutput)
	}
}

type serverRecordedRequests struct {
	mu   sync.Mutex
	reqs []string
	cmds []string
}

func (s *serverRecordedRequests) record(reqType string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reqs = append(s.reqs, reqType)
}

func (s *serverRecordedRequests) recordCommand(cmd string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cmds = append(s.cmds, cmd)
}

func (s *serverRecordedRequests) snapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.reqs)
}

func (s *serverRecordedRequests) snapshotCommands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.cmds)
}

func (s *serverRecordedRequests) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reqs = nil
	s.cmds = nil
}

func startSessionMockServer(t *testing.T, listener net.Listener, serverConfig *cryptoSSH.ServerConfig, recorded *serverRecordedRequests) <-chan struct{} {
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		var connWorkers sync.WaitGroup
		defer connWorkers.Wait()
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			c := conn
			connWorkers.Go(func() {
				defer closeTunnelTestResource(t, c)
				server, channels, requests, hErr := cryptoSSH.NewServerConn(c, serverConfig)
				if hErr != nil {
					return
				}
				defer closeTunnelTestResource(t, server)
				var chanWorkers sync.WaitGroup
				defer chanWorkers.Wait()
				chanWorkers.Go(func() { cryptoSSH.DiscardRequests(requests) })

				for newChan := range channels {
					if newChan.ChannelType() != "session" {
						_ = newChan.Reject(cryptoSSH.UnknownChannelType, "unsupported")
						continue
					}
					ch, reqs, aErr := newChan.Accept()
					if aErr != nil {
						return
					}
					channel, inRequests := ch, reqs
					chanWorkers.Go(func() {
						defer closeTunnelTestResource(t, channel)
						for req := range inRequests {
							recorded.record(req.Type)
							switch req.Type {
							case "pty-req":
								_ = req.Reply(true, nil)
							case "exec":
								var payload struct{ Command string }
								_ = cryptoSSH.Unmarshal(req.Payload, &payload)
								recorded.recordCommand(payload.Command)
								_ = req.Reply(true, nil)
								_, _ = channel.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
								return
							case "shell":
								_ = req.Reply(true, nil)
								_, _ = channel.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
								return
							default:
								if req.WantReply {
									_ = req.Reply(false, nil)
								}
							}
						}
					})
				}
			})
		}
	}()
	return serverDone
}

func TestSSHRequestTTY_CommandStreamAllocation(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	recorded := &serverRecordedRequests{}

	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cryptoSSH.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := &cryptoSSH.ServerConfig{NoClientAuth: true}
	serverConfig.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	serverDone := startSessionMockServer(t, listener, serverConfig, recorded)
	t.Cleanup(func() {
		cancel()
		closeTunnelTestResource(t, listener)
		<-serverDone
	})

	addr := listener.Addr().(*net.TCPAddr)
	connector := ssh.NewConnector(tunnelTestProvider{&ssh.ClientConfig{
		NodeID: "test", Address: "127.0.0.1", Port: addr.Port,
		User: "test", AuthType: "password", Password: "test",
	}}, ssh.WithEnvironment(sshenv.Discover()))
	connector.AcceptNewHostKey.Store(true)
	t.Cleanup(func() {
		_ = connector.CloseAll()
	})

	client, err := connector.Connect(ctx, "test")
	if err != nil {
		t.Fatalf("connector.Connect failed: %v", err)
	}

	t.Run("-tt with command and non-TTY stdin sends pty-req followed by exec", func(t *testing.T) {
		recorded.reset()
		opts := NewSshOptions()
		opts.ForceTTYCount = 2

		var stdout, stderr bytes.Buffer
		stdin := bytes.NewBufferString("hello")

		if err := opts.runCommandWithStreams(ctx, client, "echo hi", stdin, &stdout, &stderr); err != nil {
			t.Fatalf("runCommandWithStreams failed: %v", err)
		}

		reqs := recorded.snapshot()
		want := []string{"pty-req", "exec"}
		if !slices.Equal(reqs, want) {
			t.Fatalf("received requests = %v, want %v", reqs, want)
		}
	})

	t.Run("single -t with command and non-TTY stdin suppresses pty-req and warns", func(t *testing.T) {
		recorded.reset()
		opts := NewSshOptions()
		opts.ForceTTYCount = 1

		var stdout, stderr bytes.Buffer
		stdin := bytes.NewBufferString("hello")

		if err := opts.runCommandWithStreams(ctx, client, "echo hi", stdin, &stdout, &stderr); err != nil {
			t.Fatalf("runCommandWithStreams failed: %v", err)
		}

		reqs := recorded.snapshot()
		if slices.Contains(reqs, "pty-req") {
			t.Fatalf("pty-req was unexpectedly sent: %v", reqs)
		}
		if !slices.Contains(reqs, "exec") {
			t.Fatalf("exec request missing from: %v", reqs)
		}

		if !strings.Contains(stderr.String(), "Pseudo-terminal will not be allocated because stdin is not a terminal.") {
			t.Fatalf("stderr missing pseudo-terminal warning, got: %q", stderr.String())
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout unexpectedly contains output: %q", stdout.String())
		}
	})

	t.Run("stdinScript with -tt and empty Command sends pty-req followed by shell", func(t *testing.T) {
		recorded.reset()
		opts := NewSshOptions()
		opts.ForceTTYCount = 2
		opts.stdinScript = true
		opts.Command = ""

		var stdout, stderr bytes.Buffer
		stdin := strings.NewReader("echo hi\n")

		if err := opts.runCommandWithStreams(ctx, client, "", stdin, &stdout, &stderr); err != nil {
			t.Fatalf("runCommandWithStreams failed: %v", err)
		}

		reqs := recorded.snapshot()
		want := []string{"pty-req", "shell"}
		if !slices.Equal(reqs, want) {
			t.Fatalf("received requests = %v, want %v", reqs, want)
		}
	})
}

func TestSSHRequestTTY_InterpreterCommandStreamAllocation(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	recorded := &serverRecordedRequests{}

	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cryptoSSH.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := &cryptoSSH.ServerConfig{NoClientAuth: true}
	serverConfig.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	serverDone := startSessionMockServer(t, listener, serverConfig, recorded)
	t.Cleanup(func() {
		cancel()
		closeTunnelTestResource(t, listener)
		<-serverDone
	})

	addr := listener.Addr().(*net.TCPAddr)
	bashConnector := ssh.NewConnector(tunnelTestProvider{&ssh.ClientConfig{
		NodeID: "test-bash", Address: "127.0.0.1", Port: addr.Port,
		User: "test", AuthType: "password", Password: "test",
		Execution: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX},
	}}, ssh.WithEnvironment(sshenv.Discover()))
	bashConnector.AcceptNewHostKey.Store(true)
	t.Cleanup(func() {
		_ = bashConnector.CloseAll()
	})

	bashClient, err := bashConnector.Connect(ctx, "test-bash")
	if err != nil {
		t.Fatalf("bashConnector.Connect failed: %v", err)
	}

	t.Run("stdinScript with -tt and InterpreterBash client requests pty-req and exec bash", func(t *testing.T) {
		recorded.reset()
		opts := NewSshOptions()
		opts.ForceTTYCount = 2
		opts.stdinScript = true
		opts.Command = ""

		var stdout, stderr bytes.Buffer
		stdin := strings.NewReader("echo hi\n")

		if err := opts.runCommandWithStreams(ctx, bashClient, "", stdin, &stdout, &stderr); err != nil {
			t.Fatalf("runCommandWithStreams failed: %v", err)
		}

		reqs := recorded.snapshot()
		wantReqs := []string{"pty-req", "exec"}
		if !slices.Equal(reqs, wantReqs) {
			t.Fatalf("received requests = %v, want %v", reqs, wantReqs)
		}
		cmds := recorded.snapshotCommands()
		if len(cmds) != 1 || cmds[0] != "bash" {
			t.Fatalf("received commands = %v, want ['bash']", cmds)
		}
	})

	t.Run("stdinScript with -t and InterpreterBash client writes warning and execs bash without pty", func(t *testing.T) {
		recorded.reset()
		opts := NewSshOptions()
		opts.ForceTTYCount = 1
		opts.stdinScript = true
		opts.Command = ""

		var stdout, stderr bytes.Buffer
		stdin := strings.NewReader("echo hi\n")

		if err := opts.runCommandWithStreams(ctx, bashClient, "", stdin, &stdout, &stderr); err != nil {
			t.Fatalf("runCommandWithStreams failed: %v", err)
		}

		reqs := recorded.snapshot()
		if slices.Contains(reqs, "pty-req") {
			t.Fatalf("pty-req was unexpectedly sent: %v", reqs)
		}
		if !slices.Contains(reqs, "exec") {
			t.Fatalf("exec request missing from: %v", reqs)
		}
		cmds := recorded.snapshotCommands()
		if len(cmds) != 1 || cmds[0] != "bash" {
			t.Fatalf("received commands = %v, want ['bash']", cmds)
		}
		if !strings.Contains(stderr.String(), "Pseudo-terminal will not be allocated because stdin is not a terminal.") {
			t.Fatalf("stderr missing pseudo-terminal warning, got: %q", stderr.String())
		}
	})
}

// -----------------------------------------------------------------------------
// Matrix 4: Multiplexing Isolation
// -----------------------------------------------------------------------------

func TestSSHMuxDaemon_MuxDaemonArgsIsolation(t *testing.T) {
	client, _ := newTunnelTestClient(t)
	sockPath := filepath.Join(t.TempDir(), "cm.sock")
	master, err := ssh.NewMuxServer(ssh.MuxServerOptions{
		ControlPath: sockPath,
		SSHClient:   client.SSHClient(),
		Target:      ssh.TargetContext{OriginalHost: "web-01", Host: "web-01", Port: 22, User: "deploy"},
	})
	if err != nil {
		t.Fatalf("NewMuxServer failed: %v", err)
	}
	t.Cleanup(func() {
		_ = master.Shutdown()
	})

	opts := NewSshOptions()
	opts.control.Options = []string{
		"LocalForward=8080 127.0.0.1:80",
		"RemoteForward=9090 127.0.0.1:90",
		"DynamicForward=1080",
		"Tunnel=point-to-point",
		"TunnelDevice=0:1",
		"RequestTTY=force",
		"Port 2222",
		"ServerAliveInterval=15",
	}

	args := opts.muxDaemonArgs("web-01", sockPath, master)
	joined := strings.Join(args, " ")

	if !strings.Contains(joined, "-o ClearAllForwardings=yes") {
		t.Fatalf("expected '-o ClearAllForwardings=yes' in muxDaemonArgs, got %q", joined)
	}
	if !strings.Contains(joined, "-o ServerAliveInterval=15") {
		t.Fatalf("expected '-o ServerAliveInterval=15' in muxDaemonArgs, got %q", joined)
	}

	forbiddenOptions := []string{
		"LocalForward",
		"RemoteForward",
		"DynamicForward",
		"Tunnel=",
		"TunnelDevice",
		"RequestTTY",
		"Port 2222",
		"Port=2222",
	}
	for _, forbidden := range forbiddenOptions {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("muxDaemonArgs contains forbidden option %q: %q", forbidden, joined)
		}
	}
}

func TestSSHMuxDaemon_ParseForwardRequestsFromOptions(t *testing.T) {
	t.Run("includes LocalForward, RemoteForward, DynamicForward and multiple -D", func(t *testing.T) {
		opts := NewSshOptions()
		opts.control.Options = []string{
			"LocalForward 8080 127.0.0.1:80",
			"RemoteForward 9090 127.0.0.1:90",
			"DynamicForward 1080",
		}
		opts.DynamicForwards = []string{"1081", "127.0.0.1:1082"}

		reqs, err := parseForwardRequestsFromOptions(opts)
		if err != nil {
			t.Fatalf("parseForwardRequestsFromOptions failed: %v", err)
		}

		var localCount, remoteCount, dynamicCount int
		for _, req := range reqs {
			switch req.Type {
			case ssh.ForwardLocal:
				localCount++
				if req.ListenPort != 8080 || req.ConnectHost != "127.0.0.1" || req.ConnectPort != 80 {
					t.Fatalf("unexpected LocalForward req: %+v", req)
				}
			case ssh.ForwardRemote:
				remoteCount++
				if req.ListenPort != 9090 || req.ConnectHost != "127.0.0.1" || req.ConnectPort != 90 {
					t.Fatalf("unexpected RemoteForward req: %+v", req)
				}
			case ssh.ForwardDynamic:
				dynamicCount++
			}
		}

		if localCount != 1 {
			t.Fatalf("localCount = %d, want 1", localCount)
		}
		if remoteCount != 1 {
			t.Fatalf("remoteCount = %d, want 1", remoteCount)
		}
		if dynamicCount != 3 {
			t.Fatalf("dynamicCount = %d, want 3 (1080 from -o, 1081 and 127.0.0.1:1082 from -D)", dynamicCount)
		}
	})

	t.Run("returns empty when ClearAllForwardings=yes", func(t *testing.T) {
		opts := NewSshOptions()
		opts.control.Options = []string{
			"LocalForward 8080 127.0.0.1:80",
			"RemoteForward 9090 127.0.0.1:90",
			"DynamicForward 1080",
			"ClearAllForwardings=yes",
		}
		opts.DynamicForwards = []string{"1081"}

		reqs, err := parseForwardRequestsFromOptions(opts)
		if err != nil {
			t.Fatalf("parseForwardRequestsFromOptions failed: %v", err)
		}
		if len(reqs) != 0 {
			t.Fatalf("expected 0 forward requests when ClearAllForwardings=yes, got %d", len(reqs))
		}
	})
}

func TestSSHMuxDaemon_ChildProcessNormalization(t *testing.T) {
	t.Setenv(sshMuxDaemonEnv, "true")

	if !isMuxDaemonChild() {
		t.Fatal("expected isMuxDaemonChild() == true")
	}

	opts := NewSshOptions()
	opts.LocalForwards = []string{"8080:127.0.0.1:80"}
	opts.RemoteForwards = []string{"9090:127.0.0.1:90"}
	opts.DynamicForward = "1080"
	opts.DynamicForwards = []string{"1080"}
	opts.TunnelDevice = "0:1"
	opts.Command = "whoami"
	opts.StdioForward = "127.0.0.1:80"

	cfg, err := opts.resolveSessionForwardConfig()
	if err != nil {
		t.Fatalf("resolveSessionForwardConfig failed: %v", err)
	}
	if len(cfg.localForwards) != 0 || len(cfg.remoteForwards) != 0 || len(cfg.dynamicForwards) != 0 || cfg.hasTunnelDevice {
		t.Fatalf("expected resolveSessionForwardConfig to clear all forwardings in mux daemon child, got: %+v", cfg)
	}

	opts.normalizeForMuxDaemon()

	if !opts.NoCmd {
		t.Fatal("expected opts.NoCmd == true after normalizeForMuxDaemon")
	}
	if opts.Command != "" {
		t.Fatalf("expected opts.Command == '', got %q", opts.Command)
	}
	if opts.stdinScript {
		t.Fatal("expected opts.stdinScript == false after normalizeForMuxDaemon")
	}
	if opts.StdioForward != "" {
		t.Fatalf("expected opts.StdioForward == '', got %q", opts.StdioForward)
	}
	if opts.TunnelDevice != "" {
		t.Fatalf("expected opts.TunnelDevice == '', got %q", opts.TunnelDevice)
	}
	if opts.LocalForwards != nil {
		t.Fatalf("expected opts.LocalForwards == nil, got %v", opts.LocalForwards)
	}
	if opts.RemoteForwards != nil {
		t.Fatalf("expected opts.RemoteForwards == nil, got %v", opts.RemoteForwards)
	}
	if opts.DynamicForward != "" {
		t.Fatalf("expected opts.DynamicForward == '', got %q", opts.DynamicForward)
	}
	if opts.DynamicForwards != nil {
		t.Fatalf("expected opts.DynamicForwards == nil, got %v", opts.DynamicForwards)
	}
}
