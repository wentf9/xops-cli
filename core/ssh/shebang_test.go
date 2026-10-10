package ssh_test

import (
	"errors"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
)

func TestParseShebang(t *testing.T) {
	tests := []struct {
		name        string
		data        string
		hasShebang  bool
		supported   bool
		interpreter ssh.Interpreter
		dialect     ssh.LaunchDialect
	}{
		{
			name:        "standard /bin/bash",
			data:        "#!/bin/bash\necho ok\n",
			hasShebang:  true,
			supported:   true,
			interpreter: ssh.InterpreterBash,
			dialect:     ssh.LaunchPOSIX,
		},
		{
			name:        "standard /usr/bin/env sh with windows CRLF",
			data:        "#!/usr/bin/env sh\r\necho ok\r\n",
			hasShebang:  true,
			supported:   true,
			interpreter: ssh.InterpreterBash,
			dialect:     ssh.LaunchPOSIX,
		},
		{
			name:        "bash without path",
			data:        "#!bash\necho ok\n",
			hasShebang:  true,
			supported:   true,
			interpreter: ssh.InterpreterBash,
			dialect:     ssh.LaunchPOSIX,
		},
		{
			name:        "sh without path",
			data:        "#!sh\necho ok\n",
			hasShebang:  true,
			supported:   true,
			interpreter: ssh.InterpreterBash,
			dialect:     ssh.LaunchPOSIX,
		},
		{
			name:       "bash with flags rejected",
			data:       "#!/bin/bash -e\necho ok\n",
			hasShebang: true,
			supported:  false,
		},
		{
			name:       "env with -S rejected",
			data:       "#!/usr/bin/env -S bash\necho ok\n",
			hasShebang: true,
			supported:  false,
		},
		{
			name:       "python shebang rejected",
			data:       "#!/usr/bin/python3\nimport os\n",
			hasShebang: true,
			supported:  false,
		},
		{
			name:       "no shebang comment",
			data:       "# just a comment\necho ok\n",
			hasShebang: false,
		},
		{
			name:       "empty script",
			data:       "",
			hasShebang: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			info := ssh.ParseShebang([]byte(tc.data))
			if info.HasShebang != tc.hasShebang {
				t.Fatalf("HasShebang = %v, want %v", info.HasShebang, tc.hasShebang)
			}
			if info.Supported != tc.supported {
				t.Fatalf("Supported = %v, want %v", info.Supported, tc.supported)
			}
			if tc.supported {
				if info.Interpreter != tc.interpreter {
					t.Errorf("Interpreter = %q, want %q", info.Interpreter, tc.interpreter)
				}
				if info.Dialect != tc.dialect {
					t.Errorf("Dialect = %q, want %q", info.Dialect, tc.dialect)
				}
			}
		})
	}
}

func TestResolveScriptExecution_ExplicitAndLegacy(t *testing.T) {
	t.Run("all nil returns nil nil indicating legacy mode", func(t *testing.T) {
		res, err := ssh.ResolveScriptExecution(nil, nil, nil, nil, []byte("echo legacy"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res != nil {
			t.Fatalf("expected nil res for legacy, got %+v", res)
		}
	})

	t.Run("explicit step server interpreter is rejected", func(t *testing.T) {
		step := &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer}
		_, err := ssh.ResolveScriptExecution(step, nil, nil, nil, []byte("echo hi"))
		if err == nil {
			t.Fatal("expected error selecting server interpreter for script")
		}
		if !errors.Is(err, ssh.ErrExecutionValidation) {
			t.Fatalf("expected ErrExecutionValidation, got: %v", err)
		}
	})

	t.Run("explicit settings server interpreter is rejected", func(t *testing.T) {
		settings := &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer}
		_, err := ssh.ResolveScriptExecution(nil, settings, nil, nil, []byte("echo hi"))
		if err == nil {
			t.Fatal("expected error selecting server interpreter for script")
		}
		if !errors.Is(err, ssh.ErrExecutionValidation) {
			t.Fatalf("expected ErrExecutionValidation, got: %v", err)
		}
	})
}

func TestResolveScriptExecution_Shebang(t *testing.T) {
	t.Run("unsupported shebang without override fails", func(t *testing.T) {
		global := &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX}
		_, err := ssh.ResolveScriptExecution(nil, nil, nil, global, []byte("#!/bin/bash -e\necho hi"))
		if err == nil {
			t.Fatal("expected error for unsupported shebang")
		}
		if !errors.Is(err, ssh.ErrExecutionValidation) {
			t.Fatalf("expected ErrExecutionValidation, got: %v", err)
		}
	})

	t.Run("unsupported shebang with explicit step override succeeds", func(t *testing.T) {
		step := &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX}
		res, err := ssh.ResolveScriptExecution(step, nil, nil, nil, []byte("#!/bin/bash -e\necho hi"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res == nil || res.Interpreter != ssh.InterpreterBash {
			t.Fatalf("expected bash interpreter, got %+v", res)
		}
	})

	t.Run("supported shebang resolves interpreter", func(t *testing.T) {
		global := &ssh.ExecutionConfig{LaunchDialect: ssh.LaunchPOSIX}
		res, err := ssh.ResolveScriptExecution(nil, nil, nil, global, []byte("#!/bin/sh\necho hi"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res == nil || res.Interpreter != ssh.InterpreterBash || res.LaunchDialect != ssh.LaunchPOSIX {
			t.Fatalf("unexpected res: %+v", res)
		}
	})
}

func TestResolveScriptExecution_FallbackAndOverrides(t *testing.T) {
	t.Run("node server does not block global bash default", func(t *testing.T) {
		node := &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer}
		global := &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX}
		res, err := ssh.ResolveScriptExecution(nil, nil, node, global, []byte("echo no-shebang"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res == nil || res.Interpreter != ssh.InterpreterBash {
			t.Fatalf("expected global bash, got %+v", res)
		}
	})

	t.Run("all server without shebang fails", func(t *testing.T) {
		node := &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer}
		global := &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer}
		_, err := ssh.ResolveScriptExecution(nil, nil, node, global, []byte("echo no-shebang"))
		if err == nil {
			t.Fatal("expected error when no script interpreter can be determined")
		}
		if !errors.Is(err, ssh.ErrExecutionValidation) {
			t.Fatalf("expected ErrExecutionValidation, got: %v", err)
		}
	})

	t.Run("step login override with node server posix and shebang succeeds", func(t *testing.T) {
		stepLogin := false
		step := &ssh.ExecutionConfig{Login: &stepLogin}
		node := &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer, LaunchDialect: ssh.LaunchPOSIX}
		res, err := ssh.ResolveScriptExecution(step, nil, node, nil, []byte("#!/bin/bash\necho hi"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res == nil {
			t.Fatal("expected non-nil res")
		}
		if res.Interpreter != ssh.InterpreterBash {
			t.Errorf("expected bash, got %v", res.Interpreter)
		}
		if res.LaunchDialect != ssh.LaunchPOSIX {
			t.Errorf("expected posix, got %v", res.LaunchDialect)
		}
		if res.Login == nil || *res.Login != false {
			t.Errorf("expected login false, got %v", res.Login)
		}
	})

	t.Run("settings login override with node server posix and shebang succeeds", func(t *testing.T) {
		setLogin := false
		settings := &ssh.ExecutionConfig{Login: &setLogin}
		node := &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer, LaunchDialect: ssh.LaunchPOSIX}
		res, err := ssh.ResolveScriptExecution(nil, settings, node, nil, []byte("#!/bin/bash\necho hi"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res == nil {
			t.Fatal("expected non-nil res")
		}
		if res.Interpreter != ssh.InterpreterBash {
			t.Errorf("expected bash, got %v", res.Interpreter)
		}
		if res.LaunchDialect != ssh.LaunchPOSIX {
			t.Errorf("expected posix, got %v", res.LaunchDialect)
		}
		if res.Login == nil || *res.Login != false {
			t.Errorf("expected login false, got %v", res.Login)
		}
	})
}
