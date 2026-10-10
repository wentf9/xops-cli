package ssh

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func boolPtr(b bool) *bool { return &b }

func TestExecutionConfig_YAMLRoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantExec ExecutionConfig
	}{
		{
			name:  "server with posix dialect",
			input: "interpreter: server\nlaunch_dialect: posix\n",
			wantExec: ExecutionConfig{
				Interpreter:   InterpreterServer,
				LaunchDialect: LaunchPOSIX,
			},
		},
		{
			name:  "bash with login true",
			input: "interpreter: bash\nlaunch_dialect: posix\nlogin: true\n",
			wantExec: ExecutionConfig{
				Interpreter:   InterpreterBash,
				LaunchDialect: LaunchPOSIX,
				Login:         boolPtr(true),
			},
		},
		{
			name:  "bash with explicit login false",
			input: "interpreter: bash\nlaunch_dialect: posix\nlogin: false\n",
			wantExec: ExecutionConfig{
				Interpreter:   InterpreterBash,
				LaunchDialect: LaunchPOSIX,
				Login:         boolPtr(false),
			},
		},
		{
			name:     "empty config",
			input:    "{}\n",
			wantExec: ExecutionConfig{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var decoded ExecutionConfig
			if err := yaml.Unmarshal([]byte(tc.input), &decoded); err != nil {
				t.Fatalf("unmarshal error: %v", err)
			}
			if decoded.Interpreter != tc.wantExec.Interpreter {
				t.Errorf("interpreter = %q, want %q", decoded.Interpreter, tc.wantExec.Interpreter)
			}
			if decoded.LaunchDialect != tc.wantExec.LaunchDialect {
				t.Errorf("launch_dialect = %q, want %q", decoded.LaunchDialect, tc.wantExec.LaunchDialect)
			}
			if tc.wantExec.Login == nil {
				if decoded.Login != nil {
					t.Errorf("login = %v, want nil", *decoded.Login)
				}
			} else {
				if decoded.Login == nil || *decoded.Login != *tc.wantExec.Login {
					t.Errorf("login = %v, want %v", decoded.Login, *tc.wantExec.Login)
				}
			}

			// Marshal back and verify
			marshaled, err := yaml.Marshal(&decoded)
			if err != nil {
				t.Fatalf("marshal error: %v", err)
			}
			var reDecoded ExecutionConfig
			if err := yaml.Unmarshal(marshaled, &reDecoded); err != nil {
				t.Fatalf("remarshal decode error: %v", err)
			}
			if reDecoded.LoginMode() != tc.wantExec.LoginMode() {
				t.Errorf("login mode roundtrip mismatch: got %v, want %v", reDecoded.LoginMode(), tc.wantExec.LoginMode())
			}
		})
	}
}

func TestExecutionConfig_YAMLRejections(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{
			name:    "unknown field",
			input:   "interpreter: bash\nunknown_field: true\n",
			wantErr: "unknown field",
		},
		{
			name:    "unsupported interpreter",
			input:   "interpreter: zsh\n",
			wantErr: "unsupported interpreter",
		},
		{
			name:    "unsupported launch dialect",
			input:   "launch_dialect: fish\n",
			wantErr: "unsupported launch_dialect",
		},
		{
			name:    "server with login true",
			input:   "interpreter: server\nlogin: true\n",
			wantErr: "server interpreter requires inherited login mode",
		},
		{
			name:    "server with explicit login false",
			input:   "interpreter: server\nlogin: false\n",
			wantErr: "server interpreter requires inherited login mode",
		},
		{
			name:    "bash with cmd dialect",
			input:   "interpreter: bash\nlaunch_dialect: cmd\n",
			wantErr: "bash interpreter requires posix launch dialect",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var exec ExecutionConfig
			err := yaml.Unmarshal([]byte(tc.input), &exec)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
			if !errors.Is(err, ErrExecutionValidation) {
				t.Fatalf("expected ErrExecutionValidation, got: %v", err)
			}
		})
	}
}

func TestExecutionConfig_JSONRoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantExec ExecutionConfig
	}{
		{
			name:  "camelCase with boolean login",
			input: `{"interpreter":"bash","launchDialect":"posix","login":true}`,
			wantExec: ExecutionConfig{
				Interpreter:   InterpreterBash,
				LaunchDialect: LaunchPOSIX,
				Login:         boolPtr(true),
			},
		},
		{
			name:  "snake_case with boolean login false",
			input: `{"interpreter":"bash","launch_dialect":"posix","login":false}`,
			wantExec: ExecutionConfig{
				Interpreter:   InterpreterBash,
				LaunchDialect: LaunchPOSIX,
				Login:         boolPtr(false),
			},
		},
		{
			name:  "string login enabled",
			input: `{"interpreter":"bash","launchDialect":"posix","login":"enabled"}`,
			wantExec: ExecutionConfig{
				Interpreter:   InterpreterBash,
				LaunchDialect: LaunchPOSIX,
				Login:         boolPtr(true),
			},
		},
		{
			name:  "string login disabled",
			input: `{"interpreter":"bash","launchDialect":"posix","login":"disabled"}`,
			wantExec: ExecutionConfig{
				Interpreter:   InterpreterBash,
				LaunchDialect: LaunchPOSIX,
				Login:         boolPtr(false),
			},
		},
		{
			name:  "string login inherit",
			input: `{"interpreter":"server","launchDialect":"posix","login":"inherit"}`,
			wantExec: ExecutionConfig{
				Interpreter:   InterpreterServer,
				LaunchDialect: LaunchPOSIX,
				Login:         nil,
			},
		},
		{
			name:  "null login alone",
			input: `{"login":null}`,
			wantExec: ExecutionConfig{
				Login: nil,
			},
		},
		{
			name:  "server with null login",
			input: `{"interpreter":"server","launchDialect":"posix","login":null}`,
			wantExec: ExecutionConfig{
				Interpreter:   InterpreterServer,
				LaunchDialect: LaunchPOSIX,
				Login:         nil,
			},
		},
		{
			name:  "bash with null login",
			input: `{"interpreter":"bash","launchDialect":"posix","login":null}`,
			wantExec: ExecutionConfig{
				Interpreter:   InterpreterBash,
				LaunchDialect: LaunchPOSIX,
				Login:         nil,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var decoded ExecutionConfig
			if err := json.Unmarshal([]byte(tc.input), &decoded); err != nil {
				t.Fatalf("unmarshal error: %v", err)
			}
			if decoded.Interpreter != tc.wantExec.Interpreter {
				t.Errorf("interpreter = %q, want %q", decoded.Interpreter, tc.wantExec.Interpreter)
			}
			if decoded.LaunchDialect != tc.wantExec.LaunchDialect {
				t.Errorf("launch_dialect = %q, want %q", decoded.LaunchDialect, tc.wantExec.LaunchDialect)
			}
			if tc.wantExec.Login == nil {
				if decoded.Login != nil {
					t.Errorf("login = %v, want nil", *decoded.Login)
				}
			} else {
				if decoded.Login == nil || *decoded.Login != *tc.wantExec.Login {
					t.Errorf("login = %v, want %v", decoded.Login, *tc.wantExec.Login)
				}
			}

			// Marshal and verify camelCase
			marshaled, err := json.Marshal(&decoded)
			if err != nil {
				t.Fatalf("marshal error: %v", err)
			}
			var checkMap map[string]any
			if err := json.Unmarshal(marshaled, &checkMap); err != nil {
				t.Fatalf("unmarshal map error: %v", err)
			}
			if _, ok := checkMap["launch_dialect"]; ok {
				t.Error("JSON marshaling should use camelCase launchDialect, not launch_dialect")
			}
		})
	}
}

func TestExecutionConfig_JSONRejections(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{
			name:    "unknown field",
			input:   `{"unknown": 123}`,
			wantErr: "unknown field",
		},
		{
			name:    "conflicting dialects",
			input:   `{"launchDialect":"posix","launch_dialect":"cmd"}`,
			wantErr: "conflicting launchDialect and launch_dialect",
		},
		{
			name:    "invalid login string",
			input:   `{"interpreter":"bash","login":"invalid"}`,
			wantErr: "invalid login mode",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var exec ExecutionConfig
			err := json.Unmarshal([]byte(tc.input), &exec)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestResolveExecution_NilCombinations(t *testing.T) {
	res, err := ResolveExecution(nil, nil)
	if err != nil || res != nil {
		t.Fatalf("expected nil, nil, got %v, %v", res, err)
	}

	parent := &ExecutionConfig{Interpreter: InterpreterBash, LaunchDialect: LaunchPOSIX}
	res, err = ResolveExecution(nil, parent)
	if err != nil || res.Interpreter != InterpreterBash {
		t.Fatalf("expected parent copy, got %v, %v", res, err)
	}

	child := &ExecutionConfig{Interpreter: InterpreterServer}
	res, err = ResolveExecution(child, nil)
	if err != nil || res.Interpreter != InterpreterServer {
		t.Fatalf("expected child copy, got %v, %v", res, err)
	}
}

func TestResolveExecution_OverrideInterpreterDropsParentLogin(t *testing.T) {
	parent := &ExecutionConfig{
		Interpreter:   InterpreterBash,
		LaunchDialect: LaunchPOSIX,
		Login:         boolPtr(true),
	}
	child := &ExecutionConfig{
		Interpreter: InterpreterServer,
	}
	resolved, err := ResolveExecution(child, parent)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved.Interpreter != InterpreterServer {
		t.Errorf("interpreter = %v, want server", resolved.Interpreter)
	}
	if resolved.LaunchDialect != LaunchPOSIX {
		t.Errorf("dialect = %v, want posix (inherited from parent)", resolved.LaunchDialect)
	}
	if resolved.Login != nil {
		t.Errorf("login = %v, want nil (server drops parent's login: true)", *resolved.Login)
	}
}

func TestResolveExecution_OverrideDialectAndLogin(t *testing.T) {
	t.Run("child overrides dialect only keeps parent interpreter and login", func(t *testing.T) {
		parent := &ExecutionConfig{
			Interpreter:   InterpreterBash,
			LaunchDialect: "",
			Login:         boolPtr(true),
		}
		child := &ExecutionConfig{
			LaunchDialect: LaunchPOSIX,
		}
		resolved, err := ResolveExecution(child, parent)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resolved.Interpreter != InterpreterBash {
			t.Errorf("interpreter = %v, want bash", resolved.Interpreter)
		}
		if resolved.LaunchDialect != LaunchPOSIX {
			t.Errorf("dialect = %v, want posix", resolved.LaunchDialect)
		}
		if resolved.Login == nil || !*resolved.Login {
			t.Errorf("login = %v, want true", resolved.Login)
		}
	})

	t.Run("child overrides login only keeps parent interpreter and dialect", func(t *testing.T) {
		parent := &ExecutionConfig{
			Interpreter:   InterpreterBash,
			LaunchDialect: LaunchPOSIX,
			Login:         boolPtr(true),
		}
		child := &ExecutionConfig{
			Login: boolPtr(false),
		}
		resolved, err := ResolveExecution(child, parent)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resolved.Interpreter != InterpreterBash {
			t.Errorf("interpreter = %v, want bash", resolved.Interpreter)
		}
		if resolved.LaunchDialect != LaunchPOSIX {
			t.Errorf("dialect = %v, want posix", resolved.LaunchDialect)
		}
		if resolved.Login == nil || *resolved.Login != false {
			t.Errorf("login = %v, want false", resolved.Login)
		}
	})
}

func TestResolveExecution_IncompatibleMergedResultFails(t *testing.T) {
	parent := &ExecutionConfig{
		LaunchDialect: LaunchCmd,
	}
	child := &ExecutionConfig{
		Interpreter: InterpreterBash,
	}
	_, err := ResolveExecution(child, parent)
	if err == nil {
		t.Fatal("expected error merging bash with cmd dialect")
	}
}

func TestEffectiveExecution_MultiLayer(t *testing.T) {
	global := &ExecutionConfig{
		Interpreter:   InterpreterBash,
		LaunchDialect: LaunchPOSIX,
		Login:         boolPtr(true),
	}
	node := &ExecutionConfig{
		Login: boolPtr(false),
	}
	settings := &ExecutionConfig{}
	step := &ExecutionConfig{
		LaunchDialect: LaunchPOSIX,
	}

	effective, err := EffectiveExecution(step, settings, node, global)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if effective.Interpreter != InterpreterBash {
		t.Errorf("interpreter = %v, want bash", effective.Interpreter)
	}
	if effective.LaunchDialect != LaunchPOSIX {
		t.Errorf("launch_dialect = %v, want posix", effective.LaunchDialect)
	}
	if effective.Login == nil || *effective.Login != false {
		t.Errorf("login = %v, want false (overridden by node)", effective.Login)
	}
}

func TestExecutionConfig_JSONNullLoginPreservesInheritance(t *testing.T) {
	// 1. {"login": null} preserves parent's login default instead of forcing false
	var child ExecutionConfig
	if err := json.Unmarshal([]byte(`{"login":null}`), &child); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if child.Login != nil {
		t.Fatalf("expected child.Login == nil, got %v", *child.Login)
	}

	parent := &ExecutionConfig{
		Interpreter:   InterpreterBash,
		LaunchDialect: LaunchPOSIX,
		Login:         boolPtr(true),
	}
	resolved, err := ResolveExecution(&child, parent)
	if err != nil {
		t.Fatalf("resolve execution failed: %v", err)
	}
	if resolved.Login == nil || !*resolved.Login {
		t.Fatalf("expected resolved.Login to inherit parent true, got %v", resolved.Login)
	}

	// 2. {"interpreter":"server","login":null} succeeds validation and leaves login nil
	var serverChild ExecutionConfig
	if err := json.Unmarshal([]byte(`{"interpreter":"server","login":null}`), &serverChild); err != nil {
		t.Fatalf("unmarshal server with null login failed: %v", err)
	}
	if serverChild.Login != nil {
		t.Fatalf("expected serverChild.Login == nil, got %v", *serverChild.Login)
	}
	serverResolved, err := ResolveExecution(&serverChild, parent)
	if err != nil {
		t.Fatalf("resolve serverChild failed: %v", err)
	}
	if serverResolved.Login != nil {
		t.Fatalf("expected serverResolved.Login to be nil, got %v", *serverResolved.Login)
	}
}

func TestResolveExecution_DefaultInterpreterDropInheritedLogin(t *testing.T) {
	// 1. Implicit Bash parent ({login: false}) + explicit Server child -> drops login, leaves nil
	parentImplicitBash := &ExecutionConfig{Login: boolPtr(false)}
	childServer := &ExecutionConfig{Interpreter: InterpreterServer}

	resolved, err := ResolveExecution(childServer, parentImplicitBash)
	if err != nil {
		t.Fatalf("expected successful resolution when switching from implicit Bash to server, got: %v", err)
	}
	if resolved.Interpreter != InterpreterServer {
		t.Fatalf("expected interpreter server, got: %v", resolved.Interpreter)
	}
	if resolved.Login != nil {
		t.Fatalf("expected login to be dropped (nil), got: %v", *resolved.Login)
	}

	// 2. Explicit Bash parent + explicit Server child -> drops login, leaves nil
	parentExplicitBash := &ExecutionConfig{Interpreter: InterpreterBash, Login: boolPtr(false)}
	resolved2, err := ResolveExecution(childServer, parentExplicitBash)
	if err != nil {
		t.Fatalf("expected successful resolution when switching from explicit Bash to server, got: %v", err)
	}
	if resolved2.Login != nil {
		t.Fatalf("expected login to be dropped (nil), got: %v", *resolved2.Login)
	}

	// 3. Implicit Bash parent + explicit Bash child -> retains login: false
	childBash := &ExecutionConfig{Interpreter: InterpreterBash}
	resolved3, err := ResolveExecution(childBash, parentImplicitBash)
	if err != nil {
		t.Fatalf("expected successful resolution for bash child with implicit bash parent, got: %v", err)
	}
	if resolved3.Login == nil || *resolved3.Login != false {
		t.Fatalf("expected login false to be inherited, got: %v", resolved3.Login)
	}

	// 4. Multi-layer EffectiveExecution: global {login: false} + node {interpreter: server}
	global := &ExecutionConfig{Login: boolPtr(false)}
	node := &ExecutionConfig{Interpreter: InterpreterServer}
	settings := &ExecutionConfig{}
	step := &ExecutionConfig{}

	effective, err := EffectiveExecution(step, settings, node, global)
	if err != nil {
		t.Fatalf("expected EffectiveExecution to succeed for node server over global login:false, got: %v", err)
	}
	if effective.Interpreter != InterpreterServer {
		t.Fatalf("expected effective interpreter server, got: %v", effective.Interpreter)
	}
	if effective.Login != nil {
		t.Fatalf("expected effective login nil, got: %v", *effective.Login)
	}
}
