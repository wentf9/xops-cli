package host

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	"github.com/wentf9/xops-cli/pkg/config"
	cryptoSSH "golang.org/x/crypto/ssh"
)

func testProbeResult() *ssh.ProbeResult {
	login := false
	return &ssh.ProbeResult{
		DetectedDialect: ssh.LaunchPOSIX, AvailableInterpreters: []ssh.Interpreter{ssh.InterpreterBash, ssh.InterpreterSh},
		RecommendedInterpreter: ssh.InterpreterBash, RemoteOS: "Linux", RemoteShellPath: "/bin/bash",
		SuggestedConfig: ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX, Login: &login},
	}
}

func TestHostAddExecutionProbe(t *testing.T) {
	for _, tt := range []struct {
		name, interpreter, dialect string
		flags                      []string
		probe, warning             bool
		probeErr                   error
	}{
		{name: "default", interpreter: "bash", dialect: "posix", probe: true},
		{name: "no probe", flags: []string{"--no-probe"}},
		{name: "probe false", flags: []string{"--probe=false"}},
		{name: "offline", flags: []string{"--skip-verify"}},
		{name: "explicit zsh", flags: []string{"--interpreter", "zsh"}, interpreter: "zsh", dialect: "posix", probe: true},
		{name: "explicit fish", flags: []string{"--interpreter", "fish"}, interpreter: "fish", dialect: "posix", probe: true},
		{name: "explicit sh", flags: []string{"--interpreter", "sh"}, interpreter: "sh", dialect: "posix", probe: true},
		{name: "explicit server", flags: []string{"--interpreter", "server"}, interpreter: "server", dialect: "posix", probe: true},
		{name: "explicit dialect", flags: []string{"--launch-dialect", "cmd"}, dialect: "cmd", probe: true, warning: true},
		{name: "probe failed", probe: true, warning: true, probeErr: context.DeadlineExceeded},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, store := verificationRepository(t)
			calls := 0
			cmd := newCmdInventoryAdd(func(_ context.Context, repo *config.Repository, nodeID string, check *inventoryVerification) error {
				calls++
				if check.Probe != tt.probe {
					t.Fatalf("probe = %v, want %v", check.Probe, tt.probe)
				}
				if _, saved := repo.GetNode(nodeID); saved {
					t.Error("node persisted before verification/probing")
				}
				if check.Probe {
					check.Result, check.ProbeErr = testProbeResult(), tt.probeErr
				}
				return nil
			})
			var output bytes.Buffer
			cmd.SetArgs(append([]string{"--address", "192.0.2.1", "--identity", "fixture"}, tt.flags...))
			cmd.SetContext(t.Context())
			cmd.SetOut(&output)
			cmd.SetErr(&output)
			if err := cmd.Execute(); err != nil {
				t.Fatal(err)
			}
			cfg, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			node, found := cfg.Nodes.Get("root@192.0.2.1:22")
			if !found {
				t.Fatal("node not persisted")
			}
			if tt.interpreter == "" && tt.dialect == "" {
				if node.Execution != nil {
					t.Fatalf("fallback must omit execution: %+v", node.Execution)
				}
			} else if node.Execution == nil || string(node.Execution.Interpreter) != tt.interpreter || string(node.Execution.LaunchDialect) != tt.dialect {
				t.Fatalf("execution = %+v", node.Execution)
			}
			if strings.Contains(output.String(), "warning:") != tt.warning {
				t.Fatalf("warning mismatch: %q", output.String())
			}
			if tt.name == "offline" && calls != 0 {
				t.Fatal("skip-verify connected")
			}
		})
	}
}

func TestHostAddExecutionValidationBeforeConnection(t *testing.T) {
	for _, flags := range [][]string{
		{"--interpreter="}, {"--interpreter", "python3"},
		{"--interpreter", "bash", "--launch-dialect", "cmd"},
		{"--probe", "--no-probe"},
	} {
		t.Run(strings.Join(flags, " "), func(t *testing.T) {
			_, store := verificationRepository(t)
			cmd := newCmdInventoryAdd(func(context.Context, *config.Repository, string, *inventoryVerification) error {
				t.Error("invalid execution attempted verification")
				return nil
			})
			cmd.SetArgs(append([]string{"--address", "192.0.2.1", "--identity", "fixture"}, flags...))
			cmd.SetContext(t.Context())
			cmd.SetErr(new(bytes.Buffer))
			cmd.SetOut(new(bytes.Buffer))
			if err := cmd.Execute(); err == nil {
				t.Fatal("invalid options accepted")
			}
			cfg, err := store.Load()
			if err != nil || cfg.Nodes.Count() != 0 {
				t.Fatalf("invalid options persisted a node: %v", err)
			}
		})
	}
}

func TestImportExecutionProbePersistenceAndWarnings(t *testing.T) {
	repo, store := verificationRepository(t)
	var output bytes.Buffer
	verify := func(_ context.Context, _ *config.Repository, nodeID string, check *inventoryVerification) error {
		if !check.Probe {
			t.Error("new import did not enable probe")
		}
		check.Result = testProbeResult()
		if strings.Contains(nodeID, "192.0.2.2") {
			check.ProbeErr = errors.New("restricted shell")
		}
		return nil
	}
	rows := []utils.HostInfo{{Host: "192.0.2.1", User: "root"}, {Host: "192.0.2.2", User: "root"}}
	if err := executeImport(t.Context(), repo, rows, ImportOptions{Output: &output}, verify); err != nil {
		t.Fatal(err)
	}
	cfg, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	good, _ := cfg.Nodes.Get("root@192.0.2.1:22")
	failed, _ := cfg.Nodes.Get("root@192.0.2.2:22")
	if cfg.Nodes.Count() != 2 || good.Execution == nil || good.Execution.Interpreter != ssh.InterpreterBash || failed.Execution != nil || !strings.Contains(output.String(), "restricted shell") {
		t.Fatalf("import probe persistence or warning incorrect: %s", output.String())
	}
	// Re-import existing nodes without changing their execution configuration.
	if err := executeImport(t.Context(), repo, rows, ImportOptions{Output: &output}, func(_ context.Context, _ *config.Repository, _ string, check *inventoryVerification) error {
		if check.Probe {
			t.Error("existing node was probed automatically")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	after, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	updated, _ := after.Nodes.Get("root@192.0.2.1:22")
	if !reflect.DeepEqual(updated.Execution, good.Execution) {
		t.Fatal("re-import changed execution")
	}
}

func TestHostProbeSaveAndConflict(t *testing.T) {
	for _, mode := range []string{"diagnose", "save", "probe failure", "conflict"} {
		t.Run(mode, func(t *testing.T) {
			repo, store := verificationRepository(t)
			draft, err := prepareImport(repo, utils.HostInfo{Host: "192.0.2.1", User: "root", Alias: "probe-fixture"}, "original")
			if err != nil {
				t.Fatal(err)
			}
			if err := draft.save(t.Context(), repo); err != nil {
				t.Fatal(err)
			}
			cmd := newCmdInventoryProbe(func(ctx context.Context, active *config.Repository, nodeID string, check *inventoryVerification) error {
				if !check.Probe || nodeID != draft.nodeID {
					t.Error("diagnostic did not resolve the saved alias")
				}
				check.Result = testProbeResult()
				if mode == "probe failure" {
					check.ProbeErr = ssh.ErrExecutionProbe
				}
				if mode == "conflict" {
					_, err := active.UpdateNodeTagsContext(ctx, []string{nodeID}, []string{"concurrent"}, true)
					return err
				}
				return nil
			})
			args := []string{"probe-fixture"}
			if mode != "diagnose" {
				args = append(args, "--save")
			}
			var output bytes.Buffer
			cmd.SetArgs(args)
			cmd.SetOut(&output)
			cmd.SetErr(&output)
			cmd.SetContext(t.Context())
			err = cmd.Execute()
			if (err != nil) != (mode == "probe failure" || mode == "conflict") {
				t.Fatalf("command error = %v", err)
			}
			if mode == "conflict" && !errors.Is(err, config.ErrConfigConflict) {
				t.Fatalf("concurrent edit not protected: %v", err)
			}
			cfg, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			node, _ := cfg.Nodes.Get(draft.nodeID)
			if (node.Execution != nil) != (mode == "save") {
				t.Fatalf("unexpected saved execution: %+v", node.Execution)
			}
			if !strings.Contains(output.String(), "Available interpreters") || !strings.Contains(output.String(), "bash, sh") {
				t.Fatalf("missing diagnostic output: %s", output.String())
			}
		})
	}
}

func TestImportExplicitExecutionWithoutProbing(t *testing.T) {
	for _, skipVerify := range []bool{false, true} {
		t.Run(map[bool]string{false: "no-probe", true: "skip-verify"}[skipVerify], func(t *testing.T) {
			repo, store := verificationRepository(t)
			var output bytes.Buffer
			execution := &ssh.ExecutionConfig{Interpreter: ssh.InterpreterSh, LaunchDialect: ssh.LaunchPOSIX}
			err := executeImport(t.Context(), repo, []utils.HostInfo{{Host: "192.0.2.1", User: "root"}}, ImportOptions{
				NoProbe: true, SkipVerify: skipVerify, Execution: execution, Output: &output,
			}, func(_ context.Context, _ *config.Repository, _ string, check *inventoryVerification) error {
				if skipVerify || check.Probe {
					t.Error("disabled verification/probing ran")
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			cfg, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			node, _ := cfg.Nodes.Get("root@192.0.2.1:22")
			if !reflect.DeepEqual(node.Execution, execution) {
				t.Fatalf("explicit execution not persisted: %+v", node.Execution)
			}
		})
	}
}

func TestHostProbeRejectsUnknownNodeBeforeConnecting(t *testing.T) {
	verificationRepository(t)
	cmd := newCmdInventoryProbe(func(context.Context, *config.Repository, string, *inventoryVerification) error {
		t.Error("unknown node attempted SSH")
		return nil
	})
	cmd.SetArgs([]string{"missing", "--save"})
	cmd.SetContext(t.Context())
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	if err := cmd.Execute(); err == nil {
		t.Fatal("unknown probe target accepted")
	}
}

func TestProbeTableEscapesControlCharacters(t *testing.T) {
	result := testProbeResult()
	result.RemoteShellPath = "/bin/bash\x1b[31m\tFAKE\nROW"
	var output bytes.Buffer
	if err := writeProbeResult(&output, "fixture", result); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "\x1b") || strings.Contains(output.String(), "\tFAKE") || strings.Contains(output.String(), "\nROW") {
		t.Fatalf("remote metadata injected terminal controls: %q", output.String())
	}
}

func TestEnrollmentProbePersistsWithCredentialsOverRealSSH(t *testing.T) {
	for _, mode := range []string{"add", "import"} {
		t.Run(mode, func(t *testing.T) {
			repo, store := verificationRepository(t)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			server, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{ExecHandler: func(command string, channel cryptoSSH.Channel) {
				output := "__XOPS_INTERP__:bash\n__XOPS_INTERP__:sh\n__XOPS_INTERP_END__\n"
				if strings.Contains(command, "__XOPS_DIALECT_POSIX__") {
					output = "__XOPS_DIALECT_POSIX__:Linux:/bin/bash\n"
				}
				if _, err := io.WriteString(channel, output); err != nil {
					t.Error(err)
					return
				}
				if _, err := channel.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0})); err != nil {
					t.Error(err)
				}
			}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := server.Close(); err != nil {
					t.Error(err)
				}
			})
			host, portText, err := net.SplitHostPort(server.Address)
			if err != nil {
				t.Fatal(err)
			}
			port, err := strconv.ParseUint(portText, 10, 16)
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			if mode == "add" {
				cmd := NewCmdInventoryAdd()
				cmd.SetArgs([]string{"--address", host, "--port", portText, "--user", "fixture", "--password-stdin"})
				cmd.SetIn(strings.NewReader(sshfixture.Password + "\n"))
				cmd.SetContext(ctx)
				cmd.SetOut(&output)
				cmd.SetErr(&output)
				err = cmd.Execute()
			} else {
				err = executeImport(ctx, repo, []utils.HostInfo{{Host: host, Port: uint16(port), User: "fixture", Password: sshfixture.Password}}, ImportOptions{Output: &output}, verifyInventoryNode)
			}
			if err != nil {
				t.Fatalf("enroll via %s: %v", mode, err)
			}
			cfg, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			node, saved := cfg.Nodes.Get(config.FormatNodeID("fixture", host, uint16(port)))
			if !saved || node.Execution == nil || node.Execution.Interpreter != ssh.InterpreterBash {
				t.Fatal("enrollment did not persist execution with the node")
			}
			identity, _ := cfg.Identities.Get(node.IdentityRef)
			if persistedTestPassword(t, cfg, identity) != sshfixture.Password {
				t.Fatal("enrollment did not retain encrypted credentials")
			}
			if server.Authenticated.Load() != 1 || server.Executed.Load() != 2 {
				t.Fatal("enrollment probing repeated authentication or exec requests")
			}
		})
	}
}
