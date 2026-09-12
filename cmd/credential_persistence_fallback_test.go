package cmd

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/ssh"
)

func unavailablePersistenceFixture(t *testing.T) (*config.Repository, *config.Configuration, string, []byte) {
	t.Helper()
	initCredentialPolicyTestI18n(t)
	store := phase6Config(t, config.StoreConfig{Type: config.StoreTypeHelper, Command: os.Args[0]})
	cfg, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	cfg.SchemaVersion = 2
	cfg.Credential.RememberPrompted = "always"
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	_, repo, cfg, err := utils.GetConfigStore()
	if err != nil {
		t.Fatal(err)
	}
	path, _, err := utils.GetConfigFilePath()
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	blocked := filepath.Join(t.TempDir(), "private-journal-location")
	if err := os.WriteFile(blocked, []byte("occupied"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XOPS_JOURNAL_DIR", blocked)
	return repo, cfg, path, before
}

func TestInteractivePersistenceInitializationFallbackDisablesAllRecording(t *testing.T) {
	for _, command := range []string{"ssh", "exec"} {
		for _, policy := range []string{"always", "ask", "never"} {
			t.Run(command+"/"+policy, func(t *testing.T) {
				repo, cfg, path, before := unavailablePersistenceFixture(t)
				var output bytes.Buffer
				ui := newCLIInteractionHandlerWithStreams(strings.NewReader("yes\n"), &output)
				var opts []adapter.Option
				var err error
				if command == "ssh" {
					o := &SshOptions{Remember: policy, interaction: ui}
					opts, err = o.buildAdapterOptions("node", cfg, repo)
				} else {
					o := &ExecOptions{SshOptions: SshOptions{Remember: policy}, Interactive: true, interaction: ui}
					opts, err = o.buildAdapterOptions([]execHostTask{{nodeID: "node"}}, cfg, repo)
				}
				if err != nil {
					t.Fatal(err)
				}
				adp := adapter.NewSSHAdapter(repo, opts...)
				connection, err := adp.GetConfig("node")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := adp.UpdateAuth(t.Context(), "node", connection.AuthUpdateToken, "must-not-save", "", ""); err != nil {
					t.Fatal(err)
				}
				if _, err := adp.UpdateSudo(t.Context(), "node", connection.SudoUpdateToken, ssh.SudoModeSu, "must-not-save-su"); err != nil {
					t.Fatal(err)
				}
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatalf("session-only authentication modified configuration: %v", err)
				}
				wantWarning := policy != "never"
				if strings.Contains(output.String(), i18n.T("credential_save_unavailable")) != wantWarning {
					t.Fatalf("incorrect fallback warning: %q", output.String())
				}
				if strings.Contains(output.String(), "private-journal-location") || strings.Contains(output.String(), "Save credential") {
					t.Fatalf("fallback leaked backend details or asked to save: %q", output.String())
				}
			})
		}
	}
}

func TestPersistenceInitializationWithoutInteractionFailsClosed(t *testing.T) {
	repo, cfg, _, _ := unavailablePersistenceFixture(t)
	var output bytes.Buffer
	ui := newCLIInteractionHandlerWithStreams(strings.NewReader("unused"), &output)
	ui.canRemember = false
	o := &SshOptions{interaction: ui}
	if _, err := o.buildAdapterOptions("node", cfg, repo); err == nil {
		t.Fatal("non-interactive initialization silently recovered")
	}
	if output.Len() != 0 {
		t.Fatal("non-interactive recovery produced a warning or prompt")
	}
}

func TestSCPPersistenceInitializationFallback(t *testing.T) {
	for _, batch := range []bool{false, true} {
		t.Run(map[bool]string{false: "interactive", true: "batch"}[batch], func(t *testing.T) {
			repo, cfg, path, before := unavailablePersistenceFixture(t)
			var output bytes.Buffer
			ui := newCLIInteractionHandlerWithStreams(strings.NewReader(""), &output)
			o := &ScpOptions{}
			if batch {
				o.Host = "node,other"
			}
			connector, err := o.credentialConnectorWithInteraction(repo, cfg, ui)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := connector.CloseAll(); err != nil {
					t.Error(err)
				}
			}()
			if strings.Contains(output.String(), i18n.T("credential_save_unavailable")) == batch {
				t.Fatalf("incorrect SCP warning for batch=%v: %q", batch, output.String())
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("connector setup modified configuration: %v", err)
			}
		})
	}
}

type failingPersistenceNoticeWriter struct{}

func (failingPersistenceNoticeWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestPersistenceInitializationWarningFailureIsReturned(t *testing.T) {
	repo, cfg, _, _ := unavailablePersistenceFixture(t)
	ui := newCLIInteractionHandlerWithStreams(strings.NewReader(""), failingPersistenceNoticeWriter{})
	if _, err := ui.automaticPersistenceOptions(repo, cfg); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("lost warning write error: %v", err)
	}
}
