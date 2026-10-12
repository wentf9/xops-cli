package host

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/models"
)

func verificationRepository(t *testing.T) (*config.Repository, config.Store) {
	t.Helper()
	return verificationRepositoryAtDirectory(t, t.TempDir())
}

func verificationRepositoryAtDirectory(t *testing.T, directory string) (*config.Repository, config.Store) {
	t.Helper()
	// macOS exposes its temporary directory through a system symlink. The
	// offline vault intentionally rejects symlink ancestors, so fixtures must
	// use the physical path rather than weakening that production boundary.
	physical, err := filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("XOPS_CONFIG_DIR", physical)
	// Real SSH fixtures must not read personal keys, agents, OpenSSH config or
	// known_hosts; reused loopback ports otherwise collide with earlier runs.
	t.Setenv("HOME", physical)
	t.Setenv("USERPROFILE", physical)
	t.Setenv("SSH_AUTH_SOCK", "")
	if err := i18n.Init("en"); err != nil {
		t.Fatal(err)
	}
	path, key, err := utils.GetConfigFilePath()
	if err != nil {
		t.Fatal(err)
	}
	store := config.NewDefaultStore(path, key)
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.SchemaVersion = 2
	cfg.Credential = config.DefaultCredentialConfig()
	owner := config.NewEncryptedRuntime(t.Context(), path, nil)
	detach, err := utils.InstallCredentialRuntime(owner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		detach()
		if err := owner.Close(); err != nil {
			t.Error(err)
		}
	})
	cfg.Identities.Set("fixture", models.Identity{User: "root", AuthType: "auto"})
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	repo, err := config.NewRepositoryWithoutOpenSSH(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	return repo, store
}

func TestImportFixtureWithSymlinkedTemporaryDirectory(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "temporary-directory-alias")
	if err := os.Symlink(directory, alias); err != nil {
		t.Skipf("directory symlinks unavailable: %v", err)
	}
	repo, store := verificationRepositoryAtDirectory(t, alias)
	draft, err := prepareImport(repo, utils.HostInfo{Host: "192.0.2.1", User: "root", Port: 2222, Password: "symlink-fixture-secret"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := draft.save(t.Context(), repo); err != nil {
		t.Fatalf("import through system temporary alias: %v", err)
	}
	cfg, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	node, ok := cfg.Nodes.Get(draft.nodeID)
	if !ok {
		t.Fatal("import did not persist the node")
	}
	id, ok := cfg.Identities.Get(node.IdentityRef)
	if !ok || persistedTestPassword(t, cfg, id) != "symlink-fixture-secret" {
		t.Fatal("import did not persist the credential reference")
	}
}

func TestImportVerificationPolicies(t *testing.T) {
	for _, tc := range []struct {
		name          string
		opts          ImportOptions
		count, checks int
		status        string
	}{
		{name: "default", count: 1, checks: 2, status: "NOT saved"},
		{name: "skip", opts: ImportOptions{SkipVerify: true}, count: 2, status: "verification skipped"},
		{name: "save_failed", opts: ImportOptions{SaveOnVerifyFailure: true}, count: 2, checks: 2, status: "saved because --save-on-verify-failure"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo, store := verificationRepository(t)
			var calls atomic.Int32
			wantErr := errors.New("authentication rejected")
			verify := func(_ context.Context, repo *config.Repository, id string, draft *inventoryVerification) error {
				calls.Add(1)
				if _, ok := repo.GetNode(id); ok {
					t.Error("node was saved before verification")
				}
				if draft.Host.Port != 2222 || draft.Identity.Password != "candidate-secret" {
					t.Error("verification did not receive the imported port and password")
				}
				if draft.Host.Address == "192.0.2.2" {
					return wantErr
				}
				return nil
			}
			var out bytes.Buffer
			tc.opts.Output = &out
			err := executeImport(t.Context(), repo, []utils.HostInfo{
				{Host: "192.0.2.1", User: "root", Port: 2222, Password: "candidate-secret"},
				{Host: "192.0.2.2", User: "root", Port: 2222, Password: "candidate-secret"},
			}, tc.opts, verify)
			if errors.Is(err, wantErr) != !tc.opts.SkipVerify {
				t.Fatalf("unexpected import error: %v", err)
			}
			cfg, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Nodes.Count() != tc.count || int(calls.Load()) != tc.checks {
				t.Fatalf("saved %d nodes, ran %d checks", cfg.Nodes.Count(), calls.Load())
			}
			if !strings.Contains(out.String(), tc.status) || !strings.Contains(out.String(), "root@192.0.2.2:2222") {
				t.Fatalf("missing failed-node disposition: %s", out.String())
			}
		})
	}
}

func TestFailedImportDoesNotUpdateExistingNode(t *testing.T) {
	repo, _ := verificationRepository(t)
	addr := utils.HostInfo{Host: "192.0.2.1", User: "root", Port: 2222, Password: "old-secret"}
	draft, err := prepareImport(repo, addr, "old-tag")
	if err != nil {
		t.Fatal(err)
	}
	if err := draft.save(t.Context(), repo); err != nil {
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
	addr.Password, addr.Alias = "wrong-new-secret", "new-alias"
	verify := func(_ context.Context, _ *config.Repository, _ string, bundle *inventoryVerification) error {
		if bundle.Identity.Password != addr.Password {
			t.Error("verification used old credentials")
		}
		return errors.New("new password rejected")
	}
	var out bytes.Buffer
	if err := executeImport(t.Context(), repo, []utils.HostInfo{addr}, ImportOptions{Tag: "new-tag", Output: &out}, verify); err == nil {
		t.Fatal("failed verification reported success")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("failed import changed existing data: %v", err)
	}
}

func TestImportCancellationNeverForcesSave(t *testing.T) {
	repo, store := verificationRepository(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	verify := func(context.Context, *config.Repository, string, *inventoryVerification) error {
		cancel()
		return context.Canceled
	}
	var out bytes.Buffer
	err := executeImport(ctx, repo, []utils.HostInfo{{Host: "192.0.2.1", User: "root"}}, ImportOptions{SaveOnVerifyFailure: true, Output: &out}, verify)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation was lost: %v", err)
	}
	cfg, err := store.Load()
	if err != nil || cfg.Nodes.Count() != 0 {
		t.Fatalf("canceled import saved a node: %v", err)
	}
}

func TestHostAddVerificationConfirmation(t *testing.T) {
	for _, tc := range []struct {
		name, answer      string
		fail, skip, saved bool
	}{
		{name: "success", saved: true},
		{name: "failure_declined", fail: true, answer: "n\n"},
		{name: "failure_default_no", fail: true, answer: "\n"},
		{name: "failure_eof", fail: true},
		{name: "failure_accepted", fail: true, answer: "y\n", saved: true},
		{name: "skip", skip: true, saved: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, store := verificationRepository(t)
			calls := 0
			verify := func(_ context.Context, repo *config.Repository, id string, _ *inventoryVerification) error {
				calls++
				if _, ok := repo.GetNode(id); ok {
					t.Error("add saved before verification")
				}
				if tc.fail {
					return errors.New("connection refused")
				}
				return nil
			}
			cmd := newCmdInventoryAdd(verify)
			args := []string{"--address", "192.0.2.1", "--identity", "fixture"}
			if tc.skip {
				args = append(args, "--skip-verify")
			}
			var output bytes.Buffer
			cmd.SetArgs(args)
			cmd.SetIn(io.NopCloser(strings.NewReader(tc.answer)))
			cmd.SetOut(&output)
			cmd.SetErr(&output)
			cmd.SetContext(t.Context())
			err := cmd.Execute()
			if (err == nil) != tc.saved {
				t.Fatalf("save=%v, error=%v", tc.saved, err)
			}
			cfg, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			if (cfg.Nodes.Count() == 1) != tc.saved {
				t.Fatalf("unexpected saved nodes: %d", cfg.Nodes.Count())
			}
			if (calls == 0) != tc.skip {
				t.Fatalf("verification calls=%d, skip=%v", calls, tc.skip)
			}
			if tc.fail && !strings.Contains(output.String(), "[y/N]") {
				t.Fatalf("missing save confirmation: %s", output.String())
			}
		})
	}
}

func TestImportVerificationFlagsMutuallyExclusive(t *testing.T) {
	cmd := NewCmdInventoryLoad()
	cmd.SetArgs([]string{"--skip-verify", "--save-on-verify-failure", "not-read.csv"})
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "none of the others") {
		t.Fatalf("contradictory options accepted: %v", err)
	}
}

func TestImportFailedDefaultPortDoesNotPolluteNextImport(t *testing.T) {
	repo, store := verificationRepository(t)
	verify := func(_ context.Context, _ *config.Repository, _ string, bundle *inventoryVerification) error {
		if bundle.Host.Port == 22 {
			return errors.New("connection refused on default port")
		}
		return nil
	}
	var out bytes.Buffer
	opts := ImportOptions{Output: &out}
	addr := utils.HostInfo{Host: "192.0.2.1", User: "root"}
	if err := executeImport(t.Context(), repo, []utils.HostInfo{addr}, opts, verify); err == nil {
		t.Fatal("default-port verification unexpectedly succeeded")
	}
	addr.Port = 2222
	if err := executeImport(t.Context(), repo, []utils.HostInfo{addr}, opts, verify); err != nil {
		t.Fatal(err)
	}
	cfg, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Nodes.Count() != 1 || cfg.Hosts.Count() != 1 {
		t.Fatal("failed default port left inventory entities")
	}
	if id, err := repo.ResolveSelector(addr.Host); err != nil || id != "root@192.0.2.1:2222" {
		t.Fatalf("saved address is ambiguous or incorrect: %q, %v", id, err)
	}
}

func TestImportPassphraseReplacementVerifiesNewSecret(t *testing.T) {
	draft := importDraft{
		bundle: config.ConnectionSnapshot{Identity: models.Identity{User: "root", AuthType: "key", KeyPath: "/saved/key", Passphrase: "old-secret", PassphraseRef: &credential.Ref{}}},
		addr:   utils.HostInfo{Passphrase: "replacement-secret"},
	}
	check := draft.verificationBundle()
	if check.Identity.KeyPath != "/saved/key" || check.Identity.Passphrase != "replacement-secret" || check.Identity.PassphraseRef != nil {
		t.Fatal("passphrase-only import would verify old credentials instead of the replacement")
	}
	if draft.bundle.Identity.Passphrase != "old-secret" || draft.bundle.Identity.PassphraseRef == nil {
		t.Fatal("verification changed the stored credential snapshot")
	}
}

func TestHostAddSkipVerificationWithoutCredentials(t *testing.T) {
	_, store := verificationRepository(t)
	cmd := newCmdInventoryAdd(func(context.Context, *config.Repository, string, *inventoryVerification) error {
		t.Error("skip-verify attempted a connection")
		return errors.New("unexpected verification")
	})
	cmd.SetArgs([]string{"--address", "192.0.2.1", "--user", "root", "--skip-verify"})
	cmd.SetIn(io.NopCloser(strings.NewReader("")))
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetContext(t.Context())
	if err := cmd.Execute(); err != nil {
		t.Fatalf("offline addition prompted for credentials: %v", err)
	}
	cfg, err := store.Load()
	if err != nil || cfg.Nodes.Count() != 1 {
		t.Fatalf("offline node was not saved: %v", err)
	}
}

func persistedTestPassword(t *testing.T, cfg *config.Configuration, id models.Identity) string {
	t.Helper()
	if id.Password != "" || id.LoginPasswordRef == nil {
		t.Fatal("expected a credential reference without plaintext")
	}
	registry, err := utils.GetCredentialRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := registry.Resolve(t.Context(), *id.LoginPasswordRef)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Zero()
	return string(secret.Value)
}
