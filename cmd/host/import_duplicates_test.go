package host

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
)

func TestImportRepeatedEndpointPreservesRowOrder(t *testing.T) {
	for _, existing := range []bool{false, true} {
		for _, mode := range []string{"skip", "verify", "save_failed"} {
			t.Run(fmt.Sprintf("existing=%t/%s", existing, mode), func(t *testing.T) {
				repo, store := verificationRepository(t)
				addr := utils.HostInfo{Host: "192.0.2.10", User: "root", Port: 22}
				wantAliases := []string{}
				if existing {
					addr.Alias = "existing"
					draft, err := prepareImport(repo, addr, "")
					if err != nil {
						t.Fatal(err)
					}
					if err := draft.save(t.Context(), repo); err != nil {
						t.Fatal(err)
					}
					wantAliases = append(wantAliases, addr.Alias)
				}
				var rows []utils.HostInfo
				for index := range 8 {
					row := addr
					row.Alias = fmt.Sprintf("alias-%d", index)
					row.Password = fmt.Sprintf("secret-%d", index)
					// Omitted/default ports and surrounding whitespace must share
					// the same serialized endpoint as their explicit equivalents.
					if index%2 == 0 {
						row.Port, row.Host, row.User = 0, " 192.0.2.10 ", " root "
					}
					rows = append(rows, row)
					wantAliases = append(wantAliases, row.Alias)
				}
				wantErr := errors.New("verification rejected")
				verify := func(context.Context, *config.Repository, string, *inventoryVerification) error {
					if mode == "skip" {
						t.Error("skip-verify attempted verification")
					}
					if mode == "save_failed" {
						return wantErr
					}
					return nil
				}
				var out bytes.Buffer
				err := executeImport(t.Context(), repo, rows, ImportOptions{SkipVerify: mode == "skip", SaveOnVerifyFailure: mode == "save_failed", Output: &out}, verify)
				if mode == "save_failed" {
					if !errors.Is(err, wantErr) || errors.Is(err, config.ErrConfigConflict) {
						t.Fatalf("unexpected failure: %v", err)
					}
				} else if err != nil {
					t.Fatalf("duplicate rows failed: %v", err)
				}
				assertRepeatedImportSaved(t, store, wantAliases)
				if lines := bytes.Count(out.Bytes(), []byte("\n")); lines != len(rows) {
					t.Fatalf("reported %d rows, want %d", lines, len(rows))
				}
			})
		}
	}
}

func TestImportDifferentEndpointsRemainConcurrent(t *testing.T) {
	repo, _ := verificationRepository(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	entered := make(chan string, 4)
	release := make(chan struct{})
	verify := func(ctx context.Context, _ *config.Repository, id string, draft *inventoryVerification) error {
		if len(draft.Node.Alias) == 1 {
			entered <- id
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	}
	rows := []utils.HostInfo{
		{Host: "192.0.2.1", User: "root", Alias: "a-first"},
		{Host: "192.0.2.2", User: "root", Alias: "b-first"},
		{Host: "192.0.2.1", User: "root", Alias: "a-second"},
		{Host: "192.0.2.2", User: "root", Alias: "b-second"},
	}
	var out bytes.Buffer
	var importErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		importErr = executeImport(ctx, repo, rows, ImportOptions{Output: &out}, verify)
	}()
	defer func() { cancel(); <-done }()
	endpoints := make(map[string]bool)
	for range 2 {
		select {
		case id := <-entered:
			endpoints[id] = true
		case <-ctx.Done():
			t.Fatal("different endpoints did not verify concurrently")
		}
	}
	if len(endpoints) != 2 {
		t.Fatal("concurrent checks targeted the same node")
	}
	close(release)
	<-done
	if importErr != nil {
		t.Fatal(importErr)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != len(rows) {
		t.Fatalf("reported %d rows", len(lines))
	}
	for index, row := range rows {
		if !strings.Contains(lines[index], config.FormatNodeID(row.User, row.Host, 22)) {
			t.Fatalf("results did not preserve CSV order: %s", out.String())
		}
	}
}

func assertRepeatedImportSaved(t *testing.T, store config.Store, wantAliases []string) {
	t.Helper()
	cfg, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Nodes.Count() != 1 {
		t.Fatalf("saved %d nodes", cfg.Nodes.Count())
	}
	node, ok := cfg.Nodes.Get("root@192.0.2.10:22")
	if !ok || !reflect.DeepEqual(node.Alias, wantAliases) {
		t.Fatalf("aliases = %v, want %v", node.Alias, wantAliases)
	}
	identity, ok := cfg.Identities.Get(node.IdentityRef)
	if !ok || persistedTestPassword(t, cfg, identity) != "secret-7" {
		t.Fatal("last CSV row did not determine the saved credential")
	}
}
