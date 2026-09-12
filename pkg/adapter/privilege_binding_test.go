package adapter

import (
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/ssh"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
	"testing"
)

func TestSudoDetectionPreservesExistingSuReference(t *testing.T) {
	cfg := &config.Configuration{Nodes: concurrent.NewMap[string, models.Node](concurrent.HashString), Hosts: concurrent.NewMap[string, models.Host](concurrent.HashString), Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString)}
	ref := credential.Ref{StoreID: "file", ItemID: "root-password"}
	cfg.Hosts.Set("host", models.Host{Address: "127.0.0.1", Port: 22})
	cfg.Identities.Set("identity", models.Identity{User: "user", AuthType: "password"})
	cfg.Nodes.Set("node", models.Node{HostRef: "host", IdentityRef: "identity", SudoMode: models.SudoModeAuto, PrivilegePasswordRef: &ref})
	repo, err := config.NewRepositoryWithoutOpenSSH(cfg, adapterTestStore{})
	if err != nil {
		t.Fatal(err)
	}
	adapter := NewSSHAdapter(repo, WithCredentialRecording(true))
	snapshot, err := repo.ResolveConnection("node")
	if err != nil {
		t.Fatal(err)
	}
	token := string(snapshot.UpdateRef.SudoVersion[:])
	if got, err := adapter.UpdateSudo(t.Context(), "node", token, ssh.SudoModeSudo, ""); err != nil || got != token {
		t.Fatalf("detection: %v", err)
	}
	if _, err := adapter.UpdateSudo(t.Context(), "node", token, ssh.SudoModeSudo, "different-sudo-secret"); err == nil {
		t.Fatal("overwrote su credential as sudo")
	}
	after, err := repo.ResolveConnection("node")
	if err != nil {
		t.Fatal(err)
	}
	if after.Node.SudoMode != models.SudoModeAuto || after.Node.PrivilegePasswordRef == nil || *after.Node.PrivilegePasswordRef != ref {
		t.Fatal("detection changed original binding")
	}
}
