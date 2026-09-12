package utils

import (
	"context"
	"fmt"

	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
)

// RememberLocalSudoPassword applies the configured policy after successful sudo.
// none always leaves the secret in the session, including on new installations.
func RememberLocalSudoPassword(ctx context.Context, password string) error {
	_, _, cfg, err := GetConfigStore()
	if err != nil {
		return err
	}
	credCfg := credentialConfigOrDefault(cfg)
	if store, ok := credCfg.Stores[credCfg.DefaultStore]; ok && store.Type == config.StoreTypeNone {
		return nil
	}
	if !ShouldRememberConfiguredCredential(EffectiveRememberPolicy("", cfg), "local sudo", cfg) {
		return nil
	}
	return SaveLocalSudoPasswordContext(ctx, password)
}

func saveLocalSudoCredential(ctx context.Context, repo *config.Repository, username, password string) error {
	if password == "" {
		return fmt.Errorf("local sudo password is empty")
	}
	nodeID, err := resolveFirstSelector(repo, "localhost", "local", username)
	if err != nil {
		return err
	}
	var identity models.Identity
	var version string
	var updater credential.ConfigUpdater
	create := nodeID == ""
	if create {
		nodeID = username + "@localhost"
		identity = models.Identity{User: username, AuthType: "password"}
		updater = repo.NodeCredentialCreate(nodeID, models.Node{
			Alias: []string{"localhost", "local", username}, HostRef: "localhost",
			IdentityRef: username + "@local", SudoMode: models.SudoModeSudo,
		}, models.Host{Address: "127.0.0.1", Port: 22, Alias: []string{"localhost", "local"}}, identity)
	} else {
		connection, err := repo.ResolveConnection(nodeID)
		if err != nil {
			return fmt.Errorf("resolve local sudo connection: %w", err)
		}
		if connection.UpdateRef == nil {
			return fmt.Errorf("local sudo node has no writable authentication version")
		}
		version = string(connection.UpdateRef.AuthVersion[:])
		identity = connection.Identity
	}
	write, err := PrepareInventoryCredential(repo, credential.Target{NodeID: nodeID}, identity, password, "", "", updater)
	if err != nil {
		return err
	}
	defer write.Clear()
	return write.Save(ctx, version)
}
