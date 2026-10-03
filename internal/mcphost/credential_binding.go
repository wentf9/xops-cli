package mcphost

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
	"gopkg.in/yaml.v3"
)

// Read-only providers intentionally lack credential-write CAS tokens. Bind
// their credential dependencies separately instead of inventing writable tokens
// or persisting secrets in the connection plan. The provider is the same frozen
// view used to capture all hops; no secret-store reads are performed here.
func credentialVersion(provider config.ConfigProvider, plan ssh.ConnectionPlan) (string, error) {
	type dependency struct {
		NodeID, IdentityRef  string
		Identity             models.Identity
		SudoMode             models.SudoMode
		SuPassword           string
		PrivilegePasswordRef *credential.Ref
	}
	dependencies := make([]dependency, 0, len(plan.Hops))
	stores := make(map[string]*config.StoreConfig)
	configuration := provider.Snapshot()
	for _, hop := range plan.Hops {
		snapshot, err := provider.ResolveConnection(hop.NodeID)
		if err != nil {
			return "", fmt.Errorf("resolve MCP credential dependencies for %q: %w", hop.NodeID, err)
		}
		dependencies = append(dependencies, dependency{
			NodeID: hop.NodeID, IdentityRef: snapshot.Node.IdentityRef, Identity: snapshot.Identity,
			SudoMode: snapshot.Node.SudoMode, SuPassword: snapshot.Node.SuPwd, PrivilegePasswordRef: snapshot.Node.PrivilegePasswordRef,
		})
		for _, ref := range []*credential.Ref{snapshot.Identity.LoginPasswordRef, snapshot.Identity.PassphraseRef, snapshot.Node.PrivilegePasswordRef} {
			if ref == nil || ref.IsEmpty() {
				continue
			}
			stores[ref.StoreID] = nil
			if configuration != nil && configuration.Credential != nil {
				if source, ok := configuration.Credential.Stores[ref.StoreID]; ok {
					stores[ref.StoreID] = &source
				}
			}
		}
	}
	// YAML preserves arbitrary bytes in legacy values, unlike JSON strings.
	// Only the digest survives; display fields and unrelated stores are excluded.
	data, err := yaml.Marshal(struct {
		Dependencies []dependency
		Stores       map[string]*config.StoreConfig
	}{dependencies, stores})
	if err != nil {
		return "", fmt.Errorf("encode MCP credential dependencies: %w", err)
	}
	defer clear(data)
	digest := sha256.Sum256(data)
	return "credentials-v1:" + hex.EncodeToString(digest[:]), nil
}
