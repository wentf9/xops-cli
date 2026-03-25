package host

import (
	"reflect"
	"testing"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
)

// mockProvider implements config.ConfigProvider for testing
type mockProvider struct {
	nodes      map[string]models.Node
	hosts      map[string]models.Host
	identities map[string]models.Identity
}

func newMockProvider() *mockProvider {
	return &mockProvider{
		nodes:      make(map[string]models.Node),
		hosts:      make(map[string]models.Host),
		identities: make(map[string]models.Identity),
	}
}

func (m *mockProvider) GetNode(name string) (models.Node, bool) {
	n, ok := m.nodes[name]
	return n, ok
}
func (m *mockProvider) GetHost(name string) (models.Host, bool) {
	h, ok := m.hosts[name]
	return h, ok
}
func (m *mockProvider) GetIdentity(name string) (models.Identity, bool) {
	i, ok := m.identities[name]
	return i, ok
}
func (m *mockProvider) AddHost(name string, host models.Host) { m.hosts[name] = host }
func (m *mockProvider) AddIdentity(name string, identity models.Identity) {
	m.identities[name] = identity
}
func (m *mockProvider) AddNode(name string, node models.Node)           { m.nodes[name] = node }
func (m *mockProvider) DeleteNode(name string)                          { delete(m.nodes, name) }
func (m *mockProvider) ListNodes() map[string]models.Node               { return m.nodes }
func (m *mockProvider) GetNodesByTag(tag string) map[string]models.Node { return nil }
func (m *mockProvider) ListIdentities() map[string]models.Identity      { return m.identities }
func (m *mockProvider) DeleteIdentity(name string)                      { delete(m.identities, name) }
func (m *mockProvider) Find(input string) string                        { return "" }
func (m *mockProvider) FindAlias(alias string) string                   { return "" }
func (m *mockProvider) GetConfig() *config.Configuration {
	return &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
}

func TestApplyNodeUpdates(t *testing.T) {
	host := &models.Host{Address: "old_ip", Port: 22}
	identity := &models.Identity{User: "old_user"}
	node := &models.Node{Alias: []string{"old_alias"}}
	provider := newMockProvider()
	oldName := "old_user@old_ip:22"

	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("alias", []string{}, "")
	cmd.Flags().String("jump", "", "")

	// Test 1: update address, port, user
	flags := &editFlags{
		address: "new_ip",
		port:    2222,
		user:    "new_user",
	}

	updated, nameChanged := applyNodeUpdates(cmd, provider, oldName, host, identity, node, flags)
	if !updated || !nameChanged {
		t.Errorf("expected updated/nameChanged = true, got %v/%v", updated, nameChanged)
	}
	if host.Address != "new_ip" || host.Port != 2222 || identity.User != "new_user" {
		t.Errorf("Test 1 fields did not update correctly")
	}

	// Test 2: Set flag manually for alias
	flags2 := &editFlags{
		alias: []string{"new_alias"},
	}
	_ = cmd.Flags().Set("alias", "new_alias")
	updated, nameChanged = applyNodeUpdates(cmd, provider, oldName, host, identity, node, flags2)
	if !updated || nameChanged {
		t.Errorf("expected updated=true, nameChanged=false, got %v/%v", updated, nameChanged)
	}
	if !reflect.DeepEqual(node.Alias, []string{"new_alias"}) {
		t.Errorf("alias did not update to new_alias")
	}

	// Test 3: Password change
	flags3 := &editFlags{
		password: "new_password",
	}
	updated, nameChanged = applyNodeUpdates(cmd, provider, oldName, host, identity, node, flags3)
	if !updated || nameChanged {
		t.Errorf("expected updated=true, nameChanged=false, got %v/%v", updated, nameChanged)
	}
	if identity.Password != "new_password" || identity.AuthType != "password" {
		t.Errorf("Test 3 fields did not update correctly")
	}
}
