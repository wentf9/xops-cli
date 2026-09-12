package config

import (
	"fmt"
	"github.com/wentf9/xops-cli/pkg/credential"
)

// BackupReferences reads a caller-selected stopped schema-v2 backup without
// loading legacy secrets or publishing configuration. Only matching refs return.
func BackupReferences(path, storeID string) ([]credential.Ref, error) {
	data, err := readMigrationFile(path)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	cfg, err := UnmarshalV2(data)
	if err != nil {
		return nil, err
	}
	if st, ok := cfg.Credential.Stores[storeID]; !ok || st.Type != StoreTypeEncryptedFile {
		return nil, fmt.Errorf("backup does not declare the encrypted-file StoreID")
	}
	var refs []credential.Ref
	add := func(ref *credential.Ref) {
		if ref != nil && ref.StoreID == storeID {
			refs = append(refs, *ref)
		}
	}
	for _, id := range cfg.Identities {
		add(id.LoginPasswordRef)
		add(id.PassphraseRef)
	}
	for _, node := range cfg.Nodes {
		add(node.PrivilegePasswordRef)
	}
	return refs, nil
}
