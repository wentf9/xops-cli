package config

// DefaultCredentialConfig returns independent, lazy new-install defaults. Paths
// are relative to the configuration file, never to the working directory.
// Callers must preserve existing explicit backend and remember-policy choices.
func DefaultCredentialConfig() *CredentialConfig {
	return &CredentialConfig{
		DefaultStore:     "file",
		RememberPrompted: "always",
		Stores: map[string]StoreConfig{
			"file": FileStoreDefaults(StoreConfig{
				Type:    StoreTypeEncryptedFile,
				Path:    "credentials",
				Unlock:  "key-file",
				KeyFile: "credentials.key",
			}),
		},
	}
}
