package config

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/wentf9/xops-cli/internal/credentialfile/format"
	"github.com/wentf9/xops-cli/pkg/credential"
	"gopkg.in/yaml.v3"
)

func (s *StoreConfig) decodeFileDurations(raw rawStoreConfig, node *yaml.Node) error {
	for _, field := range []struct {
		name string
		raw  *string
		dest *time.Duration
	}{
		{"unlock_idle_ttl", raw.UnlockIdleTTL, &s.UnlockIdleTTL},
		{"prompt_timeout", raw.PromptTimeout, &s.PromptTimeout},
		{"unlock_timeout", raw.UnlockTimeout, &s.UnlockTimeout},
	} {
		if field.raw != nil {
			duration, err := time.ParseDuration(*field.raw)
			if err != nil || duration <= 0 {
				return fmt.Errorf("%w: %s must be a positive duration", ErrSchemaValidation, field.name)
			}
			*field.dest = duration
		}
	}
	if s.Type == StoreTypeEncryptedFile {
		for i := 0; i < len(node.Content); i += 2 {
			name := node.Content[i].Value
			if node.Content[i+1].Tag == "!!null" {
				return fmt.Errorf("%w: null encrypted-file field %s", ErrSchemaValidation, name)
			}
			if name == "timeout" && s.Timeout <= 0 {
				return fmt.Errorf("%w: timeout must be positive", ErrSchemaValidation)
			}
			if name == "command" || name == "args" || name == "prefix" {
				return fmt.Errorf("%w: encrypted-file rejects %s", ErrSchemaValidation, name)
			}
		}
		*s = FileStoreDefaults(*s)
	}
	return validateFileStore(*s)
}

// FileStoreDefaults applies the encrypted-file defaults to an in-memory configuration.
// YAML decoding separately rejects explicit zero duration fields.
func FileStoreDefaults(s StoreConfig) StoreConfig {
	if s.Type != StoreTypeEncryptedFile {
		return s
	}
	if s.UnlockIdleTTL == 0 {
		s.UnlockIdleTTL = 5 * time.Minute
	}
	if s.PromptTimeout == 0 {
		s.PromptTimeout = 2 * time.Minute
	}
	if s.UnlockTimeout == 0 {
		s.UnlockTimeout = 30 * time.Second
	}
	if s.Timeout == 0 {
		s.Timeout = 10 * time.Second
	}
	return s
}

func validateFileStore(s StoreConfig) error {
	if s.Type != StoreTypeEncryptedFile {
		if s.Path != "" || s.Unlock != "" || s.KeyFile != "" || s.UnlockIdleTTL != 0 || s.PromptTimeout != 0 || s.UnlockTimeout != 0 {
			return fmt.Errorf("%w: offline fields require encrypted-file", ErrSchemaValidation)
		}
		return nil
	}
	s = FileStoreDefaults(s)
	if s.Path == "" || (s.Unlock != "prompt" && s.Unlock != "key-file") || (s.Unlock == "key-file") != (s.KeyFile != "") {
		return fmt.Errorf("%w: encrypted-file requires path and matching unlock/key_file", ErrSchemaValidation)
	}
	if fileStoreHasHelper(s) {
		return fmt.Errorf("%w: encrypted-file rejects helper settings", ErrSchemaValidation)
	}
	if s.UnlockIdleTTL <= 0 || s.UnlockIdleTTL > 30*time.Minute || s.PromptTimeout <= 0 || s.UnlockTimeout <= 0 || s.Timeout <= 0 || s.CacheTTL < 0 {
		return fmt.Errorf("%w: invalid encrypted-file duration", ErrSchemaValidation)
	}
	return nil
}

// ResolveFileStore resolves vault paths relative to the actual configuration file.
// An empty configuration filename permits only absolute vault and key paths.
func ResolveFileStore(s StoreConfig, configPath string) (StoreConfig, error) {
	if err := validateFileStore(s); err != nil {
		return s, err
	}
	s = FileStoreDefaults(s)
	for _, path := range []*string{&s.Path, &s.KeyFile} {
		if *path == "" {
			continue
		}
		if !filepath.IsAbs(*path) {
			if configPath == "" || !filepath.IsAbs(configPath) {
				return s, fmt.Errorf("%w: relative vault path requires absolute configuration filename", ErrSchemaValidation)
			}
			*path = filepath.Join(filepath.Dir(configPath), *path)
		}
		*path = filepath.Clean(*path)
	}
	return s, nil
}

func fileStoreHasHelper(s StoreConfig) bool {
	return s.Command != "" || len(s.Args) != 0 || s.Prefix != ""
}

// MarshalYAML writes effective offline defaults so in-memory zero defaults do
// not turn into explicitly invalid zero durations when configuration is saved.
func (s StoreConfig) MarshalYAML() (any, error) {
	type plain StoreConfig
	return plain(FileStoreDefaults(s)), nil
}

func validateFileStoreIdentity(id string, cfg StoreConfig) error {
	if cfg.Type == StoreTypeEncryptedFile && len(id) > format.MaxIDBytes {
		return fmt.Errorf("%w: encrypted-file StoreID exceeds limit", ErrSchemaValidation)
	}
	return validateFileStore(cfg)
}
func validateConfiguredRef(ref credential.Ref, stores map[string]StoreConfig) error {
	if err := ref.Validate(); err != nil {
		return err
	}
	if stores[ref.StoreID].Type == StoreTypeEncryptedFile && (len(ref.StoreID) > format.MaxIDBytes || len(ref.ItemID) > format.MaxIDBytes) {
		return fmt.Errorf("%w: encrypted-file reference exceeds limit", credential.ErrInvalidRef)
	}
	return nil
}
