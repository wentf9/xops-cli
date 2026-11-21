// Command offline-vault-verify is a release-test driver, not an XOps helper.
// It checks the public drill fixture through the original configuration reference.
package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/wentf9/xops-cli/core/fsx"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
)

const fixtureValue = "release-drill-public-secret"

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		if _, writeErr := fmt.Fprintln(os.Stderr, "offline release fixture verification failed"); writeErr != nil {
			os.Exit(1)
		}
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) (err error) {
	if len(args) != 1 {
		return fmt.Errorf("configuration filename required")
	}
	ctx, cancel := context.WithTimeout(credential.WithoutInteraction(context.Background()), 10*time.Second)
	defer cancel()
	raw, err := readConfig(args[0])
	if err != nil {
		return err
	}
	defer clear(raw)
	cfg, err := config.UnmarshalV2(raw)
	if err != nil {
		return err
	}
	identity, ok := cfg.Identities["demo"]
	if !ok || identity.LoginPasswordRef == nil {
		return fmt.Errorf("fixture reference missing")
	}
	ref := *identity.LoginPasswordRef
	st, ok := cfg.Credential.Stores[ref.StoreID]
	if !ok || ref.StoreID != "offline" || st.Type != config.StoreTypeEncryptedFile || st.Unlock != "key-file" {
		return fmt.Errorf("unexpected fixture backend")
	}
	owner := config.NewEncryptedRuntime(ctx, args[0], nil)
	defer func() { err = errors.Join(err, owner.Close()) }()
	registry, err := owner.Registry(&cfg.Credential)
	if err != nil {
		return err
	}
	secret, err := registry.Resolve(ctx, ref)
	defer secret.Zero()
	if err != nil {
		return err
	}
	if !matchesFixture(secret) {
		return fmt.Errorf("restored fixture differs")
	}
	return json.NewEncoder(out).Encode(struct {
		Verified bool           `json:"verified"`
		Ref      credential.Ref `json:"ref"`
	}{true, ref})
}

func matchesFixture(secret credential.Secret) bool {
	return secret.ExpiresAt == nil && subtle.ConstantTimeCompare(secret.Value, []byte(fixtureValue)) == 1
}

func readConfig(path string) ([]byte, error) {
	const limit = 16 << 20
	raw, err := fsx.ReadAllBounded(path, fsx.Limits{MaxBytes: limit}, fsx.FollowSymlinks())
	if err != nil {
		if errors.Is(err, fsx.ErrTooLarge) {
			return nil, fmt.Errorf("fixture configuration too large: %w", err)
		}
		if errors.Is(err, fsx.ErrNonRegular) {
			return nil, fmt.Errorf("invalid fixture configuration file: %w", err)
		}
		return nil, err
	}
	return raw, nil
}
