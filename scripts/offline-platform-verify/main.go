// Command offline-platform-verify exercises the vault and real KDF child on the
// current platform using only disposable test data. It never reads user config.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/wentf9/xops-cli/internal/credentialfile"
	"github.com/wentf9/xops-cli/internal/kdfhelper"
	"github.com/wentf9/xops-cli/pkg/credential"
)

type testPrompt struct{}

func (testPrompt) Password(context.Context, string) ([]byte, error) {
	return []byte("public-platform-test-password"), nil
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == kdfhelper.PrivateArgument {
		os.Exit(kdfhelper.ServeFiles(os.Stdin, os.Stdout))
	}
	if err := verify(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("PASS: key-file initialization, persistence, missing-key rejection, password KDF, rewrap, clone, reencrypt, deletion")
}

func verify() (err error) {
	stage := "prepare"
	defer func() {
		if err != nil {
			err = fmt.Errorf("%s: %w", stage, err)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	temporary, err := os.MkdirTemp("", "xops-platform-")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(temporary)) }()
	root, err := filepath.EvalSymlinks(temporary)
	if err != nil {
		return err
	}
	path, key := filepath.Join(root, "vault"), filepath.Join(root, "unlock.key")
	if _, err := credentialfile.ProbeCompatibility(ctx, path); err != nil {
		return fmt.Errorf("filesystem probe: %w", err)
	}
	runtime := credentialfile.NewRuntime(ctx, testPrompt{}, nil)
	defer func() { err = errors.Join(err, runtime.Close()) }()
	if _, err = runtime.Init(ctx, path, "test", credentialfile.Wrapping{Mode: "key-file", KeyFile: key}); err != nil {
		return fmt.Errorf("initialize: %w", err)
	}
	store, err := runtime.OpenStore(ctx, path, "test", credentialfile.Options{}, credentialfile.SessionOptions{Mode: "key-file", KeyFile: key})
	if err != nil {
		return err
	}
	ref := credential.Ref{StoreID: "test", ItemID: "sample"}
	value := credential.NewSecret([]byte("public-test-value"))
	defer value.Zero()
	if err = store.Put(ctx, ref, value); err != nil {
		return fmt.Errorf("put: %w", err)
	}
	if err = checkValue(ctx, store, ref, value.Value); err != nil {
		return err
	}
	if err = store.Lock(ctx); err != nil {
		return err
	}
	if err = os.Rename(key, key+".backup"); err != nil {
		return err
	}
	if err = store.Unlock(ctx); err == nil {
		return errors.New("missing original key accepted")
	}
	if err = os.Rename(key+".backup", key); err != nil {
		return err
	}
	stage = "unlock restored key"
	if err = store.Unlock(ctx); err != nil {
		return err
	}
	password := []byte("public-platform-test-password")
	if _, err = store.Rewrap(ctx, credentialfile.Wrapping{Mode: "prompt", Password: password}); err != nil {
		return fmt.Errorf("rewrap to password: %w", err)
	}
	if err = runtime.Close(); err != nil {
		return err
	}
	runtime = credentialfile.NewRuntime(ctx, testPrompt{}, nil)
	store, err = runtime.OpenStore(ctx, path, "test", credentialfile.Options{}, credentialfile.SessionOptions{Mode: "prompt"})
	if err != nil {
		return err
	}
	if err = checkValue(ctx, store, ref, value.Value); err != nil {
		return fmt.Errorf("password unlock: %w", err)
	}
	return verifyClone(ctx, runtime, store, root, ref, value.Value)
}

func verifyClone(ctx context.Context, runtime *credentialfile.Runtime, store *credentialfile.Store, root string, ref credential.Ref, value []byte) (err error) {
	stage := "clone"
	defer func() {
		if err != nil {
			err = fmt.Errorf("%s: %w", stage, err)
		}
	}()
	clonePath, cloneKey := filepath.Join(root, "clone"), filepath.Join(root, "clone.key")
	target := credentialfile.Wrapping{Mode: "key-file", KeyFile: cloneKey}
	if _, err = store.Clone(ctx, clonePath, "copy", target); err != nil {
		return fmt.Errorf("clone: %w", err)
	}
	clone, err := runtime.OpenStore(ctx, clonePath, "copy", credentialfile.Options{}, credentialfile.SessionOptions{Mode: "key-file", KeyFile: cloneKey})
	if err != nil {
		return err
	}
	cloneRef := credential.Ref{StoreID: "copy", ItemID: ref.ItemID}
	if err = checkValue(ctx, clone, cloneRef, value); err != nil {
		return err
	}
	stage = "reencrypt clone"
	if _, err = clone.Reencrypt(ctx, target); err != nil {
		return fmt.Errorf("reencrypt: %w", err)
	}
	if err = checkValue(ctx, clone, cloneRef, value); err != nil {
		return err
	}
	stage = "delete clone value"
	if err = clone.Delete(ctx, cloneRef); err != nil {
		return err
	}
	got, err := clone.Get(ctx, cloneRef)
	got.Zero()
	if !errors.Is(err, credential.ErrCredentialNotFound) {
		return fmt.Errorf("delete verification: %w", err)
	}
	return nil
}
func checkValue(ctx context.Context, store *credentialfile.Store, ref credential.Ref, want []byte) error {
	got, err := store.Get(ctx, ref)
	defer got.Zero()
	if err != nil {
		return err
	}
	if !bytes.Equal(got.Value, want) {
		return errors.New("stored value changed")
	}
	return nil
}
