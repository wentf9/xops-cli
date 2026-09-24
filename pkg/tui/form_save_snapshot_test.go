package tui

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	sshcrypto "golang.org/x/crypto/ssh"
)

func newCredentialSaveTestModel(t *testing.T, authType string) (*Model, *memoryCredentialStore) {
	t.Helper()
	repo := newTestRepository(t, newFormCredentialTestConfiguration(""))
	store := newMemoryCredentialStore()
	m := newPasswordReplaceFormModel(repo, newFormCredentialTestService(t, repo, store), "submitted-secret")
	m.ctx = t.Context()
	m.state = viewForm
	m.lastSize = tea.WindowSizeMsg{Width: 80, Height: 24}
	if authType == "key" {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		block, err := sshcrypto.MarshalPrivateKeyWithPassphrase(key, "", []byte("submitted-secret"))
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "key")
		if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
			t.Fatal(err)
		}
		m.formState.authType = "key"
		m.formState.keyPath = path
		m.formState.passphrase = "submitted-secret"
		m.formState.passphraseAction = "replace"
	}
	m.initForm("")
	t.Cleanup(func() { closeTUITestResource(t, m) })
	return m, store
}

func assertSubmittedCredential(t *testing.T, m *Model, store *memoryCredentialStore) {
	t.Helper()
	if m.state != viewList || len(store.data) != 1 {
		t.Fatalf("credential save did not complete: %s", m.status)
	}
	for _, secret := range store.data {
		if string(secret.Value) != "submitted-secret" {
			t.Fatal("save used credentials changed after submission")
		}
	}
}

func TestFormSaveUsesSubmittedCredentialSnapshot(t *testing.T) {
	for _, authType := range []string{"password", "key"} {
		t.Run(authType, func(t *testing.T) {
			m, store := newCredentialSaveTestModel(t, authType)
			_, cmd := m.Update(tea.KeyPressMsg{Code: 's', Mod: tea.ModCtrl})
			m.formState.password = "changed-after-submission"
			m.formState.passphrase = "changed-after-submission"
			completeConfigurationMutation(t, m, cmd)
			assertSubmittedCredential(t, m, store)
		})
	}
}

func TestFormResizeDuringCredentialSave(t *testing.T) {
	for _, authType := range []string{"password", "key"} {
		t.Run(authType, func(t *testing.T) {
			m, store := newCredentialSaveTestModel(t, authType)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			m.ctx = ctx
			_, cmd := m.Update(tea.KeyPressMsg{Code: 's', Mod: tea.ModCtrl})
			if cmd == nil {
				t.Fatal("save command missing")
			}
			started, done := make(chan struct{}), make(chan struct{})
			var result tea.Msg
			go func() {
				defer close(done)
				close(started)
				result = cmd()
			}()
			defer func() { cancel(); <-done }()
			<-started
			for range 20 {
				m.Update(tea.WindowSizeMsg{Width: 40, Height: 12})
				m.View()
				m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
				m.Update(tea.KeyPressMsg{Code: 'x', Text: "x"})
			}
			<-done
			m.Update(result)
			assertSubmittedCredential(t, m, store)
		})
	}
}
