package ssh

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestPrivilegePromptWriterPreservesOutput(t *testing.T) {
	for split := 0; split <= len("first<marker>middle<marker>last<mar"); split++ {
		var out bytes.Buffer
		w := &privilegePromptWriter{marker: []byte("<marker>"), target: &out}
		data := []byte("first<marker>middle<marker>last<mar")
		for _, part := range [][]byte{data[:split], data[split:]} {
			if _, err := w.Write(part); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.flush(); err != nil {
			t.Fatal(err)
		}
		if !w.observed || out.String() != "firstmiddlelast<mar" {
			t.Fatalf("split %d corrupted output: %q", split, out.String())
		}
	}
}

func TestPrivilegeAcquisitionNeverSaves(t *testing.T) {
	recorder := &testRecorder{}
	ui := &probeSecretPrompter{returnSecret: "unverified"}
	c := &Client{prompter: ui, recorder: recorder, connCfg: ConnectionConfig{NodeID: "test", SudoMode: SudoModeSu, SudoUpdateToken: "sudo-token"}}
	value, err := c.resolvePrivilegeMaterial(t.Context(), SecretKindSuPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer value.Zero()
	if recorder.sudoCalls != 0 {
		t.Fatal("saved before remote verification")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := c.confirmPrivilege(ctx, value); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if recorder.sudoCalls != 0 {
		t.Fatal("saved after cancellation")
	}
}

func TestSudoVerifiedPasswordUsesIndependentRecorder(t *testing.T) {
	setTestHome(t)
	server := startLifetimeTestSSHServerWithRecorder(t, "password", nil, true)
	defer server.cleanup()
	provider := &trackingProvider{cfg: &ClientConfig{NodeID: "test", Address: server.host, Port: server.port, User: "user", AuthType: "password", Password: "password", SudoMode: SudoModeSudo, AuthUpdateToken: "auth", SudoUpdateToken: "sudo"}}
	recorder := &testRecorder{}
	c := NewConnector(provider, WithSecretPrompter(&probeSecretPrompter{returnSecret: "password"}), WithCredentialRecorder(recorder))
	c.AcceptNewHostKey.Store(true)
	defer func() {
		if err := c.CloseAll(); err != nil {
			t.Error(err)
		}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client, err := c.Connect(ctx, "test")
	if err != nil {
		t.Fatal(err)
	}
	output, err := client.RunWithSudo(ctx, "whoami")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "mock-sudo-success") || strings.Contains(output, "xops-password") {
		t.Fatalf("unexpected output: %q", output)
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.authCalls != 0 || recorder.sudoCalls != 1 || recorder.lastSuPass != "password" {
		t.Fatal("sudo secret did not use independent privilege recorder")
	}
}

func TestRejectedPrivilegePasswordIsNotSaved(t *testing.T) {
	for _, mode := range []SudoMode{SudoModeSudo, SudoModeSu} {
		t.Run(string(mode), func(t *testing.T) {
			setTestHome(t)
			server := startLifetimeTestSSHServerWithRecorder(t, "valid", nil, true)
			defer server.cleanup()
			provider := &trackingProvider{cfg: &ClientConfig{NodeID: "test", Address: server.host, Port: server.port, User: "user", AuthType: "password", Password: "valid", SudoMode: mode, AuthUpdateToken: "auth", SudoUpdateToken: "sudo"}}
			recorder := &testRecorder{}
			ui := &probeSecretPrompter{returnSecret: "rejected"}
			c := NewConnector(provider, WithSecretPrompter(ui), WithCredentialRecorder(recorder))
			c.AcceptNewHostKey.Store(true)
			defer func() {
				if err := c.CloseAll(); err != nil {
					t.Error(err)
				}
			}()
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			client, err := c.Connect(ctx, "test")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.RunWithSudo(ctx, "whoami"); err == nil {
				t.Fatal("rejected password succeeded")
			}
			recorder.mu.Lock()
			calls := recorder.authCalls + recorder.sudoCalls
			recorder.mu.Unlock()
			if calls != 0 {
				t.Fatal("rejected password persisted")
			}
			ui.mu.Lock()
			ui.returnSecret = "valid"
			ui.mu.Unlock()
			if _, err := client.RunWithSudo(ctx, "whoami"); err != nil {
				t.Fatal(err)
			}
			recorder.mu.Lock()
			defer recorder.mu.Unlock()
			if recorder.authCalls != 0 || recorder.sudoCalls != 1 {
				t.Fatal("validated password not saved independently")
			}
		})
	}
}

func TestAutoSuDoesNotPromptAndDiscardCandidate(t *testing.T) {
	setTestHome(t)
	server := startLifetimeTestSSHServerWithRecorder(t, "valid", nil, true)
	defer server.cleanup()
	provider := &trackingProvider{cfg: &ClientConfig{NodeID: "test", Address: server.host, Port: server.port, User: "user", AuthType: "password", Password: "valid", SudoMode: SudoModeAuto, SudoUpdateToken: "sudo"}}
	recorder := &testRecorder{}
	ui := &recoveryTestUI{values: []string{"sudo-rejected", "valid"}}
	c := NewConnector(provider, WithInteractionHandler(ui), WithCredentialRecorder(recorder))
	defer func() {
		if err := c.CloseAll(); err != nil {
			t.Error(err)
		}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client, err := c.Connect(ctx, "test")
	if err != nil {
		t.Fatal(err)
	}
	output, err := client.RunWithSudo(ctx, "whoami")
	if err != nil || !strings.Contains(output, "mock-su-success") {
		t.Fatalf("su fallback failed: %v", err)
	}
	ui.mu.Lock()
	defer ui.mu.Unlock()
	if ui.prompts != 2 {
		t.Fatalf("got %d prompts; expected one sudo and one su prompt", ui.prompts)
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.sudoCalls != 1 || recorder.lastSuPass != "valid" {
		t.Fatal("unverified candidate saved or verified su password lost")
	}
}

type detectedSudoRecorder struct {
	nopCredentialRecorder
	provider *trackingProvider
	tokens   []string
}

func (r *detectedSudoRecorder) UpdateSudo(_ context.Context, _ string, token string, _ SudoMode, _ string) (string, error) {
	r.tokens = append(r.tokens, token)
	r.provider.mu.Lock()
	r.provider.cfg.SudoUpdateToken = "committed-mode"
	r.provider.cfg.SudoMode = SudoModeSudo
	r.provider.mu.Unlock()
	return "committed-mode", nil
}
func TestDetectedSudoSavesAgainstCommittedModeVersion(t *testing.T) {
	provider := &trackingProvider{cfg: &ClientConfig{NodeID: "test", SudoUpdateToken: "original", AuthUpdateToken: "login"}}
	recorder := &detectedSudoRecorder{provider: provider}
	client := &Client{provider: provider, recorder: recorder, connCfg: provider.cfg.ToConnectionConfig()}
	material := &PrivilegeMaterial{Password: []byte("verified"), verified: true, confirmedSave: func(context.Context, []byte) error { return errors.New("stale callback used") }}
	defer material.Zero()
	if err := client.confirmDetectedSudo(t.Context(), material); err != nil {
		t.Fatal(err)
	}
	if len(recorder.tokens) != 2 || recorder.tokens[0] != "original" || recorder.tokens[1] != "committed-mode" {
		t.Fatalf("incorrect write versions: %v", recorder.tokens)
	}
	if client.ConnectionConfig().AuthUpdateToken != "login" {
		t.Fatal("mode confirmation changed login authorization")
	}
}
