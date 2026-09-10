//go:build linux

package credentialhelper

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/wentf9/xops-cli/pkg/credential"
	"go.uber.org/goleak"
)

func TestSecretServiceStalledAuthentication(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	for _, mode := range []string{"timeout", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "bus")
			listener, err := net.Listen("unix", path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := listener.Close(); err != nil {
					t.Error(err)
				}
			}()
			t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path="+path)
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			store := &linuxNativeStore{timeout: 100 * time.Millisecond}
			if mode == "cancel" {
				store.timeout = 5 * time.Second
			}
			done := make(chan error, 1)
			go func() {
				got, err := store.getWithoutPrompt(ctx, credential.Ref{StoreID: "system", ItemID: "item"})
				got.Zero()
				done <- err
			}()
			// The context always ends the client and this test waits for its result.
			if err := listener.(*net.UnixListener).SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			peer, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := peer.Close(); err != nil {
					t.Error(err)
				}
			}()
			if mode == "cancel" {
				cancel()
			}
			select {
			case err := <-done:
				want := context.DeadlineExceeded
				if mode == "cancel" {
					want = context.Canceled
				}
				if !errors.Is(err, want) {
					t.Fatalf("got %v, want %v", err, want)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("stalled authentication did not stop")
			}
		})
	}
}

func TestReadServiceSecretWithoutPrompt(t *testing.T) {
	item := dbus.ObjectPath("/items/test")
	session := dbus.ObjectPath("/sessions/test")
	cases := []struct {
		name                    string
		unlocked, locked        []dbus.ObjectPath
		readErr, closeErr, want error
		byteSessionOutput       bool
	}{
		{name: "existing unlocked credential", unlocked: []dbus.ObjectPath{item}},
		{name: "KDE empty byte session output", unlocked: []dbus.ObjectPath{item}, byteSessionOutput: true},
		{name: "locked credential", locked: []dbus.ObjectPath{item}, want: credential.ErrCredentialStoreLocked},
		{name: "missing credential", want: credential.ErrCredentialNotFound},
		{name: "relocked during read", unlocked: []dbus.ObjectPath{item}, readErr: dbus.Error{Name: "org.freedesktop.Secret.Error.IsLocked"}, want: credential.ErrCredentialStoreLocked},
		{name: "service failure", unlocked: []dbus.ObjectPath{item}, readErr: dbus.Error{Name: "org.freedesktop.DBus.Error.Failed", Body: []any{"secret-must-not-leak"}}, want: credential.ErrCredentialStoreUnavailable},
		{name: "cleanup failure", unlocked: []dbus.ObjectPath{item}, closeErr: errors.New("secret-must-not-leak"), want: credential.ErrCredentialStoreUnavailable},
		{name: "ambiguous credential", unlocked: []dbus.ObjectPath{item, "/items/other"}, want: credential.ErrCredentialStoreUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var methods []string
			payload := []byte("public-test-value")
			call := func(_ context.Context, path dbus.ObjectPath, method string, args ...any) *dbus.Call {
				methods = append(methods, method)
				switch method {
				case secretServiceInterface + ".SearchItems":
					if path != secretServicePath || !reflect.DeepEqual(args, []any{map[string]string{"xops-store": "system", "xops-item": "item"}}) {
						t.Fatal("incorrect search identity")
					}
					return &dbus.Call{Body: []any{tc.unlocked, tc.locked}}
				case secretServiceInterface + ".OpenSession":
					outputs := map[bool]dbus.Variant{false: dbus.MakeVariant(""), true: dbus.MakeVariant([]byte{})}
					return &dbus.Call{Body: []any{outputs[tc.byteSessionOutput], session}}
				case "org.freedesktop.Secret.Item.GetSecret":
					if path != item || len(args) != 1 || args[0] != session {
						t.Fatal("incorrect secret request")
					}
					return &dbus.Call{Err: tc.readErr, Body: []any{serviceSecret{Session: session, Value: payload, ContentType: "text/plain"}}}
				case "org.freedesktop.Secret.Session.Close":
					return &dbus.Call{Err: tc.closeErr}
				default:
					t.Fatalf("unexpected method, including forbidden Unlock/Prompt: %s", method)
					return nil
				}
			}
			got, err := readServiceSecret(t.Context(), credential.Ref{StoreID: "system", ItemID: "item"}, call)
			defer got.Zero()
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if err != nil && strings.Contains(err.Error(), "secret-must-not-leak") {
				t.Fatal("service error body leaked")
			}
			if err == nil && string(got.Value) != "public-test-value" {
				t.Fatal("existing credential not returned")
			}
			if err != nil && len(got.Value) != 0 {
				t.Fatal("secret returned on failure")
			}
			if len(methods) > 1 && methods[len(methods)-1] != "org.freedesktop.Secret.Session.Close" {
				t.Fatal("session not closed")
			}
		})
	}
}

func TestSessionBusSocket(t *testing.T) {
	for _, tc := range []struct{ address, want string }{
		{"unix:path=/run/user/1000/bus", "/run/user/1000/bus"},
		{"unix:abstract=test%2Bbus,guid=abc", "\x00test+bus"},
	} {
		got, err := sessionBusSocket(tc.address)
		if err != nil || got != tc.want {
			t.Fatalf("socket %q: %q, %v", tc.address, got, err)
		}
	}
	for _, address := range []string{"", "autolaunch:", "tcp:host=example.com", "unix:path=relative", "unix:path=/a,abstract=b", "unix:path=/a;unix:path=/b", "unix:path=/%00", "unix:path=/%zz"} {
		if _, err := sessionBusSocket(address); err == nil {
			t.Fatalf("accepted %q", address)
		}
	}
}

func TestSecretServiceRejectsInvalidValues(t *testing.T) {
	session := dbus.ObjectPath("/sessions/test")
	for _, tc := range []struct {
		name  string
		value serviceSecret
		want  error
	}{
		{"wrong session", serviceSecret{Session: "/sessions/other", Value: []byte("public")}, credential.ErrCredentialStoreUnavailable},
		{"unexpected encryption parameters", serviceSecret{Session: session, Parameters: []byte{1}, Value: []byte("public")}, credential.ErrCredentialStoreUnavailable},
		{"oversized value", serviceSecret{Session: session, Value: make([]byte, MaxResponseBytes+1)}, credential.ErrCredentialStoreUnavailable},
		{"empty value", serviceSecret{Session: session}, credential.ErrCredentialNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			closed := false
			call := func(_ context.Context, _ dbus.ObjectPath, method string, _ ...any) *dbus.Call {
				switch method {
				case secretServiceInterface + ".SearchItems":
					return &dbus.Call{Body: []any{[]dbus.ObjectPath{"/items/test"}, []dbus.ObjectPath{}}}
				case secretServiceInterface + ".OpenSession":
					return &dbus.Call{Body: []any{dbus.MakeVariant(""), session}}
				case "org.freedesktop.Secret.Item.GetSecret":
					return &dbus.Call{Body: []any{tc.value}}
				case "org.freedesktop.Secret.Session.Close":
					closed = true
					return &dbus.Call{}
				default:
					t.Fatalf("unexpected method %s", method)
					return nil
				}
			}
			got, err := readServiceSecret(t.Context(), credential.Ref{StoreID: "system", ItemID: "item"}, call)
			defer got.Zero()
			if !errors.Is(err, tc.want) || len(got.Value) != 0 || !closed {
				t.Fatalf("invalid value accepted or session leaked: %v", err)
			}
			for _, b := range tc.value.Value {
				if b != 0 {
					t.Fatal("returned transport buffer not cleared")
				}
			}
		})
	}
}
