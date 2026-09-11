//go:build linux

package credentialhelper

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/wentf9/xops-cli/pkg/credential"
)

const secretService = "org.freedesktop.secrets"
const secretServicePath dbus.ObjectPath = "/org/freedesktop/secrets"
const secretServiceInterface = "org.freedesktop.Secret.Service"

// secretServiceCall keeps the no-prompt protocol independently testable.
type secretServiceCall func(context.Context, dbus.ObjectPath, string, ...any) *dbus.Call

type serviceSecret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

// sessionBusSocket deliberately accepts only an explicitly configured local bus.
// It never autolaunches a desktop session or connects to a remote TCP bus.
func sessionBusSocket(address string) (string, error) {
	if !strings.HasPrefix(address, "unix:") || strings.Contains(address, ";") {
		return "", errors.New("a single local Unix D-Bus address is required")
	}
	var socket string
	for _, field := range strings.Split(strings.TrimPrefix(address, "unix:"), ",") {
		key, raw, ok := strings.Cut(field, "=")
		if !ok {
			return "", errors.New("invalid D-Bus address field")
		}
		value, err := url.PathUnescape(raw)
		if err != nil || value == "" || strings.ContainsRune(value, 0) {
			return "", errors.New("invalid D-Bus address value")
		}
		switch key {
		case "path", "abstract":
			if socket != "" {
				return "", errors.New("ambiguous D-Bus socket")
			}
			if key == "abstract" {
				socket = "\x00" + value
			} else {
				if !strings.HasPrefix(value, "/") {
					return "", errors.New("D-Bus socket path must be absolute")
				}
				socket = value
			}
		case "guid":
		default:
			return "", errors.New("unsupported D-Bus address field")
		}
	}
	if socket == "" {
		return "", errors.New("missing D-Bus socket")
	}
	return socket, nil
}

func (s *linuxNativeStore) getWithoutPrompt(ctx context.Context, ref credential.Ref) (secret credential.Secret, retErr error) {
	timeout := s.timeout
	if timeout <= 0 {
		timeout = DefaultHelperTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	socket, err := sessionBusSocket(os.Getenv("DBUS_SESSION_BUS_ADDRESS"))
	if err != nil {
		return secret, fmt.Errorf("resolve Secret Service bus: %w: %w", credential.ErrCredentialStoreUnavailable, err)
	}
	var dialer net.Dialer
	wire, err := dialer.DialContext(ctx, "unix", socket)
	if err != nil {
		return secret, secretServiceError(ctx, "connect bus", err)
	}
	// The wire remains owned here; the D-Bus connection uses a borrowed closer.
	defer func() {
		if err := wire.Close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close Secret Service socket: %w", err))
		}
		if retErr != nil {
			secret.Zero()
		}
	}()
	deadline, _ := ctx.Deadline()
	if err := wire.SetDeadline(deadline); err != nil {
		return secret, fmt.Errorf("set Secret Service deadline: %w", err)
	}
	conn, err := dbus.NewConn(borrowedBusSocket{wire}, dbus.WithContext(ctx))
	if err != nil {
		return secret, fmt.Errorf("create Secret Service connection: %w", credential.ErrCredentialStoreUnavailable)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close Secret Service connection: %w", err))
		}
	}()
	if err := conn.Auth([]dbus.Auth{dbus.AuthExternal(fmt.Sprint(os.Geteuid()))}); err != nil {
		return secret, secretServiceError(ctx, "authenticate bus", err)
	}
	if err := conn.Hello(); err != nil {
		return secret, secretServiceError(ctx, "register bus connection", err)
	}
	call := func(ctx context.Context, path dbus.ObjectPath, method string, args ...any) *dbus.Call {
		return conn.Object(secretService, path).CallWithContext(ctx, method, dbus.FlagNoAutoStart, args...)
	}
	return readServiceSecret(ctx, ref, call)
}

// Closing the D-Bus transport interrupts I/O while the owner performs Close.
type borrowedBusSocket struct{ net.Conn }

func (s borrowedBusSocket) Close() error { return s.SetDeadline(time.Now()) }

func secretServiceError(ctx context.Context, operation string, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("secret service %s: %w", operation, ctx.Err())
	}
	// A socket deadline may fire just before the context timer is scheduled.
	var networkErr net.Error
	if errors.As(err, &networkErr) && networkErr.Timeout() {
		return fmt.Errorf("secret service %s: %w", operation, context.DeadlineExceeded)
	}
	var busErr dbus.Error
	if errors.As(err, &busErr) {
		switch busErr.Name {
		case "org.freedesktop.Secret.Error.IsLocked":
			return fmt.Errorf("secret service %s: %w", operation, credential.ErrCredentialStoreLocked)
		case "org.freedesktop.DBus.Error.NameHasNoOwner", "org.freedesktop.DBus.Error.ServiceUnknown":
			return fmt.Errorf("secret service %s: %w: org.freedesktop.secrets is not running or unavailable on the session bus; non-interactive probes do not auto-start it; start your desktop keyring service and retry", operation, credential.ErrCredentialStoreUnavailable)
		case "org.freedesktop.DBus.Error.AccessDenied":
			return fmt.Errorf("secret service %s: %w: session bus access denied", operation, credential.ErrCredentialStoreUnavailable)
		}
	}
	// Service error bodies may contain secrets. Do not include them in diagnostics.
	return fmt.Errorf("secret service %s: %w", operation, credential.ErrCredentialStoreUnavailable)
}

// SearchItems and GetSecret never request Unlock or Prompt. A relock between
// search and read is handled by the service's IsLocked error, without fallback.
func readServiceSecret(ctx context.Context, ref credential.Ref, call secretServiceCall) (result credential.Secret, retErr error) {
	var unlocked, locked []dbus.ObjectPath
	err := call(ctx, secretServicePath, secretServiceInterface+".SearchItems", map[string]string{
		"xops-store": ref.StoreID, "xops-item": ref.ItemID,
	}).Store(&unlocked, &locked)
	if err != nil {
		return result, secretServiceError(ctx, "search items", err)
	}
	if len(unlocked) == 0 {
		if len(locked) != 0 {
			return result, credential.ErrCredentialStoreLocked
		}
		return result, credential.ErrCredentialNotFound
	}
	if len(unlocked) != 1 || len(locked) != 0 || !unlocked[0].IsValid() || unlocked[0] == "/" {
		return result, fmt.Errorf("ambiguous Secret Service item: %w", credential.ErrCredentialStoreUnavailable)
	}
	var output dbus.Variant
	var session dbus.ObjectPath
	err = call(ctx, secretServicePath, secretServiceInterface+".OpenSession", "plain", dbus.MakeVariant("")).Store(&output, &session)
	if err != nil {
		return result, secretServiceError(ctx, "open session", err)
	}
	if !session.IsValid() || session == "/" {
		return result, fmt.Errorf("invalid Secret Service session: %w", credential.ErrCredentialStoreUnavailable)
	}
	defer func() {
		if err := call(ctx, session, "org.freedesktop.Secret.Session.Close").Err; err != nil {
			retErr = errors.Join(retErr, secretServiceError(ctx, "close session", err))
		}
		if retErr != nil {
			result.Zero()
		}
	}()
	// Plain sessions have no negotiation payload. Implementations differ in
	// the type of their empty output variant; validate the actual secret below.
	var value serviceSecret
	err = call(ctx, unlocked[0], "org.freedesktop.Secret.Item.GetSecret", session).Store(&value)
	defer clear(value.Value)
	if err != nil {
		return result, secretServiceError(ctx, "read item", err)
	}
	if value.Session != session || len(value.Parameters) != 0 || len(value.Value) > MaxResponseBytes {
		return result, fmt.Errorf("invalid Secret Service secret: %w", credential.ErrCredentialStoreUnavailable)
	}
	if len(value.Value) == 0 {
		return result, credential.ErrCredentialNotFound
	}
	if err := ctx.Err(); err != nil {
		return result, fmt.Errorf("read Secret Service item: %w", err)
	}
	return credential.NewSecret(value.Value), nil
}
