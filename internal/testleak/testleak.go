package testleak

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
)

// AssertNoSecretInBytes asserts that none of the provided non-empty secrets
// appear anywhere in the given byte slice.
// If a secret is leaked, the test fails without exposing the raw secret value in the failure message.
func AssertNoSecretInBytes(t testing.TB, data []byte, secrets ...string) {
	t.Helper()
	for idx, secret := range secrets {
		if secret == "" {
			continue
		}
		if bytes.Contains(data, []byte(secret)) {
			t.Fatalf("security violation: secret #%d (length %d) leaked in byte slice (payload length %d)", idx+1, len(secret), len(data))
		}
	}
}

// AssertNoSecretInString asserts that none of the provided non-empty secrets
// appear anywhere in the given text string.
func AssertNoSecretInString(t testing.TB, text string, secrets ...string) {
	t.Helper()
	AssertNoSecretInBytes(t, []byte(text), secrets...)
}

// AssertNoSecretInError asserts that if err is non-nil, none of the secrets
// appear in err.Error().
func AssertNoSecretInError(t testing.TB, err error, secrets ...string) {
	t.Helper()
	if err == nil {
		return
	}
	AssertNoSecretInString(t, err.Error(), secrets...)
}

// AssertNoSecretInYAML asserts that raw serialized YAML bytes do not contain any
// plaintext secret values.
func AssertNoSecretInYAML(t testing.TB, yamlData []byte, secrets ...string) {
	t.Helper()
	AssertNoSecretInBytes(t, yamlData, secrets...)
}

// AssertSecretPresentInBytes asserts that the expected non-empty secret is present in the byte slice.
func AssertSecretPresentInBytes(t testing.TB, data []byte, secret string) {
	t.Helper()
	if secret == "" {
		t.Fatal("assert secret present called with empty secret")
	}
	if !bytes.Contains(data, []byte(secret)) {
		t.Fatalf("expected secret (length %d) to be present in byte slice (payload length %d), but was absent", len(secret), len(data))
	}
}

// AssertSecretPresentInString asserts that the expected non-empty secret is present in text.
func AssertSecretPresentInString(t testing.TB, text string, secret string) {
	t.Helper()
	AssertSecretPresentInBytes(t, []byte(text), secret)
}

// BufferLogger implements logger.DebugLogger to capture runtime logs safely in memory.
type BufferLogger struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

// NewBufferLogger creates a thread-safe in-memory buffer logger.
func NewBufferLogger() *BufferLogger {
	return &BufferLogger{}
}

func (l *BufferLogger) Debug(msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(args) == 0 {
		l.buf.WriteString(msg)
		l.buf.WriteByte('\n')
		return
	}
	fmt.Fprintf(&l.buf, msg, args...)
	l.buf.WriteByte('\n')
}

func (l *BufferLogger) Debugf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(&l.buf, format, args...)
	l.buf.WriteByte('\n')
}

// Bytes returns a thread-safe snapshot copy of captured log bytes.
func (l *BufferLogger) Bytes() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	copied := make([]byte, l.buf.Len())
	copy(copied, l.buf.Bytes())
	return copied
}

// String returns a thread-safe snapshot string of captured logs.
func (l *BufferLogger) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// AssertNoSecretInLogs asserts that none of the provided secrets appear in the captured logs.
func AssertNoSecretInLogs(t testing.TB, l *BufferLogger, secrets ...string) {
	t.Helper()
	if l == nil {
		return
	}
	AssertNoSecretInBytes(t, l.Bytes(), secrets...)
}
