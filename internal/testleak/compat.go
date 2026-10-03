// Package testleak preserves the original import path for the shared XOps implementation.
package testleak

import (
	core "github.com/wentf9/xops-cli/core/testutil/testleak"
	testing "testing"
)

func AssertNoSecretInBytes(t testing.TB, data []byte, secrets ...string) {
	core.AssertNoSecretInBytes(t, data, secrets...)
}

func AssertNoSecretInString(t testing.TB, text string, secrets ...string) {
	core.AssertNoSecretInString(t, text, secrets...)
}

func AssertNoSecretInError(t testing.TB, err error, secrets ...string) {
	core.AssertNoSecretInError(t, err, secrets...)
}

func AssertNoSecretInYAML(t testing.TB, yamlData []byte, secrets ...string) {
	core.AssertNoSecretInYAML(t, yamlData, secrets...)
}

func AssertSecretPresentInBytes(t testing.TB, data []byte, secret string) {
	core.AssertSecretPresentInBytes(t, data, secret)
}

func AssertSecretPresentInString(t testing.TB, text string, secret string) {
	core.AssertSecretPresentInString(t, text, secret)
}

type BufferLogger = core.BufferLogger

func NewBufferLogger() *BufferLogger { return core.NewBufferLogger() }

func AssertNoSecretInLogs(t testing.TB, l *BufferLogger, secrets ...string) {
	core.AssertNoSecretInLogs(t, l, secrets...)
}
