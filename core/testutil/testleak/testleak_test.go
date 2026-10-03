package testleak

import (
	"errors"
	"testing"
)

func TestTestLeakAssertions(t *testing.T) {
	data := []byte("hello world token=super-secret-1234")
	secret := "super-secret-1234"
	otherSecret := "not-present"

	AssertSecretPresentInBytes(t, data, secret)
	AssertSecretPresentInString(t, string(data), secret)
	AssertNoSecretInBytes(t, data, otherSecret)
	AssertNoSecretInString(t, string(data), otherSecret)

	err := errors.New("something went wrong without sensitive data")
	AssertNoSecretInError(t, err, secret, otherSecret)
	AssertNoSecretInError(t, nil, secret)

	yamlData := []byte("user: test\npassword: \"[ENC:AES-GCM:fake-ciphertext]\"\n")
	AssertNoSecretInYAML(t, yamlData, secret)

	bufLogger := NewBufferLogger()
	bufLogger.Debug("connecting to host %s:%d", "127.0.0.1", 22)
	bufLogger.Debugf("session established successfully")
	AssertNoSecretInLogs(t, bufLogger, secret)
	AssertSecretPresentInString(t, bufLogger.String(), "127.0.0.1")
}
