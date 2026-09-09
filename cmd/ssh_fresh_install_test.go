package cmd

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/ssh"
)

func TestHostKeyConfirmationAcceptsExplicitYesForms(t *testing.T) {
	for _, answer := range []string{"y", "Y", "yes", "YES", "no", "", "maybe"} {
		t.Run(answer, func(t *testing.T) {
			var output bytes.Buffer
			h := newCLIInteractionHandlerWithStreams(io.NopCloser(strings.NewReader(answer+"\n")), &output)
			got, err := h.ConfirmHostKey(t.Context(), ssh.HostKeyConfirmation{Hostname: "test", Fingerprint: "SHA256:test"})
			want := strings.EqualFold(answer, "y") || strings.EqualFold(answer, "yes")
			if err != nil || got != want {
				t.Fatalf("confirmation=%v, want=%v, err=%v", got, want, err)
			}
		})
	}
}

func TestSSHConnectionErrorHasNoUnboundTemplateFields(t *testing.T) {
	i18n.SetLang("zh")
	t.Cleanup(func() { i18n.SetLang("en") })
	cause := errors.New("connection refused")
	err := sshConnectionError("root@10.0.0.4:3922", cause)
	if strings.Contains(err.Error(), "<no value>") || !strings.Contains(err.Error(), "root@10.0.0.4:3922") || !errors.Is(err, cause) {
		t.Fatalf("malformed connection error: %v", err)
	}
}
