package adapter

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	cryptoSSH "golang.org/x/crypto/ssh"
)

func TestVerificationProbeReusesAuthenticationWithoutPersistence(t *testing.T) {
	setTestHome(t)
	for _, mode := range []string{"verify only", "probe", "restricted probe", "probe timeout"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			server, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{ExecHandler: func(command string, channel cryptoSSH.Channel) {
				if mode == "probe timeout" {
					<-ctx.Done()
					return
				}
				output := "restricted shell\n"
				if mode == "probe" {
					output = "__XOPS_INTERP__:bash\n__XOPS_INTERP__:sh\n__XOPS_INTERP_END__\n"
					if strings.Contains(command, "__XOPS_DIALECT_POSIX__") {
						output = "__XOPS_DIALECT_POSIX__:Linux:/bin/bash\n"
					}
				}
				if _, err := io.WriteString(channel, output); err != nil {
					t.Error(err)
					return
				}
				if _, err := channel.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0})); err != nil {
					t.Error(err)
				}
			}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := server.Close(); err != nil {
					t.Error(err)
				}
			})
			host, portText, err := net.SplitHostPort(server.Address)
			if err != nil {
				t.Fatal(err)
			}
			port, err := strconv.ParseUint(portText, 10, 16)
			if err != nil {
				t.Fatal(err)
			}
			repo, _, path, before := pendingAdapterRepository(t)
			preview, err := repo.PreviewConnection("draft", models.Node{}, models.Host{Address: host, Port: uint16(port)}, models.Identity{User: "fixture", AuthType: "password", Password: sshfixture.Password})
			if err != nil {
				t.Fatal(err)
			}
			wantCommands := int32(0)
			if mode == "verify only" {
				err = VerifyConnection(ctx, preview, "draft", nil)
			} else {
				result, verifyErr := VerifyConnectionWithProbe(ctx, preview, "draft", nil)
				err = verifyErr
				wantCommands = map[string]int32{"probe": 2, "restricted probe": 3, "probe timeout": 1}[mode]
				if mode != "probe" {
					if !errors.Is(result.ProbeErr, ssh.ErrExecutionProbe) {
						t.Fatalf("probe error not retained: %v", result.ProbeErr)
					}
				} else if result.ProbeErr != nil || result.Probe == nil || result.Probe.RecommendedInterpreter != ssh.InterpreterBash {
					t.Fatalf("unexpected probe result: %+v", result)
				}
			}
			if err != nil {
				t.Fatalf("authenticated verification failed: %v", err)
			}
			assertVerificationProbeUnchanged(t, server, wantCommands, path, before, repo)
		})
	}
}

func assertVerificationProbeUnchanged(t *testing.T, server *sshfixture.Server, wantCommands int32, path string, before []byte, repo *config.Repository) {
	t.Helper()
	if server.Authenticated.Load() != 1 || server.Executed.Load() != wantCommands {
		t.Fatalf("handshakes %d, commands %d, want 1/%d", server.Authenticated.Load(), server.Executed.Load(), wantCommands)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) || repo.Snapshot().Nodes.Count() != 0 {
		t.Fatalf("verification/probing changed persisted data: %v", err)
	}
}
