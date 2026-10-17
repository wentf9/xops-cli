package ssh

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	corelog "github.com/wentf9/xops-cli/core/log"
)

type cancelStartedDiagnostic struct {
	*diagnosticRecorder
	cancel context.CancelFunc
}

func (r cancelStartedDiagnostic) ObserveDiagnostic(event corelog.Diagnostic) {
	r.diagnosticRecorder.ObserveDiagnostic(event)
	if event.Kind == corelog.SessionStarted {
		r.cancel()
	}
}

//nolint:gocyclo // Exercise the execution/outcome matrix without splitting fixture ownership.
func TestSessionDiagnosticsPreserveResults(t *testing.T) {
	for _, mode := range []string{"plan", "stream"} {
		for _, outcome := range []string{"success", "nonzero", "signal", "missing", "reject", "cancel"} {
			t.Run(mode+"/"+outcome, func(t *testing.T) {
				scenario := &commandFixture{output: "private-output"}
				switch outcome {
				case "nonzero":
					scenario.status = 37
				case "signal":
					scenario.signal = true
				case "missing":
					scenario.missing = true
				case "reject":
					scenario.reject = true
				case "cancel":
					scenario.hangCommand = true
				}
				client := commandTestClient(t, scenario)
				recorder := &diagnosticRecorder{}
				client.diagnostics = recorder
				ctx := t.Context()
				if outcome == "cancel" {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
					defer cancel()
					// Cancel only after exec acceptance, not after an arbitrary
					// scheduling interval that can expire before channel startup.
					client.diagnostics = cancelStartedDiagnostic{recorder, cancel}
				}
				plan, err := PlanCommand("private-command-secret", CommandOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if mode == "plan" {
					err = client.ExecuteCommand(ctx, plan).Err()
				} else {
					var output, stderr bytes.Buffer
					err = client.RunCommandPlanWithIO(ctx, plan, strings.NewReader("private-input-secret"), &output, &stderr)
				}
				if (err == nil) != (outcome == "success") {
					t.Fatalf("execution changed: %v", err)
				}
				if outcome == "cancel" && !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation lost: %v", err)
				}
				exits, starts := 0, 0
				accepted := false
				for _, event := range recorder.snapshot() {
					if event.Kind == corelog.SessionRequest && event.Operation == "exec" && event.Outcome == "accepted" {
						accepted = true
					}
					if event.Kind == corelog.SessionStarted {
						if !accepted {
							t.Fatal("session start reported before request acceptance")
						}
						starts++
					}
					if strings.Contains(event.Operation+event.Outcome+event.Source+event.Destination, "private-") {
						t.Fatal("private operation data leaked")
					}
					if event.Kind != corelog.SessionFinished {
						continue
					}
					exits++
					if event.HasExitCode != (outcome == "success" || outcome == "nonzero") {
						t.Fatalf("exit status fabricated/lost: %+v", event)
					}
					if outcome == "nonzero" && event.ExitCode != 37 {
						t.Fatalf("nonzero lost: %+v", event)
					}
					if outcome == "signal" && event.Outcome != "signaled" {
						t.Fatalf("signal lost: %+v", event)
					}
				}
				if outcome == "reject" {
					if starts != 0 {
						t.Fatal("rejected exec claimed a started session")
					}
				} else if starts != 1 || (outcome != "cancel" && exits != 1) || exits > 1 {
					t.Fatalf("started=%d finished=%d", starts, exits)
				}
			})
		}
	}
}

func TestForwardDiagnosticLifecycle(t *testing.T) {
	recorder := &diagnosticRecorder{}
	client := &Client{diagnostics: recorder}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	forward, err := client.Socks5Forward(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// A second listener cannot claim an established forward on the same address.
	if _, err := client.LocalForward(ctx, forward.Addr().String(), "127.0.0.1:1"); err == nil {
		t.Fatal("duplicate listener accepted")
	}
	cancel()
	if err := forward.Wait(); err != nil {
		t.Fatal(err)
	}
	events := recorder.snapshot()
	if len(events) != 3 || events[0].Outcome != "listening" || events[1].Outcome != "listen failed" || events[2].Outcome != "closed" {
		t.Fatalf("incorrect listener events: %+v", events)
	}
}
