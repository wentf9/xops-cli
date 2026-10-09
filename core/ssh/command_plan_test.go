package ssh

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestCommandPlanServerPreservesBytes(t *testing.T) {
	command := "  printf '%s\\n' \"$HOME\"; echo $(id) &\r\n雪\\%PATH%\xff"
	input := []byte{0, 1, 255, '\n'}
	plan, err := PlanCommand(command, CommandOptions{Stdin: input})
	if err != nil {
		t.Fatal(err)
	}
	input[0] = 42
	if plan.Payload() != command || plan.Command() != command || plan.input[0] != 0 {
		t.Fatal("command or input bytes were changed")
	}
	if plan.Interpreter() != InterpreterServer || plan.LaunchDialect() != LaunchUnknown || plan.LoginMode() != LoginInherit {
		t.Fatalf("unexpected defaults: %+v", plan)
	}
	if plan.timeout != DefaultCommandTimeout || plan.outputLimit != DefaultCommandOutput || len(plan.Digest()) != 64 {
		t.Fatal("missing bounded defaults or digest")
	}
}

func TestCommandPlanBashAndDigest(t *testing.T) {
	command := "printf '%s\\n' \"$HOME\""
	base := CommandOptions{Interpreter: InterpreterBash, LaunchDialect: LaunchPOSIX}
	plan, err := PlanCommand(command, base)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Payload() != "bash -c "+shellQuote(command) || plan.LoginMode() != LoginDisabled {
		t.Fatalf("unexpected Bash plan: %+v", plan)
	}
	for _, modify := range []func(*CommandOptions){
		func(o *CommandOptions) { o.Login = LoginEnabled },
		func(o *CommandOptions) { o.Stdin = []byte("data") },
		func(o *CommandOptions) { o.Timeout = time.Second },
		func(o *CommandOptions) { o.OutputLimit = 1024 },
	} {
		options := base
		modify(&options)
		other, err := PlanCommand(command, options)
		if err != nil {
			t.Fatal(err)
		}
		if other.Digest() == plan.Digest() {
			t.Fatal("changed semantics did not change digest")
		}
	}
	base.Login = LoginEnabled
	login, err := PlanCommand(command, base)
	if err != nil || login.Payload() != "bash -l -c "+shellQuote(command) {
		t.Fatalf("login payload %q: %v", login.Payload(), err)
	}
	a, err := PlanCommand("\xff", CommandOptions{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := PlanCommand("\xfe", CommandOptions{})
	if err != nil || a.Digest() == b.Digest() {
		t.Fatalf("invalid UTF-8 collapsed in digest: %v", err)
	}
}

func TestCommandPlanRejectsUnsupportedCombinations(t *testing.T) {
	for name, options := range map[string]CommandOptions{
		"unknown interpreter":  {Interpreter: "sh"},
		"unknown dialect":      {LaunchDialect: "fish"},
		"unknown login":        {Login: "sometimes"},
		"server login":         {Login: LoginEnabled},
		"server no login":      {Login: LoginDisabled},
		"bash unknown dialect": {Interpreter: InterpreterBash},
		"bash cmd dialect":     {Interpreter: InterpreterBash, LaunchDialect: LaunchCmd},
		"negative timeout":     {Timeout: -1},
		"negative output":      {OutputLimit: -1},
		"large output":         {OutputLimit: MaxCommandOutput + 1},
		"large stdin":          {Stdin: make([]byte, MaxCommandInputBytes+1)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := PlanCommand("echo command", options); err == nil {
				t.Fatal("invalid options accepted")
			}
		})
	}
	for _, command := range []string{"", "cmd\x00data", strings.Repeat("a", MaxCommandBytes+1)} {
		if _, err := PlanCommand(command, CommandOptions{}); err == nil {
			t.Fatal("invalid command accepted")
		}
	}
}

func TestCommandPlanBashQuotingInRealShell(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("Bash not available for explicit Bash adapter test")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("POSIX launch shell not available")
	}
	literal := "雪 'quote' \"double\" \\back $HOME $(exit 99) & %PATH%\nnext"
	command := "printf '%s' " + shellQuote(literal)
	plan, err := PlanCommand(command, CommandOptions{Interpreter: InterpreterBash, LaunchDialect: LaunchPOSIX})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "sh", "-c", plan.Payload()).CombinedOutput()
	if err != nil || string(output) != literal {
		t.Fatalf("Bash quoting changed data: %q, %v", output, err)
	}
}

func TestCommandPlanRejectsOversizeQuotedPayload(t *testing.T) {
	// POSIX quoting expands each apostrophe. Validate the generated request,
	// not just the original input, before opening any SSH channel.
	command := strings.Repeat("'", MaxCommandBytes/2)
	if _, err := PlanCommand(command, CommandOptions{Interpreter: InterpreterBash, LaunchDialect: LaunchPOSIX}); err == nil || !strings.Contains(err.Error(), "generated exec payload") {
		t.Fatalf("oversize quoted payload accepted: %v", err)
	}
}
