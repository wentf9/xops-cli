package cmd

import "testing"

func TestTUIRejectsInvalidRememberPolicyBeforeStartup(t *testing.T) {
	command := NewCmdTui()
	if err := command.ParseFlags([]string{"--remember", "invalid"}); err != nil {
		t.Fatal(err)
	}
	if err := command.RunE(command, nil); err == nil {
		t.Fatal("invalid TUI policy accepted")
	}
}
