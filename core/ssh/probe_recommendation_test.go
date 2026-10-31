package ssh

import "testing"

func TestProbeRecommendationPrefersDefaultShell(t *testing.T) {
	all := []Interpreter{InterpreterBash, InterpreterSh, InterpreterZsh, InterpreterFish, InterpreterCsh, InterpreterTcsh}
	for _, tt := range []struct {
		name, shell string
		dialect     LaunchDialect
		available   []Interpreter
		want        Interpreter
	}{
		{"bash default", "/bin/bash", LaunchPOSIX, all, InterpreterBash},
		{"zsh default", "/usr/local/bin/zsh", LaunchPOSIX, all, InterpreterZsh},
		{"fish default", "/usr/bin/fish", LaunchFish, all, InterpreterFish},
		{"fish dialect with stale SHELL", "/bin/bash", LaunchFish, all, InterpreterFish},
		{"fish dialect with empty SHELL", "", LaunchFish, all, InterpreterFish},
		{"fish login shell behind POSIX wrapper", "/usr/local/bin/fish", LaunchPOSIX, all, InterpreterFish},
		{"csh default", "/bin/csh", LaunchCsh, all, InterpreterCsh},
		{"tcsh default", "/bin/tcsh", LaunchCsh, all, InterpreterTcsh},
		{"csh dialect with empty SHELL", "", LaunchCsh, all, InterpreterCsh},
		{"tcsh login shell behind POSIX wrapper", "/usr/local/bin/tcsh", LaunchPOSIX, all, InterpreterTcsh},
		{"sh default", "/bin/sh", LaunchPOSIX, all, InterpreterSh},
		{"dash default", "/bin/dash", LaunchPOSIX, all, InterpreterSh},
		{"ash default", "/bin/ash", LaunchPOSIX, all, InterpreterSh},
		{"missing metadata", "", LaunchPOSIX, all, InterpreterBash},
		{"unsupported default", "/bin/ksh", LaunchPOSIX, all, InterpreterBash},
		{"default unavailable", "/usr/bin/zsh", LaunchPOSIX, []Interpreter{InterpreterBash, InterpreterSh}, InterpreterBash},
		{"fish unavailable on PATH", "/usr/bin/fish", LaunchFish, []Interpreter{InterpreterBash, InterpreterSh}, InterpreterBash},
		{"fallback sh", "", LaunchPOSIX, []Interpreter{InterpreterSh, InterpreterZsh}, InterpreterSh},
		{"fallback zsh", "", LaunchPOSIX, []Interpreter{InterpreterZsh, InterpreterFish}, InterpreterZsh},
		{"fallback fish", "", LaunchPOSIX, []Interpreter{InterpreterFish}, InterpreterFish},
		{"path is data", "/usr/bin/zsh; touch injected", LaunchPOSIX, all, InterpreterBash},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := recommendProbeExecution(tt.dialect, tt.shell, tt.available)
			if cfg.Interpreter != tt.want || cfg.LaunchDialect != tt.dialect || cfg.Login == nil || *cfg.Login {
				t.Fatalf("recommendation = %+v, want %s with login disabled", cfg, tt.want)
			}
			if err := cfg.Validate(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
