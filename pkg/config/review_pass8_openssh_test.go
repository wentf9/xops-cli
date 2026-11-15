package config

import (
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
)

func TestPass8_H2_SendEnvTopToBottomAndSetEnvFirstDirectiveWins(t *testing.T) {
	dir := t.TempDir()
	incPath := filepath.Join(dir, "inc.conf")
	incContent := strings.Join([]string{
		"Host t",
		"    SendEnv -FOO_* BAR",
		"    SetEnv SECOND=2",
		"",
		"Host t2",
		"    SetEnv SECOND=2",
	}, "\n") + "\n"
	if err := os.WriteFile(incPath, []byte(incContent), 0o600); err != nil {
		t.Fatalf("write include: %v", err)
	}

	mainPath := filepath.Join(dir, "ssh_config")
	mainContent := strings.Join([]string{
		"Host t",
		"    HostName 10.0.0.10",
		"    SendEnv FOO_1 FOO_2",
		"    Include " + incPath,
		"    SendEnv -BAR BAZ",
		"    SetEnv FIRST=1 DUP=a DUP=b",
		"",
		"Host t2",
		"    HostName 10.0.0.11",
		"    SetEnv FIRST=1 DUP=a DUP=b",
		"    Include " + incPath,
		"",
		"Host *",
		"    SendEnv FOO_1 GLOBAL",
		"    SetEnv GLOBAL_ENV=3",
	}, "\n") + "\n"
	if err := os.WriteFile(mainPath, []byte(mainContent), 0o600); err != nil {
		t.Fatalf("write main config: %v", err)
	}

	parser, err := NewOpenSSHParserFromPath(mainPath)
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromPath: %v", err)
	}

	optsT, err := parser.GetSSHOptions("t")
	if err != nil {
		t.Fatalf("GetSSHOptions(t): %v", err)
	}
	hostEnv := func() []string {
		return []string{"FOO_1=1", "FOO_2=2", "BAR=3", "BAZ=4", "GLOBAL=5"}
	}
	resolvedT, err := ssh.ResolveSessionEnv(optsT, hostEnv)
	if err != nil {
		t.Fatalf("ResolveSessionEnv(t): %v", err)
	}
	gotT := make(map[string]string, len(resolvedT))
	for _, ev := range resolvedT {
		gotT[ev.Name] = ev.Value
	}
	for _, wantKey := range []string{"BAZ", "FOO_1", "GLOBAL", "SECOND"} {
		if _, ok := gotT[wantKey]; !ok {
			t.Errorf("host t missing expected env %s; got=%+v", wantKey, gotT)
		}
	}
	for _, unwanted := range []string{"FOO_2", "BAR", "FIRST", "DUP", "GLOBAL_ENV"} {
		if _, ok := gotT[unwanted]; ok {
			t.Errorf("host t unexpectedly included env %s=%q; got=%+v", unwanted, gotT[unwanted], gotT)
		}
	}

	optsT2, err := parser.GetSSHOptions("t2")
	if err != nil {
		t.Fatalf("GetSSHOptions(t2): %v", err)
	}
	resolvedT2, err := ssh.ResolveSessionEnv(optsT2, nil)
	if err != nil {
		t.Fatalf("ResolveSessionEnv(t2): %v", err)
	}
	if len(resolvedT2) != 2 || resolvedT2[0] != (ssh.EnvVar{Name: "FIRST", Value: "1"}) || resolvedT2[1] != (ssh.EnvVar{Name: "DUP", Value: "a"}) {
		t.Fatalf("host t2 SetEnv = %+v, want [FIRST=1 DUP=a]", resolvedT2)
	}
}

func TestPass8_M6_ParseOpenSSHHostsExpandsHostNameAndStripsBrackets(t *testing.T) {
	cfgText := strings.Join([]string{
		"Host app",
		"    HostName %h.corp.internal",
		"    User deploy",
		"",
		"Host v6",
		"    HostName [2001:db8::1]",
		"    Port 2222",
	}, "\n") + "\n"

	hosts, err := ParseOpenSSHHosts(strings.NewReader(cfgText), "fallback")
	if err != nil {
		t.Fatalf("ParseOpenSSHHosts: %v", err)
	}
	byName := make(map[string]OpenSSHHost, len(hosts))
	for _, h := range hosts {
		byName[h.Name] = h
	}
	if got := byName["app"].Host.Address; got != "app.corp.internal" {
		t.Fatalf("app Host.Address = %q, want app.corp.internal", got)
	}
	if got := byName["v6"].Host.Address; got != "2001:db8::1" {
		t.Fatalf("v6 Host.Address = %q, want 2001:db8::1", got)
	}
}

func TestPass8_L2_IncludeQuotesEscapesAndTokens(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("USERPROFILE", homeDir)

	incDir := filepath.Join(homeDir, "incdir")
	if err := os.MkdirAll(incDir, 0o700); err != nil {
		t.Fatalf("mkdir incDir: %v", err)
	}
	t.Setenv("PASS8_INC_DIR", incDir)

	writeHostCfg := func(path, host, addr string) {
		t.Helper()
		content := "Host " + host + "\n    HostName " + addr + "\n"
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	writeHostCfg(filepath.Join(incDir, "a b.conf"), "h-single", "10.1.0.1")
	writeHostCfg(filepath.Join(incDir, "c d.conf"), "h-escape", "10.1.0.2")
	writeHostCfg(filepath.Join(incDir, "pct%conf.conf"), "h-pct", "10.1.0.3")
	writeHostCfg(filepath.Join(homeDir, "from_home.conf"), "h-home", "10.1.0.4")
	writeHostCfg(filepath.Join(incDir, "from_env.conf"), "h-env", "10.1.0.5")

	curUser, userErr := user.Current()
	hasUserTokenFile := false
	if userErr == nil && curUser.Username != "" {
		writeHostCfg(filepath.Join(incDir, curUser.Username+".conf"), "h-user", "10.1.0.6")
		hasUserTokenFile = true
	}

	hasEscapedQuoteFile := false
	if runtime.GOOS != "windows" {
		writeHostCfg(filepath.Join(incDir, `e"f.conf`), "h-dquote", "10.1.0.7")
		hasEscapedQuoteFile = true
	}

	escapedSpacePath := strings.ReplaceAll(filepath.Join(incDir, "c d.conf"), " ", `\ `)
	lines := []string{
		"Include '" + filepath.Join(incDir, "a b.conf") + "'",
		"Include " + escapedSpacePath,
		`Include "` + filepath.Join(incDir, "pct%%conf.conf") + `"`,
		"Include %d/from_home.conf",
		"Include ${PASS8_INC_DIR}/from_env.conf",
		"Include ${PASS8_UNSET_VAR}/ignored.conf",
		"Include %h.conf",
	}
	if hasUserTokenFile {
		lines = append(lines, "Include "+filepath.Join(incDir, "%u.conf"))
	}
	if hasEscapedQuoteFile {
		lines = append(lines, `Include "`+filepath.Join(incDir, `e\"f.conf`)+`"`)
	}

	mainPath := filepath.Join(homeDir, "ssh_config")
	if err := os.WriteFile(mainPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write mainPath: %v", err)
	}

	parser, err := NewOpenSSHParserFromPath(mainPath)
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromPath: %v", err)
	}

	expected := []string{"h-single", "h-escape", "h-pct", "h-home", "h-env"}
	if hasUserTokenFile {
		expected = append(expected, "h-user")
	}
	if hasEscapedQuoteFile {
		expected = append(expected, "h-dquote")
	}
	for _, name := range expected {
		if !parser.HasHost(name) {
			t.Errorf("missing included host %q (HasHost=false)", name)
		}
	}

	badPath := filepath.Join(homeDir, "bad_token_config")
	if err := os.WriteFile(badPath, []byte("Include %z.conf\n"), 0o600); err != nil {
		t.Fatalf("write badPath: %v", err)
	}
	if _, err := NewOpenSSHParserFromPath(badPath); err == nil {
		t.Fatal("expected unknown Include token %z to return an error, got nil")
	}
}
