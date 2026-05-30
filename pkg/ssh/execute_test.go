package ssh

import (
	"testing"
)

func TestGetSudoParams(t *testing.T) {
	tests := []struct {
		name        string
		mode        SudoMode
		password    string
		suPwd       string
		expectedCmd string
		expectedPwd string
	}{
		{"sudo mode", SudoModeSudo, "mypass", "", "sudo -i", "mypass"},
		{"sudoer mode", SudoModeSudoer, "mypass", "", "sudo -i", ""},
		{"su mode", SudoModeSu, "", "rootpass", "su -", "rootpass"},
		{"root mode", SudoModeRoot, "", "", "", ""},
		{"invalid mode", SudoMode("unknown"), "", "", "", ""},
		{"empty mode", SudoModeNone, "", "", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				cfg: &ClientConfig{
					SudoMode: tt.mode,
					SuPwd:    tt.suPwd,
					Password: tt.password,
				},
			}

			cmd, pwd := c.getSudoParams()
			if cmd != tt.expectedCmd {
				t.Errorf("expected cmd %q, got %q", tt.expectedCmd, cmd)
			}
			if pwd != tt.expectedPwd {
				t.Errorf("expected pwd %q, got %q", tt.expectedPwd, pwd)
			}
		})
	}
}

func TestPasswordPromptRegex_TwoLayerFallback(t *testing.T) {
	// 1. 节点级正则优先
	c := newClient(nil, &ClientConfig{PasswordPromptPattern: `(?i)custom:`}, nil, `(?i)global:`)
	re := c.passwordPromptRegex()
	if !re.MatchString("Custom: ") {
		t.Errorf("node-level pattern should have priority")
	}
	if re.MatchString("Global: ") {
		t.Errorf("connector-level pattern should be overridden by node-level")
	}

	// 2. 节点级为空时回落到 Connector 全局级
	c2 := newClient(nil, &ClientConfig{}, nil, `(?i)global:`)
	re2 := c2.passwordPromptRegex()
	if !re2.MatchString("Global: ") {
		t.Errorf("connector-level pattern should be used when node-level is empty")
	}

	// 3. 两者均为空时回落到内置默认
	c3 := newClient(nil, &ClientConfig{}, nil, "")
	re3 := c3.passwordPromptRegex()
	if !re3.MatchString("Password: ") {
		t.Errorf("default pattern should match 'Password:'")
	}
	if !re3.MatchString("密码：") {
		t.Errorf("default pattern should match Chinese prompt")
	}

	// 4. 节点级正则无效时静默降级
	c4 := newClient(nil, &ClientConfig{PasswordPromptPattern: `[invalid`}, nil, "")
	re4 := c4.passwordPromptRegex()
	if !re4.MatchString("Password: ") {
		t.Errorf("should fall back to default when node-level pattern is invalid")
	}
}
