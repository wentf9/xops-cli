package utils

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestToAbsolutePath(t *testing.T) {
	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()

	tests := []struct {
		name        string
		input       string
		wantContain string // 使用包含检查而非精确匹配
	}{
		{
			name:        "empty string",
			input:       "",
			wantContain: "",
		},
		{
			name:        "tilde expansion",
			input:       "~/.ssh/id_rsa",
			wantContain: filepath.Join(home, ".ssh", "id_rsa"),
		},
		{
			name:        "tilde only",
			input:       "~",
			wantContain: home,
		},
		{
			name:        "relative path converted to absolute",
			input:       ".ssh/id_rsa",
			wantContain: filepath.Join(cwd, ".ssh", "id_rsa"),
		},
		{
			name:        "dot relative path",
			input:       "./id_rsa",
			wantContain: filepath.Join(cwd, "id_rsa"),
		},
		{
			name:        "parent relative path",
			input:       "../id_rsa",
			wantContain: filepath.Join(cwd, "..", "id_rsa"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ToAbsolutePath(tt.input)
			if result != tt.wantContain {
				t.Errorf("ToAbsolutePath(%q) = %q, want %q", tt.input, result, tt.wantContain)
			}
		})
	}
}

func TestToAbsolutePath_AbsolutePath(t *testing.T) {
	absPath := "/home/user/.ssh/id_rsa"
	result := ToAbsolutePath(absPath)
	if !filepath.IsAbs(result) {
		t.Errorf("ToAbsolutePath(%q) = %q, should be absolute path", absPath, result)
	}
}

func TestParsePort_ValidAndInvalid(t *testing.T) {
	tests := []struct {
		input   string
		want    uint16
		wantErr bool
	}{
		{"", 0, true},
		{"22", 22, false},
		{"65535", 65535, false},
		{"0", 0, true},
		{"70000", 0, true},
		{"invalid", 0, true},
	}

	for _, tt := range tests {
		got, err := ParsePort(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParsePort(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
		}
		if got != tt.want {
			t.Errorf("ParsePort(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestParseHost_ValidAndInvalid(t *testing.T) {
	tests := []struct {
		input    string
		wantHost string
		wantPort uint16
		wantErr  bool
	}{
		{"192.168.1.1:2222", "192.168.1.1", 2222, false},
		{"example.com", "example.com", 0, false},
		{"[::1]:22", "::1", 22, false},
		{"[::1]", "::1", 0, false},
		{"::1", "::1", 0, false},
		{"2001:db8::1", "2001:db8::1", 0, false},
		{"[2001:db8::1]:2200", "2001:db8::1", 2200, false},
		{"host:", "", 0, true},
		{"[::1]:", "", 0, true},
		{"[::1:22", "", 0, true},
		{"[invalid_ip]", "", 0, true},
		{"example.com:badport", "", 0, true},
		{"example.com:99999", "", 0, true},
		{"", "", 0, true},
	}

	for _, tt := range tests {
		h, p, err := ParseHost(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseHost(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
		}
		if h != tt.wantHost || p != tt.wantPort {
			t.Errorf("ParseHost(%q) = (%q, %d), want (%q, %d)", tt.input, h, p, tt.wantHost, tt.wantPort)
		}
	}
}

func TestParseAddr_ValidAndInvalid(t *testing.T) {
	tests := []struct {
		input    string
		wantUser string
		wantHost string
		wantPort uint16
		wantErr  bool
	}{
		{"root@10.0.0.1:2200", "root", "10.0.0.1", 2200, false},
		{"web-server", "", "web-server", 0, false},
		{"user@[2001:db8::1]:2200", "user", "2001:db8::1", 2200, false},
		{"user@[::1]", "user", "::1", 0, false},
		{"@server", "", "", 0, true},
		{"user@", "", "", 0, true},
		{"user@host:", "", "", 0, true},
		{"admin@server:99999", "", "", 0, true},
		{"", "", "", 0, true},
	}

	for _, tt := range tests {
		u, h, p, err := ParseAddr(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseAddr(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
		}
		if u != tt.wantUser || h != tt.wantHost || p != tt.wantPort {
			t.Errorf("ParseAddr(%q) = (%q, %q, %d), want (%q, %q, %d)", tt.input, u, h, p, tt.wantUser, tt.wantHost, tt.wantPort)
		}
	}
}

func TestGetConfigFilePath_And_GetCurrentUser(t *testing.T) {
	cfgPath, keyPath, err := GetConfigFilePath()
	if err != nil {
		t.Fatalf("GetConfigFilePath failed: %v", err)
	}
	if !strings.HasSuffix(cfgPath, ConfigFileName) {
		t.Errorf("expected config path to end with %s, got %s", ConfigFileName, cfgPath)
	}
	if !strings.HasSuffix(keyPath, ConfigKeyName) {
		t.Errorf("expected key path to end with %s, got %s", ConfigKeyName, keyPath)
	}

	user, err := GetCurrentUser()
	if err != nil || user == "" {
		t.Errorf("GetCurrentUser failed: user=%q, err=%v", user, err)
	}
}
