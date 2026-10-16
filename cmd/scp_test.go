package cmd

import (
	"io"
	"os"
	"strings"
	"testing"
)

func TestScpOptionsCompletePaths(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		source, dest string
		wantErr      bool
	}{
		{"positional upload", []string{"./file", "web:~/file"}, "./file", "web:~/file", false},
		{"positional download", []string{"web:~/file", "./file"}, "web:~/file", "./file", false},
		{"relay", []string{"web1:file", "user@web2:file"}, "web1:file", "user@web2:file", false},
		{"selector literal paths", []string{"--host", "5", "user@name:file[", "other@name:target["}, "user@name:file[", "other@name:target[", false},
		{"flag pair", []string{"--src", "file", "--dest", "web:target"}, "file", "web:target", false},
		{"selector flag pair", []string{"--tag", "web", "--src", "file", "--dest", "target"}, "file", "target", false},
		{"no paths", nil, "", "", true},
		{"one path", []string{"file"}, "", "", true},
		{"three paths", []string{"file", "web:target", "extra"}, "", "", true},
		{"mixed destination", []string{"file", "--dest", "target", "--host", "5"}, "", "", true},
		{"mixed source", []string{"--src", "file", "web:target"}, "", "", true},
		{"mixed pair", []string{"--src", "file", "--dest", "target", "one", "two"}, "", "", true},
		{"explicit empty flag", []string{"--src=", "file", "web:target"}, "", "", true},
		{"missing source", []string{"--dest", "target"}, "", "", true},
		{"missing destination", []string{"--src", "file", "--host", "5"}, "", "", true},
		{"empty destination", []string{"--src", "file", "--dest="}, "", "", true},
		{"host needs target", []string{"--host", "5", "file"}, "", "", true},
		{"file selector needs target", []string{"--ifile", "hosts.txt", "--src", "file"}, "", "", true},
		{"empty host selector", []string{"--host=", "file", "web:target"}, "", "", true},
		{"empty tag selector", []string{"--tag=", "file", "web:target"}, "", "", true},
		{"empty file selector", []string{"--ifile=", "file", "web:target"}, "", "", true},
		{"explicit zero port", []string{"-P", "0", "file", "web:target"}, "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewCmdScp()
			if err := cmd.ParseFlags(tt.args); err != nil {
				t.Fatal(err)
			}
			o := NewScpOptions()
			o.Source, _ = cmd.Flags().GetString("src")
			o.Dest, _ = cmd.Flags().GetString("dest")
			o.Host, _ = cmd.Flags().GetString("host")
			o.Tag, _ = cmd.Flags().GetString("tag")
			o.HostFile, _ = cmd.Flags().GetString("ifile")
			err := o.Complete(cmd, cmd.Flags().Args())
			if (err != nil) != tt.wantErr {
				t.Fatalf("Complete error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && (o.Source != tt.source || o.Dest != tt.dest) {
				t.Fatalf("paths = %q, %q; want %q, %q", o.Source, o.Dest, tt.source, tt.dest)
			}
		})
	}
}

func TestSCPPortFlag(t *testing.T) {
	for _, flag := range []string{"-P", "--port"} {
		cmd := NewCmdScp()
		if err := cmd.ParseFlags([]string{flag, "122", "local", "user@host:22:file"}); err != nil {
			t.Fatal(err)
		}
		port, err := cmd.Flags().GetUint16("port")
		if err != nil || port != 122 {
			t.Fatalf("%s port = %d, err = %v", flag, port, err)
		}
	}
	cmd := NewCmdScp()
	if err := cmd.ParseFlags([]string{"-p", "122", "local", "host:file"}); err == nil {
		t.Fatal("lowercase -p must not select an SSH port")
	}
	if use := cmd.UseLine(); !strings.Contains(use, "[flags]") {
		t.Fatalf("missing flags in SCP usage: %s", use)
	}
}

func TestSCPCommandRejectsInvalidPathsBeforeCredentials(t *testing.T) {
	setSCPTestConfirmation(t, "credential-must-not-be-read")
	for _, args := range [][]string{
		{"file", "--dest", "target", "--host", "5"},
		{"--src", "file", "--dest", "target", "extra"},
		{"file", "target", "extra"},
		{"--host", "5", "file"},
		{"--host", "5", "--tag", "web", "file", "target"},
	} {
		cmd := NewCmdScp()
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SetArgs(append(args, "--password-stdin"))
		if err := cmd.Execute(); err == nil {
			t.Fatalf("expected argument error for %v", args)
		}
		position, err := os.Stdin.Seek(0, io.SeekCurrent)
		if err != nil || position != 0 {
			t.Fatalf("invalid arguments consumed credential input: position=%d, err=%v", position, err)
		}
	}
}

func TestResolvePathInfo(t *testing.T) {
	tests := []struct {
		name     string
		optHost  string
		optUser  string
		optPort  uint16
		path     PathInfo
		wantHost string
		wantUser string
		wantPort uint16
		wantErr  bool
	}{
		{
			name:     "flags override path info",
			optHost:  "default_host",
			optUser:  "default_user",
			optPort:  2222,
			path:     PathInfo{Host: "h1", User: "u1", Port: 22},
			wantHost: "h1",
			wantUser: "default_user",
			wantPort: 2222,
			wantErr:  false,
		},
		{
			name:     "path info used when flags empty",
			optHost:  "default_host",
			optUser:  "",
			optPort:  0,
			path:     PathInfo{Host: "h1", User: "u1", Port: 22},
			wantHost: "h1",
			wantUser: "u1",
			wantPort: 22,
			wantErr:  false,
		},
		{
			name:     "flags provide fallback when path empty",
			optHost:  "default_host",
			optUser:  "default_user",
			optPort:  2222,
			path:     PathInfo{},
			wantHost: "default_host",
			wantUser: "default_user",
			wantPort: 2222,
			wantErr:  false,
		},
		{
			name:     "empty host error",
			optHost:  "",
			optUser:  "",
			optPort:  0,
			path:     PathInfo{},
			wantHost: "",
			wantUser: "",
			wantPort: 0,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := NewScpOptions()
			o.Host = tt.optHost
			o.User = tt.optUser
			o.Port = tt.optPort

			h, u, p, err := o.resolvePathInfo(tt.path)
			if (err != nil) != tt.wantErr {
				t.Fatalf("expected error %v, got %v", tt.wantErr, err)
			}
			if !tt.wantErr {
				if h != tt.wantHost || u != tt.wantUser || p != tt.wantPort {
					t.Errorf("expected %v@%v:%v, got %v@%v:%v", tt.wantUser, tt.wantHost, tt.wantPort, u, h, p)
				}
			}
		})
	}
}

func TestParsePath_ValidAndInvalid(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		wantRemote bool
		wantUser   string
		wantHost   string
		wantPort   uint16
		wantPath   string
		wantErr    bool
	}{
		{
			name:       "local file",
			path:       "relative/local/file.txt",
			wantRemote: false,
			wantPath:   "relative/local/file.txt",
			wantErr:    false,
		},
		{
			name:       "local file with colon and slash",
			path:       "./foo:bar/baz.txt",
			wantRemote: false,
			wantPath:   "./foo:bar/baz.txt",
			wantErr:    false,
		},
		{
			name: "literal brackets in local file", path: "file[unfinished",
			wantPath: "file[unfinished",
		},
		{
			name: "local directory with bracket and colon", path: "./dir[/name:with@chars",
			wantPath: "./dir[/name:with@chars",
		},
		{
			name: "literal brackets in remote path", path: "web:file[unfinished",
			wantRemote: true, wantHost: "web", wantPath: "file[unfinished",
		},
		{
			name:       "windows path",
			path:       `C:\Users\foo\bar.txt`,
			wantRemote: false,
			wantPath:   `C:\Users\foo\bar.txt`,
			wantErr:    false,
		},
		{
			name:       "remote standard",
			path:       "root@10.0.0.1:/var/log/app.log",
			wantRemote: true,
			wantUser:   "root",
			wantHost:   "10.0.0.1",
			wantPort:   0,
			wantPath:   "/var/log/app.log",
			wantErr:    false,
		},
		{
			name:       "remote ipv6 with numeric path prefix",
			path:       "user@[::1]:2222:/tmp/data",
			wantRemote: true,
			wantUser:   "user",
			wantHost:   "::1",
			wantPort:   0,
			wantPath:   "2222:/tmp/data",
			wantErr:    false,
		},
		{
			name: "numeric path prefix", path: "user@host:2222:relative/path",
			wantRemote: true, wantUser: "user", wantHost: "host", wantPath: "2222:relative/path",
		},
		{
			name: "IPv6 numeric path prefix", path: "user@[::1]:2222:relative/path",
			wantRemote: true, wantUser: "user", wantHost: "::1", wantPath: "2222:relative/path",
		},
		{
			name: "node alias with Windows path", path: "vm:C:/Users/example/file.txt",
			wantRemote: true, wantHost: "vm", wantPath: "C:/Users/example/file.txt",
		},
		{
			name: "node alias with Windows backslash path", path: `vm:C:\Users\example\file.txt`,
			wantRemote: true, wantHost: "vm", wantPath: `C:\Users\example\file.txt`,
		},
		{
			name: "numeric alias", path: "5:relative/file@name",
			wantRemote: true, wantHost: "5", wantPath: "relative/file@name",
		},
		{
			name:    "malformed remote empty user",
			path:    "@server:/tmp/file",
			wantErr: true,
		},
		{
			name: "remote path with literal colon", path: "user@host:folder:/tmp/file",
			wantRemote: true, wantUser: "user", wantHost: "host", wantPath: "folder:/tmp/file",
		},
		{
			name: "large numeric filename", path: "user@host:65536:relative/file",
			wantRemote: true, wantUser: "user", wantHost: "host", wantPath: "65536:relative/file",
		},
		{
			name: "IPv6 large numeric filename", path: "user@[::1]:65536:relative/file",
			wantRemote: true, wantUser: "user", wantHost: "::1", wantPath: "65536:relative/file",
		},
		{
			name: "numeric filename beyond integer range", path: "user@host:99999999999999999999999:file",
			wantRemote: true, wantUser: "user", wantHost: "host", wantPath: "99999999999999999999999:file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := parsePath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parsePath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
			if !tt.wantErr {
				if res.IsRemote != tt.wantRemote || res.User != tt.wantUser || res.Host != tt.wantHost || res.Port != tt.wantPort || res.Path != tt.wantPath {
					t.Errorf("parsePath(%q) = %+v, want (remote=%v, user=%q, host=%q, port=%d, path=%q)",
						tt.path, res, tt.wantRemote, tt.wantUser, tt.wantHost, tt.wantPort, tt.wantPath)
				}
			}
		})
	}
}
