package cmd

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/core/concurrent"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/models"
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
			name:     "inline path info overrides global flags",
			optHost:  "default_host",
			optUser:  "default_user",
			optPort:  2222,
			path:     PathInfo{Host: "h1", User: "u1", Port: 22},
			wantHost: "h1",
			wantUser: "u1",
			wantPort: 22,
			wantErr:  false,
		},
		{
			name:     "flags apply when path has host only",
			optHost:  "default_host",
			optUser:  "default_user",
			optPort:  2222,
			path:     PathInfo{Host: "h1"},
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

func TestScpOptionsInteractionConsistency(t *testing.T) {
	o := NewScpOptions()
	if o.interaction != nil {
		t.Fatalf("expected initial interaction to be nil, got %v", o.interaction)
	}
	cfg := &config.Configuration{}
	repo, err := config.NewRepositoryWithoutOpenSSH(cfg, &memoryStore{cfg: cfg})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := o.credentialConnector(repo, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if conn == nil {
		t.Fatal("expected non-nil connector")
	}
	if o.interaction == nil {
		t.Fatal("expected o.interaction to be initialized")
	}
	firstInteraction := o.interaction
	firstGate := o.interaction.promptGate

	// Subsequent call to credentialConnector must reuse the exact same interaction handler and promptGate
	conn2, err := o.credentialConnector(repo, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if conn2 == nil {
		t.Fatal("expected non-nil connector on second call")
	}
	if o.interaction != firstInteraction {
		t.Fatal("expected o.interaction to be preserved and reused across calls")
	}
	if o.interaction.promptGate != firstGate {
		t.Fatal("expected promptGate to remain identical")
	}
}

func TestScpBatchZeroDiskMutationAndPositionalInvalidExcludeBeforeNodePrep(t *testing.T) {
	_ = setupTestEnvironment(t)
	if err := i18n.Init("zh"); err != nil {
		t.Fatalf("i18n.Init failed: %v", err)
	}
	cfg := &config.Configuration{
		SchemaVersion: 2,
		Hosts:         concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities:    concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Nodes:         concurrent.NewMap[string, models.Node](concurrent.HashString),
		Credential: &config.CredentialConfig{
			DefaultStore:     "none",
			RememberPrompted: "always",
			Stores:           map[string]config.StoreConfig{"none": {Type: config.StoreTypeNone}},
		},
	}
	cfg.Hosts.Set("h-1", models.Host{Address: "10.238.221.181", Port: 22})
	cfg.Identities.Set("id-1", models.Identity{User: "iaas", AuthType: "auto"})
	cfg.Nodes.Set("iaas@10.238.221.181:22", models.Node{
		HostRef:     "h-1",
		IdentityRef: "id-1",
		ProxyJump:   "jump-old",
		Alias:       []string{"web-1"},
		Tags:        []string{"prod"},
	})
	path, key, err := utils.GetConfigFilePath()
	if err != nil {
		t.Fatalf("GetConfigFilePath: %v", err)
	}
	store := config.NewDefaultStore(path, key)
	if err := store.Save(cfg); err != nil {
		t.Fatalf("store.Save: %v", err)
	}
	_, repo, _, err := utils.GetConfigStore()
	if err != nil {
		t.Fatalf("GetConfigStore: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(before): %v", err)
	}

	t.Run("batch scp does not persist node updates on disk", func(t *testing.T) {
		o := NewScpOptions()
		o.Host = "iaas@10.238.221.181"
		o.JumpHost = "10.0.0.88:22"
		o.Remember = "always"
		o.Source = "./local.txt"
		o.Dest = "/tmp/remote.txt"
		o.control.ConfigFile = "none"
		if err := o.Complete(NewCmdScp(), nil); err != nil {
			t.Fatalf("Complete(batch): %v", err)
		}
		if err := o.Validate(); err != nil {
			t.Fatalf("Validate(batch): %v", err)
		}
		nodeID, mutated, err := o.getOrCreateNodeForPath(t.Context(), repo, PathInfo{
			Host:     "10.238.221.181",
			User:     "iaas",
			Port:     22,
			IsRemote: true,
		}, "")
		if err != nil {
			t.Fatalf("getOrCreateNodeForPath: %v", err)
		}
		if nodeID != "iaas@10.238.221.181:22" || mutated {
			t.Fatalf("expected existing node without disk mutation, got nodeID=%q mutated=%v", nodeID, mutated)
		}
		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(after): %v", err)
		}
		if !bytes.Equal(before, after) {
			t.Fatal("expected batch scp getOrCreateNodeForPath NOT to mutate saved config on disk")
		}
	})

	t.Run("positional scp with invalid --exclude fails before node prep", func(t *testing.T) {
		localSrc := filepath.Join(t.TempDir(), "payload.txt")
		if err := os.WriteFile(localSrc, []byte("hello"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		o := NewScpOptions()
		o.JumpHost = "10.0.0.99:22"
		o.Remember = "always"
		o.Exclude = []string{"nonexistent-exclude-node"}
		o.control.ConfigFile = "none"
		args := []string{localSrc, "iaas@10.238.221.181:/tmp/remote.txt"}
		if err := o.Complete(NewCmdScp(), args); err != nil {
			t.Fatalf("Complete(positional): %v", err)
		}
		if err := o.Validate(); err != nil {
			t.Fatalf("Validate(positional): %v", err)
		}
		err := o.runTransfer(t.Context(), repo, nil)
		if err == nil || !strings.Contains(err.Error(), "no matching node") {
			t.Fatalf("expected fail-closed exclude error before node prep, got: %v", err)
		}
		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(after): %v", err)
		}
		if !bytes.Equal(before, after) {
			t.Fatal("expected positional scp with invalid --exclude NOT to mutate disk before failing")
		}
	})
}

func TestScp_SingleHostBatchMode_CanonicalOriginalHost_AndValidateExcludesFailClosed(t *testing.T) {
	t.Run("single --host enters batch mode cleanly across Complete and credentialConnector", func(t *testing.T) {
		cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
		prov := config.NewProviderWithoutOpenSSH(cfg)
		o := NewScpOptions()
		o.Host = "10.0.0.55"
		o.Remember = "always"
		if !o.isBatchMode() {
			t.Fatal("expected single --host to report isBatchMode() == true")
		}
		if _, err := o.credentialConnectorWithInteraction(prov, cfg, newCLIInteractionHandler()); err != nil {
			t.Fatalf("credentialConnectorWithInteraction single host: %v", err)
		}
	})

	t.Run("resolvePathTargetAndHosts preserves canonical OriginalHost on PathInfo", func(t *testing.T) {
		p := PathInfo{IsRemote: true, Host: "short", Path: "/tmp/file"}
		o := NewScpOptions()
		o.canonicalCache = map[string]config.CanonicalizeResult{
			o.canonicalCacheKey(p): {
				Canonicalized: true,
				OriginalHost:  "short",
				CanonicalHost: "short.corp.example.com",
			},
		}
		sshCfgPath := filepath.Join(t.TempDir(), "ssh_config")
		if err := os.WriteFile(sshCfgPath, []byte("Host short\n  User alice\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		parser, err := config.NewOpenSSHParserFromPath(sshCfgPath)
		if err != nil {
			t.Fatal(err)
		}
		prov := config.NewProviderWithOpenSSHParser(nil, parser)

		target, origHost, _, ok := o.resolvePathTargetAndHosts(prov, p)
		if !ok {
			t.Fatal("expected resolvePathTargetAndHosts ok == true")
		}
		if target.OriginalHost != "short" || origHost != "short" {
			t.Fatalf("canonical OriginalHost mismatch: target=%+v origHost=%q", target, origHost)
		}
	})

	t.Run("validateTransferExcludes fails closed on ambiguous positional remote host", func(t *testing.T) {
		cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
		cfg.Hosts.Set("10.0.0.1:22", models.Host{Address: "10.0.0.1", Port: 22})
		cfg.Hosts.Set("10.0.0.2:22", models.Host{Address: "10.0.0.2", Port: 22})
		cfg.Identities.Set("ops1", models.Identity{User: "ops1", AuthType: "auto"})
		cfg.Identities.Set("ops2", models.Identity{User: "ops2", AuthType: "auto"})
		cfg.Nodes.Set("ops1@10.0.0.1:22", models.Node{HostRef: "10.0.0.1:22", IdentityRef: "ops1", Alias: []string{"shared-host"}})
		cfg.Nodes.Set("ops2@10.0.0.2:22", models.Node{HostRef: "10.0.0.2:22", IdentityRef: "ops2", Alias: []string{"shared-host"}})
		prov := config.NewProviderWithoutOpenSSH(cfg)

		o := NewScpOptions()
		o.Exclude = []string{"ops1@10.0.0.1:22"}
		err := o.validateTransferExcludes(prov, PathInfo{IsRemote: false, Path: "/tmp/local"}, PathInfo{IsRemote: true, Host: "shared-host", Path: "/tmp/remote"})
		if err == nil {
			t.Fatal("expected validateTransferExcludes to fail closed on ambiguous host")
		}
	})
}
