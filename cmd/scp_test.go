package cmd

import (
	"testing"
)

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
			name:       "remote ipv6 with port",
			path:       "user@[::1]:2222:/tmp/data",
			wantRemote: true,
			wantUser:   "user",
			wantHost:   "::1",
			wantPort:   2222,
			wantPath:   "/tmp/data",
			wantErr:    false,
		},
		{
			name:    "malformed remote empty user",
			path:    "@server:/tmp/file",
			wantErr: true,
		},
		{
			name:    "malformed remote invalid port",
			path:    "user@host:badport:/tmp/file",
			wantErr: true,
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
