package config

import (
	"testing"
)

func TestParseTargetRef_Matrix(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		want     TargetRef
		wantSel  string
		wantNorm string
		wantErr  bool
	}{
		{
			name:     "plain host",
			input:    "web-01",
			want:     TargetRef{Host: "web-01"},
			wantSel:  "web-01",
			wantNorm: "web-01",
		},
		{
			name:     "user and host",
			input:    "deploy@web-01",
			want:     TargetRef{User: "deploy", Host: "web-01"},
			wantSel:  "web-01",
			wantNorm: "deploy@web-01",
		},
		{
			name:     "user containing at-sign",
			input:    "alice@corp.local@web-01:2202",
			want:     TargetRef{User: "alice@corp.local", Host: "web-01", Port: 2202, HasPort: true},
			wantSel:  "web-01",
			wantNorm: "alice@corp.local@web-01:2202",
		},
		{
			name:     "host and port",
			input:    "10.0.0.5:2222",
			want:     TargetRef{Host: "10.0.0.5", Port: 2222, HasPort: true},
			wantSel:  "10.0.0.5",
			wantNorm: "10.0.0.5:2222",
		},
		{
			name:     "user host and port",
			input:    "root@10.0.0.5:2200",
			want:     TargetRef{User: "root", Host: "10.0.0.5", Port: 2200, HasPort: true},
			wantSel:  "10.0.0.5",
			wantNorm: "root@10.0.0.5:2200",
		},
		{
			name:     "bracketed ipv6",
			input:    "[::1]",
			want:     TargetRef{Host: "::1"},
			wantSel:  "::1",
			wantNorm: "::1",
		},
		{
			name:     "bracketed ipv6 with port",
			input:    "ops@[::1]:2222",
			want:     TargetRef{User: "ops", Host: "::1", Port: 2222, HasPort: true},
			wantSel:  "::1",
			wantNorm: "ops@[::1]:2222",
		},
		{
			name:     "bare ipv6",
			input:    "2001:db8::1",
			want:     TargetRef{Host: "2001:db8::1"},
			wantSel:  "2001:db8::1",
			wantNorm: "2001:db8::1",
		},
		{
			name:     "bare ipv6 trailing double colon",
			input:    "2001:db8::",
			want:     TargetRef{Host: "2001:db8::"},
			wantSel:  "2001:db8::",
			wantNorm: "2001:db8::",
		},
		{
			name:     "bracketed ipv6 unspecified",
			input:    "[::]",
			want:     TargetRef{Host: "::"},
			wantSel:  "::",
			wantNorm: "::",
		},
		{
			name:     "bare ipv6 unspecified",
			input:    "::",
			want:     TargetRef{Host: "::"},
			wantSel:  "::",
			wantNorm: "::",
		},
		{
			name:     "bracketed zoned ipv6",
			input:    "[fe80::1%eth0]",
			want:     TargetRef{Host: "fe80::1%eth0"},
			wantSel:  "fe80::1%eth0",
			wantNorm: "fe80::1%eth0",
		},
		{
			name:     "bracketed zoned ipv6 with port",
			input:    "ops@[fe80::1%eth0]:2222",
			want:     TargetRef{User: "ops", Host: "fe80::1%eth0", Port: 2222, HasPort: true},
			wantSel:  "fe80::1%eth0",
			wantNorm: "ops@[fe80::1%eth0]:2222",
		},
		{
			name:     "bare zoned ipv6",
			input:    "fe80::1%eth0",
			want:     TargetRef{Host: "fe80::1%eth0"},
			wantSel:  "fe80::1%eth0",
			wantNorm: "fe80::1%eth0",
		},
		{
			name:     "openssh simple",
			input:    "openssh:web",
			want:     TargetRef{OpenSSH: true, Host: "web"},
			wantSel:  "openssh:web",
			wantNorm: "openssh:web",
		},
		{
			name:     "openssh composite",
			input:    "openssh:alice@web:2222",
			want:     TargetRef{OpenSSH: true, User: "alice", Host: "web", Port: 2222, HasPort: true},
			wantSel:  "openssh:web",
			wantNorm: "openssh:alice@web:2222",
		},
		{
			name:     "openssh ipv6 with port",
			input:    "openssh:[::1]:22",
			want:     TargetRef{OpenSSH: true, Host: "::1", Port: 22, HasPort: true},
			wantSel:  "openssh:::1",
			wantNorm: "openssh:[::1]:22",
		},
		{name: "empty", input: "", wantErr: true},
		{name: "openssh empty", input: "openssh:", wantErr: true},
		{name: "openssh space", input: "openssh: web", wantErr: true},
		{name: "openssh double prefix", input: "openssh:openssh:web", wantErr: true},
		{name: "empty user", input: "@host", wantErr: true},
		{name: "empty host after user", input: "user@", wantErr: true},
		{name: "trailing colon", input: "host:", wantErr: true},
		{name: "bracketed trailing colon", input: "[::1]:", wantErr: true},
		{name: "invalid bracketed ip", input: "[invalid_ip]", wantErr: true},
		{name: "bracketed ipv4 rejected", input: "[127.0.0.1]:22", wantErr: true},
		{name: "nested bracket", input: "[[::1]]", wantErr: true},
		{name: "zero port", input: "host:0", wantErr: true},
		{name: "overflow port", input: "host:65536", wantErr: true},
		{name: "invalid multi colon", input: "a:b:c", wantErr: true},
		{name: "trailing comma", input: "a,", wantErr: true},
		{name: "leading comma", input: ",a", wantErr: true},
		{name: "bare comma", input: ",", wantErr: true},
		{name: "multi target comma", input: "a,b", wantErr: true},
		{name: "bare alias with comma", input: "Prod Web,01", wantErr: true},
		{name: "user with comma", input: "alice,bob@web-01", wantErr: true},
		{name: "openssh with comma", input: "openssh:a,", wantErr: true},
		{name: "host port with comma", input: "10.0.0.1:22,", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseTargetRef(tc.input)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseTargetRef(%q) error = %v, wantErr %v", tc.input, err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if got != tc.want {
				t.Errorf("ParseTargetRef(%q) = %+v, want %+v", tc.input, got, tc.want)
			}
			if sel := got.Selector(); sel != tc.wantSel {
				t.Errorf("Selector() = %q, want %q", sel, tc.wantSel)
			}
			if norm := got.NormalizedString(); norm != tc.wantNorm {
				t.Errorf("NormalizedString() = %q, want %q", norm, tc.wantNorm)
			}
		})
	}
}

func TestIsOpenSSHNodeID(t *testing.T) {
	if !IsOpenSSHNodeID("openssh:web") || IsOpenSSHNodeID("web") || IsOpenSSHNodeID("") {
		t.Fatal("unexpected IsOpenSSHNodeID behavior")
	}
}

func FuzzTargetRefParse(f *testing.F) {
	seeds := []string{
		"",
		"web",
		"alice@web:2222",
		"alice@corp@web:22",
		"openssh:web",
		"openssh:alice@web:2201",
		"openssh:[::1]:22",
		"[fe80::1%eth0]:2222",
		"fe80::1%eth0",
		"openssh:",
		"openssh: web",
		"openssh:openssh:web",
		"[invalid]",
		"host:0",
		"a:b:c",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 512 {
			return
		}
		ref, err := ParseTargetRef(raw)
		if err != nil {
			return
		}
		norm := ref.NormalizedString()
		reparsed, err := ParseTargetRef(norm)
		if err != nil {
			t.Fatalf("NormalizedString(%q) = %q failed re-parse: %v", raw, norm, err)
		}
		if reparsed != ref {
			t.Fatalf("non-idempotent re-parse of %q (%q): got %+v, want %+v", raw, norm, reparsed, ref)
		}
	})
}
