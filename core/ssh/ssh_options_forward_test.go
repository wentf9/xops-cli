package ssh

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestParseTunnelOption(t *testing.T) {
	tests := []struct {
		input   string
		want    string
		wantErr bool
	}{
		{"yes", string(TunnelModeYes), false},
		{"true", string(TunnelModeYes), false},
		{"YES", string(TunnelModeYes), false},
		{"point-to-point", string(TunnelModePointToPoint), false},
		{"POINT-TO-POINT", string(TunnelModePointToPoint), false},
		{"ethernet", string(TunnelModeEthernet), false},
		{"ETHERNET", string(TunnelModeEthernet), false},
		{"no", string(TunnelModeNo), false},
		{"false", string(TunnelModeNo), false},
		{"NO", string(TunnelModeNo), false},
		{"", "", true},
		{"invalid", "", true},
		{"none", "", true},
		{"1", "", true},
	}

	for _, tt := range tests {
		got, err := ParseTunnelOption(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseTunnelOption(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if !tt.wantErr && got != tt.want {
			t.Errorf("ParseTunnelOption(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestEffectiveTunnelModeFromValue(t *testing.T) {
	tests := []struct {
		input string
		want  TunnelMode
	}{
		{"yes", TunnelModePointToPoint},
		{"true", TunnelModePointToPoint},
		{"point-to-point", TunnelModePointToPoint},
		{"ethernet", TunnelModeEthernet},
		{"no", TunnelModeNo},
		{"false", TunnelModeNo},
		{"", TunnelModeNo},
		{"unknown", TunnelModeNo},
	}

	for _, tt := range tests {
		got := EffectiveTunnelModeFromValue(tt.input)
		if got != tt.want {
			t.Errorf("EffectiveTunnelModeFromValue(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestParseTunnelDevice(t *testing.T) {
	tests := []struct {
		input       string
		wantLocal   int
		wantRemote  int
		wantStr     string
		wantErr     bool
		errContains string
	}{
		{input: "0", wantLocal: 0, wantRemote: TunnelIDAny, wantStr: "0:any"},
		{input: "any", wantLocal: TunnelIDAny, wantRemote: TunnelIDAny, wantStr: "any:any"},
		{input: "0:1", wantLocal: 0, wantRemote: 1, wantStr: "0:1"},
		{input: "any:0", wantLocal: TunnelIDAny, wantRemote: 0, wantStr: "any:0"},
		{input: "1:any", wantLocal: 1, wantRemote: TunnelIDAny, wantStr: "1:any"},
		{input: "any:any", wantLocal: TunnelIDAny, wantRemote: TunnelIDAny, wantStr: "any:any"},
		{input: "", wantErr: true, errContains: "value cannot be empty"},
		{input: "0:", wantErr: true, errContains: "tunnel unit cannot be empty"},
		{input: ":0", wantErr: true, errContains: "tunnel unit cannot be empty"},
		{input: "0:1:2", wantErr: true, errContains: "expected local_tun[:remote_tun]"},
		{input: "-1", wantErr: true, errContains: "expected non-negative integer or \"any\""},
		{input: "2147483647", wantErr: true, errContains: "out of range"},
		{input: "0:2147483647", wantErr: true, errContains: "out of range"},
		{input: "abc", wantErr: true, errContains: "expected non-negative integer or \"any\""},
		{input: "0:abc", wantErr: true, errContains: "expected non-negative integer or \"any\""},
	}

	for _, tt := range tests {
		spec, err := ParseTunnelDevice(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseTunnelDevice(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if tt.wantErr {
			if tt.errContains != "" && (err == nil || !slices.Contains([]string{err.Error()}, tt.errContains) && !containsSubstring(err.Error(), tt.errContains)) {
				t.Errorf("ParseTunnelDevice(%q) error %q does not contain %q", tt.input, err, tt.errContains)
			}
			continue
		}
		if spec.LocalUnit != tt.wantLocal || spec.RemoteUnit != tt.wantRemote {
			t.Errorf("ParseTunnelDevice(%q) = {%d, %d}, want {%d, %d}", tt.input, spec.LocalUnit, spec.RemoteUnit, tt.wantLocal, tt.wantRemote)
		}
		if spec.String() != tt.wantStr {
			t.Errorf("spec.String() for %q = %q, want %q", tt.input, spec.String(), tt.wantStr)
		}
	}
}

func containsSubstring(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || searchSubstr(s, sub))
}

func searchSubstr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestParseRequestTTYMode(t *testing.T) {
	tests := []struct {
		input   string
		want    RequestTTYMode
		wantErr bool
	}{
		{"no", RequestTTYNo, false},
		{"false", RequestTTYNo, false},
		{"yes", RequestTTYYes, false},
		{"true", RequestTTYYes, false},
		{"force", RequestTTYForce, false},
		{"FORCE", RequestTTYForce, false},
		{"auto", RequestTTYAuto, false},
		{"AUTO", RequestTTYAuto, false},
		{"", "", true},
		{"never", "", true},
		{"always", "", true},
		{"invalid", "", true},
	}

	for _, tt := range tests {
		got, err := ParseRequestTTYMode(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseRequestTTYMode(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if !tt.wantErr && got != tt.want {
			t.Errorf("ParseRequestTTYMode(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestParseStdioForward(t *testing.T) {
	tests := []struct {
		input    string
		wantHost string
		wantPort uint16
		wantErr  bool
	}{
		{"example.com:80", "example.com", 80, false},
		{"127.0.0.1:22", "127.0.0.1", 22, false},
		{"[::1]:2222", "::1", 2222, false},
		{"[fe80::1]:8080", "fe80::1", 8080, false},
		{"", "", 0, true},
		{"example.com:0", "", 0, true},
		{"example.com:65536", "", 0, true},
		{":80", "", 0, true},
		{"[]:80", "", 0, true},
		{"[::1:80", "", 0, true},
		{"/run/user/1000/gnupg/S.gpg-agent:80", "", 0, true},
		{"a:b:c", "", 0, true},
		{"example.com", "", 0, true},
	}

	for _, tt := range tests {
		host, port, err := ParseStdioForward(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseStdioForward(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if !tt.wantErr {
			if host != tt.wantHost || port != tt.wantPort {
				t.Errorf("ParseStdioForward(%q) = (%q, %d), want (%q, %d)", tt.input, host, port, tt.wantHost, tt.wantPort)
			}
		}
	}
}

func TestParseForwardSpec(t *testing.T) {
	tests := []struct {
		input         string
		wantBind      string
		wantDest      string
		wantErr       bool
		skipRoundTrip bool
	}{
		// OpenSSH two-field whitespace format
		{input: "8080 127.0.0.1:80", wantBind: "127.0.0.1:8080", wantDest: "127.0.0.1:80"},
		{input: "127.0.0.1:8080 127.0.0.1:80", wantBind: "127.0.0.1:8080", wantDest: "127.0.0.1:80"},
		{input: "10.0.0.1:8080 remote:80", wantBind: "10.0.0.1:8080", wantDest: "remote:80"},
		{input: "[::1]:8080 [::1]:80", wantBind: "[::1]:8080", wantDest: "[::1]:80"},
		{input: "*:8080 remote:80", wantBind: ":8080", wantDest: "remote:80"},
		{input: ":8080 remote:80", wantBind: ":8080", wantDest: "remote:80"},
		{input: "0 remote:80", wantBind: "127.0.0.1:0", wantDest: "remote:80"},

		// CLI colon format
		{input: "8080:remote:80", wantBind: "127.0.0.1:8080", wantDest: "remote:80"},
		{input: "127.0.0.1:8080:remote:80", wantBind: "127.0.0.1:8080", wantDest: "remote:80"},
		{input: "[::1]:8080:[::1]:80", wantBind: "[::1]:8080", wantDest: "[::1]:80"},
		{input: "*:8080:remote:80", wantBind: ":8080", wantDest: "remote:80"},
		{input: ":8080:remote:80", wantBind: ":8080", wantDest: "remote:80"},
		{input: "0:remote:80", wantBind: "127.0.0.1:0", wantDest: "remote:80"},

		// Unix domain socket formats
		{input: "/run/user/1000/gnupg/S.gpg-agent /run/user/1000/gnupg/S.gpg-agent.extra", wantBind: "/run/user/1000/gnupg/S.gpg-agent", wantDest: "/run/user/1000/gnupg/S.gpg-agent.extra"},
		{input: "/tmp/sock:remote:80", wantBind: "/tmp/sock", wantDest: "remote:80"},

		// Error cases
		{input: "", wantErr: true},
		{input: "8080 remote:0", wantErr: true},
		{input: "8080 remote:65536", wantErr: true},
		{input: "8080:remote", wantErr: true},
		{input: "1:2:3:4:5", wantErr: true},
		{input: "a b c", wantErr: true},
	}

	for _, tt := range tests {
		spec, err := ParseForwardSpec(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseForwardSpec(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if tt.wantErr {
			continue
		}
		if spec.BindAddr != tt.wantBind || spec.DestAddr != tt.wantDest {
			t.Errorf("ParseForwardSpec(%q) = {%q, %q}, want {%q, %q}", tt.input, spec.BindAddr, spec.DestAddr, tt.wantBind, tt.wantDest)
		}
		if !tt.skipRoundTrip {
			// Spec.String() format is "<bind_addr> <dest_addr>"
			formatted := spec.String()
			spec2, err2 := ParseForwardSpec(formatted)
			if err2 != nil {
				t.Errorf("ParseForwardSpec round-trip failed for %q (formatted %q): %v", tt.input, formatted, err2)
			} else if spec2 != spec {
				t.Errorf("ParseForwardSpec round-trip mismatch: got %v, want %v", spec2, spec)
			}
		}
	}
}

func TestParseDynamicForwardSpec(t *testing.T) {
	tests := []struct {
		input   string
		want    string
		wantErr bool
	}{
		{"1080", "1080", false},
		{"127.0.0.1:1080", "127.0.0.1:1080", false},
		{"0.0.0.0:1080", "0.0.0.0:1080", false},
		{"[::1]:1080", "[::1]:1080", false},
		{"*:1080", "*:1080", false},
		{":1080", "*:1080", false},
		{"0", "0", false},
		{"/run/user/1000/proxy", "/run/user/1000/proxy", false},
		{"", "", true},
		{"1080 1081", "", true},
		{"1080:extra:foo", "", true},
		{"65536", "", true},
	}

	for _, tt := range tests {
		got, err := ParseDynamicForwardSpec(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseDynamicForwardSpec(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if !tt.wantErr && got != tt.want {
			t.Errorf("ParseDynamicForwardSpec(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestOptions_MultiValueAppendAndGetAll(t *testing.T) {
	opts := &Options{}

	t.Run("LocalForward", func(t *testing.T) {
		testOptions_MultiValueLocalForward(t, opts)
	})
	t.Run("RemoteForward", func(t *testing.T) {
		testOptions_MultiValueRemoteForward(t, opts)
	})
	t.Run("DynamicForward", func(t *testing.T) {
		testOptions_MultiValueDynamicForward(t, opts)
	})
	t.Run("ScalarOption", func(t *testing.T) {
		testOptions_MultiValueScalar(t, opts)
	})
}

func testOptions_MultiValueLocalForward(t *testing.T, opts *Options) {
	t.Helper()
	if err := opts.Append("local_forward", "8080 127.0.0.1:80"); err != nil {
		t.Fatalf("Append LocalForward failed: %v", err)
	}
	// Append equivalent colon format -> deduplication test (both canonicalize to "8080 127.0.0.1:80")
	if err := opts.Append("local_forward", "8080:127.0.0.1:80"); err != nil {
		t.Fatalf("Append LocalForward duplicate failed: %v", err)
	}
	// Distinct forward with explicit bind host
	if err := opts.Append("local_forward", "127.0.0.1:8080:127.0.0.1:80"); err != nil {
		t.Fatalf("Append LocalForward explicit host failed: %v", err)
	}
	// Wildcard forwards deduplicate: "*:8080 remote:80" and ":8080:remote:80" both normalize to "*:8080 remote:80"
	if err := opts.Append("local_forward", "*:8080 remote:80"); err != nil {
		t.Fatalf("Append LocalForward wildcard 1 failed: %v", err)
	}
	if err := opts.Append("local_forward", ":8080:remote:80"); err != nil {
		t.Fatalf("Append LocalForward wildcard 2 dup failed: %v", err)
	}
	if err := opts.Append("LocalForward", "9090 remote:90"); err != nil {
		t.Fatalf("Append second LocalForward failed: %v", err)
	}

	lf := opts.LocalForwards()
	if len(lf) != 4 {
		t.Fatalf("expected 4 LocalForwards, got %d: %v", len(lf), lf)
	}
	if lf[0] != "8080 127.0.0.1:80" || lf[1] != "127.0.0.1:8080 127.0.0.1:80" || lf[2] != "*:8080 remote:80" || lf[3] != "9090 remote:90" {
		t.Fatalf("unexpected LocalForwards entries: %v", lf)
	}
}

func testOptions_MultiValueRemoteForward(t *testing.T, opts *Options) {
	t.Helper()
	if err := opts.Append("remote_forward", "8080 127.0.0.1:80"); err != nil {
		t.Fatalf("Append RemoteForward failed: %v", err)
	}
	if err := opts.Append("RemoteForward", "9090 127.0.0.1:90"); err != nil {
		t.Fatalf("Append RemoteForward 2 failed: %v", err)
	}
	if err := opts.Append("RemoteForward", "1080"); err != nil {
		t.Fatalf("Append RemoteForward dynamic failed: %v", err)
	}
	rf := opts.RemoteForwards()
	if len(rf) != 3 {
		t.Fatalf("expected 3 RemoteForwards, got %d: %v", len(rf), rf)
	}
	if rf[0] != "8080 127.0.0.1:80" || rf[1] != "9090 127.0.0.1:90" || rf[2] != "1080" {
		t.Fatalf("unexpected RemoteForwards entries: %v", rf)
	}
}

func testOptions_MultiValueDynamicForward(t *testing.T, opts *Options) {
	t.Helper()
	if err := opts.Append("dynamic_forward", "1080"); err != nil {
		t.Fatalf("Append DynamicForward failed: %v", err)
	}
	if err := opts.Append("DynamicForward", "1080"); err != nil {
		t.Fatalf("Append DynamicForward dup failed: %v", err)
	}
	if err := opts.Append("dynamic_forward", "127.0.0.1:1080"); err != nil {
		t.Fatalf("Append DynamicForward explicit failed: %v", err)
	}
	if err := opts.Append("dynamic_forward", "1081"); err != nil {
		t.Fatalf("Append DynamicForward 2 failed: %v", err)
	}
	df := opts.DynamicForwards()
	if len(df) != 3 {
		t.Fatalf("expected 3 DynamicForwards, got %d: %v", len(df), df)
	}
	if df[0] != "1080" || df[1] != "127.0.0.1:1080" || df[2] != "1081" {
		t.Fatalf("unexpected DynamicForwards: %v", df)
	}
}

func testOptions_MultiValueScalar(t *testing.T, opts *Options) {
	t.Helper()
	if err := opts.Append("tunnel", "ethernet"); err != nil {
		t.Fatalf("Append scalar tunnel failed: %v", err)
	}
	if opts.Tunnel() != "ethernet" || opts.EffectiveTunnelMode() != TunnelModeEthernet {
		t.Fatalf("unexpected tunnel mode: %v", opts.Tunnel())
	}
}

func mustSetTestOption(t *testing.T, opts *Options, key, val string) {
	t.Helper()
	if err := opts.Set(key, val); err != nil {
		t.Fatalf("opts.Set(%q, %q) failed: %v", key, val, err)
	}
}

func mustAppendTestOption(t *testing.T, opts *Options, key, val string) {
	t.Helper()
	if err := opts.Append(key, val); err != nil {
		t.Fatalf("opts.Append(%q, %q) failed: %v", key, val, err)
	}
}

func TestOptions_ForwardYAMLAndJSONSerialization(t *testing.T) {
	opts := &Options{}
	mustAppendTestOption(t, opts, "local_forward", "8080 127.0.0.1:80")
	mustAppendTestOption(t, opts, "local_forward", "9090 remote:90")
	mustAppendTestOption(t, opts, "dynamic_forward", "1080")
	mustSetTestOption(t, opts, "tunnel", "point-to-point")
	mustSetTestOption(t, opts, "tunnel_device", "0:1")
	mustSetTestOption(t, opts, "request_tty", "force")
	mustSetTestOption(t, opts, "exit_on_forward_failure", "yes")
	mustSetTestOption(t, opts, "clear_all_forwardings", "yes")

	// YAML round-trip
	yamlBytes, err := yaml.Marshal(opts)
	if err != nil {
		t.Fatalf("yaml.Marshal failed: %v", err)
	}
	var unmarshaledYAML Options
	if err := yaml.Unmarshal(yamlBytes, &unmarshaledYAML); err != nil {
		t.Fatalf("yaml.Unmarshal failed: %v", err)
	}
	if !opts.Equal(&unmarshaledYAML) {
		t.Fatalf("YAML round-trip mismatch:\nwant: %+v\ngot:  %+v", opts, &unmarshaledYAML)
	}

	// YAML single-scalar unmarshal for multi-value option
	singleYAML := `local_forward: "8080 127.0.0.1:80"`
	var singleOpts Options
	if err := yaml.Unmarshal([]byte(singleYAML), &singleOpts); err != nil {
		t.Fatalf("yaml.Unmarshal single scalar failed: %v", err)
	}
	if len(singleOpts.LocalForwards()) != 1 || singleOpts.LocalForwards()[0] != "8080 127.0.0.1:80" {
		t.Fatalf("unexpected singleOpts LocalForwards: %v", singleOpts.LocalForwards())
	}

	// JSON round-trip
	jsonBytes, err := json.Marshal(opts)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	var unmarshaledJSON Options
	if err := json.Unmarshal(jsonBytes, &unmarshaledJSON); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	if !opts.Equal(&unmarshaledJSON) {
		t.Fatalf("JSON round-trip mismatch:\nwant: %+v\ngot:  %+v", opts, &unmarshaledJSON)
	}

	// JSON single-string unmarshal for multi-value option
	singleJSON := `{"local_forward": "8080 127.0.0.1:80"}`
	var singleJSONOpts Options
	if err := json.Unmarshal([]byte(singleJSON), &singleJSONOpts); err != nil {
		t.Fatalf("json.Unmarshal single string failed: %v", err)
	}
	if len(singleJSONOpts.LocalForwards()) != 1 {
		t.Fatalf("unexpected singleJSONOpts LocalForwards: %v", singleJSONOpts.LocalForwards())
	}
}

func TestOptions_MergeOptionLayers(t *testing.T) {
	layer1 := &Options{}
	mustAppendTestOption(t, layer1, "local_forward", "8080 127.0.0.1:80")
	mustSetTestOption(t, layer1, "connect_timeout", "5")
	mustSetTestOption(t, layer1, "tunnel", "ethernet")

	layer2 := &Options{}
	mustAppendTestOption(t, layer2, "local_forward", "9090 remote:90")
	mustAppendTestOption(t, layer2, "local_forward", "8080 127.0.0.1:80") // duplicate
	mustSetTestOption(t, layer2, "connect_timeout", "10")                 // overridden by layer1
	mustSetTestOption(t, layer2, "tunnel", "point-to-point")              // overridden by layer1
	mustSetTestOption(t, layer2, "request_tty", "yes")

	merged := MergeOptionLayers(layer1, layer2)
	if merged == nil {
		t.Fatalf("expected non-nil merged options")
	}

	// LocalForward should accumulate in order: layer1 entries then layer2 entries (deduplicated)
	lf := merged.LocalForwards()
	if len(lf) != 2 {
		t.Fatalf("expected 2 LocalForwards, got %d: %v", len(lf), lf)
	}
	if lf[0] != "8080 127.0.0.1:80" || lf[1] != "9090 remote:90" {
		t.Fatalf("unexpected merged LocalForwards: %v", lf)
	}

	// Scalar options should follow first-match-wins
	if merged.Get("connect_timeout") != "5" {
		t.Errorf("expected connect_timeout=5, got %q", merged.Get("connect_timeout"))
	}
	if merged.Tunnel() != "ethernet" {
		t.Errorf("expected tunnel=ethernet, got %q", merged.Tunnel())
	}
	if merged.RequestTTY() != RequestTTYYes {
		t.Errorf("expected request_tty=yes, got %q", merged.RequestTTY())
	}
}

func TestNormalizePlan_StripsForwardAndSessionClasses(t *testing.T) {
	opts := &Options{}
	mustSetTestOption(t, opts, "connect_timeout", "5")
	mustSetTestOption(t, opts, "control_master", "auto")
	mustSetTestOption(t, opts, "control_path", "/tmp/cp")
	mustAppendTestOption(t, opts, "local_forward", "8080 127.0.0.1:80")
	mustSetTestOption(t, opts, "tunnel", "ethernet")
	mustSetTestOption(t, opts, "request_tty", "force")

	plan := ConnectionPlan{
		Scope: "test-scope",
		Hops: []ConnectionConfig{
			{
				NodeID:  "node-target",
				Address: "192.168.1.10",
				Port:    22,
				User:    "root",
				Options: opts,
			},
		},
	}

	normalized, err := normalizePlan(plan)
	if err != nil {
		t.Fatalf("normalizePlan failed: %v", err)
	}

	hopOpts := normalized.Hops[0].Options
	if hopOpts == nil {
		t.Fatalf("expected non-nil hop Options")
	}

	// Transport class option must remain
	if hopOpts.Get("connect_timeout") != "5" {
		t.Errorf("connect_timeout should be preserved, got %q", hopOpts.Get("connect_timeout"))
	}

	// Mux, Forward, and Session class options must be stripped
	if hopOpts.Has("control_master") || hopOpts.Has("control_path") {
		t.Errorf("control_master/control_path should be stripped")
	}
	if hopOpts.Has("local_forward") {
		t.Errorf("local_forward should be stripped")
	}
	if hopOpts.Has("tunnel") {
		t.Errorf("tunnel should be stripped")
	}
	if hopOpts.Has("request_tty") {
		t.Errorf("request_tty should be stripped")
	}
}

func TestOptions_MultiValueEmptyAndInvalidUnmarshaling(t *testing.T) {
	// Empty YAML sequence for multi-value forward options should unmarshal cleanly and be empty.
	emptyYAML := `
local_forward: []
remote_forward: []
dynamic_forward: []
`
	var yamlOpts Options
	if err := yaml.Unmarshal([]byte(emptyYAML), &yamlOpts); err != nil {
		t.Fatalf("yaml.Unmarshal empty multi-value sequences failed: %v", err)
	}
	if !yamlOpts.IsEmpty() {
		t.Errorf("expected empty options after unmarshaling empty sequences, got %+v", yamlOpts)
	}
	if len(yamlOpts.LocalForwards()) != 0 || len(yamlOpts.RemoteForwards()) != 0 || len(yamlOpts.DynamicForwards()) != 0 {
		t.Errorf("expected nil/empty forwards, got lf=%v, rf=%v, df=%v", yamlOpts.LocalForwards(), yamlOpts.RemoteForwards(), yamlOpts.DynamicForwards())
	}

	// Empty JSON arrays for multi-value forward options should unmarshal cleanly and be empty.
	emptyJSON := `{"local_forward":[],"remote_forward":[],"dynamic_forward":[]}`
	var jsonOpts Options
	if err := json.Unmarshal([]byte(emptyJSON), &jsonOpts); err != nil {
		t.Fatalf("json.Unmarshal empty multi-value arrays failed: %v", err)
	}
	if !jsonOpts.IsEmpty() {
		t.Errorf("expected empty options after unmarshaling empty arrays, got %+v", jsonOpts)
	}
	if len(jsonOpts.LocalForwards()) != 0 || len(jsonOpts.RemoteForwards()) != 0 || len(jsonOpts.DynamicForwards()) != 0 {
		t.Errorf("expected nil/empty forwards, got lf=%v, rf=%v, df=%v", jsonOpts.LocalForwards(), jsonOpts.RemoteForwards(), jsonOpts.DynamicForwards())
	}

	// Sequences or strings containing empty items must still fail normalization.
	invalidCases := []struct {
		name string
		yaml string
		json string
	}{
		{
			name: "local_forward",
			yaml: `local_forward: [""]`,
			json: `{"local_forward":[""]}`,
		},
		{
			name: "local_forward empty scalar",
			yaml: `local_forward: ""`,
			json: `{"local_forward":""}`,
		},
		{
			name: "remote_forward",
			yaml: `remote_forward: [""]`,
			json: `{"remote_forward":[""]}`,
		},
		{
			name: "remote_forward empty scalar",
			yaml: `remote_forward: ""`,
			json: `{"remote_forward":""}`,
		},
		{
			name: "dynamic_forward",
			yaml: `dynamic_forward: [""]`,
			json: `{"dynamic_forward":[""]}`,
		},
		{
			name: "dynamic_forward empty scalar",
			yaml: `dynamic_forward: ""`,
			json: `{"dynamic_forward":""}`,
		},
	}

	for _, tc := range invalidCases {
		t.Run("YAML_"+tc.name, func(t *testing.T) {
			var opts Options
			if err := yaml.Unmarshal([]byte(tc.yaml), &opts); err == nil {
				t.Fatalf("expected error unmarshaling invalid YAML %s, got nil", tc.yaml)
			}
		})
		t.Run("JSON_"+tc.name, func(t *testing.T) {
			var opts Options
			if err := json.Unmarshal([]byte(tc.json), &opts); err == nil {
				t.Fatalf("expected error unmarshaling invalid JSON %s, got nil", tc.json)
			}
		})
	}
}

func TestForwardEndpoint_Methods(t *testing.T) {
	t.Run("Unix", testForwardEndpoint_Unix)
	t.Run("Wildcard", testForwardEndpoint_Wildcard)
	t.Run("OmittedHost", testForwardEndpoint_OmittedHost)
	t.Run("ExplicitHost", testForwardEndpoint_ExplicitHost)
}

func testForwardEndpoint_Unix(t *testing.T) {
	u := ForwardEndpoint{SocketPath: "/tmp/test.sock"}
	if !u.IsUnix() {
		t.Errorf("expected IsUnix to be true")
	}
	if u.String() != "/tmp/test.sock" {
		t.Errorf("u.String() = %q, want %q", u.String(), "/tmp/test.sock")
	}
	netw, addr := u.LocalListenAddress(false)
	if netw != "unix" || addr != "/tmp/test.sock" {
		t.Errorf("LocalListenAddress(false) = (%q, %q)", netw, addr)
	}
	netw, addr = u.LocalListenAddress(true)
	if netw != "unix" || addr != "/tmp/test.sock" {
		t.Errorf("LocalListenAddress(true) = (%q, %q)", netw, addr)
	}
	netw, addr = u.RemoteListenAddress()
	if netw != "unix" || addr != "/tmp/test.sock" {
		t.Errorf("RemoteListenAddress = (%q, %q)", netw, addr)
	}
	netw, addr = u.ConnectAddress()
	if netw != "unix" || addr != "/tmp/test.sock" {
		t.Errorf("ConnectAddress = (%q, %q)", netw, addr)
	}
	h, p := u.MuxListenEndpoint()
	if h != "/tmp/test.sock" || p != MUX_SPECIAL_PORT_UNIX {
		t.Errorf("MuxListenEndpoint = (%q, %d)", h, p)
	}
	h, p = u.MuxConnectEndpoint()
	if h != "/tmp/test.sock" || p != MUX_SPECIAL_PORT_UNIX {
		t.Errorf("MuxConnectEndpoint = (%q, %d)", h, p)
	}
}

func testForwardEndpoint_Wildcard(t *testing.T) {
	w := ForwardEndpoint{Port: 8080, HasHost: true, Wildcard: true}
	if w.IsUnix() {
		t.Errorf("expected IsUnix to be false")
	}
	if w.String() != "*:8080" {
		t.Errorf("w.String() = %q, want %q", w.String(), "*:8080")
	}
	netw, addr := w.LocalListenAddress(false)
	if netw != "tcp" || addr != ":8080" {
		t.Errorf("w.LocalListenAddress(false) = (%q, %q)", netw, addr)
	}
	netw, addr = w.LocalListenAddress(true)
	if netw != "tcp" || addr != ":8080" {
		t.Errorf("w.LocalListenAddress(true) = (%q, %q)", netw, addr)
	}
	netw, addr = w.RemoteListenAddress()
	if netw != "tcp" || addr != ":8080" {
		t.Errorf("w.RemoteListenAddress = (%q, %q)", netw, addr)
	}
	h, p := w.MuxListenEndpoint()
	if h != "*" || p != 8080 {
		t.Errorf("w.MuxListenEndpoint = (%q, %d)", h, p)
	}
}

func testForwardEndpoint_OmittedHost(t *testing.T) {
	o := ForwardEndpoint{Port: 8080, HasHost: false, Wildcard: false}
	if o.String() != "8080" {
		t.Errorf("o.String() = %q, want %q", o.String(), "8080")
	}
	netw, addr := o.LocalListenAddress(false)
	if netw != "tcp" || addr != "127.0.0.1:8080" {
		t.Errorf("o.LocalListenAddress(false) = (%q, %q)", netw, addr)
	}
	netw, addr = o.LocalListenAddress(true)
	if netw != "tcp" || addr != ":8080" {
		t.Errorf("o.LocalListenAddress(true) = (%q, %q)", netw, addr)
	}
	netw, addr = o.RemoteListenAddress()
	if netw != "tcp" || addr != "localhost:8080" {
		t.Errorf("o.RemoteListenAddress = (%q, %q)", netw, addr)
	}
	h, p := o.MuxListenEndpoint()
	if h != "" || p != 8080 {
		t.Errorf("o.MuxListenEndpoint = (%q, %d)", h, p)
	}
}

func testForwardEndpoint_ExplicitHost(t *testing.T) {
	e := ForwardEndpoint{Host: "192.168.1.100", Port: 8080, HasHost: true, Wildcard: false}
	if e.String() != "192.168.1.100:8080" {
		t.Errorf("e.String() = %q, want %q", e.String(), "192.168.1.100:8080")
	}
	netw, addr := e.LocalListenAddress(false)
	if netw != "tcp" || addr != "192.168.1.100:8080" {
		t.Errorf("e.LocalListenAddress(false) = (%q, %q)", netw, addr)
	}
	netw, addr = e.LocalListenAddress(true)
	if netw != "tcp" || addr != "192.168.1.100:8080" {
		t.Errorf("e.LocalListenAddress(true) = (%q, %q)", netw, addr)
	}
	netw, addr = e.RemoteListenAddress()
	if netw != "tcp" || addr != "192.168.1.100:8080" {
		t.Errorf("e.RemoteListenAddress = (%q, %q)", netw, addr)
	}
	netw, addr = e.ConnectAddress()
	if netw != "tcp" || addr != "192.168.1.100:8080" {
		t.Errorf("e.ConnectAddress = (%q, %q)", netw, addr)
	}
	h, p := e.MuxListenEndpoint()
	if h != "192.168.1.100" || p != 8080 {
		t.Errorf("e.MuxListenEndpoint = (%q, %d)", h, p)
	}
	h, p = e.MuxConnectEndpoint()
	if h != "192.168.1.100" || p != 8080 {
		t.Errorf("e.MuxConnectEndpoint = (%q, %d)", h, p)
	}
}

func TestParseForwardSpec_AllCombinations(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantBind ForwardEndpoint
		wantDest ForwardEndpoint
		wantStr  string
	}{
		// TCP -> TCP (whitespace and colon)
		{
			name:     "TCP->TCP whitespace omitted bind host",
			input:    "8080 127.0.0.1:80",
			wantBind: ForwardEndpoint{Port: 8080, HasHost: false},
			wantDest: ForwardEndpoint{Host: "127.0.0.1", Port: 80, HasHost: true},
			wantStr:  "8080 127.0.0.1:80",
		},
		{
			name:     "TCP->TCP colon 3-part",
			input:    "8080:127.0.0.1:80",
			wantBind: ForwardEndpoint{Port: 8080, HasHost: false},
			wantDest: ForwardEndpoint{Host: "127.0.0.1", Port: 80, HasHost: true},
			wantStr:  "8080 127.0.0.1:80",
		},
		{
			name:     "TCP->TCP colon 4-part",
			input:    "127.0.0.1:8080:127.0.0.1:80",
			wantBind: ForwardEndpoint{Host: "127.0.0.1", Port: 8080, HasHost: true},
			wantDest: ForwardEndpoint{Host: "127.0.0.1", Port: 80, HasHost: true},
			wantStr:  "127.0.0.1:8080 127.0.0.1:80",
		},
		{
			name:     "TCP->TCP IPv6 brackets",
			input:    "[::1]:8080:[::1]:80",
			wantBind: ForwardEndpoint{Host: "::1", Port: 8080, HasHost: true},
			wantDest: ForwardEndpoint{Host: "::1", Port: 80, HasHost: true},
			wantStr:  "[::1]:8080 [::1]:80",
		},
		{
			name:     "TCP->TCP wildcard asterisk colon",
			input:    "*:8080:remote:80",
			wantBind: ForwardEndpoint{Port: 8080, HasHost: true, Wildcard: true},
			wantDest: ForwardEndpoint{Host: "remote", Port: 80, HasHost: true},
			wantStr:  "*:8080 remote:80",
		},
		{
			name:     "TCP->TCP wildcard empty colon",
			input:    ":8080:remote:80",
			wantBind: ForwardEndpoint{Port: 8080, HasHost: true, Wildcard: true},
			wantDest: ForwardEndpoint{Host: "remote", Port: 80, HasHost: true},
			wantStr:  "*:8080 remote:80",
		},

		// TCP -> Unix
		{
			name:     "TCP->Unix whitespace",
			input:    "8080 /tmp/dest.sock",
			wantBind: ForwardEndpoint{Port: 8080, HasHost: false},
			wantDest: ForwardEndpoint{SocketPath: "/tmp/dest.sock"},
			wantStr:  "8080 /tmp/dest.sock",
		},
		{
			name:     "TCP->Unix colon 2-part",
			input:    "8080:/tmp/dest.sock",
			wantBind: ForwardEndpoint{Port: 8080, HasHost: false},
			wantDest: ForwardEndpoint{SocketPath: "/tmp/dest.sock"},
			wantStr:  "8080 /tmp/dest.sock",
		},
		{
			name:     "TCP->Unix colon 3-part",
			input:    "127.0.0.1:8080:/tmp/dest.sock",
			wantBind: ForwardEndpoint{Host: "127.0.0.1", Port: 8080, HasHost: true},
			wantDest: ForwardEndpoint{SocketPath: "/tmp/dest.sock"},
			wantStr:  "127.0.0.1:8080 /tmp/dest.sock",
		},
		{
			name:     "TCP->Unix wildcard colon 3-part",
			input:    "*:8080:/tmp/dest.sock",
			wantBind: ForwardEndpoint{Port: 8080, HasHost: true, Wildcard: true},
			wantDest: ForwardEndpoint{SocketPath: "/tmp/dest.sock"},
			wantStr:  "*:8080 /tmp/dest.sock",
		},

		// Unix -> TCP
		{
			name:     "Unix->TCP whitespace",
			input:    "/tmp/bind.sock 127.0.0.1:80",
			wantBind: ForwardEndpoint{SocketPath: "/tmp/bind.sock"},
			wantDest: ForwardEndpoint{Host: "127.0.0.1", Port: 80, HasHost: true},
			wantStr:  "/tmp/bind.sock 127.0.0.1:80",
		},
		{
			name:     "Unix->TCP colon 3-part",
			input:    "/tmp/bind.sock:127.0.0.1:80",
			wantBind: ForwardEndpoint{SocketPath: "/tmp/bind.sock"},
			wantDest: ForwardEndpoint{Host: "127.0.0.1", Port: 80, HasHost: true},
			wantStr:  "/tmp/bind.sock 127.0.0.1:80",
		},
		{
			name:     "Unix->TCP Windows drive letter path",
			input:    `C:\temp\a.sock:127.0.0.1:80`,
			wantBind: ForwardEndpoint{SocketPath: `C:\temp\a.sock`},
			wantDest: ForwardEndpoint{Host: "127.0.0.1", Port: 80, HasHost: true},
			wantStr:  `C:\temp\a.sock 127.0.0.1:80`,
		},

		// Unix -> Unix
		{
			name:     "Unix->Unix whitespace",
			input:    "/tmp/bind.sock /tmp/dest.sock",
			wantBind: ForwardEndpoint{SocketPath: "/tmp/bind.sock"},
			wantDest: ForwardEndpoint{SocketPath: "/tmp/dest.sock"},
			wantStr:  "/tmp/bind.sock /tmp/dest.sock",
		},
		{
			name:     "Unix->Unix colon 2-part",
			input:    "/tmp/bind.sock:/tmp/dest.sock",
			wantBind: ForwardEndpoint{SocketPath: "/tmp/bind.sock"},
			wantDest: ForwardEndpoint{SocketPath: "/tmp/dest.sock"},
			wantStr:  "/tmp/bind.sock /tmp/dest.sock",
		},
		{
			name:     "Unix->Unix Windows drive letter paths",
			input:    `C:\temp\a.sock:D:\temp\b.sock`,
			wantBind: ForwardEndpoint{SocketPath: `C:\temp\a.sock`},
			wantDest: ForwardEndpoint{SocketPath: `D:\temp\b.sock`},
			wantStr:  `C:\temp\a.sock D:\temp\b.sock`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := ParseForwardSpec(tt.input)
			if err != nil {
				t.Fatalf("ParseForwardSpec(%q) failed: %v", tt.input, err)
			}
			if spec.Bind != tt.wantBind {
				t.Errorf("Bind = %+v, want %+v", spec.Bind, tt.wantBind)
			}
			if spec.Dest != tt.wantDest {
				t.Errorf("Dest = %+v, want %+v", spec.Dest, tt.wantDest)
			}
			if spec.String() != tt.wantStr {
				t.Errorf("String() = %q, want %q", spec.String(), tt.wantStr)
			}

			// Round-trip parse from String()
			roundTrip, err := ParseForwardSpec(spec.String())
			if err != nil {
				t.Fatalf("round-trip parse failed for %q: %v", spec.String(), err)
			}
			if roundTrip != spec {
				t.Errorf("roundTrip mismatch: got %+v, want %+v", roundTrip, spec)
			}
		})
	}
}

func TestParseRemoteForwardSpec_Comprehensive(t *testing.T) {
	// Reverse dynamic specs
	dynTests := []struct {
		input       string
		wantBind    ForwardEndpoint
		wantBindStr string
	}{
		{"1080", ForwardEndpoint{Port: 1080, HasHost: false}, "1080"},
		{"0", ForwardEndpoint{Port: 0, HasHost: false}, "0"},
		{"127.0.0.1:1080", ForwardEndpoint{Host: "127.0.0.1", Port: 1080, HasHost: true}, "127.0.0.1:1080"},
		{"*:1080", ForwardEndpoint{Port: 1080, HasHost: true, Wildcard: true}, "*:1080"},
		{":1080", ForwardEndpoint{Port: 1080, HasHost: true, Wildcard: true}, "*:1080"},
		{"[::1]:1080", ForwardEndpoint{Host: "::1", Port: 1080, HasHost: true}, "[::1]:1080"},
		{"/tmp/remote.sock", ForwardEndpoint{SocketPath: "/tmp/remote.sock"}, "/tmp/remote.sock"},
	}

	for _, tt := range dynTests {
		t.Run("dynamic_"+tt.input, func(t *testing.T) {
			spec, err := ParseRemoteForwardSpec(tt.input)
			if err != nil {
				t.Fatalf("ParseRemoteForwardSpec(%q) failed: %v", tt.input, err)
			}
			if !spec.IsDynamic {
				t.Errorf("expected IsDynamic to be true for %q", tt.input)
			}
			if spec.Bind != tt.wantBind {
				t.Errorf("Bind = %+v, want %+v", spec.Bind, tt.wantBind)
			}
			if spec.Dest != (ForwardEndpoint{}) {
				t.Errorf("Dest should be zero, got %+v", spec.Dest)
			}
			if spec.DestAddr != "" {
				t.Errorf("DestAddr should be empty, got %q", spec.DestAddr)
			}
			if spec.String() != tt.wantBindStr {
				t.Errorf("String() = %q, want %q", spec.String(), tt.wantBindStr)
			}
		})
	}

	// Two-endpoint specs accepted by ParseRemoteForwardSpec
	twoEndpointTests := []string{
		"8080 127.0.0.1:80",
		"8080:127.0.0.1:80",
		"127.0.0.1:8080:127.0.0.1:80",
		"8080:/tmp/remote.sock",
		"127.0.0.1:8080:/tmp/remote.sock",
		"/tmp/remote.sock:127.0.0.1:80",
		"/tmp/remote.sock:/tmp/local.sock",
	}

	for _, input := range twoEndpointTests {
		t.Run("two_endpoint_"+input, func(t *testing.T) {
			spec, err := ParseRemoteForwardSpec(input)
			if err != nil {
				t.Fatalf("ParseRemoteForwardSpec(%q) failed: %v", input, err)
			}
			if spec.IsDynamic {
				t.Errorf("expected IsDynamic=false for %q", input)
			}
			expected, err := ParseForwardSpec(input)
			if err != nil {
				t.Fatalf("ParseForwardSpec(%q) failed: %v", input, err)
			}
			if spec != expected {
				t.Errorf("spec mismatch with ParseForwardSpec: got %+v, want %+v", spec, expected)
			}
		})
	}

	// Invalid remote forward specs
	invalid := []string{
		"",
		"   ",
		"1080 1081 1082",
		"/tmp/remote.sock:1080", // unix socket cannot have a port
		"65536",
		"localhost:65536",
	}
	for _, inv := range invalid {
		t.Run("invalid_"+inv, func(t *testing.T) {
			_, err := ParseRemoteForwardSpec(inv)
			if err == nil {
				t.Errorf("expected error for %q, got nil", inv)
			}
		})
	}
}

func TestNewOptions_GettersAndEffective(t *testing.T) {
	opts := &Options{}
	t.Run("Defaults", func(t *testing.T) {
		testNewOptions_Defaults(t, opts)
	})
	t.Run("GatewayPorts", func(t *testing.T) {
		testNewOptions_GatewayPorts(t, opts)
	})
	t.Run("StreamLocalBindUnlink", func(t *testing.T) {
		testNewOptions_StreamLocalBindUnlink(t, opts)
	})
	t.Run("StreamLocalBindMask", func(t *testing.T) {
		testNewOptions_StreamLocalBindMask(t, opts)
	})
	t.Run("SessionAndAuth", func(t *testing.T) {
		testNewOptions_SessionAndAuth(t, opts)
	})
	t.Run("NilReceiver", func(t *testing.T) {
		testNewOptions_NilReceiver(t)
	})
}

func testNewOptions_Defaults(t *testing.T, opts *Options) {
	t.Helper()
	if v, ok := opts.GatewayPorts(); ok || v {
		t.Errorf("default GatewayPorts = (%v, %v), want (false, false)", v, ok)
	}
	if opts.EffectiveGatewayPorts() != false {
		t.Errorf("default EffectiveGatewayPorts = true, want false")
	}

	if v, ok := opts.StreamLocalBindUnlink(); ok || v {
		t.Errorf("default StreamLocalBindUnlink = (%v, %v), want (false, false)", v, ok)
	}
	if opts.EffectiveStreamLocalBindUnlink() != false {
		t.Errorf("default EffectiveStreamLocalBindUnlink = true, want false")
	}

	if v, ok := opts.StreamLocalBindMask(); ok || v != 0 {
		t.Errorf("default StreamLocalBindMask = (%v, %v), want (0, false)", v, ok)
	}
	if opts.EffectiveStreamLocalBindMask() != DefaultStreamLocalBindMask {
		t.Errorf("default EffectiveStreamLocalBindMask = %04o, want %04o", opts.EffectiveStreamLocalBindMask(), DefaultStreamLocalBindMask)
	}

	if v, ok := opts.ForkAfterAuthentication(); ok || v {
		t.Errorf("default ForkAfterAuthentication = (%v, %v), want (false, false)", v, ok)
	}

	if v, ok := opts.StdinNull(); ok || v {
		t.Errorf("default StdinNull = (%v, %v), want (false, false)", v, ok)
	}

	if opts.SessionType() != "" {
		t.Errorf("default SessionType = %q, want empty", opts.SessionType())
	}
}

func testNewOptions_GatewayPorts(t *testing.T, opts *Options) {
	t.Helper()
	mustSetTestOption(t, opts, "gateway_ports", "yes")
	if v, ok := opts.GatewayPorts(); !ok || !v {
		t.Errorf("GatewayPorts after 'yes' = (%v, %v), want (true, true)", v, ok)
	}
	if !opts.EffectiveGatewayPorts() {
		t.Errorf("EffectiveGatewayPorts after 'yes' should be true")
	}

	mustSetTestOption(t, opts, "gateway_ports", "no")
	if v, ok := opts.GatewayPorts(); !ok || v {
		t.Errorf("GatewayPorts after 'no' = (%v, %v), want (false, true)", v, ok)
	}
	if opts.EffectiveGatewayPorts() {
		t.Errorf("EffectiveGatewayPorts after 'no' should be false")
	}

	if err := opts.Set("gateway_ports", "clientspecified"); err == nil {
		t.Errorf("expected gateway_ports 'clientspecified' to fail")
	}
}

func testNewOptions_StreamLocalBindUnlink(t *testing.T, opts *Options) {
	t.Helper()
	mustSetTestOption(t, opts, "stream_local_bind_unlink", "true")
	if v, ok := opts.StreamLocalBindUnlink(); !ok || !v {
		t.Errorf("StreamLocalBindUnlink after 'true' = (%v, %v), want (true, true)", v, ok)
	}
	if !opts.EffectiveStreamLocalBindUnlink() {
		t.Errorf("EffectiveStreamLocalBindUnlink should be true")
	}
}

func testNewOptions_StreamLocalBindMask(t *testing.T, opts *Options) {
	t.Helper()
	validMasks := []struct {
		input    string
		wantMask uint32
		wantNorm string
	}{
		{"0177", 0o177, "0177"},
		{"177", 0o177, "0177"},
		{"0000", 0, "0000"},
		{"0", 0, "0000"},
		{"0777", 0o777, "0777"},
		{"0077", 0o77, "0077"},
		{"77", 0o77, "0077"},
	}
	for _, vm := range validMasks {
		if err := opts.Set("stream_local_bind_mask", vm.input); err != nil {
			t.Fatalf("opts.Set(stream_local_bind_mask, %q) failed: %v", vm.input, err)
		}
		mask, ok := opts.StreamLocalBindMask()
		if !ok || mask != vm.wantMask {
			t.Errorf("StreamLocalBindMask for %q = (%04o, %v), want (%04o, true)", vm.input, mask, ok, vm.wantMask)
		}
		if opts.Get("stream_local_bind_mask") != vm.wantNorm {
			t.Errorf("normalized StreamLocalBindMask = %q, want %q", opts.Get("stream_local_bind_mask"), vm.wantNorm)
		}
	}

	invalidMasks := []string{"0888", "01000", "1777", "-1", "abc", "", "0o177", "8", "9"}
	for _, inv := range invalidMasks {
		if _, err := ParseStreamLocalBindMask(inv); err == nil {
			t.Errorf("expected ParseStreamLocalBindMask(%q) to fail", inv)
		}
		if _, err := ParseStreamLocalBindMaskOption(inv); err == nil {
			t.Errorf("expected ParseStreamLocalBindMaskOption(%q) to fail", inv)
		}
		if inv != "" {
			if err := opts.Set("stream_local_bind_mask", inv); err == nil {
				t.Errorf("expected StreamLocalBindMask %q to fail in opts.Set", inv)
			}
		}
	}
}

func testNewOptions_SessionAndAuth(t *testing.T, opts *Options) {
	t.Helper()
	mustSetTestOption(t, opts, "fork_after_authentication", "yes")
	if v, ok := opts.ForkAfterAuthentication(); !ok || !v {
		t.Errorf("ForkAfterAuthentication after 'yes' = (%v, %v), want (true, true)", v, ok)
	}

	mustSetTestOption(t, opts, "stdin_null", "true")
	if v, ok := opts.StdinNull(); !ok || !v {
		t.Errorf("StdinNull after 'true' = (%v, %v), want (true, true)", v, ok)
	}

	mustSetTestOption(t, opts, "session_type", "none")
	if opts.SessionType() != SessionTypeNone {
		t.Errorf("SessionType after 'none' = %q, want %q", opts.SessionType(), SessionTypeNone)
	}
	mustSetTestOption(t, opts, "session_type", "default")
	if opts.SessionType() != SessionTypeDefault {
		t.Errorf("SessionType after 'default' = %q, want %q", opts.SessionType(), SessionTypeDefault)
	}
	if err := opts.Set("session_type", "subsystem"); err == nil {
		t.Errorf("expected session_type 'subsystem' to fail")
	}
}

func testNewOptions_NilReceiver(t *testing.T) {
	t.Helper()
	var nilOpts *Options
	if v, ok := nilOpts.GatewayPorts(); ok || v {
		t.Errorf("nilOpts.GatewayPorts = (%v, %v)", v, ok)
	}
	if nilOpts.EffectiveGatewayPorts() != false {
		t.Errorf("nilOpts.EffectiveGatewayPorts != false")
	}
	if v, ok := nilOpts.StreamLocalBindUnlink(); ok || v {
		t.Errorf("nilOpts.StreamLocalBindUnlink = (%v, %v)", v, ok)
	}
	if nilOpts.EffectiveStreamLocalBindUnlink() != false {
		t.Errorf("nilOpts.EffectiveStreamLocalBindUnlink != false")
	}
	if v, ok := nilOpts.StreamLocalBindMask(); ok || v != 0 {
		t.Errorf("nilOpts.StreamLocalBindMask = (%v, %v)", v, ok)
	}
	if nilOpts.EffectiveStreamLocalBindMask() != DefaultStreamLocalBindMask {
		t.Errorf("nilOpts.EffectiveStreamLocalBindMask != DefaultStreamLocalBindMask")
	}
	if v, ok := nilOpts.ForkAfterAuthentication(); ok || v {
		t.Errorf("nilOpts.ForkAfterAuthentication = (%v, %v)", v, ok)
	}
	if v, ok := nilOpts.StdinNull(); ok || v {
		t.Errorf("nilOpts.StdinNull = (%v, %v)", v, ok)
	}
	if nilOpts.SessionType() != "" {
		t.Errorf("nilOpts.SessionType != empty")
	}
}

func TestExpandStreamLocalPath(t *testing.T) {
	env := Environment{
		LocalUser: "localuser",
		LocalHost: "myhost.example.com",
		LocalUID:  "1000",
		HomeDir:   "/home/localuser",
		LookupEnv: func(key string) (string, bool) {
			if key == "SOCK_DIR" {
				return "/run/user/1000", true
			}
			return "", false
		},
	}
	target := TargetContext{
		Host:         "remote.example.com",
		Port:         2222,
		User:         "remoteuser",
		OriginalHost: "remotedev",
	}

	// Local tilde true vs false
	expanded, err := ExpandStreamLocalPath("~/mysock.sock", env, target, true)
	if err != nil {
		t.Fatalf("ExpandStreamLocalPath with tilde true failed: %v", err)
	}
	if expanded != "/home/localuser/mysock.sock" {
		t.Errorf("expanded tilde true = %q, want %q", expanded, "/home/localuser/mysock.sock")
	}

	expandedFalse, err := ExpandStreamLocalPath("~/mysock.sock", env, target, false)
	if err != nil {
		t.Fatalf("ExpandStreamLocalPath with tilde false failed: %v", err)
	}
	if expandedFalse != "~/mysock.sock" {
		t.Errorf("expanded tilde false = %q, want %q", expandedFalse, "~/mysock.sock")
	}

	// Environment variable ${VAR}
	expandedEnv, err := ExpandStreamLocalPath("${SOCK_DIR}/app.sock", env, target, false)
	if err != nil {
		t.Fatalf("ExpandStreamLocalPath with ${VAR} failed: %v", err)
	}
	if expandedEnv != "/run/user/1000/app.sock" {
		t.Errorf("expandedEnv = %q, want %q", expandedEnv, "/run/user/1000/app.sock")
	}

	// Percent tokens: %h, %p, %r, %C, %%
	connHash := ComputeConnectionHash("myhost.example.com", "remote.example.com", "2222", "remoteuser", "")
	expandedTokens, err := ExpandStreamLocalPath("/tmp/%r-%h-%p-%C-%%.sock", env, target, false)
	if err != nil {
		t.Fatalf("ExpandStreamLocalPath with tokens failed: %v", err)
	}
	wantTokens := fmt.Sprintf("/tmp/remoteuser-remote.example.com-2222-%s-%%.sock", connHash)
	if expandedTokens != wantTokens {
		t.Errorf("expandedTokens = %q, want %q", expandedTokens, wantTokens)
	}

	// Errors on empty, null byte, unknown token, missing env var
	if _, err := ExpandStreamLocalPath("", env, target, false); err == nil {
		t.Errorf("expected error on empty path")
	}
	if _, err := ExpandStreamLocalPath("/tmp/a\x00b.sock", env, target, false); err == nil {
		t.Errorf("expected error on null byte")
	}
	if _, err := ExpandStreamLocalPath("/tmp/%x.sock", env, target, false); err == nil {
		t.Errorf("expected error on unknown token %%x")
	}
	if _, err := ExpandStreamLocalPath("${NONEXISTENT}/a.sock", env, target, false); err == nil {
		t.Errorf("expected error on nonexistent env var")
	}

	// ValidateStreamLocalPathSyntax
	if err := ValidateStreamLocalPathSyntax("/tmp/%h-%p.sock"); err != nil {
		t.Errorf("ValidateStreamLocalPathSyntax valid path failed: %v", err)
	}
	if err := ValidateStreamLocalPathSyntax(""); err == nil {
		t.Errorf("ValidateStreamLocalPathSyntax expected error on empty")
	}
	if err := ValidateStreamLocalPathSyntax("/tmp/a\x00b.sock"); err == nil {
		t.Errorf("ValidateStreamLocalPathSyntax expected error on null byte")
	}
	if err := ValidateStreamLocalPathSyntax("/tmp/%z.sock"); err == nil {
		t.Errorf("ValidateStreamLocalPathSyntax expected error on unknown token")
	}
}

func TestOptions_NewOptionsYAMLAndJSONRoundTrip(t *testing.T) {
	opts := &Options{}
	mustSetTestOption(t, opts, "gateway_ports", "yes")
	mustSetTestOption(t, opts, "stream_local_bind_unlink", "yes")
	mustSetTestOption(t, opts, "stream_local_bind_mask", "0077")
	mustSetTestOption(t, opts, "fork_after_authentication", "yes")
	mustSetTestOption(t, opts, "stdin_null", "yes")
	mustSetTestOption(t, opts, "session_type", "none")
	mustAppendTestOption(t, opts, "local_forward", "8080 127.0.0.1:80")
	mustAppendTestOption(t, opts, "local_forward", "/tmp/local.sock /tmp/remote.sock")
	mustAppendTestOption(t, opts, "remote_forward", "1080")
	mustAppendTestOption(t, opts, "remote_forward", "/tmp/remote.sock")
	mustAppendTestOption(t, opts, "dynamic_forward", "1080")
	mustAppendTestOption(t, opts, "dynamic_forward", "/tmp/socks.sock")

	// YAML round-trip
	yamlBytes, err := yaml.Marshal(opts)
	if err != nil {
		t.Fatalf("yaml.Marshal failed: %v", err)
	}
	var unmarshaledYAML Options
	if err := yaml.Unmarshal(yamlBytes, &unmarshaledYAML); err != nil {
		t.Fatalf("yaml.Unmarshal failed: %v", err)
	}
	if !opts.Equal(&unmarshaledYAML) {
		t.Fatalf("YAML round-trip mismatch:\nwant: %+v\ngot:  %+v", opts, &unmarshaledYAML)
	}

	// JSON round-trip
	jsonBytes, err := json.Marshal(opts)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	var unmarshaledJSON Options
	if err := json.Unmarshal(jsonBytes, &unmarshaledJSON); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	if !opts.Equal(&unmarshaledJSON) {
		t.Fatalf("JSON round-trip mismatch:\nwant: %+v\ngot:  %+v", opts, &unmarshaledJSON)
	}
}
