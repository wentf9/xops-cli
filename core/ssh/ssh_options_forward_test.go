package ssh

import (
	"encoding/json"
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

		// Error cases
		{input: "", wantErr: true},
		{input: "8080 remote:0", wantErr: true},
		{input: "8080 remote:65536", wantErr: true},
		{input: "/run/user/1000/gnupg/S.gpg-agent /run/user/1000/gnupg/S.gpg-agent.extra", wantErr: true},
		{input: "/tmp/sock:remote:80", wantErr: true},
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
		{"1080", "127.0.0.1:1080", false},
		{"127.0.0.1:1080", "127.0.0.1:1080", false},
		{"0.0.0.0:1080", "0.0.0.0:1080", false},
		{"[::1]:1080", "[::1]:1080", false},
		{"*:1080", ":1080", false},
		{":1080", ":1080", false},
		{"0", "127.0.0.1:0", false},
		{"", "", true},
		{"/run/user/1000/proxy", "", true},
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

	// Append LocalForward
	if err := opts.Append("local_forward", "8080 127.0.0.1:80"); err != nil {
		t.Fatalf("Append LocalForward failed: %v", err)
	}
	// Append equivalent colon format -> deduplication test
	if err := opts.Append("local_forward", "127.0.0.1:8080:127.0.0.1:80"); err != nil {
		t.Fatalf("Append LocalForward duplicate failed: %v", err)
	}
	// Append second distinct forward
	if err := opts.Append("LocalForward", "9090 remote:90"); err != nil {
		t.Fatalf("Append second LocalForward failed: %v", err)
	}

	lf := opts.LocalForwards()
	if len(lf) != 2 {
		t.Fatalf("expected 2 LocalForwards, got %d: %v", len(lf), lf)
	}
	if lf[0] != "127.0.0.1:8080 127.0.0.1:80" || lf[1] != "127.0.0.1:9090 remote:90" {
		t.Fatalf("unexpected LocalForwards entries: %v", lf)
	}

	// RemoteForward
	if err := opts.Append("remote_forward", "8080 127.0.0.1:80"); err != nil {
		t.Fatalf("Append RemoteForward failed: %v", err)
	}
	if err := opts.Append("RemoteForward", "9090 127.0.0.1:90"); err != nil {
		t.Fatalf("Append RemoteForward 2 failed: %v", err)
	}
	rf := opts.RemoteForwards()
	if len(rf) != 2 {
		t.Fatalf("expected 2 RemoteForwards, got %d: %v", len(rf), rf)
	}

	// DynamicForward
	if err := opts.Append("dynamic_forward", "1080"); err != nil {
		t.Fatalf("Append DynamicForward failed: %v", err)
	}
	if err := opts.Append("DynamicForward", "127.0.0.1:1080"); err != nil {
		t.Fatalf("Append DynamicForward dup failed: %v", err)
	}
	if err := opts.Append("dynamic_forward", "1081"); err != nil {
		t.Fatalf("Append DynamicForward 2 failed: %v", err)
	}
	df := opts.DynamicForwards()
	if len(df) != 2 {
		t.Fatalf("expected 2 DynamicForwards, got %d: %v", len(df), df)
	}
	if df[0] != "127.0.0.1:1080" || df[1] != "127.0.0.1:1081" {
		t.Fatalf("unexpected DynamicForwards: %v", df)
	}

	// Scalar option through Append behaves as Set
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
	if len(singleOpts.LocalForwards()) != 1 || singleOpts.LocalForwards()[0] != "127.0.0.1:8080 127.0.0.1:80" {
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
	if lf[0] != "127.0.0.1:8080 127.0.0.1:80" || lf[1] != "127.0.0.1:9090 remote:90" {
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
