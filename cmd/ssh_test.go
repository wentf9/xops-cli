package cmd

import (
	"testing"
)

func TestParseForwardArg(t *testing.T) {
	tests := []struct {
		name     string
		arg      string
		wantBind string
		wantDest string
		wantErr  bool
	}{
		{
			name:     "port:host:hostport",
			arg:      "8080:localhost:80",
			wantBind: "127.0.0.1:8080",
			wantDest: "localhost:80",
			wantErr:  false,
		},
		{
			name:     "bind_address:port:host:hostport",
			arg:      "0.0.0.0:8080:localhost:80",
			wantBind: "0.0.0.0:8080",
			wantDest: "localhost:80",
			wantErr:  false,
		},
		{
			name:     "invalid format",
			arg:      "8080",
			wantBind: "",
			wantDest: "",
			wantErr:  true,
		},
		{
			name:     "invalid format with one colon",
			arg:      "localhost:80",
			wantBind: "",
			wantDest: "",
			wantErr:  true,
		},
		{
			name:     "too many colons (ipv6 with brackets without port)",
			arg:      "127.0.0.1:8080:[::1]:80",
			wantBind: "127.0.0.1:8080",
			wantDest: "[::1]:80",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotBind, gotDest, err := parseForwardArg(tt.arg)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseForwardArg() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotBind != tt.wantBind {
				t.Errorf("parseForwardArg() gotBind = %v, want %v", gotBind, tt.wantBind)
			}
			if gotDest != tt.wantDest {
				t.Errorf("parseForwardArg() gotDest = %v, want %v", gotDest, tt.wantDest)
			}
		})
	}
}
