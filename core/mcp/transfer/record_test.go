package transfer

import (
	"strings"
	"testing"
)

func TestSpecValidate_DriveRoot(t *testing.T) {
	baseSpec := Spec{
		RequestID:     "req-1",
		Scope:         "test-scope",
		NodeID:        "node-1",
		TargetID:      "target-1",
		RequestedPath: "/test",
		RemotePath:    "/tmp/test.txt",
		Direction:     Download,
	}

	tests := []struct {
		name       string
		remotePath string
		wantErr    bool
		errSubstr  string
	}{
		{"valid posix path", "/tmp/file.txt", false, ""},
		{"valid windows normalized path", "/C:/Users/wentf/test.txt", false, ""},
		{"posix root rejected", "/", true, "normalized absolute remote file path"},
		{"windows drive root upper rejected", "/C:", true, "normalized absolute remote file path"},
		{"windows drive root lower rejected", "/c:", true, "normalized absolute remote file path"},
		{"windows drive root other letter rejected", "/D:", true, "normalized absolute remote file path"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := baseSpec
			s.RemotePath = tt.remotePath
			err := s.validate()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for remotePath %q, got nil", tt.remotePath)
				}
				if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
			} else if err != nil {
				t.Fatalf("unexpected error for remotePath %q: %v", tt.remotePath, err)
			}
		})
	}
}
