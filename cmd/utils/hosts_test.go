package utils

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestReadCSVFile(t *testing.T) {
	content := `主机,端口,别名,用户,密码,私钥,私钥密码
192.168.1.1,22,host1,root,pass1,/path/id_rsa,

10.0.0.1,2222,host2,admin,pass2,,keypass
`
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.csv")
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	hosts, err := ReadCSVFile(filePath)
	if err != nil {
		t.Fatalf("ReadCSVFile failed: %v", err)
	}

	if len(hosts) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(hosts))
	}

	expected := []HostInfo{
		{Host: "192.168.1.1", Port: 22, Alias: "host1", User: "root", Password: "pass1", KeyPath: "/path/id_rsa", Passphrase: ""},
		{Host: "10.0.0.1", Port: 2222, Alias: "host2", User: "admin", Password: "pass2", KeyPath: "", Passphrase: "keypass"},
	}

	for i, h := range hosts {
		if !reflect.DeepEqual(h, expected[i]) {
			t.Errorf("expected %+v, got %+v", expected[i], h)
		}
	}
}

func TestReadCSVFile_Errors(t *testing.T) {
	tests := []struct {
		name       string
		content    string
		wantErrSub string
	}{
		{
			name: "port zero",
			content: `主机,端口
10.0.0.1,0
`,
			wantErrSub: "csv row 2: parse port \"0\" failed",
		},
		{
			name: "port 65536 out of range",
			content: `主机,端口
10.0.0.1,65536
`,
			wantErrSub: "csv row 2: parse port \"65536\" failed",
		},
		{
			name: "port non-numeric",
			content: `主机,端口
10.0.0.1,abc
`,
			wantErrSub: "csv row 2: parse port \"abc\" failed",
		},
		{
			name: "invalid host on row 3",
			content: `主机,端口
10.0.0.1,22
host:,22
`,
			wantErrSub: "csv row 3: parse host \"host:\" failed",
		},
		{
			name: "empty host field on row 2",
			content: `主机,端口
,22
`,
			wantErrSub: "csv row 2: host field is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			filePath := filepath.Join(tmpDir, "test.csv")
			if err := os.WriteFile(filePath, []byte(tt.content), 0644); err != nil {
				t.Fatal(err)
			}
			_, err := ReadCSVFile(filePath)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErrSub) {
				t.Errorf("expected error containing %q, got: %v", tt.wantErrSub, err)
			}
		})
	}
}
