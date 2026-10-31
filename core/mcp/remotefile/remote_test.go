package remotefile

import "testing"

func TestNormalizeSFTPPath(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"posix root", "/", "/"},
		{"posix file", "/tmp/test.txt", "/tmp/test.txt"},
		{"posix with backslash in filename", "/tmp/foo\\bar", "/tmp/foo\\bar"},
		{"relative posix", "relative/path.txt", "relative/path.txt"},
		{"windows native backslash", `C:\Users\wentf\test.txt`, "/C:/Users/wentf/test.txt"},
		{"windows native forward slash", "c:/Users/wentf/test.txt", "/C:/Users/wentf/test.txt"},
		{"windows prefixed backslash", `/C:\Users\wentf\test.txt`, "/C:/Users/wentf/test.txt"},
		{"windows prefixed forward slash", "/c:/Users/wentf/test.txt", "/C:/Users/wentf/test.txt"},
		{"windows drive root backslash", `C:\`, "/C:"},
		{"windows drive root bare", "C:", "/C:"},
		{"windows drive root forward slash", "c:/", "/C:"},
		{"windows drive root prefixed bare", "/C:", "/C:"},
		{"windows drive root prefixed forward slash", "/c:/", "/C:"},
		{"windows drive root prefixed backslash", `/C:\`, "/C:"},
		{"windows relative drive", "C:file.txt", "C:file.txt"},
		{"windows D root", `D:\`, "/D:"},
		{"windows Z root", `Z:\`, "/Z:"},
		{"windows C forward slash root", "C:/", "/C:"},
		{"windows C prefixed slash root", "/C:/", "/C:"},
		{"windows c lower backslash", `c:\`, "/C:"},
		{"posix backslash relative", `\tmp\foo`, `\tmp\foo`},
		{"windows multiple backslashes", `C:\\`, "/C:"},
		{"windows mixed trailing slashes", `C:///\\`, "/C:"},
		{"windows collapse to root double dot", `C:\Users\..\..`, "/C:"},
		{"windows collapse to root triple dot", `C:\Users\..\..\..`, "/C:"},
		{"windows clamp does not cross drive", `C:\..\D:\foo`, "/C:/D:/foo"},
		{"windows prefixed collapse to root", `/C:/Users/../..`, "/C:"},
		{"windows prefixed clamp does not cross drive", `/C:/../D:/foo`, "/C:/D:/foo"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeSFTPPath(tt.in)
			if got != tt.want {
				t.Errorf("NormalizeSFTPPath(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestIsRootPath(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"empty", "", false},
		{"posix root", "/", true},
		{"posix subpath", "/etc", false},
		{"windows root backslash", `C:\`, true},
		{"windows root forward slash", "c:/", true},
		{"windows root bare", "C:", true},
		{"windows root prefixed", "/C:", true},
		{"windows root prefixed slash", "/c:/", true},
		{"windows root prefixed backslash", `/C:\`, true},
		{"windows non-root", `C:\Users\wentf`, false},
		{"windows non-root prefixed", "/C:/Users", false},
		{"windows D root", `D:\`, true},
		{"windows Z root", `Z:\`, true},
		{"windows C forward slash", "C:/", true},
		{"windows C prefixed slash", "/C:/", true},
		{"windows c lower backslash", `c:\`, true},
		{"windows c lower forward slash", "c:/", true},
		{"windows c lower prefixed slash", "/c:/", true},
		{"posix backslash relative", `\tmp\foo`, false},
		{"posix with backslash", `/tmp/foo\bar`, false},
		{"windows collapsed to root", `C:\Users\..\..`, true},
		{"windows prefixed collapsed to root", `/C:/Users/../..`, true},
		{"windows cross drive attempt is not root", `C:\..\D:\foo`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsRootPath(tt.in)
			if got != tt.want {
				t.Errorf("IsRootPath(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
