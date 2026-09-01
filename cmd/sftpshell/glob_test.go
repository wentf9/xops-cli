package sftpshell

import (
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/pkg/i18n"
)

func TestHasWildcard(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"plain", "foo.txt", false},
		{"star", "*.txt", true},
		{"question", "f?o", true},
		{"class", "f[abc]o", true},
		{"escaped_star", "foo\\*.txt", false},
		{"escaped_question", "foo\\?", false},
		{"escaped_class", "foo\\[abc", false},
		{"trailing_backslash", "foo\\", false},
		{"star_in_middle", "/home/*/bin", true},
		{"dot_only", "foo.txt", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasWildcard(tt.in); got != tt.want {
				t.Errorf("hasWildcard(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestExpandLocal(t *testing.T) {
	if err := i18n.Init("zh"); err != nil {
		t.Fatalf("i18n.Init failed: %v", err)
	}
	dir := t.TempDir()
	for _, name := range []string{"a.go", "b.go", "c.txt"} {
		writeTestFile(t, filepath.Join(dir, name), nil)
	}
	s := &Shell{localCwd: dir}

	t.Run("star match sorted", func(t *testing.T) {
		got, err := s.expandLocal("*.go")
		if err != nil {
			t.Fatal(err)
		}
		sort.Strings(got)
		want := []string{filepath.Join(dir, "a.go"), filepath.Join(dir, "b.go")}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("no match error", func(t *testing.T) {
		_, err := s.expandLocal("*.md")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "未找到匹配项") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("no wildcard passthrough", func(t *testing.T) {
		got, err := s.expandLocal("a.go")
		if err != nil {
			t.Fatal(err)
		}
		want := []string{filepath.Join(dir, "a.go")}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("single char class match", func(t *testing.T) {
		got, err := s.expandLocal("[ab].go")
		if err != nil {
			t.Fatal(err)
		}
		sort.Strings(got)
		want := []string{filepath.Join(dir, "a.go"), filepath.Join(dir, "b.go")}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})
}

func TestClassifyGlobResult(t *testing.T) {
	if err := i18n.Init("zh"); err != nil {
		t.Fatalf("i18n.Init failed: %v", err)
	}
	tests := []struct {
		name         string
		pattern      string
		matches      []string
		expectSingle bool
		wantErr      bool
		wantLen      int
	}{
		{"empty matches", "*.x", nil, false, true, 0},
		{"single ok when expect single", "f?", []string{"foo"}, true, false, 1},
		{"multiple error when expect single", "*", []string{"a", "b"}, true, true, 0},
		{"multiple ok when not expect single", "*", []string{"a", "b"}, false, false, 2},
		{"single ok when not expect single", "f?", []string{"a"}, false, false, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := classifyGlobResult(tt.pattern, tt.matches, tt.expectSingle)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && len(got) != tt.wantLen {
				t.Errorf("got %d items, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestResolveMultiSrcLocal(t *testing.T) {
	if err := i18n.Init("zh"); err != nil {
		t.Fatalf("i18n.Init failed: %v", err)
	}

	t.Run("single src dst not dir", func(t *testing.T) {
		got, err := resolveMultiSrcLocal([]string{"/a/b.go"}, "/dst/b.go", false)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0] != "/dst/b.go" {
			t.Errorf("got %v", got)
		}
	})

	t.Run("single src dst is dir", func(t *testing.T) {
		got, err := resolveMultiSrcLocal([]string{"/a/b.go"}, "/dst", true)
		if err != nil {
			t.Fatal(err)
		}
		want := filepath.Join("/dst", "b.go")
		if len(got) != 1 || got[0] != want {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("multi src dst is dir", func(t *testing.T) {
		got, err := resolveMultiSrcLocal([]string{"/a/b.go", "/a/c.go"}, "/dst", true)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 {
			t.Errorf("got %d items, want 2", len(got))
		}
		want0 := filepath.Join("/dst", "b.go")
		want1 := filepath.Join("/dst", "c.go")
		if got[0] != want0 || got[1] != want1 {
			t.Errorf("got %v, want [%s, %s]", got, want0, want1)
		}
	})

	t.Run("multi src dst not dir error", func(t *testing.T) {
		_, err := resolveMultiSrcLocal([]string{"/a/b.go", "/a/c.go"}, "/dst", false)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("empty srcs error", func(t *testing.T) {
		_, err := resolveMultiSrcLocal(nil, "/dst", true)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func TestResolveMultiSrc(t *testing.T) {
	initTestI18n(t)

	t.Run("single src dst not dir", func(t *testing.T) {
		got, err := resolveMultiSrc([]string{"/a/b.go"}, "/dst/b.go", false)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0] != "/dst/b.go" {
			t.Errorf("got %v", got)
		}
	})

	t.Run("single src dst is dir uses forward slash", func(t *testing.T) {
		got, err := resolveMultiSrc([]string{"/a/b.go"}, "/dst", true)
		if err != nil {
			t.Fatal(err)
		}
		// SFTP 强制使用 / 分隔符
		want := "/dst/b.go"
		if len(got) != 1 || got[0] != want {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("multi src dst not dir error", func(t *testing.T) {
		_, err := resolveMultiSrc([]string{"/a/b.go", "/a/c.go"}, "/dst", false)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}
