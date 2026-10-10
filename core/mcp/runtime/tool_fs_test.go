package runtime

import (
	"context"
	"testing"
)

func TestFSRmAndCpInputValidation(t *testing.T) {
	r := &Runtime{}
	ctx := context.Background()

	// fsRmHandler validation
	if _, _, err := r.fsRmHandler(ctx, nil, FSRmInput{}); err == nil {
		t.Fatal("expected error for empty FSRmInput")
	}
	if _, _, err := r.fsRmHandler(ctx, nil, FSRmInput{NodeID: "node"}); err == nil {
		t.Fatal("expected error for missing path in FSRmInput")
	}
	if _, _, err := r.fsRmHandler(ctx, nil, FSRmInput{Path: "/path"}); err == nil {
		t.Fatal("expected error for missing nodeID in FSRmInput")
	}

	// fsCpHandler validation
	if _, _, err := r.fsCpHandler(ctx, nil, FSCpInput{}); err == nil {
		t.Fatal("expected error for empty FSCpInput")
	}
	if _, _, err := r.fsCpHandler(ctx, nil, FSCpInput{NodeID: "node", Src: "/src"}); err == nil {
		t.Fatal("expected error for missing dest in FSCpInput")
	}
	if _, _, err := r.fsCpHandler(ctx, nil, FSCpInput{NodeID: "node", Dest: "/dest"}); err == nil {
		t.Fatal("expected error for missing src in FSCpInput")
	}
	if _, _, err := r.fsCpHandler(ctx, nil, FSCpInput{Src: "/src", Dest: "/dest"}); err == nil {
		t.Fatal("expected error for missing nodeID in FSCpInput")
	}
}

func TestIsRootEquivalentPath(t *testing.T) {
	rootCases := []string{
		"/",
		"//",
		"///",
		"/.",
		"/..",
		"//..",
		"/a/..",
		"/a/b/../../",
		".",
		"..",
		"./",
		"../",
		"a/..",
		"a/b/../..",
		"",
		"   ",
		"\\",
		"\\\\",
		"\\a\\..",
		"C:",
		"C:\\",
		"C:/",
		"c:\\",
		"c:/",
		"C:\\\\",
		"C://",
		"/C:/",
		"/c:/",
		"/C:",
		"/c:",
		"C:\\..",
		"C:/..",
		"C:\\a\\..",
		"C:/a/..",
		"C:\\.",
		"C:/.",
		"/C:/..",
		"/C:/a/..",
	}

	for _, tc := range rootCases {
		if !isRootEquivalentPath(tc) {
			t.Errorf("expected isRootEquivalentPath(%q) to be true, got false", tc)
		}
	}

	safeCases := []string{
		"/tmp",
		"/home/user",
		"/etc/hosts",
		"relative/path",
		"file.txt",
		"C:/Users",
		"C:\\Windows\\System32",
		"/c:/Users",
		"C:foo",
		"/a:b",
		"a/b",
	}

	for _, tc := range safeCases {
		if isRootEquivalentPath(tc) {
			t.Errorf("expected isRootEquivalentPath(%q) to be false, got true", tc)
		}
	}
}
