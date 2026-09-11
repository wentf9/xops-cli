//go:build windows

package vaultsys

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsPrivateACLRejectsPublicRead(t *testing.T) {
	root := t.TempDir()
	parent, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := parent.Close(); err != nil {
			t.Error(err)
		}
	}()
	fd, err := Openat(int(parent.Fd()), "private", O_RDWR|O_CREAT|O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := windows.CloseHandle(windows.Handle(fd)); err != nil {
			t.Error(err)
		}
	}()
	var st Stat_t
	if err := Fstat(fd, &st); err != nil {
		t.Fatal(err)
	}
	if st.Mode != S_IFREG|0600 || st.Uid != ^uint32(0) {
		t.Fatal("new file does not have private owner/ACL")
	}
	sid, err := currentSID()
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + sid + ")(A;;FR;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(filepath.Join(root, "private"), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	if err := Fstat(fd, &st); err != nil && !errors.Is(err, os.ErrPermission) {
		t.Fatal(err)
	}
	if st.Mode == S_IFREG|0600 {
		t.Fatal("public-read ACL accepted as private")
	}
}

func TestWindowsDirectoryDotOpensForEnumeration(t *testing.T) {
	root, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	}()
	fd, err := Openat(int(root.Fd()), ".", O_RDONLY|O_DIRECTORY|O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	directory := os.NewFile(uintptr(fd), "directory-enumeration")
	defer func() {
		if err := directory.Close(); err != nil {
			t.Error(err)
		}
	}()
	entries, err := directory.ReadDir(-1)
	if err != nil || len(entries) != 0 {
		t.Fatalf("directory enumeration: %v", err)
	}
	var original, reopened Stat_t
	if err := Fstat(int(root.Fd()), &original); err != nil {
		t.Fatal(err)
	}
	if err := Fstat(fd, &reopened); err != nil {
		t.Fatal(err)
	}
	if original.Ino != reopened.Ino || original.Dev != reopened.Dev {
		t.Fatal("dot opened a different directory")
	}
}
