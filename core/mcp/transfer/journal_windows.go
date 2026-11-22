//go:build windows

package transfer

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/wentf9/xops-cli/core/fsx"
	"github.com/wentf9/xops-cli/core/winsec"
	"golang.org/x/sys/windows"
)

func validateJournalEntryName(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return errors.New("invalid transfer metadata filename")
	}
	return nil
}

// evaluateOwnerOnlyRegularFileSecurity verifies that a regular disk file is not
// a reparse point or device, has a trusted owner (current user, SYSTEM, or
// Builtin\Administrators), has a non-nil DACL, and grants zero access bits to
// any untrusted principal.
func evaluateOwnerOnlyRegularFileSecurity(attrs uint32, ownerTrusted, hasDACL bool, aces []winsec.ParsedACE) bool {
	if !winsec.EvaluateAttributes(attrs, false) {
		return false
	}
	if !ownerTrusted || !hasDACL {
		return false
	}
	for _, ace := range aces {
		if !winsec.EvaluateOwnerOnlyACE(ace) {
			return false
		}
	}
	return true
}

func inspectWindowsDiskHandleAttributes(h windows.Handle, expectDir bool) (uint32, error) {
	if h == 0 || h == windows.InvalidHandle {
		return winsec.InvalidFileAttributes, fmt.Errorf("%w: invalid Windows handle", winsec.ErrInsecureControlDir)
	}
	fileType, err := windows.GetFileType(h)
	if err != nil || fileType != windows.FILE_TYPE_DISK {
		return winsec.InvalidFileAttributes, fmt.Errorf("%w: handle is not a disk object", winsec.ErrInsecureControlDir)
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return winsec.InvalidFileAttributes, fmt.Errorf("%w: query handle attributes: %w", winsec.ErrInsecureControlDir, err)
	}
	if !winsec.EvaluateAttributes(info.FileAttributes, expectDir) {
		return winsec.InvalidFileAttributes, fmt.Errorf("%w: handle is a reparse point, device, or unexpected file type", winsec.ErrInsecureControlDir)
	}
	return info.FileAttributes, nil
}

func verifyWindowsOwnerOnlyHandle(file *os.File, expectDir bool) error {
	if file == nil {
		return fmt.Errorf("%w: nil file handle", winsec.ErrInsecureControlDir)
	}
	defer runtime.KeepAlive(file)
	h := windows.Handle(file.Fd())
	attrs, err := inspectWindowsDiskHandleAttributes(h, expectDir)
	if err != nil {
		return err
	}
	currSID, err := winsec.CurrentProcessUserSID()
	if err != nil {
		return fmt.Errorf("query current Windows user SID: %w", err)
	}
	sd, err := winsec.GetSecurityInfoByHandle(h)
	if err != nil {
		return fmt.Errorf("%w: query security descriptor by handle: %w", winsec.ErrInsecureControlDir, err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("%w: query owner SID by handle: %w", winsec.ErrInsecureControlDir, err)
	}
	ownerTrusted := winsec.IsTrustedPrincipalSID(owner, currSID)
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("%w: handle has missing or nil DACL", winsec.ErrInsecureControlDir)
	}
	aces, ok := winsec.ParseACL(dacl, currSID)
	if !ok {
		return fmt.Errorf("%w: parse handle DACL failed", winsec.ErrInsecureControlDir)
	}
	if expectDir {
		if !winsec.EvaluateOwnerOnlyDirectorySecurity(attrs, ownerTrusted, true, aces) {
			return fmt.Errorf("%w: directory permits untrusted local access", winsec.ErrInsecureControlDir)
		}
		return nil
	}
	if !evaluateOwnerOnlyRegularFileSecurity(attrs, ownerTrusted, true, aces) {
		return fmt.Errorf("%w: file permits untrusted local access", winsec.ErrInsecureControlDir)
	}
	return nil
}

func createJournalDirectory(directory string) error {
	_, lstatErr := os.Lstat(directory)
	existed := lstatErr == nil
	if err := winsec.EnsureOwnerOnlyDirectory(directory); err != nil {
		if errors.Is(err, winsec.ErrInsecureControlDir) {
			return fmt.Errorf("transfer metadata directory must be a private directory, not a symbolic link: %w", err)
		}
		return fmt.Errorf("create transfer metadata directory: %w", err)
	}
	if !existed {
		absDir, err := filepath.Abs(filepath.Clean(directory))
		if err != nil {
			return fmt.Errorf("resolve transfer metadata directory: %w", err)
		}
		parent := filepath.Dir(absDir)
		if parent != absDir {
			if err := fsx.SyncDir(parent); err != nil {
				return err
			}
		}
	}
	return nil
}

func verifyJournalRoot(root *os.Root) error {
	dirFile, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("inspect transfer metadata directory: %w", err)
	}
	defer func() { _ = dirFile.Close() }()
	if err := verifyWindowsOwnerOnlyHandle(dirFile, true); err != nil {
		return fmt.Errorf("transfer metadata directory must be a private directory, not a symbolic link: %w", err)
	}
	return nil
}

func verifyRootPathMatchesHandle(root *os.Root) error {
	pinned, err := root.Stat(".")
	if err != nil {
		return fmt.Errorf("inspect pinned transfer metadata directory: %w", err)
	}
	current, err := os.Lstat(root.Name())
	if err != nil {
		return fmt.Errorf("inspect transfer metadata directory path: %w", err)
	}
	if !current.IsDir() || !os.SameFile(pinned, current) {
		return errors.New("transfer metadata directory must be a private directory, not a symbolic link")
	}
	return nil
}

func openJournalLockFile(root *os.Root, name string) (*os.File, error) {
	if err := validateJournalEntryName(name); err != nil {
		return nil, err
	}
	fullPath := filepath.Join(root.Name(), name)
	for range fsx.DefaultLockRetries {
		file, err := root.OpenFile(name, os.O_RDWR, 0600)
		if err == nil {
			return file, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if err := verifyRootPathMatchesHandle(root); err != nil {
			return nil, err
		}
		created, createErr := fsx.CreateExclusive(fullPath, fsx.OwnerOnlyPerm)
		if createErr == nil {
			return created, nil
		}
		if !errors.Is(createErr, os.ErrExist) {
			return nil, createErr
		}
	}
	return nil, fmt.Errorf("%w: open transfer metadata lock %q", fsx.ErrRetryExhausted, name)
}

func createJournalTempFile(root *os.Root, name string) (*os.File, error) {
	if err := validateJournalEntryName(name); err != nil {
		return nil, err
	}
	if err := verifyRootPathMatchesHandle(root); err != nil {
		return nil, err
	}
	file, err := fsx.CreateExclusive(filepath.Join(root.Name(), name), fsx.OwnerOnlyPerm)
	if err != nil {
		return nil, err
	}
	if err := checkJournalFile(root, file, name); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func checkJournalFilePrivacy(file *os.File, _ os.FileMode) error {
	if err := verifyWindowsOwnerOnlyHandle(file, false); err != nil {
		return fmt.Errorf("transfer metadata must be a private regular file: %w", err)
	}
	return nil
}

func replaceJournalFile(root *os.Root, source, destination string) error {
	if err := validateJournalEntryName(source); err != nil {
		return err
	}
	if err := validateJournalEntryName(destination); err != nil {
		return err
	}
	if err := verifyRootPathMatchesHandle(root); err != nil {
		return err
	}
	from, err := windows.UTF16PtrFromString(filepath.Join(root.Name(), source))
	if err != nil {
		return fmt.Errorf("encode temporary transfer metadata path: %w", err)
	}
	to, err := windows.UTF16PtrFromString(filepath.Join(root.Name(), destination))
	if err != nil {
		return fmt.Errorf("encode transfer metadata path: %w", err)
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return fmt.Errorf("replace transfer metadata: %w", err)
	}
	return nil
}
