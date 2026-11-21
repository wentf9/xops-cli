//go:build windows

package ssh

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/wentf9/xops-cli/core/fsx"
	"github.com/wentf9/xops-cli/core/verdict"
	"github.com/wentf9/xops-cli/core/winsec"
	"golang.org/x/sys/windows"
)

// openGlobalKnownHostsFile opens a read-only Windows global ssh_known_hosts
// file without following reparse points and verifies its ACL directly on the
// opened handle at read time via winsec.OpenSecureSystemSSHFileByHandle.
//
// Paths under %ProgramData% require strict SYSTEM/Administrators ownership and
// DACL (currSID == nil) plus verified parent/ancestor directories; explicit
// custom paths outside %ProgramData% verify non-reparse handle attributes and
// ACLs trusting only current user / SYSTEM / Administrators.
func openGlobalKnownHostsFile(filename string, limit int64) (io.ReadCloser, error) {
	if limit <= 0 {
		return nil, fsx.ErrInvalidLimit
	}
	absPath, err := filepath.Abs(filepath.Clean(filename))
	if err != nil {
		return nil, err
	}

	var (
		currSID            *windows.SID
		verifyParentGlobal bool
	)
	underProgramData, pdErr := isUnderWindowsProgramData(absPath)
	if pdErr != nil {
		return nil, fmt.Errorf("resolve ProgramData trust scope for %q: %w", filename, pdErr)
	}
	if underProgramData.Allowed() {
		verifyParentGlobal = true
	} else {
		currSID, err = winsec.CurrentProcessUserSID()
		if err != nil {
			return nil, err
		}
	}

	f, err := winsec.OpenSecureSystemSSHFileByHandle(absPath, currSID, verifyParentGlobal)
	if err != nil {
		return nil, err
	}
	st, statErr := f.Stat()
	if statErr != nil || !st.Mode().IsRegular() || st.Size() > limit {
		_ = f.Close()
		if statErr != nil {
			return nil, statErr
		}
		if !st.Mode().IsRegular() {
			return nil, fmt.Errorf("%w: %q", fsx.ErrNonRegular, filename)
		}
		return nil, fmt.Errorf("%w: %q exceeds %d bytes", fsx.ErrTooLarge, filename, limit)
	}
	return f, nil
}

func isUnderWindowsProgramData(absPath string) (verdict.Verdict, error) {
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DONT_VERIFY)
	if err != nil {
		return verdict.Deny, err
	}
	cleanPD := filepath.Clean(strings.TrimSpace(programData))
	if cleanPD == "" {
		return verdict.Deny, fmt.Errorf("empty ProgramData known folder path")
	}
	if strings.EqualFold(absPath, cleanPD) {
		return verdict.Allow, nil
	}
	prefix := cleanPD
	if !strings.HasSuffix(prefix, `\`) {
		prefix += `\`
	}
	if len(absPath) > len(prefix) && strings.EqualFold(absPath[:len(prefix)], prefix) {
		return verdict.Allow, nil
	}
	return verdict.Deny, nil
}
