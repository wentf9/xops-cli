package remotefile

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"slices"
	"strings"

	pkgsftp "github.com/pkg/sftp"
	"github.com/wentf9/xops-cli/core/sftp"
)

// PathInspection holds read-only SFTP path canonicalization metadata resolved
// before guardrail authorization and execution.
type PathInspection struct {
	// CanonicalPath is the SFTP RealPath-resolved canonical path (or canonical
	// nearest existing ancestor joined with the remaining clean suffix when the
	// target itself does not exist or is a dangling symlink).
	CanonicalPath string
	// ParentPath is the canonical RealPath of path.Dir(target) (or its nearest
	// existing ancestor + remaining suffix) when target is not a root path.
	ParentPath string
	// ExtraPaths lists additional canonical paths discovered during inspection
	// (such as the resolved target of a dangling symbolic link).
	ExtraPaths []string
	// Exists reports whether Lstat succeeded on the target path.
	Exists bool
	// IsDir reports whether Stat (following symlinks) resolved to a directory.
	IsDir bool
	// IsSymlink reports whether Lstat reported a symbolic link at the target.
	IsSymlink bool
}

// ValidateResolvedRealPath validates a path returned by an SFTP server's
// RealPath RPC, rejecting relative, control-tainted, or anomalous Win32 paths.
func ValidateResolvedRealPath(raw string) (string, error) {
	return validateResolvedRealPath(raw)
}

// InspectPath resolves canonical remote path metadata over SFTP using only
// RealPath, Lstat, Stat, and ReadLink. It never reads or modifies file data.
func InspectPath(ctx context.Context, client Client, remotePath string) (inspection PathInspection, retErr error) {
	retErr = client.Do(ctx, func(c *pkgsftp.Client) error {
		var err error
		inspection, err = inspectRemotePathClient(c, remotePath)
		return err
	})
	return inspection, retErr
}

// InspectPathWithClient performs read-only canonicalization on an already-open
// *pkgsftp.Client.
func InspectPathWithClient(c *pkgsftp.Client, remotePath string) (PathInspection, error) {
	return inspectRemotePathClient(c, remotePath)
}

// ResolveCanonicalParent resolves the canonical directory path of dir on c via
// RealPath, walking to the nearest existing ancestor when dir does not yet
// exist.
func ResolveCanonicalParent(c *pkgsftp.Client, dir string) (string, error) {
	resolved, _, err := resolveNearestCanonicalPath(c, dir)
	return resolved, err
}

func validateInspectInputPath(raw string) (string, error) {
	if _, err := sftp.ParseRemotePath(raw); err != nil {
		return "", fmt.Errorf("invalid remote path: %w", err)
	}
	if err := ValidateWindowsDrivePath(raw); err != nil {
		return "", fmt.Errorf("invalid remote path: %w", err)
	}
	norm := NormalizeSFTPPath(raw)
	parsed, err := sftp.ParseRemotePath(norm)
	if err != nil || !parsed.IsAbs() {
		return "", fmt.Errorf("invalid remote path: %w", sftp.ErrInvalidRemotePath)
	}
	if err := ValidateWindowsDrivePath(parsed.String()); err != nil {
		return "", fmt.Errorf("invalid remote path: %w", err)
	}
	return parsed.String(), nil
}

func isRemoteNotExist(err error) bool {
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, pkgsftp.ErrSSHFxNoSuchFile) {
		return true
	}
	return false
}

func resolveNearestCanonicalPath(c *pkgsftp.Client, cleanPath string) (string, bool, error) {
	rawCanon, err := c.RealPath(cleanPath)
	if err == nil {
		canon, valErr := validateResolvedRealPath(rawCanon)
		if valErr != nil {
			return "", false, fmt.Errorf("resolve remote path %q: %w", cleanPath, valErr)
		}
		return canon, true, nil
	}
	if !isRemoteNotExist(err) {
		return "", false, fmt.Errorf("resolve remote path %q: %w", cleanPath, err)
	}

	var suffix []string
	cur := cleanPath
	for {
		if IsRootPath(cur) {
			rawRoot, rootErr := c.RealPath(cur)
			if rootErr != nil {
				return cleanPath, false, nil
			}
			rootCanon, valErr := validateResolvedRealPath(rawRoot)
			if valErr != nil {
				return "", false, fmt.Errorf("resolve remote root %q: %w", cur, valErr)
			}
			return joinCanonicalSuffix(rootCanon, suffix)
		}
		parent := path.Dir(cur)
		base := path.Base(cur)
		if parent == cur {
			return cleanPath, false, nil
		}
		suffix = append(suffix, base)
		cur = parent
		rawAnc, ancErr := c.RealPath(cur)
		if ancErr == nil {
			ancCanon, valErr := validateResolvedRealPath(rawAnc)
			if valErr != nil {
				return "", false, fmt.Errorf("resolve remote ancestor %q: %w", cur, valErr)
			}
			return joinCanonicalSuffix(ancCanon, suffix)
		}
		if !isRemoteNotExist(ancErr) {
			return "", false, fmt.Errorf("resolve remote ancestor %q: %w", cur, ancErr)
		}
	}
}

func joinCanonicalSuffix(base string, reversedSuffix []string) (string, bool, error) {
	parts := make([]string, 0, len(reversedSuffix)+1)
	parts = append(parts, base)
	for i := len(reversedSuffix) - 1; i >= 0; i-- {
		parts = append(parts, reversedSuffix[i])
	}
	joined := path.Join(parts...)
	if err := ValidateWindowsDrivePath(joined); err != nil {
		return "", false, fmt.Errorf("resolve canonical remote path: %w", err)
	}
	parsed, err := sftp.ParseRemotePath(joined)
	if err != nil || !parsed.IsAbs() {
		return "", false, fmt.Errorf("resolve canonical remote path: %w", sftp.ErrInvalidRemotePath)
	}
	if err := ValidateWindowsDrivePath(parsed.String()); err != nil {
		return "", false, fmt.Errorf("resolve canonical remote path: %w", err)
	}
	return NormalizeSFTPPath(parsed.String()), false, nil
}

func inspectRemotePathClient(c *pkgsftp.Client, remotePath string) (PathInspection, error) {
	cleanPath, err := validateInspectInputPath(remotePath)
	if err != nil {
		return PathInspection{}, err
	}
	res := PathInspection{}

	info, lstatErr := c.Lstat(cleanPath)
	if lstatErr == nil {
		res.Exists = true
		res.IsSymlink = info.Mode()&os.ModeSymlink != 0
	} else if !isRemoteNotExist(lstatErr) {
		return PathInspection{}, fmt.Errorf("inspect remote path %q: %w", cleanPath, lstatErr)
	}

	if !IsRootPath(cleanPath) {
		parent := path.Dir(cleanPath)
		parentCanon, _, parentErr := resolveNearestCanonicalPath(c, parent)
		if parentErr != nil {
			return PathInspection{}, parentErr
		}
		res.ParentPath = parentCanon
	}

	canon, exact, canonErr := resolveNearestCanonicalPath(c, cleanPath)
	if canonErr != nil {
		return PathInspection{}, canonErr
	}
	res.CanonicalPath = canon

	if res.IsSymlink && !exact {
		if err := appendDanglingSymlinkTarget(c, cleanPath, &res); err != nil {
			return PathInspection{}, err
		}
	}

	if st, statErr := c.Stat(cleanPath); statErr == nil {
		res.IsDir = st.IsDir()
	} else if !isRemoteNotExist(statErr) && !res.IsSymlink {
		return PathInspection{}, fmt.Errorf("stat remote path %q: %w", cleanPath, statErr)
	}

	return res, nil
}

// appendDanglingSymlinkTarget resolves the target of a dangling symlink via
// ReadLink so ProtectedPaths still catches links pointing into protected dirs.
func appendDanglingSymlinkTarget(c *pkgsftp.Client, cleanPath string, res *PathInspection) error {
	linkTarget, rlErr := c.ReadLink(cleanPath)
	if rlErr != nil || linkTarget == "" {
		return nil
	}
	candidate := linkTarget
	if !strings.HasPrefix(candidate, "/") {
		parentDir := res.ParentPath
		if parentDir == "" {
			parentDir = path.Dir(cleanPath)
		}
		candidate = path.Join(parentDir, candidate)
	}
	validTarget, validErr := validateInspectInputPath(candidate)
	if validErr != nil {
		if candidate != "" && !slices.Contains(res.ExtraPaths, candidate) {
			res.ExtraPaths = append(res.ExtraPaths, candidate)
		}
		return nil
	}
	resolvedTarget, _, targetErr := resolveNearestCanonicalPath(c, validTarget)
	if targetErr != nil {
		return targetErr
	}
	if resolvedTarget != "" && resolvedTarget != res.CanonicalPath && !slices.Contains(res.ExtraPaths, resolvedTarget) {
		res.ExtraPaths = append(res.ExtraPaths, resolvedTarget)
	}
	return nil
}
