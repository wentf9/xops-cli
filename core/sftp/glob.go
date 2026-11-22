package sftp

import (
	"cmp"
	"context"
	"fmt"
	"path"
	"slices"
	"strings"
)

// Glob expands a POSIX remote glob pattern over SFTP while validating every
// directory entry returned by the server with ParseRemoteName and enforcing
// strict child containment beneath each matched parent directory. Cancellation
// interrupts this SFTP subsystem, so the client must not be reused afterwards.
func (c *Client) Glob(ctx context.Context, pattern string) ([]string, error) {
	if c == nil || c.SFTPClient() == nil {
		return nil, fmt.Errorf("sftp client is nil")
	}
	remotePattern, err := ParseRemotePath(pattern)
	if err != nil {
		return nil, err
	}
	var matchedPaths []RemotePath
	err = runInterruptibleOperation(ctx, c.interruptTransfers, func() error {
		var globErr error
		matchedPaths, globErr = c.globPaths(ctx, remotePattern)
		return globErr
	})
	if err != nil {
		return nil, err
	}
	if len(matchedPaths) == 0 {
		return nil, nil
	}
	out := make([]string, len(matchedPaths))
	for i, p := range matchedPaths {
		out[i] = p.String()
	}
	return out, nil
}

func hasGlobMeta(p string) bool {
	return strings.ContainsAny(p, "\\*?[")
}

func cleanGlobDir(dir string) string {
	switch dir {
	case "":
		return "."
	case "/":
		return "/"
	default:
		return strings.TrimSuffix(dir, "/")
	}
}

func (c *Client) globPaths(ctx context.Context, pattern RemotePath) ([]RemotePath, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !pattern.IsValid() {
		return nil, fmt.Errorf("%w: remote glob pattern is invalid", ErrInvalidRemotePath)
	}
	patStr := pattern.String()
	if !hasGlobMeta(patStr) {
		_, err := c.SFTPClient().Lstat(patStr)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			return nil, nil
		}
		return []RemotePath{pattern}, nil
	}

	dirRaw, filePattern := path.Split(patStr)
	if _, err := path.Match(filePattern, ""); err != nil {
		return nil, err
	}
	dirStr := cleanGlobDir(dirRaw)
	if dirStr == patStr {
		return nil, path.ErrBadPattern
	}
	dirPath, err := ParseRemotePath(dirStr)
	if err != nil {
		return nil, err
	}

	var parentDirs []RemotePath
	if !hasGlobMeta(dirPath.String()) {
		parentDirs = []RemotePath{dirPath}
	} else {
		parentDirs, err = c.globPaths(ctx, dirPath)
		if err != nil {
			return nil, err
		}
	}

	var matches []RemotePath
	for _, parent := range parentDirs {
		dirMatches, dirErr := c.globDir(ctx, parent, filePattern)
		if dirErr != nil {
			return nil, dirErr
		}
		matches = append(matches, dirMatches...)
	}
	slices.SortFunc(matches, func(a, b RemotePath) int {
		return cmp.Compare(a.String(), b.String())
	})
	return matches, nil
}

func (c *Client) globDir(ctx context.Context, parent RemotePath, filePattern string) ([]RemotePath, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fi, err := c.SFTPClient().Stat(parent.String())
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, nil
	}
	if !fi.IsDir() {
		return nil, nil
	}
	entries, err := c.SFTPClient().ReadDirContext(ctx, parent.String())
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, nil
	}

	validated, err := validateRemoteDirEntries(ctx, parent, entries, "glob")
	if err != nil {
		return nil, err
	}
	matches := make([]RemotePath, 0, len(validated))
	for _, item := range validated {
		matched, matchErr := path.Match(filePattern, item.name.String())
		if matchErr != nil {
			return nil, matchErr
		}
		if !matched {
			continue
		}
		matches = append(matches, item.child)
	}
	return matches, nil
}
