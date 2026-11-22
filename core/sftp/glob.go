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
	entries, err := c.SFTPClient().ReadDir(parent.String())
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, nil
	}

	seen := make(map[string]struct{}, len(entries))
	matches := make([]RemotePath, 0, len(entries))
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if entry == nil {
			return nil, fmt.Errorf("glob %q: %w: missing file metadata", parent.String(), ErrInvalidRemoteName)
		}
		entryName, nameErr := ParseRemoteName(entry.Name())
		if nameErr != nil {
			return nil, fmt.Errorf("glob %q: unsafe remote filename %q: %w", parent.String(), entry.Name(), nameErr)
		}
		rawName := entryName.String()
		if _, dup := seen[rawName]; dup {
			return nil, fmt.Errorf("glob %q: duplicate remote directory entry %q", parent.String(), rawName)
		}
		seen[rawName] = struct{}{}

		matched, matchErr := path.Match(filePattern, rawName)
		if matchErr != nil {
			return nil, matchErr
		}
		if !matched {
			continue
		}
		child := parent.Join(entryName)
		rels, relErr := child.RelativeTo(parent)
		if relErr != nil || len(rels) != 1 || !rels[0].Equal(entryName) {
			return nil, fmt.Errorf("glob %q: match %q escapes parent directory", parent.String(), child.String())
		}
		matches = append(matches, child)
	}
	return matches, nil
}
