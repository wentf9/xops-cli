package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/wentf9/xops-cli/pkg/sftp"
)

// expandSCPRemotePath uses the SFTP login directory, normally the remote user's
// home. Resolve only the home prefix so new upload targets need not exist yet.
func expandSCPRemotePath(ctx context.Context, client *sftp.Client, remotePath string) (string, error) {
	if remotePath == "" {
		return ".", nil
	}
	if !strings.HasPrefix(remotePath, "~") {
		return remotePath, nil
	}
	if remotePath != "~" && !strings.HasPrefix(remotePath, "~/") {
		return "", fmt.Errorf("remote home expansion for %q is unsupported; use an absolute path", remotePath)
	}
	resolveCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	home, err := client.Cwd(resolveCtx)
	if err != nil {
		return "", fmt.Errorf("resolve remote home directory failed: %w", err)
	}
	if remotePath == "~" {
		return home, nil
	}
	// Preserve trailing slashes and path components; the remote server resolves
	// them, including any symbolic links in intermediate directories.
	return strings.TrimSuffix(home, "/") + remotePath[1:], nil
}
