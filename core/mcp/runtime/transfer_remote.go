package runtime

import (
	"context"
	"github.com/wentf9/xops-cli/core/mcp/remotefile"
	"io"
)

type remoteFileMetadata = remotefile.Metadata
type streamResult = remotefile.StreamResult
type commitResult = remotefile.CommitResult
type transferRemote = remotefile.Remote

func copyTransferStream(ctx context.Context, dst io.Writer, src io.Reader, size int64, progress func(int64) error) (int64, string, error) {
	return remotefile.CopyStream(ctx, dst, src, size, progress)
}
