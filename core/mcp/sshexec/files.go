package sshexec

import (
	"context"
	"io"

	pkgsftp "github.com/pkg/sftp"
	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/sftp"
)

// Every I/O entry intersects its caller context with the immutable permit.
// In particular a commit requires a separately admitted commit session rather
// than extending a cancelled streaming permit with a longer context.
type fileSession struct {
	*sftp.Client
	backend *Backend
	permit  ports.Permit
	phases  []ports.Phase
	release func() error
}

func (s *fileSession) Close() error { return s.release() }
func (s *fileSession) Do(ctx context.Context, operation func(*pkgsftp.Client) error) error {
	work, cancel, err := s.backend.work(ctx, s.permit, s.phases...)
	if err != nil {
		return err
	}
	defer cancel()
	return s.Client.Do(work, operation)
}
func (s *fileSession) Upload(ctx context.Context, local, remote string, progress sftp.ProgressCallback) error {
	work, cancel, err := s.backend.work(ctx, s.permit, s.phases...)
	if err != nil {
		return err
	}
	defer cancel()
	return s.Client.Upload(work, local, remote, progress)
}
func (s *fileSession) Download(ctx context.Context, remote, local string, progress sftp.ProgressCallback) error {
	work, cancel, err := s.backend.work(ctx, s.permit, s.phases...)
	if err != nil {
		return err
	}
	defer cancel()
	return s.Client.Download(work, remote, local, progress)
}
func (s *fileSession) CreatePrivateExclusive(ctx context.Context, name string, write func(io.Writer) error) (bool, bool, error) {
	work, cancel, err := s.backend.work(ctx, s.permit, s.phases...)
	if err != nil {
		return false, false, err
	}
	defer cancel()
	return s.Client.CreatePrivateExclusive(work, name, write)
}
