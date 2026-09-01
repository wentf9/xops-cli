package ssh

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/wentf9/xops-cli/pkg/logger"
)

func closeResource(closer io.Closer, resource string) error {
	if closer == nil {
		return nil
	}
	if err := closer.Close(); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
		return fmt.Errorf("close %s failed: %w", resource, err)
	}
	return nil
}

func joinResourceCloseError(target *error, closer io.Closer, resource string) {
	*target = errors.Join(*target, closeResource(closer, resource))
}

func debugCloseResource(l logger.DebugLogger, closer io.Closer, resource string) {
	if err := closeResource(closer, resource); err != nil {
		if l == nil {
			l = logger.NopLogger
		}
		l.Debugf("%v", err)
	}
}

func copySessionOutput(stdout, stderr io.Reader, stdoutWriter, stderrWriter io.Writer) func() error {
	errCh := make(chan error, 2)
	var wg sync.WaitGroup

	copyOne := func(name string, dst io.Writer, src io.Reader) {
		wg.Go(func() {
			_, err := io.Copy(dst, src)
			if err != nil {
				err = fmt.Errorf("copy SSH %s failed: %w", name, err)
			}
			errCh <- err
		})
	}
	copyOne("stdout", stdoutWriter, stdout)
	copyOne("stderr", stderrWriter, stderr)

	return func() error {
		wg.Wait()
		return errors.Join(<-errCh, <-errCh)
	}
}
