//go:build (linux || darwin || windows) && (amd64 || arm64)

package kdfhelper

import (
	"context"
	"errors"
	"time"
)

func withCause(err, cause error) error {
	if cause != nil && !errors.Is(err, cause) {
		return errors.Join(err, cause)
	}
	return err
}

func processTimeout(ctx context.Context, configured time.Duration) (time.Duration, error) {
	if err := context.Cause(ctx); err != nil {
		return 0, err
	}
	if configured < 0 {
		return 0, ErrProtocol
	}
	if configured > 0 {
		return configured, nil
	}
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0, context.DeadlineExceeded
		}
		return remaining, nil
	}
	return 30 * time.Second, nil
}

func processResponse(data []byte, processErr error) ([]byte, error) {
	response, err := ParseResponse(data)
	if err != nil {
		return nil, errors.Join(err, processErr)
	}
	if response.Status != Success {
		response.Zero()
		kind := ErrProcess
		switch response.Status {
		case InvalidRequest:
			kind = ErrProtocol
		case UnsupportedVersion:
			kind = ErrUnsupported
		case ResourceFailure:
			kind = ErrResource
		}
		return nil, errors.Join(kind, processErr)
	}
	if processErr != nil {
		response.Zero()
		return nil, errors.Join(ErrProcess, processErr)
	}
	return response.Key, nil
}
