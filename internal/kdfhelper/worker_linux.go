//go:build linux && amd64

package kdfhelper

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/sys/unix"
)

// ServeFiles is the private process entry. It accepts only bounded pipes and
// returns an exit code without logging, loading configuration or printing secrets.
func ServeFiles(in, out *os.File) (code int) {
	input, err := pollablePipe(in)
	if err != nil {
		return 1
	}
	defer func() {
		if err := input.Close(); err != nil {
			code = 1
		}
	}()
	output, err := pollablePipe(out)
	if err != nil {
		return 1
	}
	defer func() {
		if err := output.Close(); err != nil {
			code = 1
		}
	}()
	timeout := 30 * time.Second
	if value := os.Getenv("XOPS_INTERNAL_KDF_TIMEOUT"); value != "" {
		duration, err := time.ParseDuration(value)
		if err != nil || duration <= 0 {
			return 1
		}
		timeout = duration
	}
	deadline := time.Now().Add(timeout)
	if err := input.SetReadDeadline(deadline); err != nil {
		return 1
	}
	if err := output.SetWriteDeadline(deadline); err != nil {
		return 1
	}
	return serve(input, output)
}

func pollablePipe(f *os.File) (*os.File, error) {
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Mode()&os.ModeNamedPipe == 0 {
		return nil, ErrProtocol
	}
	fd, err := unix.FcntlInt(f.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, errors.Join(err, unix.Close(fd))
	}
	return os.NewFile(uintptr(fd), "private-kdf-pipe"), nil
}

func serve(in io.Reader, out io.Writer) int {
	b, err := io.ReadAll(io.LimitReader(in, MaxRequestBytes+1))
	defer clear(b)
	if err != nil || len(b) > MaxRequestBytes {
		return writeFailure(out, InvalidRequest)
	}
	req, err := ParseRequest(b)
	if err != nil {
		if len(b) >= 10 && string(b[:8]) == "XOPSKDFQ" && binary.BigEndian.Uint16(b[8:10]) != 1 {
			return writeFailure(out, UnsupportedVersion)
		}
		return writeFailure(out, InvalidRequest)
	}
	defer req.Zero()
	key := argon2.IDKey(req.Password, req.Salt[:], 3, 65536, 1, 32)
	defer clear(key)
	response, err := (Response{Status: Success, Key: key}).MarshalBinary()
	if err != nil {
		return 1
	}
	defer clear(response)
	n, err := out.Write(response)
	if err != nil || n != len(response) {
		return 1
	}
	return 0
}

func writeFailure(out io.Writer, status Status) int {
	b, err := (Response{Status: status}).MarshalBinary()
	if err != nil {
		return 1
	}
	if n, err := out.Write(b); err != nil || n != len(b) {
		return 1
	}
	return 1
}
