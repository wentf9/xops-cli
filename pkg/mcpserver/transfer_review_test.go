package mcpserver

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	pkgsftp "github.com/pkg/sftp"
	sshfx "github.com/pkg/sftp/v2/encoding/ssh/filexfer"
	"github.com/wentf9/xops-cli/pkg/mcpserver/transfer"
)

type diskCreationWriter struct{ directory string }

func (w diskCreationWriter) Filewrite(req *pkgsftp.Request) (io.WriterAt, error) {
	flags := req.Pflags()
	if !flags.Creat || !flags.Excl || !flags.Write {
		return nil, errors.New("exclusive write flags missing")
	}
	// Require private permissions in the initial OPEN on every platform.
	// Checking only a later chmod would miss an already-open public handle.
	if len(req.Attrs) != 4 || binary.BigEndian.Uint32(req.Attrs) != 0600 {
		return nil, errors.New("initial OPEN must request mode 0600")
	}
	// Model a POSIX target with umask 022 where the host supports those bits.
	mode := os.FileMode(binary.BigEndian.Uint32(req.Attrs))
	file, err := os.OpenFile(filepath.Join(w.directory, "temporary"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode&^0022)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err == nil {
		err = checkDiskCreationPermissions(info)
	}
	if err != nil {
		return nil, errors.Join(err, file.Close())
	}
	return file, nil
}

func checkDiskCreationPermissions(info os.FileInfo) error {
	if !info.Mode().IsRegular() {
		return errors.New("temporary is not a regular file")
	}
	// Windows FileMode reports the read-only attribute as 0444/0666, not ACLs
	// or POSIX permissions. The wire-level OPEN assertion above still applies.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		return errors.New("temporary POSIX permissions are not 0600")
	}
	return nil
}
func TestUploadTemporaryPrivateAtCreation(t *testing.T) {
	dir := t.TempDir()
	handlers := pkgsftp.InMemHandler()
	handlers.FilePut = diskCreationWriter{dir}
	r, _, _ := startTransferRuntime(t, nil, handlers)
	remote, err := r.openTransferRemote(t.Context(), "files")
	if err != nil {
		t.Fatal(err)
	}
	defer closeTransferTestResource(t, remote)
	confirmed := false
	data := []byte("private upload contents")
	result, err := remote.Upload(t.Context(), "/temporary", bytes.NewReader(data), int64(len(data)), func() error {
		info, err := os.Stat(filepath.Join(dir, "temporary"))
		if err != nil {
			return err
		}
		if err := checkDiskCreationPermissions(info); err != nil {
			return err
		}
		confirmed = true
		return nil
	}, nil)
	if err != nil || !confirmed || !result.Created {
		t.Fatalf("private create: %+v %v", result, err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "temporary"))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("upload content: %q %v", got, err)
	}
	result, err = remote.Upload(t.Context(), "/temporary", bytes.NewReader(data), int64(len(data)), nil, nil)
	if err == nil || result.Created {
		t.Fatal("exclusive creation overwrote a collision")
	}
}

func TestContinuousPartialUploadIsNotIdle(t *testing.T) {
	_, server, client := startTransferRuntime(t, func(o *HTTPOptions) { o.StreamIdle = transferTestIdle }, pkgsftp.InMemHandler())
	data := bytes.Repeat([]byte("x"), 80)
	p := prepareTransferTest(t, client, "xops_prepare_upload", uploadBoundaryInput("trickle", "/destination", data))
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	reader, writer := io.Pipe()
	defer closeTransferTestResource(t, reader)
	done := make(chan error, 1)
	go func() {
		defer closeTransferTestResource(t, writer)
		// The body spans more than one idle window, while individual reads
		// leave enough scheduling margin for Windows race builds.
		timer := time.NewTicker(40 * time.Millisecond)
		defer timer.Stop()
		for _, b := range data {
			select {
			case <-ctx.Done():
				done <- ctx.Err()
				return
			case <-timer.C:
			}
			if _, err := writer.Write([]byte{b}); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	// Closing the reader on every path also releases a blocked pipe writer.
	defer func() {
		closeTransferTestResource(t, reader)
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-ctx.Done():
			t.Error("trickle writer did not stop")
		}
	}()
	req, err := http.NewRequestWithContext(ctx, p.Method, p.URL, reader)
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = int64(len(data))
	for k, v := range p.Headers {
		req.Header.Set(k, v)
	}
	start := time.Now()
	response, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTransferTestResource(t, response.Body)
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("continuous partial reads expired: %d %s", response.StatusCode, body)
	}
	if time.Since(start) < transferTestIdle {
		t.Fatal("partial upload did not cross an idle window")
	}
	status := transferTestStatus(t, server, p)
	if status.State != transfer.Completed || status.Bytes != int64(len(data)) {
		t.Fatalf("trickle upload: %+v", status)
	}
}

type largeRecoveryRemote struct {
	transferRemote
	size  int64
	reads int
}

func (r *largeRecoveryRemote) Inspect(context.Context, string, bool, bool) (remoteFileMetadata, error) {
	return remoteFileMetadata{Path: "/large", Size: r.size}, nil
}
func (r *largeRecoveryRemote) Download(_ context.Context, _ remoteFileMetadata, _ io.Writer, _ func(int64) error) (streamResult, error) {
	r.reads++
	return streamResult{Bytes: r.size, SHA256: strings.Repeat("a", 64)}, nil
}
func (*largeRecoveryRemote) Close() error { return nil }
func TestRecoveryVerificationUsesConfiguredFileLimit(t *testing.T) {
	for _, limit := range []int64{20 << 30, 10 << 30, 1 << 20} {
		r := &Runtime{provider: runtimeTestProvider("files")}
		remote := &largeRecoveryRemote{size: 11 << 30}
		r.transferDial = func(context.Context, string) (transferRemote, error) { return remote, nil }
		id, target, err := r.resolveTransferTarget("files")
		if err != nil {
			t.Fatal(err)
		}
		record := transfer.Record{State: transfer.Unknown, Spec: transfer.Spec{NodeID: id, TargetID: target, RemotePath: "/large", Size: remote.size, SHA256: strings.Repeat("a", 64)}}
		entry, err := recoverTransferRecord(t.Context(), r, nil, record, RecoveryOptions{Verify: true, MaxFileBytes: limit})
		if limit >= remote.size {
			if err != nil || !entry.MatchesExpected || remote.reads != 1 || entry.Task.State != transfer.Unknown {
				t.Fatalf("configured large-file verification: %+v %v", entry, err)
			}
		} else if err == nil || remote.reads != 0 {
			t.Fatalf("verification bypassed size cap %d: %v", limit, err)
		}
	}
}

type dataAndEOFReader struct{ data []byte }

func (r dataAndEOFReader) Read(p []byte) (int, error) { return copy(p, r.data), io.EOF }
func TestPartialCopyHandlesDataWithEOFAndShortInput(t *testing.T) {
	for _, size := range []int64{3, 4} {
		var output bytes.Buffer
		n, _, err := copyTransferStream(t.Context(), &output, dataAndEOFReader{[]byte("abc")}, size, nil)
		if size == 3 {
			if err != nil || n != 3 || output.String() != "abc" {
				t.Fatalf("final data+EOF lost: %d %v", n, err)
			}
		} else if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("short source accepted: %v", err)
		}
	}
}

func TestUploadTemporaryRejectsUnsafeCreationRequests(t *testing.T) {
	for _, tc := range []struct {
		name  string
		mode  *uint32
		flags uint32
	}{
		{name: "missing permissions", flags: sshfx.FlagWrite | sshfx.FlagCreate | sshfx.FlagExclusive},
		{name: "public read", mode: new(uint32(0644)), flags: sshfx.FlagWrite | sshfx.FlagCreate | sshfx.FlagExclusive},
		{name: "public write", mode: new(uint32(0666)), flags: sshfx.FlagWrite | sshfx.FlagCreate | sshfx.FlagExclusive},
		{name: "not exclusive", mode: new(uint32(0600)), flags: sshfx.FlagWrite | sshfx.FlagCreate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory := t.TempDir()
			request := &pkgsftp.Request{Filepath: "/temporary", Flags: tc.flags}
			if tc.mode != nil {
				request.Attrs = make([]byte, 4)
				binary.BigEndian.PutUint32(request.Attrs, *tc.mode)
			}
			handle, err := (diskCreationWriter{directory}).Filewrite(request)
			if handle != nil {
				if closer, ok := handle.(io.Closer); ok {
					closeTransferTestResource(t, closer)
				}
			}
			if err == nil {
				t.Fatal("unsafe creation request accepted")
			}
			entries, err := os.ReadDir(directory)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatal("unsafe request created a file before being rejected")
			}
		})
	}
}
