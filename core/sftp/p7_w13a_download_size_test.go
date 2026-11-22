package sftp

import (
	"context"
	"errors"
	"math"
	"os"
	"testing"
	"time"
)

// TestP7W13a_AB13L1_DownloadTransferSizeRejectsNegativeRemoteSize verifies AB13-L1:
//   - (*Client).DownloadTransferSize fails closed with ErrInvalidRemoteSize when
//     a single non-directory remote file reports a negative wire size (< 0, i.e.
//     uint64 >= 1<<63).
//   - (*Client).DownloadTransferSize fails closed with ErrInvalidRemoteSize when
//     any regular file encountered during recursive directory walking reports a
//     negative wire size.
//   - Non-negative regular files and symlinks still return their exact (or
//     saturated MaxInt64) byte totals.
func TestP7W13a_AB13L1_DownloadTransferSizeRejectsNegativeRemoteSize(t *testing.T) {
	t.Run("single_regular_file_negative_size", func(t *testing.T) {
		for _, negSize := range []int64{-1, -50, math.MinInt64} {
			h := newW8aHostileTrackingHandler()
			h.stats["/remote/neg.bin"] = syntheticFileInfo{name: "neg.bin", size: negSize, mode: 0o644}

			client := newTestSFTPClientWithHandlers(t, h.handlers())
			remoteRoot, err := ParseRemotePath("/remote/neg.bin")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()

			got, err := client.DownloadTransferSize(ctx, remoteRoot)
			if !errors.Is(err, ErrInvalidRemoteSize) || got != 0 {
				t.Fatalf("DownloadTransferSize(single size=%d) = (%d, %v), want (0, ErrInvalidRemoteSize)", negSize, got, err)
			}
		}
	})

	t.Run("directory_walk_regular_child_negative_size", func(t *testing.T) {
		for _, negSize := range []int64{-1, -50, math.MinInt64} {
			h := newW8aHostileTrackingHandler()
			h.stats["/remote/dir"] = syntheticFileInfo{name: "dir", mode: os.ModeDir | 0o755}
			h.dirLists["/remote/dir"] = []os.FileInfo{
				syntheticFileInfo{name: "good.txt", size: 12, mode: 0o644},
				syntheticFileInfo{name: "sub", mode: os.ModeDir | 0o755},
			}
			h.dirLists["/remote/dir/sub"] = []os.FileInfo{
				syntheticFileInfo{name: "neg.bin", size: negSize, mode: 0o644},
			}

			client := newTestSFTPClientWithHandlers(t, h.handlers())
			remoteRoot, err := ParseRemotePath("/remote/dir")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()

			got, err := client.DownloadTransferSize(ctx, remoteRoot)
			if !errors.Is(err, ErrInvalidRemoteSize) || got != 0 {
				t.Fatalf("DownloadTransferSize(dir child size=%d) = (%d, %v), want (0, ErrInvalidRemoteSize)", negSize, got, err)
			}
		}
	})

	t.Run("valid_positive_and_zero_sizes_still_succeed", func(t *testing.T) {
		h := newW8aHostileTrackingHandler()
		h.stats["/remote/ok"] = syntheticFileInfo{name: "ok", mode: os.ModeDir | 0o755}
		h.dirLists["/remote/ok"] = []os.FileInfo{
			syntheticFileInfo{name: "empty.txt", size: 0, mode: 0o644},
			syntheticFileInfo{name: "data.bin", size: 123, mode: 0o644},
			syntheticFileInfo{name: "link", size: 0, mode: os.ModeSymlink | 0o777},
		}
		h.readLinks["/remote/ok/link"] = "data.bin"

		client := newTestSFTPClientWithHandlers(t, h.handlers())
		remoteRoot, err := ParseRemotePath("/remote/ok")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()

		got, err := client.DownloadTransferSize(ctx, remoteRoot)
		if err != nil {
			t.Fatalf("DownloadTransferSize(valid dir) unexpected error: %v", err)
		}
		want := int64(123 + len("data.bin"))
		if got != want {
			t.Fatalf("DownloadTransferSize(valid dir) = %d, want %d", got, want)
		}
	})
}
