//go:build unix && !linux && !darwin && !freebsd

package osfs

import "fmt"

func maxUnixSocketPathBytesOS() int { return 103 }
func isBSDFileTypeErr(error) bool   { return false }

func queryPeerCredFD(uintptr) (PeerCred, error) {
	return PeerCred{}, fmt.Errorf("%w: %w", ErrUnauthorizedPeer, ErrUnsupportedPeerCred)
}
