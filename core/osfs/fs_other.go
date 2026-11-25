//go:build !unix && !windows

package osfs

import (
	"context"
	"fmt"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/ports"
	"io/fs"
	"net"
	"os"
)

type socketFileID struct{}

func errUnsupportedPeer() (PeerCred, error) {
	return PeerCred{}, fmt.Errorf("%w: %w", ErrUnauthorizedPeer, ErrUnsupportedPeerCred)
}
func sameSocketFileID(_, _ socketFileID) bool { return false }
func localPathToNativeOS(pathalg.LocalPathKind, string) (string, error) {
	return "", ports.ErrUnsupported
}
func openLeafInRootOS(*os.Root, pathalg.LocalRootedDest, rootLeafOp, fs.FileMode) (*os.File, error) {
	return nil, ports.ErrUnsupported
}
func ensureDirOS(string, fs.FileMode) error { return ports.ErrUnsupported }
func openOperatorReadOS(string, pathalg.SymlinkPolicy) (*os.File, int64, error) {
	return nil, 0, ports.ErrUnsupported
}
func tryLockFileOS(*os.File, bool) error                                 { return ports.ErrUnsupported }
func unlockFileOS(*os.File) error                                        { return ports.ErrUnsupported }
func syncRootParentDirOS(*os.Root, pathalg.LocalRootedDest) error        { return ports.ErrUnsupported }
func mkdirSegmentInRootOS(*os.Root, []string, string, fs.FileMode) error { return ports.ErrUnsupported }
func maxUnixSocketPathBytesOS() int                                      { return 103 }
func validateControlSocketPathOS(string) (ControlSocketPath, error) {
	return ControlSocketPath{}, ports.ErrUnsupported
}
func inspectSocketEntryOS(string) (socketFileID, SocketProbeStatus, error) {
	return socketFileID{}, SocketProbeUnknown, ports.ErrUnsupported
}
func verifySocketTargetBeforeDialOS(string) error { return ports.ErrUnsupported }
func isConnRefusedOS(error) bool                  { return false }
func isAddrInUseOS(error) bool                    { return false }
func isSocketUnlinkRetryableOS(error) bool        { return false }
func withSocketDirLockOS(context.Context, string, bool, func() error) error {
	return ports.ErrUnsupported
}
func listenSocketLockedOS(context.Context, ControlSocketPath) (*net.UnixListener, socketFileID, error) {
	return nil, socketFileID{}, ports.ErrUnsupported
}
func queryPeerCredFD(uintptr) (PeerCred, error)         { return errUnsupportedPeer() }
func verifyPeerCurrentUserFD(uintptr) (PeerCred, error) { return errUnsupportedPeer() }
