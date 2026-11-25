//go:build !unix && !windows

package osfs

import (
	"context"
	"fmt"
	"io/fs"
	"net"
	"os"

	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/ports"
)

type socketFileID struct{}

func sameSocketFileID(_, _ socketFileID) bool               { return false }
func localDirToNativePath(pathalg.LocalDir) (string, error) { return "", ports.ErrUnsupported }
func localSourceToNativePath(pathalg.LocalSourcePath) (string, error) {
	return "", ports.ErrUnsupported
}
func openRegularFDInRootOS(*os.Root, pathalg.LocalRootedDest) (*os.File, error) {
	return nil, ports.ErrUnsupported
}
func createExclusiveInRootOS(*os.Root, pathalg.LocalRootedDest, fs.FileMode) (*os.File, error) {
	return nil, ports.ErrUnsupported
}
func openForLockInRootOS(*os.Root, pathalg.LocalRootedDest, ports.LockMode, bool, fs.FileMode) (*os.File, error) {
	return nil, ports.ErrUnsupported
}
func openForAppendInRootOS(*os.Root, pathalg.LocalRootedDest, fs.FileMode) (*os.File, error) {
	return nil, ports.ErrUnsupported
}
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
func queryPeerCredFD(uintptr) (PeerCred, error) {
	return PeerCred{}, fmt.Errorf("%w: %w", ErrUnauthorizedPeer, ErrUnsupportedPeerCred)
}
func verifyPeerCurrentUserFD(uintptr) (PeerCred, error) {
	return PeerCred{}, fmt.Errorf("%w: %w", ErrUnauthorizedPeer, ErrUnsupportedPeerCred)
}
