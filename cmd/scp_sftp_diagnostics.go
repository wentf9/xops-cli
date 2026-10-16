package cmd

import (
	"fmt"

	corelog "github.com/wentf9/xops-cli/core/log"
)

// observeSFTP handles SCP's own protocol diagnostics independently of the SSH
// log level, preserving OpenSSH's behavior when -q follows one or more -v flags.
func (d *scpDiagnostics) observeSFTP(e corelog.Diagnostic) bool {
	q := quotedDiagnostic
	var message string
	switch e.Kind {
	case corelog.SFTPVersion:
		message = fmt.Sprintf("%s SFTP version %d (extensions truncated: %t)", e.Direction, e.ProtocolVersion, e.Truncated)
	case corelog.SFTPExtension:
		message = fmt.Sprintf("Server supports extension %s revision %s", q(e.Extension), q(e.ExtensionVersion))
	case corelog.SFTPOperation:
		message = fmt.Sprintf("Sending %s id %d path %s", sftpPacketName(e.PacketType), e.PacketID, q(e.Path))
		if e.Extension != "" {
			message = fmt.Sprintf("Sending SSH2_FXP_EXTENDED id %d extension %s", e.PacketID, q(e.Extension))
		}
		if e.Truncated {
			message += " (metadata truncated)"
		}
	case corelog.SFTPPacket:
		message = fmt.Sprintf("%s packet %s T:%d length %d", e.Direction, sftpPacketName(e.PacketType), e.PacketType, e.PacketLength)
		if e.HasPacketID {
			message += fmt.Sprintf(" I:%d", e.PacketID)
		}
		if e.HasStatus {
			message += fmt.Sprintf(" status %d", e.StatusCode)
		}
	case corelog.SFTPMalformed:
		message = fmt.Sprintf("%s incomplete SFTP packet metadata (length %d); protocol validation remains with SFTP client", e.Direction, e.PacketLength)
	case corelog.SubsystemStderr:
		message = fmt.Sprintf("SFTP subsystem wrote %d stderr bytes (untrusted text omitted)", e.Size)
	case corelog.FileTransfer:
		message = fmt.Sprintf("%s %s: %s -> %s size %d", e.Operation, e.Outcome, q(e.Source), q(e.Destination), e.Size)
	default:
		return false
	}
	d.enqueue(fmt.Sprintf("scp: debug%d: [sftp %d] %s\n", max(e.Level, 1), e.StreamID, message))
	return true
}

var sftpPacketNames = [256]string{
	1:   "SSH2_FXP_INIT",
	2:   "SSH2_FXP_VERSION",
	3:   "SSH2_FXP_OPEN",
	4:   "SSH2_FXP_CLOSE",
	5:   "SSH2_FXP_READ",
	6:   "SSH2_FXP_WRITE",
	7:   "SSH2_FXP_LSTAT",
	8:   "SSH2_FXP_FSTAT",
	9:   "SSH2_FXP_SETSTAT",
	10:  "SSH2_FXP_FSETSTAT",
	11:  "SSH2_FXP_OPENDIR",
	12:  "SSH2_FXP_READDIR",
	13:  "SSH2_FXP_REMOVE",
	14:  "SSH2_FXP_MKDIR",
	15:  "SSH2_FXP_RMDIR",
	16:  "SSH2_FXP_REALPATH",
	17:  "SSH2_FXP_STAT",
	18:  "SSH2_FXP_RENAME",
	19:  "SSH2_FXP_READLINK",
	20:  "SSH2_FXP_SYMLINK",
	101: "SSH2_FXP_STATUS",
	102: "SSH2_FXP_HANDLE",
	103: "SSH2_FXP_DATA",
	104: "SSH2_FXP_NAME",
	105: "SSH2_FXP_ATTRS",
	200: "SSH2_FXP_EXTENDED",
	201: "SSH2_FXP_EXTENDED_REPLY",
}

func sftpPacketName(kind uint8) string {
	if name := sftpPacketNames[kind]; name != "" {
		return name
	}
	return "SSH2_FXP_UNKNOWN"
}
