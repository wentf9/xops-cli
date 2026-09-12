// Package sftpshell implements the interactive presentation layer for SFTP.
//
// Generic SFTP operations belong in pkg/sftp and return errors to their caller.
// This package translates command failures into interactive output so the REPL
// can continue, while prompt, output, and lifecycle failures are returned to the
// CLI command for final handling.
//
// On Windows, remote exec/shell input uses an owned console handle with
// interruptible event reads. Input forwarding must finish before the next
// prompt takes ownership; normal EOF and cancellation are not command errors.
package sftpshell
