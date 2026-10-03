//go:build !windows

package sshfixture

func platformPeerClosure(error) bool { return false }
