//go:build !windows

package mcpserver

func platformTunnelFixtureClose(error) bool { return false }
