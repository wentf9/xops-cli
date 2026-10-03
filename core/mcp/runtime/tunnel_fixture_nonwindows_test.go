//go:build !windows

package runtime

func platformTunnelFixtureClose(error) bool { return false }
