package ssh

import (
	"net"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// sshActivityConn measures receive progress below SSH packet buffering, so a
// large packet arriving over a slow link still proves the peer is reachable.
// Writes only prove that local buffers accept data and must not count as life.
// Each SSH hop owns its tracker: traffic on a jump cannot keep a dead target alive.
type sshActivityConn struct {
	net.Conn
	startedAt time.Time
	lastRead  atomic.Int64
}

func (c *sshActivityConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.lastRead.Store(int64(time.Since(c.startedAt)))
	}
	return n, err
}

func (c *sshActivityConn) readIdle() time.Duration {
	lastRead := c.lastRead.Load()
	return time.Since(c.startedAt) - time.Duration(lastRead)
}

// Keep activity attached to the SSH connection, including cached wrappers,
// without replacing the physical root used to interrupt ProxyJump transports.
type activitySSHConn struct {
	ssh.Conn
	activity *sshActivityConn
}

func keepAliveReadTimeout(client *ssh.Client, timeout time.Duration) time.Duration {
	if conn, ok := client.Conn.(*activitySSHConn); ok {
		return timeout - conn.activity.readIdle()
	}
	// Externally constructed clients have no receive tracker. Retain their
	// bounded request timeout rather than assuming the connection is healthy.
	return 0
}
