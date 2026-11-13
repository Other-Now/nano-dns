//go:build linux

package server

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

const reusePortSupported = true

// listenUDP binds a UDP socket, with SO_REUSEPORT when several sockets share
// the address. The kernel then hashes each client 4-tuple to one socket, so
// readers on different sockets never contend on one receive queue.
func listenUDP(addr string, reuse bool) (*net.UDPConn, error) {
	lc := net.ListenConfig{}
	if reuse {
		lc.Control = func(_, _ string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			}); err != nil {
				return err
			}
			return serr
		}
	}
	pc, err := lc.ListenPacket(context.Background(), "udp", addr)
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}
