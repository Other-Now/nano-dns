//go:build !linux

package server

import "net"

const reusePortSupported = false

func listenUDP(addr string, _ bool) (*net.UDPConn, error) {
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	return net.ListenUDP("udp", a)
}
