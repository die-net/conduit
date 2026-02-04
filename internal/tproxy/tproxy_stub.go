//go:build !linux

package tproxy

import (
	"errors"
	"net"
)

// ListenTransparentTCP is not supported on non-Linux platforms.
func ListenTransparentTCP(_ string, _ net.KeepAliveConfig) (net.Listener, error) {
	return nil, errors.New("transparent proxy is only supported on linux")
}

// OriginalDst is not supported on non-Linux platforms.
func OriginalDst(_ net.Conn) (*net.TCPAddr, bool) {
	return nil, false
}
