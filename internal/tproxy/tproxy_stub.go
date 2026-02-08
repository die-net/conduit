//go:build !linux && !freebsd && !openbsd

package tproxy

import (
	"errors"
	"net"
)

// IsSupported is true on TPROXY-supporting OSes.
const IsSupported = false

// ListenTransparentTCP is not supported on this platform.
func ListenTransparentTCP(_ string, _ net.KeepAliveConfig) (net.Listener, error) {
	return nil, errors.New("transparent proxy is only supported on Linux, FreeBSD, and OpenBSD")
}

// OriginalDst is not supported on this platform.
func OriginalDst(_ net.Conn) (*net.TCPAddr, bool) {
	return nil, false
}
