//go:build !linux && !freebsd && !openbsd

package tproxy

import (
	"errors"
	"net"
)

// IsSupported is true on TPROXY-supporting OSes.
const IsSupported = false

var errUnsupported = errors.New("transparent proxy is only supported on Linux, FreeBSD, and OpenBSD")

// ListenTransparentTCP is not supported on this platform.
func ListenTransparentTCP(_ string, _ net.KeepAliveConfig) (net.Listener, error) {
	return nil, errUnsupported
}

// OriginalDst is not supported on this platform.
func OriginalDst(_ net.Conn) (*net.TCPAddr, error) {
	return nil, errUnsupported
}
