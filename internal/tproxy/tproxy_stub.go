//go:build !linux

package tproxy

import (
	"errors"
	"net"
)

func ListenTransparentTCP(_ string, _ net.KeepAliveConfig) (net.Listener, error) {
	return nil, errors.New("transparent proxy is only supported on linux")
}

func OriginalDst(_ net.Conn) (*net.TCPAddr, bool) {
	return nil, false
}
