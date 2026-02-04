package proxy

import (
	"context"
	"fmt"
	"net"
)

// ListenTCP listens on the given network/address and returns a net.Listener
// that applies keepAliveConfig to accepted TCP connections.
func ListenTCP(network, addr string, keepAliveConfig net.KeepAliveConfig) (net.Listener, error) {
	lc := net.ListenConfig{}

	ln, err := lc.Listen(context.Background(), network, addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s %s: %w", network, addr, err)
	}

	return &KeepAliveListener{Listener: ln, KeepAliveConfig: keepAliveConfig}, nil
}

// KeepAliveListener wraps a net.Listener and applies KeepAliveConfig to any
// accepted *net.TCPConn.
type KeepAliveListener struct {
	net.Listener
	net.KeepAliveConfig
}

// Accept accepts the next connection and applies KeepAliveConfig if the
// connection is a *net.TCPConn.
func (l *KeepAliveListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	tc, ok := conn.(*net.TCPConn)
	if ok {
		_ = tc.SetKeepAliveConfig(l.KeepAliveConfig)
	}

	return conn, nil
}
