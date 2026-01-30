package proxy

import (
	"context"
	"fmt"
	"net"
)

func ListenTCP(network, addr string, keepAliveConfig net.KeepAliveConfig) (net.Listener, error) {
	lc := net.ListenConfig{}

	ln, err := lc.Listen(context.Background(), network, addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s %s: %w", network, addr, err)
	}

	return &keepAliveListener{Listener: ln, KeepAliveConfig: keepAliveConfig}, nil
}

type keepAliveListener struct {
	net.Listener
	net.KeepAliveConfig
}

func (l *keepAliveListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	tc, ok := conn.(*net.TCPConn)
	if ok {
		tc.SetKeepAliveConfig(l.KeepAliveConfig)
	}

	return conn, nil
}
