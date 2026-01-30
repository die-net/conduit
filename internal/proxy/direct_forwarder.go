package proxy

import (
	"context"
	"fmt"
	"net"
)

type directForwarder struct {
	cfg Config
}

func NewDirectForwarder(cfg Config) Forwarder {
	return &directForwarder{cfg: cfg}
}

func (f *directForwarder) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	dd := net.Dialer{Timeout: f.cfg.DialTimeout}

	conn, err := dd.DialContext(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("dial %s %s: %w", network, address, err)
	}

	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetKeepAliveConfig(f.cfg.KeepAlive)
	}

	return conn, nil
}
