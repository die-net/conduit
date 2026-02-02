package dialer

import (
	"context"
	"net"
)

type directDialer struct {
	cfg Config
}

func NewDirectDialer(cfg Config) Dialer {
	return &directDialer{cfg: cfg}
}

func (f *directDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	dd := net.Dialer{Timeout: f.cfg.DialTimeout}

	conn, err := dd.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}

	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetKeepAliveConfig(f.cfg.KeepAlive)
	}

	return conn, nil
}
