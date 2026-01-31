package dialer

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/txthinking/socks5"
)

type SOCKS5ProxyDialer struct {
	cfg       Config
	proxyAddr string
}

func NewSOCKS5ProxyDialer(cfg Config, proxyAddr string) Dialer {
	return &SOCKS5ProxyDialer{cfg: cfg, proxyAddr: proxyAddr}
}

func (f *SOCKS5ProxyDialer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	_ = ctx
	if network != "tcp" {
		return nil, fmt.Errorf("socks5 proxy dial %s %s: unsupported network", network, address)
	}

	tcpTimeout := 0
	if f.cfg.DialTimeout > 0 {
		tcpTimeout = int(time.Duration(f.cfg.DialTimeout).Seconds())
		if tcpTimeout <= 0 {
			tcpTimeout = 1
		}
	}

	client, err := socks5.NewClient(f.proxyAddr, "", "", tcpTimeout, 0)
	if err != nil {
		return nil, fmt.Errorf("socks5 proxy init: %w", err)
	}

	c, err := client.Dial(network, address)
	if err != nil {
		return nil, fmt.Errorf("socks5 proxy dial %s %s: %w", network, address, err)
	}
	return c, nil
}
