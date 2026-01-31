package proxy

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/txthinking/socks5"
)

type socks5UpstreamForwarder struct {
	cfg    Config
	upAddr string
}

func NewSOCKS5UpstreamForwarder(cfg Config, upstreamAddr string) Forwarder {
	return &socks5UpstreamForwarder{cfg: cfg, upAddr: upstreamAddr}
}

func (f *socks5UpstreamForwarder) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	_ = ctx
	if network != "tcp" {
		return nil, fmt.Errorf("socks5 upstream dial %s %s: unsupported network", network, address)
	}

	tcpTimeout := 0
	if f.cfg.DialTimeout > 0 {
		tcpTimeout = int(time.Duration(f.cfg.DialTimeout).Seconds())
		if tcpTimeout <= 0 {
			tcpTimeout = 1
		}
	}

	client, err := socks5.NewClient(f.upAddr, "", "", tcpTimeout, 0)
	if err != nil {
		return nil, fmt.Errorf("socks5 upstream init: %w", err)
	}

	c, err := client.Dial(network, address)
	if err != nil {
		return nil, fmt.Errorf("socks5 upstream dial %s %s: %w", network, address, err)
	}
	return c, nil
}
