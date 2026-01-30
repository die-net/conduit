package proxy

import (
	"context"
	"fmt"
	"net"
	"time"

	"golang.org/x/net/proxy"
)

type socks5UpstreamForwarder struct {
	cfg    Config
	upAddr string
	dialer proxy.Dialer
}

func NewSOCKS5UpstreamForwarder(cfg Config, upstreamAddr string) Forwarder {
	// Base dialer used to connect to the upstream SOCKS5 server.
	base := &contextDirectDialer{cfg: cfg}
	d, err := proxy.SOCKS5("tcp", upstreamAddr, nil, base)
	if err != nil {
		return &socks5UpstreamForwarder{cfg: cfg, upAddr: upstreamAddr}
	}
	return &socks5UpstreamForwarder{cfg: cfg, upAddr: upstreamAddr, dialer: d}
}

func (f *socks5UpstreamForwarder) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if f.dialer == nil {
		// Construct lazily if SOCKS5() previously failed.
		d, err := proxy.SOCKS5("tcp", f.upAddr, nil, &contextDirectDialer{cfg: f.cfg})
		if err != nil {
			return nil, fmt.Errorf("socks5 upstream init: %w", err)
		}
		f.dialer = d
	}

	if cd, ok := f.dialer.(proxy.ContextDialer); ok {
		c, err := cd.DialContext(ctx, network, address)
		if err != nil {
			return nil, fmt.Errorf("socks5 upstream dial %s %s: %w", network, address, err)
		}
		return c, nil
	}

	// Fallback for dialers that do not support context.
	c, err := f.dialer.Dial(network, address)
	if err != nil {
		return nil, fmt.Errorf("socks5 upstream dial %s %s: %w", network, address, err)
	}
	return c, nil
}

// contextDirectDialer implements golang.org/x/net/proxy.ContextDialer for connecting to an upstream proxy.
// It applies the configured dial timeout and TCP keepalive.
type contextDirectDialer struct {
	cfg Config
}

func (d *contextDirectDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *contextDirectDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	dd := net.Dialer{}
	if d.cfg.DialTimeout > 0 {
		dd.Timeout = time.Duration(d.cfg.DialTimeout)
	}
	c, err := dd.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	tc, ok := c.(*net.TCPConn)
	if ok {
		tc.SetKeepAliveConfig(d.cfg.KeepAlive)
	}

	return c, nil
}
