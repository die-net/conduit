package dialer

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/die-net/conduit/internal/socks5"
)

// SOCKS5ProxyDialer dials outbound TCP connections via an upstream SOCKS5
// proxy.
type SOCKS5ProxyDialer struct {
	cfg       Config
	proxyAddr string
	username  string
	password  string
	direct    Dialer
}

// NewSOCKS5ProxyDialer constructs a SOCKS5 CONNECT dialer for proxyAddr.
//
// If username is non-empty, username/password negotiation is used.
func NewSOCKS5ProxyDialer(cfg Config, proxyAddr, username, password string) Dialer {
	return &SOCKS5ProxyDialer{cfg: cfg, proxyAddr: proxyAddr, username: username, password: password, direct: NewDirectDialer(cfg)}
}

// DialContext establishes a TCP connection to address via the configured SOCKS5
// proxy, returned as a net.Conn.
//
// Canceling ctx closes the proxy connection during negotiation so callers don't
// hang waiting for a proxy response.
//
// SOCKS5 negotiation and CONNECT are performed synchronously before
// returning.
//
// If NegotiationTimeout is set, a deadline is applied during SOCKS5
// negotiation and cleared before returning.
func (f *SOCKS5ProxyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if !strings.HasPrefix(network, "tcp") {
		return nil, fmt.Errorf("socks5 proxy dial %s %s: unsupported network", network, address)
	}

	c, err := f.direct.DialContext(ctx, network, f.proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("socks5 proxy: %w", err)
	}

	if f.cfg.NegotiationTimeout > 0 {
		_ = c.SetDeadline(time.Now().Add(f.cfg.NegotiationTimeout))
	}

	stop := context.AfterFunc(ctx, func() {
		_ = c.Close()
	})
	defer stop()

	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	}

	var auth socks5.Auth
	if f.username != "" {
		auth = socks5.Auth{Username: f.username, Password: f.password}
	}
	if err := socks5.ClientDial(c, auth, address); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("socks5 proxy connect: %w", err)
	}

	if f.cfg.NegotiationTimeout > 0 {
		_ = c.SetDeadline(time.Time{})
	}
	return c, nil
}
