package dialer

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/die-net/conduit/internal/socks5"
)

type SOCKS5ProxyDialer struct {
	cfg       Config
	proxyAddr string
	username  string
	password  string
	direct    Dialer
}

func NewSOCKS5ProxyDialer(cfg Config, proxyAddr, username, password string) Dialer {
	return &SOCKS5ProxyDialer{cfg: cfg, proxyAddr: proxyAddr, username: username, password: password, direct: NewDirectDialer(cfg)}
}

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

	ctxDone := make(chan struct{})
	defer close(ctxDone)
	go func() {
		select {
		case <-ctx.Done():
			_ = c.Close()
		case <-ctxDone:
		}
	}()

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
