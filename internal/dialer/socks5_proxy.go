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
	username  string
	password  string
	direct    Dialer
}

func NewSOCKS5ProxyDialer(cfg Config, proxyAddr, username, password string) Dialer {
	return &SOCKS5ProxyDialer{cfg: cfg, proxyAddr: proxyAddr, username: username, password: password, direct: NewDirectDialer(cfg)}
}

func (f *SOCKS5ProxyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("socks5 proxy dial %s %s: unsupported network", network, address)
	}

	c, err := f.direct.DialContext(ctx, network, f.proxyAddr)
	if err != nil {
		return nil, err
	}

	if f.cfg.NegotiationTimeout > 0 {
		_ = c.SetDeadline(time.Now().Add(time.Duration(f.cfg.NegotiationTimeout)))
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

	methods := []byte{socks5.MethodNone}
	if f.username != "" {
		methods = append(methods, socks5.MethodUsernamePassword)
	}
	if _, err := socks5.NewNegotiationRequest(methods).WriteTo(c); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("socks5 proxy connect write negotiation: %w", err)
	}
	neg, err := socks5.NewNegotiationReplyFrom(c)
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("socks5 proxy connect read negotiation: %w", err)
	}
	if neg.Method == socks5.MethodUsernamePassword {
		if f.username == "" {
			_ = c.Close()
			return nil, fmt.Errorf("socks5 proxy connect negotiation failed")
		}
		if _, err := socks5.NewUserPassNegotiationRequest([]byte(f.username), []byte(f.password)).WriteTo(c); err != nil {
			_ = c.Close()
			return nil, fmt.Errorf("socks5 proxy connect write userpass: %w", err)
		}
		rep, err := socks5.NewUserPassNegotiationReplyFrom(c)
		if err != nil {
			_ = c.Close()
			return nil, fmt.Errorf("socks5 proxy connect read userpass: %w", err)
		}
		if rep.Status != socks5.UserPassStatusSuccess {
			_ = c.Close()
			return nil, fmt.Errorf("socks5 proxy connect auth failed")
		}
	} else if neg.Method != socks5.MethodNone {
		_ = c.Close()
		return nil, fmt.Errorf("socks5 proxy connect negotiation failed")
	}

	atyp, dstAddr, dstPort, err := socks5.ParseAddress(address)
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("socks5 proxy connect parse address: %w", err)
	}
	if atyp == socks5.ATYPDomain {
		dstAddr = dstAddr[1:]
	}

	if _, err := socks5.NewRequest(socks5.CmdConnect, atyp, dstAddr, dstPort).WriteTo(c); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("socks5 proxy connect write request: %w", err)
	}
	rep, err := socks5.NewReplyFrom(c)
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("socks5 proxy connect read reply: %w", err)
	}
	if rep.Rep != socks5.RepSuccess {
		_ = c.Close()
		return nil, fmt.Errorf("socks5 proxy connect failed")
	}

	if f.cfg.NegotiationTimeout > 0 {
		_ = c.SetDeadline(time.Time{})
	}
	return c, nil
}
