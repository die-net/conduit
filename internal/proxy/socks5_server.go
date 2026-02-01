package proxy

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/txthinking/socks5"
)

type SOCKS5Server struct {
	ctx     context.Context
	cfg     Config
	Verbose bool
}

func NewSOCKS5Server(ctx context.Context, cfg Config, verbose bool) *SOCKS5Server {
	if ctx == nil {
		ctx = context.Background()
	}
	return &SOCKS5Server{ctx: ctx, cfg: cfg, Verbose: verbose}
}

func (s *SOCKS5Server) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("accept: %w", err)
		}
		go func() {
			if err := s.handleConn(c); err != nil {
				if s.Verbose {
					log.Printf("socks5: connection error: %v", err)
				}
			}
		}()
	}
}

func (s *SOCKS5Server) handleConn(conn net.Conn) error {
	defer conn.Close()
	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()

	if s.cfg.NegotiationTimeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(s.cfg.NegotiationTimeout))
	}

	// negotiation (no-auth only)
	neg, err := socks5.NewNegotiationRequestFrom(conn)
	if err != nil {
		return fmt.Errorf("negotiation request: %w", err)
	}
	_ = neg
	if _, err := socks5.NewNegotiationReply(socks5.MethodNone).WriteTo(conn); err != nil {
		return fmt.Errorf("negotiation reply: %w", err)
	}

	// request
	req, err := socks5.NewRequestFrom(conn)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	if req.Cmd != socks5.CmdConnect {
		var rep *socks5.Reply
		if req.Atyp == socks5.ATYPIPv6 {
			rep = socks5.NewReply(socks5.RepCommandNotSupported, socks5.ATYPIPv6, []byte(net.IPv6zero), []byte{0x00, 0x00})
		} else {
			rep = socks5.NewReply(socks5.RepCommandNotSupported, socks5.ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
		}
		_, _ = rep.WriteTo(conn)
		return fmt.Errorf("unsupported command: %d", req.Cmd)
	}

	dst := req.Address()

	up, err := s.cfg.Dialer.DialContext(ctx, "tcp", dst)
	if err != nil {
		var rep *socks5.Reply
		if req.Atyp == socks5.ATYPIPv6 {
			rep = socks5.NewReply(socks5.RepConnectionRefused, socks5.ATYPIPv6, []byte(net.IPv6zero), []byte{0x00, 0x00})
		} else {
			rep = socks5.NewReply(socks5.RepConnectionRefused, socks5.ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
		}
		_, _ = rep.WriteTo(conn)
		return fmt.Errorf("dial %s: %w", dst, err)
	}
	defer up.Close()

	a, addr, port, err := socks5.ParseAddress(up.LocalAddr().String())
	if err != nil {
		return fmt.Errorf("parse local address %q: %w", up.LocalAddr().String(), err)
	}
	if a == socks5.ATYPDomain {
		addr = addr[1:]
	}
	if _, err := socks5.NewReply(socks5.RepSuccess, a, addr, port).WriteTo(conn); err != nil {
		return fmt.Errorf("success reply: %w", err)
	}

	if s.cfg.NegotiationTimeout > 0 {
		_ = conn.SetDeadline(time.Time{})
	}

	// Once we've finished the SOCKS5 handshake, switch to bidirectional proxying.
	if err := CopyBidirectional(ctx, conn, up); err != nil {
		return fmt.Errorf("proxy: %w", err)
	}
	return nil
}
