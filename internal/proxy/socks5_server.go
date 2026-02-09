package proxy

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/die-net/conduit/internal/conn"
	"github.com/die-net/conduit/internal/socks5"
)

// SOCKS5Server serves a SOCKS5 proxy listener.
//
// It currently supports no-auth negotiation and the CONNECT command.
type SOCKS5Server struct {
	ctx     context.Context
	cfg     Config
	Verbose bool
}

// NewSOCKS5Server constructs a SOCKS5Server.
func NewSOCKS5Server(ctx context.Context, cfg Config, verbose bool) *SOCKS5Server {
	if ctx == nil {
		ctx = context.Background()
	}
	return &SOCKS5Server{ctx: ctx, cfg: cfg, Verbose: verbose}
}

// Serve accepts connections from ln and serves SOCKS5.
//
// Each connection is handled in its own goroutine.
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

func (s *SOCKS5Server) handleConn(c net.Conn) error {
	defer c.Close()
	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()

	if s.cfg.NegotiationTimeout > 0 {
		_ = c.SetDeadline(time.Now().Add(s.cfg.NegotiationTimeout))
	}

	if err := socks5.ServerNegotiateNoAuth(c); err != nil {
		return err
	}

	req, err := socks5.ServerReadRequest(c)
	if err != nil {
		return err
	}
	if req.Cmd != socks5.CmdConnect {
		socks5.WriteCommandNotSupportedReply(c, req.Atyp)
		return fmt.Errorf("unsupported command: %d", req.Cmd)
	}

	dst := req.Address()

	up, err := s.cfg.Dialer.DialContext(ctx, "tcp", dst)
	if err != nil {
		socks5.WriteConnectionRefusedReply(c, req.Atyp)
		return err
	}
	defer up.Close()

	if err := socks5.WriteSuccessReply(c, up.LocalAddr()); err != nil {
		return err
	}

	if s.cfg.NegotiationTimeout > 0 {
		_ = c.SetDeadline(time.Time{})
	}

	// Once we've finished the SOCKS5 handshake, switch to bidirectional proxying.
	if err := conn.CopyBidirectional(ctx, c, up); err != nil {
		return fmt.Errorf("proxy: %w", err)
	}
	return nil
}
