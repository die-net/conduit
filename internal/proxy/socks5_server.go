package proxy

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/die-net/conduit/internal/socks5"
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

	if err := socks5.ServerNegotiateNoAuth(conn); err != nil {
		return err
	}

	req, err := socks5.ServerReadRequest(conn)
	if err != nil {
		return err
	}
	if req.Cmd != socks5.CmdConnect {
		socks5.WriteCommandNotSupportedReply(conn, req.Atyp)
		return fmt.Errorf("unsupported command: %d", req.Cmd)
	}

	dst := req.Address()

	up, err := s.cfg.Dialer.DialContext(ctx, "tcp", dst)
	if err != nil {
		socks5.WriteConnectionRefusedReply(conn, req.Atyp)
		return err
	}
	defer up.Close()

	if err := socks5.WriteSuccessReply(conn, up.LocalAddr()); err != nil {
		return err
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
