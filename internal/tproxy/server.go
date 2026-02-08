package tproxy

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/die-net/conduit/internal/dialer"
	"github.com/die-net/conduit/internal/proxy"
)

// Server is a transparent proxy (TPROXY-style) connection forwarder.
//
// It accepts redirected TCP connections and forwards each connection to its
// original destination (as reported by OriginalDst).
type Server struct {
	ctx     context.Context
	Dialer  dialer.ContextDialer
	Verbose bool
}

// NewServer constructs a transparent proxy Server.
func NewServer(ctx context.Context, cfg proxy.Config, verbose bool) *Server {
	if ctx == nil {
		ctx = context.Background()
	}
	return &Server{ctx: ctx, Dialer: cfg.Dialer, Verbose: verbose}
}

// Serve accepts connections from ln and forwards each one to its original
// destination.
//
// Each accepted connection is handled in its own goroutine.
func (s *Server) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("accept: %w", err)
		}
		go func() {
			if err := s.handle(c); err != nil {
				if s.Verbose {
					log.Printf("tproxy: connection error: %v", err)
				}
			}
		}()
	}
}

func (s *Server) handle(conn net.Conn) error {
	defer conn.Close()
	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()

	dst, ok := OriginalDst(conn)
	if !ok {
		return errors.New("original destination unavailable")
	}

	up, err := s.Dialer.DialContext(ctx, "tcp", dst.String())
	if err != nil {
		return err
	}
	defer up.Close()

	if err := proxy.CopyBidirectional(ctx, conn, up); err != nil {
		return fmt.Errorf("proxy: %w", err)
	}
	return nil
}
