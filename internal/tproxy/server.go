package tproxy

import (
	"context"
	"net"

	"github.com/die-net/conduit/internal/dialer"
	"github.com/die-net/conduit/internal/proxy"
)

type Server struct {
	Dialer dialer.Dialer
}

func NewServer(cfg proxy.Config) *Server {
	return &Server{Dialer: cfg.Dialer}
}

func (s *Server) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handle(c)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dst, ok := OriginalDst(conn)
	if !ok {
		return
	}

	up, err := s.Dialer.DialContext(ctx, "tcp", dst.String())
	if err != nil {
		return
	}
	defer up.Close()

	_ = proxy.CopyBidirectional(ctx, conn, up)
}
