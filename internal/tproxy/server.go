package tproxy

import (
	"context"
	"net"
	"time"

	"github.com/die-net/conduit/internal/dialer"
	"github.com/die-net/conduit/internal/proxy"
)

type Server struct {
	KeepAlive net.KeepAliveConfig
	IOTimeout time.Duration
	Forward   dialer.Dialer
}

func NewServer(cfg proxy.Config) *Server {
	return &Server{KeepAlive: cfg.KeepAlive, IOTimeout: cfg.IOTimeout, Forward: cfg.Forward}
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

	tc, ok := conn.(*net.TCPConn)
	if ok {
		tc.SetKeepAliveConfig(s.KeepAlive)
	}

	dst, ok := OriginalDst(conn)
	if !ok {
		return
	}

	up, err := s.Forward.Dial(context.Background(), "tcp", dst.String())
	if err != nil {
		return
	}
	defer up.Close()

	_ = proxy.CopyBidirectional(context.Background(), conn, up, s.IOTimeout)
}
