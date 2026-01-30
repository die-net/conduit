package tproxy

import (
	"context"
	"net"

	"github.com/die-net/conduit/internal/proxy"
)

type Server struct {
	cfg proxy.Config
}

func NewServer(cfg proxy.Config) *Server {
	return &Server{cfg: cfg}
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
		tc.SetKeepAliveConfig(s.cfg.KeepAlive)
	}

	dst, ok := OriginalDst(conn)
	if !ok {
		return
	}

	up, err := s.cfg.Forward.Dial(context.Background(), "tcp", dst.String())
	if err != nil {
		return
	}
	defer up.Close()

	_ = proxy.CopyBidirectional(context.Background(), conn, up, s.cfg.IOTimeout)
}
