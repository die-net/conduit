package proxy

import (
	"context"
	"net"
	"time"

	"github.com/txthinking/socks5"
)

type SOCKS5Server struct {
	cfg Config
}

func NewSOCKS5Server(cfg Config) *SOCKS5Server {
	return &SOCKS5Server{cfg: cfg}
}

func (s *SOCKS5Server) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handleConn(c)
	}
}

func (s *SOCKS5Server) handleConn(conn net.Conn) {
	defer conn.Close()

	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetKeepAliveConfig(s.cfg.KeepAlive)
	}

	// negotiation (no-auth only)
	neg, err := socks5.NewNegotiationRequestFrom(conn)
	if err != nil {
		return
	}
	_ = neg
	if _, err := socks5.NewNegotiationReply(socks5.MethodNone).WriteTo(conn); err != nil {
		return
	}

	// request
	req, err := socks5.NewRequestFrom(conn)
	if err != nil {
		return
	}
	if req.Cmd != socks5.CmdConnect {
		var rep *socks5.Reply
		if req.Atyp == socks5.ATYPIPv6 {
			rep = socks5.NewReply(socks5.RepCommandNotSupported, socks5.ATYPIPv6, []byte(net.IPv6zero), []byte{0x00, 0x00})
		} else {
			rep = socks5.NewReply(socks5.RepCommandNotSupported, socks5.ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
		}
		_, _ = rep.WriteTo(conn)
		return
	}

	dst := req.Address()

	ctx := context.Background()
	up, err := s.cfg.Forward.Dial(ctx, "tcp", dst)
	if err != nil {
		var rep *socks5.Reply
		if req.Atyp == socks5.ATYPIPv6 {
			rep = socks5.NewReply(socks5.RepConnectionRefused, socks5.ATYPIPv6, []byte(net.IPv6zero), []byte{0x00, 0x00})
		} else {
			rep = socks5.NewReply(socks5.RepConnectionRefused, socks5.ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
		}
		_, _ = rep.WriteTo(conn)
		return
	}
	defer up.Close()

	a, addr, port, err := socks5.ParseAddress(up.LocalAddr().String())
	if err != nil {
		return
	}
	if a == socks5.ATYPDomain {
		addr = addr[1:]
	}
	if _, err := socks5.NewReply(socks5.RepSuccess, a, addr, port).WriteTo(conn); err != nil {
		return
	}

	// Once we've finished the SOCKS5 handshake, switch to bidirectional proxying.
	if s.cfg.IOTimeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(time.Duration(s.cfg.IOTimeout)))
		_ = up.SetDeadline(time.Now().Add(time.Duration(s.cfg.IOTimeout)))
	}
	_ = CopyBidirectional(ctx, conn, up, s.cfg.IOTimeout)
}
