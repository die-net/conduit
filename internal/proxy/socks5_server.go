package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
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

	br := bufio.NewReader(conn)
	bw := bufio.NewWriter(conn)

	// greeting
	if ver, err := br.ReadByte(); err != nil || ver != 0x05 {
		return
	}

	nMethods, err := br.ReadByte()
	if err != nil {
		return
	}

	methods := make([]byte, int(nMethods))
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}

	// no-auth only
	if _, err := bw.Write([]byte{0x05, 0x00}); err != nil {
		return
	}
	if err := bw.Flush(); err != nil {
		return
	}

	// request
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return
	}

	if hdr[0] != 0x05 {
		return
	}
	cmd := hdr[1]
	atyp := hdr[3]
	if cmd != 0x01 { // CONNECT
		s.writeReply(bw, 0x07, nil) // Command not supported
		_ = bw.Flush()
		return
	}

	dstHost, err := readSocksAddr(br, atyp)
	if err != nil {
		s.writeReply(bw, 0x08, nil)
		_ = bw.Flush()
		return
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(br, portBytes); err != nil {
		return
	}
	dstPort := binary.BigEndian.Uint16(portBytes)

	dst := net.JoinHostPort(dstHost, fmt.Sprintf("%d", dstPort))

	ctx := context.Background()
	up, err := s.cfg.Forward.Dial(ctx, "tcp", dst)
	if err != nil {
		s.writeReply(bw, 0x05, nil) // Connection refused
		_ = bw.Flush()
		return
	}
	defer up.Close()

	s.writeReply(bw, 0x00, up.LocalAddr())
	if err := bw.Flush(); err != nil {
		return
	}

	_ = CopyBidirectional(ctx, conn, up, s.cfg.IOTimeout)
}

func (s *SOCKS5Server) writeReply(w *bufio.Writer, rep byte, bindAddr net.Addr) {
	// VER REP RSV ATYP BND.ADDR BND.PORT
	_ = w.WriteByte(0x05)
	_ = w.WriteByte(rep)
	_ = w.WriteByte(0x00)

	ip := net.IPv4zero
	port := uint16(0)
	if ta, ok := bindAddr.(*net.TCPAddr); ok {
		if ta.IP != nil {
			ip = ta.IP
		}
		port = uint16(ta.Port)
	}

	ip4 := ip.To4()
	if ip4 != nil {
		_ = w.WriteByte(0x01)
		_, _ = w.Write(ip4)
		pb := make([]byte, 2)
		binary.BigEndian.PutUint16(pb, port)
		_, _ = w.Write(pb)
		return
	}

	// fallback to IPv6
	ip16 := ip.To16()
	if ip16 == nil {
		ip16 = net.IPv6zero
	}
	_ = w.WriteByte(0x04)
	_, _ = w.Write(ip16)
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, port)
	_, _ = w.Write(pb)
}

var errSOCKS = errors.New("socks5")

func readSocksAddr(r *bufio.Reader, atyp byte) (string, error) {
	switch atyp {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	case 0x03:
		n, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		b := make([]byte, int(n))
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return string(b), nil
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	default:
		return "", errSOCKS
	}
}
