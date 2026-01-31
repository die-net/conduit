package dialer

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/txthinking/socks5"
)

func TestSOCKS5ProxyDialerDialSuccess(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()

	go func() {
		c, err := echoLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()

		buf := make([]byte, 1024)
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		_, _ = c.Write(buf[:n])
	}()

	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upLn.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, err := upLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()

		if _, err := socks5.NewNegotiationRequestFrom(c); err != nil {
			return
		}
		if _, err := socks5.NewNegotiationReply(socks5.MethodNone).WriteTo(c); err != nil {
			return
		}
		req, err := socks5.NewRequestFrom(c)
		if err != nil {
			return
		}
		if req.Cmd != socks5.CmdConnect {
			_, _ = socks5.NewReply(socks5.RepCommandNotSupported, socks5.ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00}).WriteTo(c)
			return
		}

		dst, err := net.Dial("tcp", req.Address())
		if err != nil {
			_, _ = socks5.NewReply(socks5.RepHostUnreachable, socks5.ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00}).WriteTo(c)
			return
		}
		defer dst.Close()

		a, addr, port, err := socks5.ParseAddress(dst.LocalAddr().String())
		if err != nil {
			return
		}
		if a == socks5.ATYPDomain {
			addr = addr[1:]
		}
		_, _ = socks5.NewReply(socks5.RepSuccess, a, addr, port).WriteTo(c)

		go func() {
			_, _ = io.Copy(dst, c)
			_ = dst.Close()
		}()
		_, _ = io.Copy(c, dst)
	}()

	f := NewSOCKS5ProxyDialer(Config{DialTimeout: 2 * time.Second}, upLn.Addr().String())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := f.Dial(ctx, "tcp", echoLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	msg := []byte("hello")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("expected %q got %q", string(msg), string(buf))
	}

	_ = upLn.Close()
	wg.Wait()
}

func TestSOCKS5ProxyDialerDialFail(t *testing.T) {
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upLn.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, err := upLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()

		if _, err := socks5.NewNegotiationRequestFrom(c); err != nil {
			return
		}
		if _, err := socks5.NewNegotiationReply(socks5.MethodNone).WriteTo(c); err != nil {
			return
		}
		req, err := socks5.NewRequestFrom(c)
		if err != nil {
			return
		}
		if req.Cmd != socks5.CmdConnect {
			return
		}
		_, _ = socks5.NewReply(socks5.RepConnectionRefused, socks5.ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00}).WriteTo(c)
	}()

	f := NewSOCKS5ProxyDialer(Config{DialTimeout: 2 * time.Second}, upLn.Addr().String())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = f.Dial(ctx, "tcp", "127.0.0.1:1")
	if err == nil {
		t.Fatalf("expected error")
	}

	_ = upLn.Close()
	wg.Wait()
}
