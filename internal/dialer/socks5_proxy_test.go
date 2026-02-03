package dialer

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/txthinking/socks5"
)

func TestSOCKS5ProxyDialerDialSuccess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	lc := net.ListenConfig{}
	echoLn, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
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

	upLn, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upLn.Close()

	var wg sync.WaitGroup
	wg.Go(func() {
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

		d := net.Dialer{}
		dst, err := d.DialContext(ctx, "tcp", req.Address())
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
	})

	f := NewSOCKS5ProxyDialer(Config{DialTimeout: 2 * time.Second}, upLn.Addr().String(), "", "")

	conn, err := f.DialContext(ctx, "tcp", echoLn.Addr().String())
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
	if !bytes.Equal(buf, msg) {
		t.Fatalf("expected %q got %q", string(msg), string(buf))
	}

	_ = upLn.Close()
	wg.Wait()
}

func TestSOCKS5ProxyDialerDialAuthSuccess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	lc := net.ListenConfig{}
	echoLn, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
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

	upLn, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upLn.Close()

	var wg sync.WaitGroup
	wg.Go(func() {
		c, err := upLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()

		neg, err := socks5.NewNegotiationRequestFrom(c)
		if err != nil {
			return
		}
		_ = neg
		if _, err := socks5.NewNegotiationReply(socks5.MethodUsernamePassword).WriteTo(c); err != nil {
			return
		}

		urq, err := socks5.NewUserPassNegotiationRequestFrom(c)
		if err != nil {
			return
		}
		if string(urq.Uname) != "user" || string(urq.Passwd) != "pass" {
			_, _ = socks5.NewUserPassNegotiationReply(socks5.UserPassStatusFailure).WriteTo(c)
			return
		}
		if _, err := socks5.NewUserPassNegotiationReply(socks5.UserPassStatusSuccess).WriteTo(c); err != nil {
			return
		}

		req, err := socks5.NewRequestFrom(c)
		if err != nil {
			return
		}
		if req.Cmd != socks5.CmdConnect {
			return
		}

		d := net.Dialer{}
		dst, err := d.DialContext(ctx, "tcp", req.Address())
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
	})

	f := NewSOCKS5ProxyDialer(Config{DialTimeout: 2 * time.Second}, upLn.Addr().String(), "user", "pass")

	conn, err := f.DialContext(ctx, "tcp", echoLn.Addr().String())
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
	if !bytes.Equal(buf, msg) {
		t.Fatalf("expected %q got %q", string(msg), string(buf))
	}

	_ = upLn.Close()
	wg.Wait()
}

func TestSOCKS5ProxyDialerDialContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	lc := net.ListenConfig{}
	upLn, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upLn.Close()

	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		c, err := upLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()

		select {}
	}()

	f := NewSOCKS5ProxyDialer(Config{DialTimeout: 2 * time.Second}, upLn.Addr().String(), "", "")

	_, err = f.DialContext(ctx, "tcp", "127.0.0.1:1")
	if err == nil {
		t.Fatalf("expected error")
	}

	_ = upLn.Close()
	<-acceptDone
}

func TestSOCKS5ProxyDialerDialFail(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	lc := net.ListenConfig{}
	upLn, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upLn.Close()

	var wg sync.WaitGroup
	wg.Go(func() {
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
	})

	f := NewSOCKS5ProxyDialer(Config{DialTimeout: 2 * time.Second}, upLn.Addr().String(), "", "")

	_, err = f.DialContext(ctx, "tcp", "127.0.0.1:1")
	if err == nil {
		t.Fatalf("expected error")
	}

	_ = upLn.Close()
	wg.Wait()
}
