package dialer

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/txthinking/socks5"

	"github.com/die-net/conduit/internal/testutil"
)

func TestSOCKS5ProxyDialerDialSuccess(t *testing.T) {
	tests := []struct {
		name string
		user string
		pass string
	}{
		{name: "no_auth"},
		{name: "user_pass", user: "user", pass: "pass"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			echoLn := testutil.StartEchoTCPServer(t, ctx)
			defer echoLn.Close()

			upLn, waitUp := testutil.StartSingleAcceptServer(t, ctx, func(c net.Conn) {
				_ = handleSOCKS5Connect(ctx, c, tt.user, tt.pass)
			})

			f := NewSOCKS5ProxyDialer(Config{DialTimeout: 2 * time.Second}, upLn.Addr().String(), tt.user, tt.pass)

			conn, err := f.DialContext(ctx, "tcp", echoLn.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()

			testutil.AssertEcho(t, conn, conn, []byte("hello"))

			waitUp()
		})
	}
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

	upLn, waitUp := testutil.StartSingleAcceptServer(t, ctx, func(c net.Conn) {
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

	_, err := f.DialContext(ctx, "tcp", "127.0.0.1:1")
	if err == nil {
		t.Fatalf("expected error")
	}

	waitUp()
}

func handleSOCKS5Connect(ctx context.Context, c net.Conn, user, pass string) error {
	if _, err := socks5.NewNegotiationRequestFrom(c); err != nil {
		return err
	}

	if user == "" && pass == "" {
		if _, err := socks5.NewNegotiationReply(socks5.MethodNone).WriteTo(c); err != nil {
			return err
		}
	} else {
		if _, err := socks5.NewNegotiationReply(socks5.MethodUsernamePassword).WriteTo(c); err != nil {
			return err
		}

		urq, err := socks5.NewUserPassNegotiationRequestFrom(c)
		if err != nil {
			return err
		}
		if string(urq.Uname) != user || string(urq.Passwd) != pass {
			_, _ = socks5.NewUserPassNegotiationReply(socks5.UserPassStatusFailure).WriteTo(c)
			return nil
		}
		if _, err := socks5.NewUserPassNegotiationReply(socks5.UserPassStatusSuccess).WriteTo(c); err != nil {
			return err
		}
	}

	req, err := socks5.NewRequestFrom(c)
	if err != nil {
		return err
	}
	if req.Cmd != socks5.CmdConnect {
		_, _ = socks5.NewReply(socks5.RepCommandNotSupported, socks5.ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00}).WriteTo(c)
		return nil
	}

	d := net.Dialer{}
	dst, err := d.DialContext(ctx, "tcp", req.Address())
	if err != nil {
		_, _ = socks5.NewReply(socks5.RepHostUnreachable, socks5.ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00}).WriteTo(c)
		return nil
	}
	defer dst.Close()

	a, addr, port, err := socks5.ParseAddress(dst.LocalAddr().String())
	if err != nil {
		return err
	}
	if a == socks5.ATYPDomain {
		addr = addr[1:]
	}
	if _, err := socks5.NewReply(socks5.RepSuccess, a, addr, port).WriteTo(c); err != nil {
		return err
	}

	go func() {
		_, _ = io.Copy(dst, c)
		_ = dst.Close()
	}()
	_, _ = io.Copy(c, dst)

	return nil
}
