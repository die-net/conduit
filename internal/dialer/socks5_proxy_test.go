package dialer

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/die-net/conduit/internal/socks5"
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

			echoLn := testutil.StartEchoTCPServer(ctx, t)
			defer echoLn.Close()

			upLn, waitUp := testutil.StartSingleAcceptServer(ctx, t, func(c net.Conn) {
				var auth socks5.Auth
				if tt.user != "" {
					auth = socks5.Auth{Username: tt.user, Password: tt.pass}
				}
				if err := socks5.ServerNegotiate(c, auth); err != nil {
					return
				}
				req, err := socks5.ServerReadRequest(c)
				if err != nil {
					return
				}
				if req.Cmd != 0x01 {
					socks5.WriteCommandNotSupportedReply(c, req.Atyp)
					return
				}

				d := net.Dialer{}
				dst, err := d.DialContext(ctx, "tcp", req.Address())
				if err != nil {
					socks5.WriteConnectionRefusedReply(c, req.Atyp)
					return
				}
				defer dst.Close()

				if err := socks5.WriteSuccessReply(c, dst.LocalAddr()); err != nil {
					return
				}

				go func() {
					_, _ = io.Copy(dst, c)
					_ = dst.Close()
				}()
				_, _ = io.Copy(c, dst)
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
		t.Fatal("expected error")
	}

	_ = upLn.Close()
	<-acceptDone
}

func TestSOCKS5ProxyDialerDialFail(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	upLn, waitUp := testutil.StartSingleAcceptServer(ctx, t, func(c net.Conn) {
		if err := socks5.ServerNegotiateNoAuth(c); err != nil {
			return
		}
		req, err := socks5.ServerReadRequest(c)
		if err != nil {
			return
		}
		socks5.WriteConnectionRefusedReply(c, req.Atyp)
	})

	f := NewSOCKS5ProxyDialer(Config{DialTimeout: 2 * time.Second}, upLn.Addr().String(), "", "")

	_, err := f.DialContext(ctx, "tcp", "127.0.0.1:1")
	if err == nil {
		t.Fatal("expected error")
	}

	waitUp()
}
