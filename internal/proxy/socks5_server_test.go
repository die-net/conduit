package proxy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/die-net/conduit/internal/conn"
	"github.com/die-net/conduit/internal/dialer"
	"github.com/die-net/conduit/internal/socks5"
	"github.com/die-net/conduit/internal/testutil"
)

func TestSOCKS5ConnectDirect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	echoLn, echoStop := testutil.StartEchoTCPServer(ctx, t)
	defer echoStop()

	dr, err := dialer.NewDirectDialer(dialer.Config{
		DialTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		Dialer:             dr,
		NegotiationTimeout: 2 * time.Second,
	}

	ln, err := conn.ListenTCP("tcp", "127.0.0.1:0", net.KeepAliveConfig{Enable: false})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srv := NewSOCKS5Server(context.Background(), cfg, false)
	go func() { _ = srv.Serve(ln) }()

	d := net.Dialer{}
	c, err := d.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	}
	if err := socks5.ClientDial(c, socks5.Auth{}, echoLn.Addr().String()); err != nil {
		t.Fatal(err)
	}

	testutil.AssertEcho(t, c, c, []byte("hello"))
}
