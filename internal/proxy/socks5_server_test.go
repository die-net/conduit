package proxy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/txthinking/socks5"

	"github.com/die-net/conduit/internal/dialer"
	"github.com/die-net/conduit/internal/testutil"
)

func TestSOCKS5ConnectDirect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	echoLn := testutil.StartEchoTCPServer(t, ctx)
	defer echoLn.Close()

	cfg := Config{
		Dialer: dialer.NewDirectDialer(dialer.Config{
			DialTimeout: 2 * time.Second,
		}),
	}

	ln, err := ListenTCP("tcp", "127.0.0.1:0", net.KeepAliveConfig{Enable: false})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srv := NewSOCKS5Server(context.Background(), cfg, false)
	go func() { _ = srv.Serve(ln) }()

	client, err := socks5.NewClient(ln.Addr().String(), "", "", 2, 0)
	if err != nil {
		t.Fatal(err)
	}

	c, err := client.Dial("tcp", echoLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	testutil.AssertEcho(t, c, c, []byte("hello"))

	select {
	case <-ctx.Done():
		// ok
	default:
	}
}
