package proxy

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/die-net/conduit/internal/dialer"
	"github.com/txthinking/socks5"
)

func TestSOCKS5ConnectDirect(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		c, _ := echoLn.Accept()
		if c == nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 1024)
		n, _ := c.Read(buf)
		_, _ = c.Write(buf[:n])
	}()

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

	srv := NewSOCKS5Server(cfg)
	go func() { _ = srv.Serve(ln) }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	client, err := socks5.NewClient(ln.Addr().String(), "", "", 2, 0)
	if err != nil {
		t.Fatal(err)
	}

	c, err := client.Dial("tcp", echoLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	msg := []byte("hello")
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("expected %q got %q", string(msg), string(buf))
	}

	select {
	case <-ctx.Done():
		// ok
	default:
	}
}
