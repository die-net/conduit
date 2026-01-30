package proxy

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestHTTPProxyConnectDirect(t *testing.T) {
	// simple echo server
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
		DialTimeout:       2 * time.Second,
		HTTPHeaderTimeout: 2 * time.Second,
		Forward:           NewDirectForwarder(Config{DialTimeout: 2 * time.Second}),
	}

	ln, err := ListenTCP("tcp", "127.0.0.1:0", net.KeepAliveConfig{Enable: false})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srv := NewHTTPProxyServer(cfg, 1*time.Second)
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	req := &http.Request{Method: http.MethodConnect, Host: echoLn.Addr().String(), URL: &url.URL{Opaque: echoLn.Addr().String()}}
	bw := bufio.NewWriter(c)
	if err := req.Write(bw); err != nil {
		t.Fatal(err)
	}
	if err := bw.Flush(); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 got %d", resp.StatusCode)
	}

	_ = resp.Body.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	msg := []byte("hello")
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := br.Read(buf); err != nil {
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
