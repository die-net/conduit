package proxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/die-net/conduit/internal/dialer"
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
		NegotiationTimeout: 2 * time.Second,
		Dialer: dialer.NewDirectDialer(dialer.Config{
			DialTimeout: 2 * time.Second,
		}),
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

func BenchmarkHTTPProxyDirect(b *testing.B) {
	b.ReportAllocs()
	b.SetBytes(1)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		b.Fatal(err)
	}

	cfg := Config{
		NegotiationTimeout: 2 * time.Second,
		Dialer: dialer.NewDirectDialer(dialer.Config{
			DialTimeout: 2 * time.Second,
		}),
	}

	ln, err := ListenTCP("tcp", "127.0.0.1:0", net.KeepAliveConfig{Enable: false})
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()

	srv := NewHTTPProxyServer(cfg, 1*time.Second)
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	proxyURL, err := url.Parse("http://" + ln.Addr().String())
	if err != nil {
		b.Fatal(err)
	}

	tr := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}
	defer tr.CloseIdleConnections()

	client := &http.Client{Transport: tr}

	b.RunParallel(func(pb *testing.PB) {
		req, err := http.NewRequest(http.MethodGet, upstreamURL.String(), nil)
		if err != nil {
			b.Fatal(err)
		}

		for pb.Next() {
			resp, err := client.Do(req)
			if err != nil {
				b.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				b.Fatalf("expected %d got %d", http.StatusOK, resp.StatusCode)
			}
		}
	})
}
