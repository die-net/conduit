package dialer

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"
)

func TestHTTPProxyDialerDialSuccess(t *testing.T) {
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

		br := bufio.NewReader(c)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		if req.Method != http.MethodConnect {
			return
		}
		target := req.Host
		_ = req.Body.Close()

		d := net.Dialer{}
		dst, err := d.DialContext(ctx, "tcp", target)
		if err != nil {
			_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
			return
		}
		defer dst.Close()

		_, _ = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")

		go func() {
			_, _ = io.Copy(dst, br)
			_ = dst.Close()
		}()
		_, _ = io.Copy(c, dst)
	})

	proxyURL, err := url.Parse("http://" + upLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	f := NewHTTPProxyDialer(Config{DialTimeout: 2 * time.Second}, proxyURL, "", "")

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

func TestHTTPProxyDialerDialAuthHeader(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	lc := net.ListenConfig{}
	upLn, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upLn.Close()

	gotAuth := make(chan string, 1)

	var wg sync.WaitGroup
	wg.Go(func() {
		c, err := upLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()

		br := bufio.NewReader(c)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		_ = req.Body.Close()
		gotAuth <- req.Header.Get("Proxy-Authorization")
		_, _ = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
	})

	proxyURL, err := url.Parse("http://user:pass@" + upLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	f := NewHTTPProxyDialer(Config{DialTimeout: 2 * time.Second}, proxyURL, "user", "pass")

	conn, err := f.DialContext(ctx, "tcp", "127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	select {
	case got := <-gotAuth:
		exp := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass"))
		if got != exp {
			t.Fatalf("expected %q got %q", exp, got)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for proxy auth header")
	}

	_ = upLn.Close()
	wg.Wait()
}

func TestHTTPProxyDialerDialNon2xx(t *testing.T) {
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

		br := bufio.NewReader(c)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		_ = req.Body.Close()

		_, _ = io.WriteString(c, "HTTP/1.1 403 Forbidden\r\n\r\n")
	})

	proxyURL, err := url.Parse("http://" + upLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	f := NewHTTPProxyDialer(Config{DialTimeout: 2 * time.Second}, proxyURL, "", "")

	_, err = f.DialContext(ctx, "tcp", "127.0.0.1:1")
	if err == nil {
		t.Fatalf("expected error")
	}

	_ = upLn.Close()
	wg.Wait()
}
