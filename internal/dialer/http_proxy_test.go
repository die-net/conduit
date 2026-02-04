package dialer

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/die-net/conduit/internal/testutil"
)

func TestHTTPProxyDialerDialSuccess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	echoLn := testutil.StartEchoTCPServer(ctx, t)
	defer echoLn.Close()

	upLn, waitUp := testutil.StartSingleAcceptServer(ctx, t, func(c net.Conn) {
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

	testutil.AssertEcho(t, conn, conn, []byte("hello"))

	waitUp()
}

func TestHTTPProxyDialerDialAuthHeader(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	gotAuth := make(chan string, 1)

	upLn, waitUp := testutil.StartSingleAcceptServer(ctx, t, func(c net.Conn) {
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
		t.Fatal("timed out waiting for proxy auth header")
	}

	waitUp()
}

func TestHTTPProxyDialerDialNon2xx(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	upLn, waitUp := testutil.StartSingleAcceptServer(ctx, t, func(c net.Conn) {
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
		t.Fatal("expected error")
	}

	waitUp()
}
