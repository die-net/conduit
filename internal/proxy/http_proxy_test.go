package proxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/die-net/conduit/internal/conn"
	"github.com/die-net/conduit/internal/dialer"
	"github.com/die-net/conduit/internal/testutil"
)

func TestHTTPProxyNonConnect(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		method         string
		path           string
		requestBody    string
		wantStatusCode int
		wantBody       string
	}{
		{
			name:           "GET request",
			method:         http.MethodGet,
			path:           "/hello",
			wantStatusCode: http.StatusOK,
			wantBody:       "Hello, World!",
		},
		{
			name:           "POST request with body",
			method:         http.MethodPost,
			path:           "/echo",
			requestBody:    "request body content",
			wantStatusCode: http.StatusOK,
			wantBody:       "request body content",
		},
		{
			name:           "HEAD request",
			method:         http.MethodHead,
			path:           "/hello",
			wantStatusCode: http.StatusOK,
			wantBody:       "", // HEAD has no body
		},
		{
			name:           "404 response",
			method:         http.MethodGet,
			path:           "/notfound",
			wantStatusCode: http.StatusNotFound,
			wantBody:       "404 page not found\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			// Start upstream HTTP server.
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/hello":
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("Hello, World!"))
				case "/echo":
					body, _ := io.ReadAll(r.Body)
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write(body)
				default:
					http.NotFound(w, r)
				}
			}))
			defer upstream.Close()

			upstreamURL, err := url.Parse(upstream.URL)
			if err != nil {
				t.Fatal(err)
			}

			// Start HTTP proxy server.
			dr, err := dialer.NewDirectDialer(dialer.Config{
				DialTimeout: 2 * time.Second,
			})
			if err != nil {
				t.Fatal(err)
			}

			cfg := Config{
				NegotiationTimeout: 2 * time.Second,
				HTTPIdleTimeout:    1 * time.Second,
				Dialer:             dr,
			}

			ln, err := conn.ListenTCP("tcp", "127.0.0.1:0", net.KeepAliveConfig{Enable: false})
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()

			srv := NewHTTPProxyServer(ctx, cfg)
			go func() { _ = srv.Serve(ln) }()
			defer srv.Close()

			// Create HTTP client that uses the proxy.
			proxyURL, err := url.Parse("http://" + ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}

			tr := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
			defer tr.CloseIdleConnections()
			client := &http.Client{Transport: tr}

			// Make request through proxy.
			reqURL := upstreamURL.String() + tt.path
			var reqBody io.Reader
			if tt.requestBody != "" {
				reqBody = strings.NewReader(tt.requestBody)
			}

			req, err := http.NewRequestWithContext(ctx, tt.method, reqURL, reqBody)
			if err != nil {
				t.Fatal(err)
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.wantStatusCode {
				t.Errorf("status code: got %d, want %d", resp.StatusCode, tt.wantStatusCode)
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("reading body: %v", err)
			}

			if string(body) != tt.wantBody {
				t.Errorf("body: got %q, want %q", body, tt.wantBody)
			}
		})
	}
}

func TestHTTPProxyConnectDirect(t *testing.T) {
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
		NegotiationTimeout: 2 * time.Second,
		HTTPIdleTimeout:    1 * time.Second,
		Dialer:             dr,
	}

	ln, err := conn.ListenTCP("tcp", "127.0.0.1:0", net.KeepAliveConfig{Enable: false})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srv := NewHTTPProxyServer(context.Background(), cfg)
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	nd := net.Dialer{}
	c, err := nd.DialContext(ctx, "tcp", ln.Addr().String())
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

	testutil.AssertEcho(t, c, br, []byte("hello"))
}

func BenchmarkHTTPProxyDirect(b *testing.B) {
	b.ReportAllocs()
	b.SetBytes(1)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		b.Fatal(err)
	}

	dr, err := dialer.NewDirectDialer(dialer.Config{
		DialTimeout: 2 * time.Second,
	})
	if err != nil {
		b.Fatal(err)
	}

	cfg := Config{
		NegotiationTimeout: 2 * time.Second,
		HTTPIdleTimeout:    1 * time.Second,
		Dialer:             dr,
	}

	ln, err := conn.ListenTCP("tcp", "127.0.0.1:0", net.KeepAliveConfig{Enable: false})
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()

	srv := NewHTTPProxyServer(context.Background(), cfg)
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
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, upstreamURL.String(), http.NoBody)
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
