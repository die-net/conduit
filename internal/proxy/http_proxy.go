package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/die-net/conduit/internal/conn"
	"github.com/die-net/conduit/internal/dialer"
)

// HTTPProxyServer serves an HTTP forward proxy.
//
// It supports:
// - HTTP CONNECT tunneling (via connection hijacking + bidirectional copy)
// - non-CONNECT proxying (via httputil.ReverseProxy)
type HTTPProxyServer struct {
	ctx    context.Context
	dialer dialer.ContextDialer
	srv    *http.Server
	rp     *httputil.ReverseProxy
}

// NewHTTPProxyServer constructs an HTTP proxy server with the given config.
//
// Serve starts accepting connections on a listener; Close stops the underlying
// http.Server.
func NewHTTPProxyServer(ctx context.Context, cfg Config) *HTTPProxyServer {
	if ctx == nil {
		ctx = context.Background()
	}
	h := &HTTPProxyServer{ctx: ctx, dialer: cfg.Dialer, rp: newReverseProxy(cfg)}
	h.srv = &http.Server{
		Handler:           http.HandlerFunc(h.handle),
		ReadHeaderTimeout: cfg.NegotiationTimeout,
		IdleTimeout:       cfg.HTTPIdleTimeout,
		BaseContext: func(net.Listener) context.Context {
			return h.ctx
		},
	}
	return h
}

// Serve serves HTTP proxy requests on ln.
func (s *HTTPProxyServer) Serve(ln net.Listener) error {
	return s.srv.Serve(ln)
}

// Close stops the HTTP server.
func (s *HTTPProxyServer) Close() error {
	return s.srv.Close()
}

func (s *HTTPProxyServer) handle(w http.ResponseWriter, r *http.Request) {
	if strings.EqualFold(r.Method, http.MethodConnect) {
		s.handleConnect(w, r)
		return
	}
	s.rp.ServeHTTP(w, r)
}

func (s *HTTPProxyServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, brw, err := hj.Hijack()
	if err != nil {
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		return
	}
	_ = brw.Flush()

	target := r.Host
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(target, "443")
	}

	ctx := r.Context()

	serverConn, err := s.dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		_, _ = writeError(brw, err, 502)
		_ = brw.Flush()
		_ = clientConn.Close()
		return
	}

	_, _ = brw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	_ = brw.Flush()

	_ = conn.CopyBidirectional(ctx, clientConn, serverConn)
}

// writeError simulates http.Error() for use on a hijacked connection.
func writeError(brw *bufio.ReadWriter, err error, code int) (int, error) {
	return fmt.Fprintf(brw, "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n%s\r\n", code, http.StatusText(code), err.Error())
}

func newReverseProxy(cfg Config) *httputil.ReverseProxy {
	rewrite := func(pr *httputil.ProxyRequest) {
		out := pr.Out
		if out.URL == nil {
			return
		}
		// Forward-proxy handling: ensure URL is absolute and points at the origin server.
		// Allow schema override via non-standard header. If not supplied, port 443 implies https.
		if s, ok := out.Header["X-Proxy-Scheme"]; ok && len(s) > 0 {
			out.Header.Del("X-Proxy-Scheme")
			out.URL.Scheme = s[0]
		} else if out.URL.Port() == "443" {
			out.URL.Scheme = "https"
		} else if out.URL.Scheme == "" {
			out.URL.Scheme = "http"
		}
		if out.URL.Host == "" {
			out.URL.Host = pr.In.Host
		}
		out.Host = out.URL.Host
		// Do not call SetXForwarded(); we do not add X-Forwarded-* headers.
	}

	errHandler := func(w http.ResponseWriter, _ *http.Request, err error) {
		http.Error(w, err.Error(), http.StatusBadGateway)
	}

	return &httputil.ReverseProxy{
		Rewrite:       rewrite,
		Transport:     newTransport(cfg),
		FlushInterval: 10 * time.Millisecond, // Only buffer incomplete responses briefly
		ErrorHandler:  errHandler,
		BufferPool:    NewBufferPool(32768),
	}
}

func newTransport(cfg Config) http.RoundTripper {
	t := &http.Transport{
		DialContext:         cfg.Dialer.DialContext,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        cfg.HTTPMaxIdleConns,
		MaxIdleConnsPerHost: (cfg.HTTPMaxIdleConns + 1) / 2,
		IdleConnTimeout:     cfg.HTTPIdleTimeout,
		TLSHandshakeTimeout: cfg.NegotiationTimeout,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			ClientSessionCache: tls.NewLRUClientSessionCache(0),
		},
	}

	// For non-CONNECT HTTP proxying, prefer the standard library proxy support when the
	// configured dialer is an HTTP proxy.
	if up, ok := cfg.Dialer.(*dialer.HTTPProxyDialer); ok {
		t.Proxy = http.ProxyURL(up.ProxyURL())
		// When using Transport.Proxy, DialContext is used to connect to the proxy itself.
		t.DialContext = up.Direct().DialContext
	}

	return t
}
