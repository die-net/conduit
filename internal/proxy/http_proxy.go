package proxy

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/die-net/conduit/internal/dialer"
)

type HTTPProxyServer struct {
	cfg Config
	srv *http.Server
	rp  *httputil.ReverseProxy
}

func NewHTTPProxyServer(cfg Config, idleTimeout time.Duration) *HTTPProxyServer {
	h := &HTTPProxyServer{cfg: cfg}
	h.rp = h.newReverseProxy()
	h.srv = &http.Server{
		Handler:           http.HandlerFunc(h.handle),
		ReadHeaderTimeout: cfg.HTTPHeaderTimeout,
		IdleTimeout:       idleTimeout,
	}
	return h
}

func (s *HTTPProxyServer) Serve(ln net.Listener) error {
	return s.srv.Serve(ln)
}

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
	serverConn, err := s.cfg.Forward.Dial(ctx, "tcp", target)
	if err != nil {
		_, _ = io.WriteString(brw, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		_ = brw.Flush()
		clientConn.Close()
		return
	}

	_, _ = io.WriteString(brw, "HTTP/1.1 200 Connection Established\r\n\r\n")
	_ = brw.Flush()

	_ = CopyBidirectional(ctx, clientConn, serverConn, s.cfg.IOTimeout)
}

func (s *HTTPProxyServer) newReverseProxy() *httputil.ReverseProxy {
	director := func(r *http.Request) {
		// Forward-proxy handling: ensure URL is absolute and points at the origin server.
		if r.URL == nil {
			return
		}

		if r.URL.Scheme == "" {
			r.URL.Scheme = "http"
		}
		if r.URL.Host == "" {
			r.URL.Host = r.Host
		}
		r.Host = r.URL.Host

		// Ask that X-Forwarded-For not be set.
		r.Header["X-Forwarded-For"] = nil
	}

	errHandler := func(w http.ResponseWriter, r *http.Request, _ error) {
		w.WriteHeader(http.StatusBadGateway)
	}

	return &httputil.ReverseProxy{
		Director:      director,
		Transport:     newForwardingTransport(s.cfg),
		FlushInterval: 10 * time.Millisecond, // Only buffer incomplete responses briefly
		ErrorHandler:  errHandler,
		BufferPool:    NewBufferPool(32768),
	}
}

type forwardingTransport struct {
	base http.Transport
}

var clientSessionCache = tls.NewLRUClientSessionCache(0)

func newForwardingTransport(cfg Config) http.RoundTripper {
	ft := &forwardingTransport{}

	proxyFunc := func(*http.Request) (*url.URL, error) { return nil, nil }
	dial := cfg.Forward.Dial

	// For non-CONNECT HTTP proxying, prefer the standard library proxy support when the
	// configured dialer is an HTTP proxy.
	if up, ok := cfg.Forward.(*dialer.HTTPProxyDialer); ok {
		proxyFunc = http.ProxyURL(&url.URL{Scheme: "http", Host: up.ProxyAddr()})
		// When using Transport.Proxy, DialContext is used to connect to the proxy itself.
		dial = up.Direct().Dial
	}

	ft.base = http.Transport{
		Proxy:               proxyFunc,
		DialContext:         dial,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        2048,
		MaxIdleConnsPerHost: 1024,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			ClientSessionCache: clientSessionCache,
		},
	}
	return ft
}

func (t *forwardingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return t.base.RoundTrip(r)
}
