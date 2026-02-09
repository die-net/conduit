package dialer

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTPProxyDialer dials outbound TCP connections via an HTTP or HTTPS proxy
// using the HTTP CONNECT method.
type HTTPProxyDialer struct {
	cfg      Config
	proxyURL *url.URL
	auth     string
	direct   ContextDialer
}

// NewHTTPProxyDialer constructs an HTTP CONNECT dialer for proxyURL.
//
// If username is non-empty, Proxy-Authorization is set using HTTP Basic auth.
func NewHTTPProxyDialer(cfg Config, proxyURL *url.URL, username, password string) (ContextDialer, error) {
	if proxyURL == nil {
		return nil, errors.New("http proxy dialer: missing proxy url")
	}
	if proxyURL.Hostname() == "" {
		return nil, errors.New("http proxy dialer: invalid proxy host")
	}
	if proxyURL.Scheme != "http" && proxyURL.Scheme != "https" {
		return nil, fmt.Errorf("http proxy dialer: unsupported scheme: %q", proxyURL.Scheme)
	}

	direct, err := NewDirectDialer(cfg)
	if err != nil {
		return nil, err
	}

	auth := ""
	if username != "" {
		auth = "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
	}

	return &HTTPProxyDialer{
		cfg:      cfg,
		proxyURL: proxyURL,
		auth:     auth,
		direct:   direct,
	}, nil
}

// ProxyAddr returns the proxy host:port.
func (f *HTTPProxyDialer) ProxyAddr() string {
	return f.proxyURL.Host
}

// ProxyURL returns the configured proxy URL.
func (f *HTTPProxyDialer) ProxyURL() *url.URL {
	return f.proxyURL
}

// Direct returns the underlying direct dialer used to reach the proxy.
func (f *HTTPProxyDialer) Direct() ContextDialer {
	return f.direct
}

// DialContext establishes a TCP connection to address via the configured
// HTTP/HTTPS proxy, returned as a net.Conn.
//
// For HTTPS proxies, this performs a TLS handshake to the proxy before sending
// CONNECT.
//
// CONNECT negotiation is performed synchronously before returning.
//
// If NegotiationTimeout is set, a deadline is applied during TLS and
// CONNECT negotiation and cleared before returning.
func (f *HTTPProxyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if !strings.HasPrefix(network, "tcp") {
		return nil, fmt.Errorf("http proxy dial %s %s: unsupported network", network, address)
	}

	c, err := f.direct.DialContext(ctx, network, f.proxyURL.Host)
	if err != nil {
		return nil, fmt.Errorf("http proxy: %w", err)
	}

	if strings.EqualFold(f.proxyURL.Scheme, "https") {
		hostname := f.proxyURL.Hostname()
		tlsConn := tls.Client(c, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: hostname})
		if f.cfg.NegotiationTimeout > 0 {
			_ = tlsConn.SetDeadline(time.Now().Add(f.cfg.NegotiationTimeout))
		}
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = tlsConn.Close()
			return nil, fmt.Errorf("http proxy connect tls handshake: %w", err)
		}
		c = tlsConn
	}

	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: address},
		Host:   address,
		Header: make(http.Header),
	}
	if f.auth != "" {
		req.Header.Set("Proxy-Authorization", f.auth)
	}

	if f.cfg.NegotiationTimeout > 0 {
		_ = c.SetDeadline(time.Now().Add(f.cfg.NegotiationTimeout))
	}

	if err := req.Write(c); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("http proxy connect write: %w", err)
	}

	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("http proxy connect read: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		_ = c.Close()
		return nil, fmt.Errorf("http proxy connect failed: %s", resp.Status)
	}

	if f.cfg.NegotiationTimeout > 0 {
		_ = c.SetDeadline(time.Time{})
	}
	return c, nil
}
