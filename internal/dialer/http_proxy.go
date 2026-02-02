package dialer

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type HTTPProxyDialer struct {
	cfg      Config
	proxyURL *url.URL
	auth     string
	direct   Dialer
}

func NewHTTPProxyDialer(cfg Config, proxyURL *url.URL, username, password string) Dialer {
	auth := ""
	if username != "" {
		auth = "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
	}

	return &HTTPProxyDialer{
		cfg:      cfg,
		proxyURL: proxyURL,
		auth:     auth,
		direct:   NewDirectDialer(cfg),
	}
}

func (f *HTTPProxyDialer) ProxyAddr() string {
	if f.proxyURL == nil {
		return ""
	}
	return f.proxyURL.Host
}

func (f *HTTPProxyDialer) ProxyURL() *url.URL {
	return f.proxyURL
}

func (f *HTTPProxyDialer) Direct() Dialer {
	return f.direct
}

func (f *HTTPProxyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if f.proxyURL == nil {
		return nil, fmt.Errorf("http proxy connect: missing proxy url")
	}
	if network != "tcp" {
		return nil, fmt.Errorf("http proxy dial %s %s: unsupported network", network, address)
	}

	c, err := f.direct.DialContext(ctx, network, f.proxyURL.Host)
	if err != nil {
		return nil, fmt.Errorf("http proxy: %w", err)
	}

	if strings.EqualFold(f.proxyURL.Scheme, "https") {
		hostname := f.proxyURL.Hostname()
		if hostname == "" {
			_ = c.Close()
			return nil, fmt.Errorf("http proxy connect: invalid proxy host")
		}
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
