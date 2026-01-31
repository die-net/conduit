package dialer

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

type HTTPProxyDialer struct {
	cfg       Config
	proxyAddr string
	direct    Dialer
}

func NewHTTPProxyDialer(cfg Config, proxyAddr string) Dialer {
	return &HTTPProxyDialer{
		cfg:       cfg,
		proxyAddr: proxyAddr,
		direct:    NewDirectDialer(cfg),
	}
}

func (f *HTTPProxyDialer) ProxyAddr() string {
	return f.proxyAddr
}

func (f *HTTPProxyDialer) Direct() Dialer {
	return f.direct
}

func (f *HTTPProxyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	c, err := f.direct.DialContext(ctx, network, f.proxyAddr)
	if err != nil {
		return nil, err
	}

	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: address},
		Host:   address,
		Header: make(http.Header),
	}

	if f.cfg.IOTimeout > 0 {
		_ = c.SetDeadline(time.Now().Add(time.Duration(f.cfg.IOTimeout)))
	}

	bw := bufio.NewWriter(c)
	if err := req.Write(bw); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("http proxy connect write: %w", err)
	}
	if err := bw.Flush(); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("http proxy connect flush: %w", err)
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

	if f.cfg.IOTimeout > 0 {
		_ = c.SetDeadline(time.Time{})
	}
	return c, nil
}
