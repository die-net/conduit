package proxy

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

type httpUpstreamForwarder struct {
	cfg      Config
	upAddr   string
	direct   Forwarder
	deadline time.Duration
}

func NewHTTPUpstreamForwarder(cfg Config, upstreamAddr string) Forwarder {
	return &httpUpstreamForwarder{
		cfg:    cfg,
		upAddr: upstreamAddr,
		direct: NewDirectForwarder(cfg),
	}
}

func (f *httpUpstreamForwarder) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	c, err := f.direct.Dial(ctx, network, f.upAddr)
	if err != nil {
		return nil, err
	}

	// CONNECT target via HTTP proxy
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
		return nil, fmt.Errorf("http upstream connect write: %w", err)
	}
	if err := bw.Flush(); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("http upstream connect flush: %w", err)
	}

	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("http upstream connect read: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		_ = c.Close()
		return nil, fmt.Errorf("http upstream connect failed: %s", resp.Status)
	}

	// Clear deadline after handshake
	if f.cfg.IOTimeout > 0 {
		_ = c.SetDeadline(time.Time{})
	}
	return c, nil
}
