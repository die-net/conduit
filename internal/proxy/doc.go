package proxy

// Package proxy implements conduit listener-side proxy servers and helpers.
//
// It contains the HTTP forward proxy (CONNECT and non-CONNECT), the SOCKS5
// server, and shared connection plumbing such as keepalive listeners and
// bidirectional copy.
