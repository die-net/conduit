package dialer

// Package dialer provides outbound dialing implementations used by conduit.
//
// Dialers implement a small interface (DialContext) and are used by proxy
// listeners to establish outbound connections either directly or via an
// upstream proxy (HTTP CONNECT, SOCKS5, or SSH).
