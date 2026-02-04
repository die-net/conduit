package dialer

import (
	"net"
	"time"
)

// Config controls timeouts and TCP keepalive settings used by outbound dialers.
type Config struct {
	// DialTimeout bounds DNS lookups and TCP connect.
	DialTimeout time.Duration
	// NegotiationTimeout bounds proxy protocol handshakes performed after TCP
	// connect (for example HTTP CONNECT, SOCKS5 negotiation, or SSH setup).
	NegotiationTimeout time.Duration
	// KeepAlive controls TCP keepalive settings applied to outbound TCP sockets.
	KeepAlive net.KeepAliveConfig
}
