package proxy

import (
	"net"
	"time"

	"github.com/die-net/conduit/internal/dialer"
)

// Config configures conduit proxy listeners (HTTP and SOCKS5).
//
// It controls protocol negotiation timeouts, HTTP keepalive/idle behavior, TCP
// keepalive settings for accepted connections, and the outbound Dialer used to
// reach target destinations.
type Config struct {
	NegotiationTimeout time.Duration
	HTTPIdleTimeout    time.Duration
	HTTPMaxIdleConns   int

	KeepAlive net.KeepAliveConfig

	Dialer dialer.Dialer
}
