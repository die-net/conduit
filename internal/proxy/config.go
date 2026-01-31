package proxy

import (
	"net"
	"time"

	"github.com/die-net/conduit/internal/dialer"
)

type Config struct {
	NegotiationTimeout time.Duration

	KeepAlive net.KeepAliveConfig

	Dialer dialer.Dialer
}
