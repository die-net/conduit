package proxy

import (
	"net"
	"time"

	"github.com/die-net/conduit/internal/dialer"
)

type Config struct {
	DialTimeout       time.Duration
	IOTimeout         time.Duration
	HTTPHeaderTimeout time.Duration

	KeepAlive net.KeepAliveConfig

	Forward dialer.Dialer
}
