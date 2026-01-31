package dialer

import (
	"net"
	"time"
)

type Config struct {
	DialTimeout        time.Duration
	NegotiationTimeout time.Duration
	KeepAlive          net.KeepAliveConfig
}
