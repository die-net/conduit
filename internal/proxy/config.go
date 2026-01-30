package proxy

import (
	"net"
	"time"
)

type Config struct {
	DialTimeout       time.Duration
	IOTimeout         time.Duration
	HTTPHeaderTimeout time.Duration

	KeepAlive net.KeepAliveConfig

	Forward Forwarder
}
