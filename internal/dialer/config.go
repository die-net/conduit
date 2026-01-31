package dialer

import (
	"net"
	"time"
)

type Config struct {
	DialTimeout time.Duration
	IOTimeout   time.Duration
	KeepAlive   net.KeepAliveConfig
}
