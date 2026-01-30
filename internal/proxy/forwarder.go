package proxy

import (
	"context"
	"net"
)

type Forwarder interface {
	Dial(ctx context.Context, network, address string) (net.Conn, error)
}
