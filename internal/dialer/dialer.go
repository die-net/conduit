package dialer

import (
	"context"
	"net"
)

type Dialer interface {
	Dial(ctx context.Context, network, address string) (net.Conn, error)
}
