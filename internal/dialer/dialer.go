package dialer

import (
	"context"
	"net"
)

// Dialer mirrors the net.Dialer interface.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}
