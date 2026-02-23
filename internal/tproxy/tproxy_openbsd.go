//go:build openbsd

package tproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/die-net/conduit/internal/conn"
)

// IsSupported is true on TPROXY-supporting OSes.
const IsSupported = true

// ListenTransparentTCP listens on addr with SO_BINDANY enabled so the socket
// can accept connections redirected by PF rdr-to rules.
//
// This requires root privileges.
//
// Note: callers still need appropriate PF rules to redirect traffic to the
// listener, and outgoing rules with divert-reply for return traffic.
func ListenTransparentTCP(addr string, keepAliveConfig net.KeepAliveConfig) (net.Listener, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var ctrlErr error
		err := c.Control(func(fd uintptr) {
			// Enable SO_BINDANY to accept connections on any IP address.
			// OpenBSD uses socket-level option (SOL_SOCKET) unlike FreeBSD's
			// protocol-level option (IPPROTO_IP).
			ctrlErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BINDANY, 1)
		})
		if err != nil {
			return err
		}
		if ctrlErr != nil {
			return fmt.Errorf("SO_BINDANY: %w (transparent proxy requires root)", ctrlErr)
		}
		return nil
	}}
	ln, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen tproxy %s: %w", addr, err)
	}
	return &conn.KeepAliveListener{Listener: ln, KeepAliveConfig: keepAliveConfig}, nil
}

var errDestUnavailable = errors.New("original destination unavailable (ensure PF rdr-to rules redirect traffic to this listener)")

// OriginalDst returns the original destination for a TCP connection redirected
// to this listener.
//
// On OpenBSD with PF rdr-to rules, the local address of the accepted connection
// IS the original destination address (PF preserves it during redirection).
func OriginalDst(c net.Conn) (*net.TCPAddr, error) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return nil, errDestUnavailable
	}

	addr, ok := tc.LocalAddr().(*net.TCPAddr)
	if !ok {
		return nil, errDestUnavailable
	}

	return addr, nil
}
