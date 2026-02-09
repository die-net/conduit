//go:build freebsd

package tproxy

import (
	"context"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/die-net/conduit/internal/conn"
)

// IsSupported is true on TPROXY-supporting OSes.
const IsSupported = true

// ListenTransparentTCP listens on addr with IP_BINDANY enabled so the socket
// can accept connections redirected by IPFW fwd or PF rdr-to rules.
//
// This requires root or the PRIV_NETINET_BINDANY privilege.
//
// Note: callers still need appropriate IPFW or PF rules to redirect traffic
// to the listener.
func ListenTransparentTCP(addr string, keepAliveConfig net.KeepAliveConfig) (net.Listener, error) {
	lc := net.ListenConfig{Control: func(network, _ string, c syscall.RawConn) error {
		var ctrlErr error
		err := c.Control(func(fd uintptr) {
			// Enable IP_BINDANY to accept connections on any IP address.
			// For IPv6 sockets, use IPV6_BINDANY; for IPv4, use IP_BINDANY.
			if network == "tcp6" {
				ctrlErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BINDANY, 1)
			} else {
				ctrlErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BINDANY, 1)
			}
		})
		if err != nil {
			return err
		}
		return ctrlErr
	}}
	ln, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen tproxy %s: %w", addr, err)
	}
	return &conn.KeepAliveListener{Listener: ln, KeepAliveConfig: keepAliveConfig}, nil
}

// OriginalDst returns the original destination for a TCP connection redirected
// to this listener.
//
// On FreeBSD with IPFW fwd or PF rdr-to rules, the local address of the
// accepted connection IS the original destination address (the firewall
// preserves it during redirection).
func OriginalDst(c net.Conn) (*net.TCPAddr, bool) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return nil, false
	}
	addr, ok := tc.LocalAddr().(*net.TCPAddr)
	return addr, ok
}
