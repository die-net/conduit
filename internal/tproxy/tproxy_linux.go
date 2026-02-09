//go:build linux

package tproxy

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/die-net/conduit/internal/conn"
)

// IsSupported is true on TPROXY-supporting OSes.
const IsSupported = true

// ListenTransparentTCP listens on addr and enables IP_TRANSPARENT so the socket
// can accept redirected connections (typical TPROXY setup).
//
// Note: callers still need appropriate iptables/nftables rules to redirect
// traffic to the listener.
func ListenTransparentTCP(addr string, keepAliveConfig net.KeepAliveConfig) (net.Listener, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var ctrlErr error
		err := c.Control(func(fd uintptr) {
			ctrlErr = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
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

// isV6 looks up the connection's local address and returns whether it is
// IPv6-capable or not.
func isV6(tc *net.TCPConn) bool {
	if la, ok := tc.LocalAddr().(*net.TCPAddr); ok {
		if la.IP != nil && la.IP.To4() == nil {
			return true
		}
	}

	return false
}

// OriginalDst returns the original destination for a TCP connection redirected
// to this listener.
//
// This relies on unix.SO_ORIGINAL_DST (getsockopt) and is supported on Linux.
func OriginalDst(c net.Conn) (*net.TCPAddr, bool) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return nil, false
	}

	rc, err := tc.SyscallConn()
	if err != nil {
		return nil, false
	}

	if isV6(tc) {
		return originalDstV6(rc)
	}

	return originalDstV4(rc)
}

func originalDstV4(rc syscall.RawConn) (*net.TCPAddr, bool) {
	success := false
	var addr *net.TCPAddr

	_ = rc.Control(func(fd uintptr) {
		// We retrieve a raw sockaddr from getsockopt.
		var raw [128]byte

		sz := uint32(len(raw))
		_, _, e := unix.Syscall6(
			unix.SYS_GETSOCKOPT,
			fd,
			uintptr(unix.IPPROTO_IP),
			uintptr(unix.SO_ORIGINAL_DST),
			uintptr(unsafe.Pointer(&raw[0])), //nolint:gosec // unsafe is needed for syscalls.
			uintptr(unsafe.Pointer(&sz)),     //nolint:gosec // unsafe is needed for syscalls.
			0,
		)
		if e != 0 || sz < uint32(unsafe.Sizeof(unix.RawSockaddrInet4{})) {
			return
		}
		sa := (*unix.RawSockaddrInet4)(unsafe.Pointer(&raw[0])) //nolint:gosec // unsafe is needed for syscalls.
		if sa.Family != unix.AF_INET {
			return
		}

		port := ntohs(sa.Port)
		ip := net.IPv4(sa.Addr[0], sa.Addr[1], sa.Addr[2], sa.Addr[3])
		addr = &net.TCPAddr{IP: ip, Port: port}
		success = true
	})

	return addr, success
}

func originalDstV6(rc syscall.RawConn) (*net.TCPAddr, bool) {
	success := false
	var addr *net.TCPAddr

	_ = rc.Control(func(fd uintptr) {
		// We retrieve a raw sockaddr from getsockopt.
		var raw [128]byte

		sz := uint32(len(raw))
		_, _, e := unix.Syscall6(
			unix.SYS_GETSOCKOPT,
			fd,
			uintptr(unix.IPPROTO_IPV6),
			uintptr(unix.SO_ORIGINAL_DST),
			uintptr(unsafe.Pointer(&raw[0])), //nolint:gosec // unsafe is needed for syscalls.
			uintptr(unsafe.Pointer(&sz)),     //nolint:gosec // unsafe is needed for syscalls.
			0,
		)
		if e != 0 || sz < uint32(unsafe.Sizeof(unix.RawSockaddrInet6{})) {
			return
		}
		sa := (*unix.RawSockaddrInet6)(unsafe.Pointer(&raw[0])) //nolint:gosec // unsafe is needed for syscalls.
		if sa.Family != unix.AF_INET6 {
			return
		}
		port := ntohs(sa.Port)
		ip := make(net.IP, net.IPv6len)
		copy(ip, sa.Addr[:])

		zone := ""
		if sa.Scope_id != 0 {
			if ifi, err := net.InterfaceByIndex(int(sa.Scope_id)); err == nil {
				zone = ifi.Name
			}
		}

		addr = &net.TCPAddr{IP: ip, Port: port, Zone: zone}
		success = true
	})

	return addr, success
}

func ntohs(p uint16) int {
	return int(p>>8)&0xff | (int(p&0xff) << 8)
}
