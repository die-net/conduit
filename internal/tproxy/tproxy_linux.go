//go:build linux

package tproxy

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"github.com/die-net/conduit/internal/proxy"
)

// ListenTransparentTCP listens on addr and enables IP_TRANSPARENT so the socket can accept redirected
// connections (typical TPROXY setup). Note: you still need appropriate iptables/nft rules.
func ListenTransparentTCP(addr string, ka net.KeepAliveConfig) (net.Listener, error) {
	lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
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
	return &keepAliveListener{Listener: ln, ka: ka}, nil
}

type keepAliveListener struct {
	net.Listener
	ka net.KeepAliveConfig
}

func (l *keepAliveListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	proxy.ApplyKeepAlive(c, l.ka)
	return c, nil
}

// OriginalDst returns the original destination for a TCP connection redirected to this listener.
func OriginalDst(c net.Conn) (*net.TCPAddr, bool) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return nil, false
	}
	rc, err := tc.SyscallConn()
	if err != nil {
		return nil, false
	}

	var (
		addr  *net.TCPAddr
		okRet bool
	)

	_ = rc.Control(func(fd uintptr) {
		// SO_ORIGINAL_DST is 80 for IPv4 in Linux.
		// We retrieve a raw sockaddr from getsockopt.
		const soOriginalDst = 80
		var raw [128]byte
		sz := uint32(len(raw))
		_, _, e := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			uintptr(fd),
			uintptr(syscall.IPPROTO_IP),
			uintptr(soOriginalDst),
			uintptr(unsafe.Pointer(&raw[0])),
			uintptr(unsafe.Pointer(&sz)),
			0,
		)
		if e != 0 {
			return
		}
		if sz < uint32(unsafe.Sizeof(syscall.RawSockaddrInet4{})) {
			return
		}
		sa := (*syscall.RawSockaddrInet4)(unsafe.Pointer(&raw[0]))
		if sa.Family != syscall.AF_INET {
			return
		}
		port := int(sa.Port>>8)&0xff | (int(sa.Port&0xff) << 8)
		ip := net.IPv4(sa.Addr[0], sa.Addr[1], sa.Addr[2], sa.Addr[3])
		addr = &net.TCPAddr{IP: ip, Port: port}
		okRet = true
	})

	return addr, okRet
}
