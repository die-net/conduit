package dialer

import (
	"context"
	"net"
)

type directDialer struct {
	dialer         net.Dialer
	defaultNetwork string
	keepAlive      net.KeepAliveConfig
}

func NewDirectDialer(cfg Config) Dialer {
	dd := &directDialer{
		dialer:         net.Dialer{Timeout: cfg.DialTimeout},
		defaultNetwork: defaultNetwork(),
		keepAlive:      cfg.KeepAlive,
	}
	return dd
}

func (f *directDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	// Don't bother doing DNS lookups for protocols we don't support.
	if network == "tcp" {
		network = f.defaultNetwork
	}

	// Add a "." to the end of hostnames to only look up fully-qualified
	// hostnames, disabling search-path.
	if host, port, err := net.SplitHostPort(address); err == nil && host != "" && port != "" {
		if net.ParseIP(host) == nil && host[len(host)-1:] != "." {
			address = net.JoinHostPort(host+".", port)
		}
	}

	conn, err := f.dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}

	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetKeepAliveConfig(f.keepAlive)
	}

	return conn, nil
}

// defaultNetwork checks whether only IPv4 or IPv6 is available, and returns
// "tcp4" or "tcp6" respectively if so.  Otherwise, it returns "tcp".
func defaultNetwork() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "tcp"
	}

	ipv4 := false
	ipv6 := false
	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err != nil {
			continue
		}

		if ip.To4() != nil {
			// LinkLocal is sometimes used for IPv4 NAT, so we allow it.
			ipv4 = ipv4 || ip.IsGlobalUnicast() || ip.IsLinkLocalUnicast()
		} else {
			ipv6 = ipv6 || ip.IsGlobalUnicast()
		}
	}

	switch {
	case ipv4 && !ipv6:
		return "tcp4"
	case !ipv4 && ipv6:
		return "tcp6"
	default:
		return "tcp"
	}
}
