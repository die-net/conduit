package dialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Dialer mirrors the net.Dialer interface.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// New parses upstream and constructs the appropriate outbound Dialer.
//
// Supported schemes:
//   - direct://
//   - http://[user:pass@]host:port
//   - https://[user:pass@]host:port
//   - socks5://[user:pass@]host:port
//   - ssh://user:pass@host:port
//
// For schemes that require a host, a default port is applied if the URL host is
// missing a port.
func New(cfg Config, upstream string) (Dialer, error) {
	u, err := url.Parse(upstream)
	if err != nil {
		return nil, fmt.Errorf("invalid url: %w", err)
	}

	u.Scheme = strings.ToLower(u.Scheme)

	if u.Path != "" && u.Path != "/" {
		return nil, errors.New("invalid URL: path should be empty")
	}

	switch u.Scheme {
	case "":
		return nil, errors.New("invalid url: missing scheme")
	case "direct":
		return NewDirectDialer(cfg)
	case "http", "https", "socks5", "ssh":
		if host := u.Hostname(); host != "" && u.Port() == "" {
			u.Host = net.JoinHostPort(host, defaultPortForScheme(u.Scheme))
		}

		var user, pass string
		if u.User != nil {
			user = u.User.Username()
			pass, _ = u.User.Password()
		}

		switch u.Scheme {
		case "http", "https":
			return NewHTTPProxyDialer(cfg, u, user, pass)
		case "socks5":
			return NewSOCKS5ProxyDialer(cfg, u.Host, user, pass)
		case "ssh":
			return NewSSHProxyDialer(cfg, u.Host, user, pass)
		default:
			return nil, errors.New("unreachable url scheme")
		}
	default:
		return nil, fmt.Errorf("invalid url scheme: %q", u.Scheme)
	}
}

func defaultPortForScheme(scheme string) string {
	switch scheme {
	case "http":
		return "80"
	case "https":
		return "443"
	case "socks5":
		return "1080"
	case "ssh":
		return "22"
	default:
		return ""
	}
}
