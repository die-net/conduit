package dialer

import (
	"net"
	"time"
)

// Config controls timeouts and TCP keepalive settings used by outbound dialers.
type Config struct {
	// DialTimeout bounds DNS lookups and TCP connect.
	DialTimeout time.Duration
	// NegotiationTimeout bounds proxy protocol handshakes performed after TCP
	// connect (for example HTTP CONNECT, SOCKS5 negotiation, or SSH setup).
	NegotiationTimeout time.Duration
	// KeepAlive controls TCP keepalive settings applied to outbound TCP sockets.
	KeepAlive net.KeepAliveConfig
	// SSHKeyPath is the optional path to a private key file for SSH
	// authentication (OpenSSH format). Supports RSA, Ed25519, ECDSA, and DSA.
	SSHKeyPath string
	// SSHKnownHostsPath is the path to the known_hosts file for SSH host key
	// verification. Empty string disables host key checking.
	SSHKnownHostsPath string
}
