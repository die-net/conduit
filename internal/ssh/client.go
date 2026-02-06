package ssh

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// ClientConfig holds configuration for establishing an SSH client connection.
type ClientConfig struct {
	// Username for SSH authentication.
	Username string
	// Password for password authentication (optional if Signers is set).
	Password string
	// Signers for public key authentication (optional if Password is set).
	// Multiple signers are supported (e.g., from an SSH agent).
	Signers []ssh.Signer
	// HostKeyCallback verifies the server's host key.
	HostKeyCallback ssh.HostKeyCallback
	// Timeout is the maximum time for the TCP connection (used by ssh.ClientConfig).
	Timeout time.Duration
	// HandshakeTimeout is the deadline for the SSH handshake. Zero means no timeout.
	HandshakeTimeout time.Duration
}

// AuthMethods returns the ssh.AuthMethod slice for this configuration.
// Public key authentication is offered first if available, followed by password.
func (c *ClientConfig) AuthMethods() []ssh.AuthMethod {
	var methods []ssh.AuthMethod
	if len(c.Signers) > 0 {
		methods = append(methods, ssh.PublicKeys(c.Signers...))
	}
	if c.Password != "" {
		methods = append(methods, ssh.Password(c.Password))
	}
	return methods
}

// NewClient establishes an SSH client connection over the given net.Conn.
//
// The conn is typically a TCP connection to the SSH server. The addr parameter
// is used for host key verification and should match the server's address.
//
// If cfg.HandshakeTimeout is set, a deadline is applied during the SSH
// handshake and cleared before returning.
//
// On error, conn is closed.
func NewClient(conn net.Conn, cfg ClientConfig, addr string) (*ssh.Client, error) {
	// Define the preferred host key algorithms in order of preference to match modern OpenSSH.
	preferredAlgos := []string{
		ssh.KeyAlgoED25519,
		ssh.KeyAlgoECDSA521,
		ssh.KeyAlgoECDSA384,
		ssh.KeyAlgoECDSA256,
		ssh.KeyAlgoRSASHA512, // rsa-sha2-512
		ssh.KeyAlgoRSASHA256, // rsa-sha2-256
	}

	sshConfig := &ssh.ClientConfig{
		User:              cfg.Username,
		Auth:              cfg.AuthMethods(),
		HostKeyCallback:   cfg.HostKeyCallback,
		HostKeyAlgorithms: preferredAlgos,
		Timeout:           cfg.Timeout,
	}

	if cfg.HandshakeTimeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(cfg.HandshakeTimeout))
	}

	cc, chans, reqs, err := ssh.NewClientConn(conn, addr, sshConfig)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ssh handshake: %w", err)
	}

	if cfg.HandshakeTimeout > 0 {
		_ = conn.SetDeadline(time.Time{})
	}

	return ssh.NewClient(cc, chans, reqs), nil
}
