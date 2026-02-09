package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/singleflight"
)

// ContextDialer is the interface for establishing TCP connections, used by Client
// to connect to the SSH server.
type ContextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

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
	// Timeout is the maximum time for the TCP connection.
	DialTimeout time.Duration
	// NegotiationTimeout is the deadline for the SSH handshake. Zero means no timeout.
	NegotiationTimeout time.Duration
}

// AuthMethods returns the ssh.AuthMethod slice for this configuration.
// Public key authentication is offered first if available, followed by password.
func (c *ClientConfig) AuthMethods() ([]ssh.AuthMethod, error) {
	if c.Username == "" {
		return nil, errors.New("missing username")
	}

	var methods []ssh.AuthMethod
	if len(c.Signers) > 0 {
		methods = append(methods, ssh.PublicKeys(c.Signers...))
	}
	if c.Password != "" {
		methods = append(methods, ssh.Password(c.Password))
	}
	if len(methods) == 0 {
		return nil, errors.New("missing password or key")
	}
	return methods, nil
}

// Client manages a persistent SSH connection with automatic reconnection.
//
// It maintains (at most) a single shared SSH transport connection and
// multiplexes many proxied TCP connections over it by opening one
// "direct-tcpip" channel per DialContext call.
//
// Lifecycle notes:
//   - The SSH transport is created lazily on the first DialContext call.
//   - Each DialContext call returns a net.Conn representing a single SSH channel.
//   - Canceling the context closes only that returned channel, not the shared SSH
//     transport.
//   - If opening a channel fails (e.g. the transport is dead), the client will
//     discard the transport, reconnect once, and retry the channel dial.
type Client struct {
	addr   string
	config ClientConfig
	dialer ContextDialer

	mu        sync.Mutex
	sshClient *ssh.Client
	sf        singleflight.Group
}

// NewClient creates a new SSH client that will connect to the given address.
//
// The actual SSH connection is established lazily on the first DialContext call.
// The dialer is used to establish the underlying TCP connection to the SSH server.
func NewClient(addr string, config ClientConfig, dialer ContextDialer) (*Client, error) {
	if addr == "" {
		return nil, errors.New("missing ssh address")
	}

	_, err := config.AuthMethods()
	if err != nil {
		return nil, err
	}

	return &Client{
		addr:   addr,
		config: config,
		dialer: dialer,
	}, nil
}

// DialContext opens a new proxied TCP connection to the given address through
// the SSH server.
//
// Under the hood this:
//   - establishes (or reuses) a shared SSH transport
//   - opens a "direct-tcpip" channel over that transport to the requested
//     destination
//
// Canceling ctx closes the returned connection (channel) to promptly unblock
// callers waiting on reads/writes. Only TCP networks are supported.
func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if !strings.HasPrefix(network, "tcp") {
		return nil, fmt.Errorf("ssh dial %s %s: unsupported network", network, address)
	}

	client, err := c.getTransport(ctx)
	if err != nil {
		return nil, err
	}

	conn, err := client.DialContext(ctx, "tcp", address)
	if err != nil {
		// Distinguish channel-level errors from transport-level errors.
		// OpenChannelError means the SSH transport is healthy but the
		// destination is unreachable - don't invalidate the client.
		var openErr *ssh.OpenChannelError
		if errors.As(err, &openErr) {
			return nil, fmt.Errorf("ssh dial %s: %w", address, err)
		}

		// Transport might be dead. Close, reconnect once, and retry.
		_ = c.Close()
		client, err2 := c.getTransport(ctx)
		if err2 != nil {
			return nil, err
		}

		conn, err = client.DialContext(ctx, "tcp", address)
		if err != nil {
			return nil, fmt.Errorf("ssh dial %s: %w", address, err)
		}
	}

	stop := context.AfterFunc(ctx, func() {
		_ = conn.Close()
	})
	return &channelConn{Conn: conn, stop: stop}, nil
}

// Close closes the SSH transport connection if one is established.
func (c *Client) Close() error {
	c.mu.Lock()
	client := c.sshClient
	c.sshClient = nil
	c.mu.Unlock()

	if client != nil {
		return client.Close()
	}
	return nil
}

// getTransport returns the shared SSH transport client, creating it if
// needed.
//
// Uses singleflight around newTransport to ensure only one connection
// attempt occurs at a time.  Callers can bail out early if their context is
// canceled, while the connection attempt continues for other waiters.
func (c *Client) getTransport(ctx context.Context) (*ssh.Client, error) {
	c.mu.Lock()
	client := c.sshClient
	c.mu.Unlock()
	if client != nil {
		return client, nil
	}

	ch := c.sf.DoChan("connect", func() (any, error) {
		// Double-check under singleflight in case a previous call just finished.
		c.mu.Lock()
		client := c.sshClient
		c.mu.Unlock()
		if client != nil {
			return client, nil
		}

		// Use a background context so the connection attempt completes even if
		// the triggering caller's context is canceled. Other waiters may still
		// want the result.
		client, err := c.newTransport(context.Background())
		if err != nil {
			return nil, err
		}

		c.mu.Lock()
		c.sshClient = client
		c.mu.Unlock()
		return client, nil
	})

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		if res.Err != nil {
			return nil, res.Err
		}
		return res.Val.(*ssh.Client), nil
	}
}

// newTransport establishes a new SSH transport connection and returns an
// *ssh.Client.
func (c *Client) newTransport(ctx context.Context) (*ssh.Client, error) {
	conn, err := c.dialer.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return nil, fmt.Errorf("ssh transport dial %s: %w", c.addr, err)
	}

	auth, err := c.config.AuthMethods()
	if err != nil {
		return nil, err
	}

	// Close conn if ctx is canceled during handshake.
	stop := context.AfterFunc(ctx, func() {
		_ = conn.Close()
	})
	defer stop()

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
		User:              c.config.Username,
		Auth:              auth,
		HostKeyCallback:   c.config.HostKeyCallback,
		HostKeyAlgorithms: preferredAlgos,
		Timeout:           c.config.DialTimeout,
	}

	if c.config.NegotiationTimeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(c.config.NegotiationTimeout))
	}

	cc, chans, reqs, err := ssh.NewClientConn(conn, c.addr, sshConfig)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ssh handshake with %s: %w", c.addr, err)
	}

	if c.config.NegotiationTimeout > 0 {
		_ = conn.SetDeadline(time.Time{})
	}

	return ssh.NewClient(cc, chans, reqs), nil
}

// channelConn wraps a single SSH "direct-tcpip" channel connection.
//
// Closing the conn stops the context cancellation hook and then closes the
// underlying channel.
type channelConn struct {
	net.Conn
	stop func() bool
}

// Close closes the underlying SSH channel.
func (c *channelConn) Close() error {
	if c.stop != nil {
		c.stop()
	}
	return c.Conn.Close()
}
