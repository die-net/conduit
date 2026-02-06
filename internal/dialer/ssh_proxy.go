package dialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/singleflight"

	internalssh "github.com/die-net/conduit/internal/ssh"
)

// SSHProxyDialer forwards outbound TCP connections through an SSH server.
//
// It maintains (at most) a single shared SSH transport connection (an
// *ssh.Client) per dialer instance and multiplexes many proxied TCP
// connections over it by opening one "direct-tcpip" channel per DialContext
// call.
//
// Lifecycle notes:
//   - The SSH transport is created lazily on the first DialContext call.
//   - Each DialContext call returns a net.Conn representing a single SSH channel.
//   - Canceling the context closes only that returned channel, not the shared SSH
//     transport.
//   - If opening a channel fails (e.g. the transport is dead), the dialer will
//     discard the shared client, reconnect once, and retry the channel dial.
type SSHProxyDialer struct {
	sshAddr   string
	sshConfig internalssh.ClientConfig
	direct    Dialer

	mu     sync.Mutex
	client *ssh.Client
	sf     singleflight.Group
}

// NewSSHProxyDialer constructs a dialer that forwards connections via an SSH
// server at sshAddr.
//
// Authentication can use password, private key, or both. If both are provided,
// both methods are offered to the server and it chooses which to use. The
// private key path (cfg.SSHKeyPath) should point to an OpenSSH-format private
// key file (RSA, Ed25519, ECDSA, or DSA).
//
// Host key checking uses cfg.SSHKnownHostsPath. If set, the file is used to
// verify host keys (creating the file and parent directory if needed). Unknown
// hosts are automatically added on first connection (trust on first use). If
// empty, host key checking is disabled.
func NewSSHProxyDialer(cfg Config, sshAddr, username, password string) (Dialer, error) {
	if sshAddr == "" {
		return nil, errors.New("ssh dialer: missing ssh address")
	}
	if username == "" {
		return nil, errors.New("ssh dialer: missing username")
	}

	signers, err := internalssh.LoadSigners(cfg.SSHKeyPath)
	if err != nil {
		return nil, fmt.Errorf("ssh dialer: %w", err)
	}

	if password == "" && len(signers) == 0 {
		return nil, errors.New("ssh dialer: missing password or key")
	}

	hostKeyCallback, err := internalssh.NewHostKeyCallback(cfg.SSHKnownHostsPath)
	if err != nil {
		return nil, fmt.Errorf("ssh dialer: %w", err)
	}

	direct, err := NewDirectDialer(cfg)
	if err != nil {
		return nil, err
	}

	return &SSHProxyDialer{
		sshAddr: sshAddr,
		sshConfig: internalssh.ClientConfig{
			Username:         username,
			Password:         password,
			Signers:          signers,
			HostKeyCallback:  hostKeyCallback,
			Timeout:          cfg.DialTimeout,
			HandshakeTimeout: cfg.NegotiationTimeout,
		},
		direct: direct,
	}, nil
}

// DialContext opens a new proxied TCP connection to address.
//
// Under the hood this:
//   - establishes (or reuses) a shared SSH transport to f.sshAddr
//   - opens a "direct-tcpip" channel over that transport to the requested
//     destination
//
// Canceling ctx closes the returned connection (channel) to promptly unblock
// callers waiting on reads/writes.
func (f *SSHProxyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if !strings.HasPrefix(network, "tcp") {
		return nil, fmt.Errorf("ssh upstream dial %s %s: unsupported network", network, address)
	}

	client, err := f.getClient(ctx)
	if err != nil {
		return nil, err
	}

	upConn, err := client.DialContext(ctx, "tcp", address)
	if err != nil {
		// Distinguish channel-level errors from transport-level errors.
		// OpenChannelError means the SSH transport is healthy but the
		// destination is unreachable - don't invalidate the client.
		var openErr *ssh.OpenChannelError
		if errors.As(err, &openErr) {
			return nil, fmt.Errorf("ssh upstream dial %s: %w", address, err)
		}

		// Transport might be dead. Invalidate, reconnect once, and retry.
		f.invalidateClient()
		client, err2 := f.getClient(ctx)
		if err2 != nil {
			return nil, err
		}
		upConn, err = client.DialContext(ctx, "tcp", address)
		if err != nil {
			return nil, fmt.Errorf("ssh upstream dial %s: %w", address, err)
		}
	}

	stop := context.AfterFunc(ctx, func() {
		_ = upConn.Close()
	})
	return &sshChannelConn{Conn: upConn, stop: stop}, nil
}

// getClient returns the shared SSH client, creating it if needed.
//
// Uses singleflight to ensure only one connection attempt occurs at a time.
// Callers can bail out early if their context is canceled, while the
// connection attempt continues for other waiters.
func (f *SSHProxyDialer) getClient(ctx context.Context) (*ssh.Client, error) {
	f.mu.Lock()
	client := f.client
	f.mu.Unlock()
	if client != nil {
		return client, nil
	}

	ch := f.sf.DoChan("connect", func() (any, error) {
		// Double-check under singleflight in case a previous call just finished.
		f.mu.Lock()
		if f.client != nil {
			c := f.client
			f.mu.Unlock()
			return c, nil
		}
		f.mu.Unlock()

		// Use a background context so the connection attempt completes even if
		// the triggering caller's context is canceled. Other waiters may still
		// want the result.
		newClient, err := f.dialSSH(context.Background())
		if err != nil {
			return nil, err
		}

		f.mu.Lock()
		f.client = newClient
		f.mu.Unlock()
		return newClient, nil
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

// dialSSH establishes a new SSH transport connection and returns an *ssh.Client.
//
// It uses f.direct to create the underlying TCP connection.
func (f *SSHProxyDialer) dialSSH(ctx context.Context) (*ssh.Client, error) {
	conn, err := f.direct.DialContext(ctx, "tcp", f.sshAddr)
	if err != nil {
		return nil, fmt.Errorf("ssh transport dial: %w", err)
	}

	// Close conn if ctx is canceled during handshake.
	stop := context.AfterFunc(ctx, func() {
		_ = conn.Close()
	})
	defer stop()

	client, err := internalssh.NewClient(conn, f.sshConfig, f.sshAddr)
	if err != nil {
		return nil, fmt.Errorf("ssh transport: %w", err)
	}

	return client, nil
}

// invalidateClient discards the currently cached shared SSH client (if any) and
// closes it.
//
// This is used when dialing a new channel fails, under the assumption the
// transport may be unhealthy.
func (f *SSHProxyDialer) invalidateClient() {
	f.mu.Lock()
	client := f.client
	f.client = nil
	f.mu.Unlock()
	if client != nil {
		_ = client.Close()
	}
}

// sshChannelConn wraps a single SSH "direct-tcpip" channel connection.
//
// Closing the conn stops the context cancellation hook and then closes the
// underlying channel.
type sshChannelConn struct {
	net.Conn
	stop func() bool
}

// Close closes the underlying SSH channel.
func (c *sshChannelConn) Close() error {
	if c.stop != nil {
		c.stop()
	}
	return c.Conn.Close()
}
