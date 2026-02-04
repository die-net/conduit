package dialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
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
	cfg      Config
	sshAddr  string
	username string
	password string
	direct   Dialer

	mu     sync.Mutex
	client *ssh.Client
}

// NewSSHProxyDialer constructs a dialer that forwards connections via an SSH
// server at sshAddr.
//
// The ssh server credentials come from username/password. Host key checking is
// currently disabled (ssh.InsecureIgnoreHostKey), so this should only be used
// in trusted environments.
func NewSSHProxyDialer(cfg Config, sshAddr, username, password string) Dialer {
	return &SSHProxyDialer{cfg: cfg, sshAddr: sshAddr, username: username, password: password, direct: NewDirectDialer(cfg)}
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
	if strings.TrimSpace(f.sshAddr) == "" {
		return nil, errors.New("ssh upstream: missing ssh address")
	}
	if f.username == "" {
		return nil, errors.New("ssh upstream: missing username")
	}

	client, err := f.getClient(ctx)
	if err != nil {
		return nil, err
	}

	upConn, err := client.Dial("tcp", address)
	if err != nil {
		// If the shared SSH client is dead, reconnect once and retry.
		f.invalidateClient()
		client, err2 := f.getClient(ctx)
		if err2 != nil {
			return nil, fmt.Errorf("ssh upstream dial: %w", err)
		}
		upConn, err = client.Dial("tcp", address)
		if err != nil {
			return nil, fmt.Errorf("ssh upstream dial: %w", err)
		}
	}

	stop := context.AfterFunc(ctx, func() {
		_ = upConn.Close()
	})
	return &sshChannelConn{Conn: upConn, stop: stop}, nil
}

// getClient returns the shared SSH client, creating it if needed.
//
// If multiple goroutines race to create the initial SSH connection, only one is
// retained and the others are closed.
func (f *SSHProxyDialer) getClient(ctx context.Context) (*ssh.Client, error) {
	f.mu.Lock()
	client := f.client
	f.mu.Unlock()
	if client != nil {
		return client, nil
	}

	newClient, err := f.dialSSH(ctx)
	if err != nil {
		return nil, err
	}

	f.mu.Lock()
	if f.client != nil {
		// Another goroutine won the race. Keep the existing one and discard ours.
		_ = newClient.Close()
		client = f.client
		f.mu.Unlock()
		return client, nil
	}
	f.client = newClient
	f.mu.Unlock()
	return newClient, nil
}

// dialSSH establishes a new SSH transport connection and returns an *ssh.Client.
//
// It uses f.direct to create the underlying TCP connection and applies
// f.cfg.NegotiationTimeout as a deadline for the SSH handshake.
func (f *SSHProxyDialer) dialSSH(ctx context.Context) (*ssh.Client, error) {
	c, err := f.direct.DialContext(ctx, "tcp", f.sshAddr)
	if err != nil {
		return nil, fmt.Errorf("ssh upstream: %w", err)
	}

	stop := context.AfterFunc(ctx, func() {
		_ = c.Close()
	})
	defer stop()

	clientConfig := &ssh.ClientConfig{
		User:            f.username,
		Auth:            []ssh.AuthMethod{ssh.Password(f.password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // TODO: Fix me, as this is insecure.
		Timeout:         f.cfg.DialTimeout,
	}

	if f.cfg.NegotiationTimeout > 0 {
		_ = c.SetDeadline(time.Now().Add(f.cfg.NegotiationTimeout))
	}

	cc, chans, reqs, err := ssh.NewClientConn(c, f.sshAddr, clientConfig)
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("ssh upstream connect: %w", err)
	}
	client := ssh.NewClient(cc, chans, reqs)

	if f.cfg.NegotiationTimeout > 0 {
		_ = c.SetDeadline(time.Time{})
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
