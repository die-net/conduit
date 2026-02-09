package dialer

import (
	"errors"
	"fmt"

	"github.com/die-net/conduit/internal/ssh"
)

// NewSSHProxyDialer constructs a dialer that forwards connections via an SSH
// server at sshAddr.
//
// Authentication can use password, private key, or both. If both are provided,
// both methods are offered to the server and it chooses which to use. The
// private key path (cfg.SSHKeyPath) can be:
//   - "agent": use the SSH agent (requires SSH_AUTH_SOCK)
//   - a file path: load the OpenSSH-format private key (RSA, Ed25519, ECDSA, DSA)
//   - empty: no key authentication (password required)
//
// Host key checking uses cfg.SSHKnownHostsPath. If set, the file is used to
// verify host keys (creating the file and parent directory if needed). Unknown
// hosts are automatically added on first connection (trust on first use). If
// empty, host key checking is disabled.
func NewSSHProxyDialer(cfg Config, sshAddr, username, password string) (ContextDialer, error) {
	if sshAddr == "" {
		return nil, errors.New("ssh dialer: missing ssh address")
	}
	if username == "" {
		return nil, errors.New("ssh dialer: missing username")
	}

	signers, err := ssh.LoadSigners(cfg.SSHKeyPath)
	if err != nil {
		return nil, fmt.Errorf("ssh dialer: %w", err)
	}

	if password == "" && len(signers) == 0 {
		return nil, errors.New("ssh dialer: missing password or key")
	}

	hostKeyCallback, err := ssh.NewHostKeyCallback(cfg.SSHKnownHostsPath)
	if err != nil {
		return nil, fmt.Errorf("ssh dialer: %w", err)
	}

	direct, err := NewDirectDialer(cfg)
	if err != nil {
		return nil, err
	}

	return ssh.NewClient(sshAddr, ssh.ClientConfig{
		Username:         username,
		Password:         password,
		Signers:          signers,
		HostKeyCallback:  hostKeyCallback,
		Timeout:          cfg.DialTimeout,
		HandshakeTimeout: cfg.NegotiationTimeout,
	}, direct)
}
