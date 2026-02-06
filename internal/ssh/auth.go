package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// AgentAuthType is the special value for --ssh-key to use the SSH agent.
const AgentAuthType = "agent"

// AgentAvailable returns true if the SSH agent socket is available.
func AgentAvailable() bool {
	return os.Getenv("SSH_AUTH_SOCK") != ""
}

// AgentSigners connects to the SSH agent and returns all available signers.
// Returns an error if the agent is not available or connection fails.
func AgentSigners() ([]ssh.Signer, error) {
	socket := os.Getenv("SSH_AUTH_SOCK")
	if socket == "" {
		return nil, errors.New("SSH_AUTH_SOCK not set")
	}

	var d net.Dialer
	conn, err := d.DialContext(context.Background(), "unix", socket)
	if err != nil {
		return nil, fmt.Errorf("connecting to SSH agent: %w", err)
	}
	// Note: We don't close conn here because the agent.NewClient uses it
	// for the lifetime of the signers. The connection will be closed when
	// the process exits.

	agentClient := agent.NewClient(conn)
	signers, err := agentClient.Signers()
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("getting signers from SSH agent: %w", err)
	}

	if len(signers) == 0 {
		_ = conn.Close()
		return nil, errors.New("no keys available in SSH agent")
	}

	return signers, nil
}

// LoadPrivateKey reads and parses an OpenSSH private key file.
// Supports RSA, Ed25519, ECDSA, and DSA key types.
func LoadPrivateKey(path string) (ssh.Signer, error) {
	keyData, err := os.ReadFile(path) //nolint:gosec // Path is from user config.
	if err != nil {
		return nil, fmt.Errorf("reading key file: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("parsing key file: %w", err)
	}

	return signer, nil
}

// LoadSigners loads SSH signers based on the keyPath value:
//   - "agent": connects to the SSH agent and returns all available signers
//   - "": returns nil (no key authentication)
//   - otherwise: loads the private key file at the given path
func LoadSigners(keyPath string) ([]ssh.Signer, error) {
	switch keyPath {
	case "":
		return nil, nil
	case AgentAuthType:
		return AgentSigners()
	default:
		signer, err := LoadPrivateKey(keyPath)
		if err != nil {
			return nil, err
		}
		return []ssh.Signer{signer}, nil
	}
}
