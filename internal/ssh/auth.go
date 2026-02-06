package ssh

import (
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

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
