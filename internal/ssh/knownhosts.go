package ssh

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// NewHostKeyCallback creates an ssh.HostKeyCallback for the given known_hosts
// file path. If path is empty, host key checking is disabled. Otherwise, the
// callback verifies host keys against the file, automatically adding unknown
// hosts on first connection (trust on first use / TOFU).
//
// The parent directory and file are created if they don't exist.
func NewHostKeyCallback(path string) (ssh.HostKeyCallback, error) {
	if path == "" {
		return ssh.InsecureIgnoreHostKey(), nil //nolint:gosec // User explicitly disabled host key checking.
	}

	// Ensure the directory exists.
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating known_hosts directory: %w", err)
	}

	// Create the file if it doesn't exist.
	if _, err := os.Stat(path); os.IsNotExist(err) {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // Path is from user config.
		if err != nil {
			return nil, fmt.Errorf("creating known_hosts file: %w", err)
		}
		_ = f.Close()
	}

	// Load existing known hosts.
	hostKeyCallback, err := knownhosts.New(path)
	if err != nil {
		return nil, fmt.Errorf("loading known_hosts: %w", err)
	}

	// Wrap the callback to implement trust-on-first-use (TOFU).
	var mu sync.Mutex
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := hostKeyCallback(hostname, remote, key)
		if err == nil {
			return nil
		}

		// Check if this is a "key not found" error (unknown host).
		var keyErr *knownhosts.KeyError
		if !errors.As(err, &keyErr) {
			return err
		}

		// If Want is non-empty, the host exists but with a different key.
		// This is a potential MITM attack - reject it.
		if len(keyErr.Want) > 0 {
			return fmt.Errorf("host key mismatch for %s (possible MITM attack): %w", hostname, err)
		}

		// Unknown host - add it (TOFU).
		mu.Lock()
		defer mu.Unlock()

		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // Path is from user config.
		if err != nil {
			return fmt.Errorf("opening known_hosts for writing: %w", err)
		}
		defer f.Close()

		// knownhosts.Normalize normalizes the hostname for the known_hosts format.
		normalizedHost := knownhosts.Normalize(hostname)
		line := knownhosts.Line([]string{normalizedHost}, key)
		if _, err := f.WriteString(line + "\n"); err != nil {
			return fmt.Errorf("writing to known_hosts: %w", err)
		}

		log.Printf("ssh: added host key for %s to %s", hostname, path)
		return nil
	}, nil
}
