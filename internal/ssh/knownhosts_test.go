package ssh

import (
	"net"
	"os"
	"strings"
	"testing"
)

func TestNewHostKeyCallback(t *testing.T) {
	t.Parallel()

	t.Run("empty path returns insecure callback", func(t *testing.T) {
		t.Parallel()

		cb, err := NewHostKeyCallback("")
		if err != nil {
			t.Fatalf("NewHostKeyCallback: %v", err)
		}

		// Should accept any key without error.
		key := mustGenerateKey(t)
		addr := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 22}
		if err := cb("example.com:22", addr, key.PublicKey()); err != nil {
			t.Fatalf("expected insecure callback to accept any key: %v", err)
		}
	})

	t.Run("creates directory and file if missing", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		path := dir + "/subdir/known_hosts"

		cb, err := NewHostKeyCallback(path)
		if err != nil {
			t.Fatalf("NewHostKeyCallback: %v", err)
		}
		if cb == nil {
			t.Fatal("expected non-nil callback")
		}

		// Verify file was created.
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("file not created: %v", err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("expected file mode 0600, got %o", info.Mode().Perm())
		}
	})

	t.Run("TOFU adds unknown host", func(t *testing.T) {
		t.Parallel()

		path := t.TempDir() + "/known_hosts"
		cb, err := NewHostKeyCallback(path)
		if err != nil {
			t.Fatalf("NewHostKeyCallback: %v", err)
		}

		key := mustGenerateKey(t)
		addr := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 22}

		// First connection - should succeed and add the key.
		if err := cb("192.0.2.1:22", addr, key.PublicKey()); err != nil {
			t.Fatalf("TOFU should accept unknown host: %v", err)
		}

		// Verify key was written to file.
		data, err := os.ReadFile(path) //nolint:gosec // Test path from t.TempDir().
		if err != nil {
			t.Fatalf("reading known_hosts: %v", err)
		}
		if len(data) == 0 {
			t.Fatal("expected key to be written to file")
		}
		if !strings.Contains(string(data), "192.0.2.1") {
			t.Errorf("expected file to contain host, got: %s", data)
		}
	})

	t.Run("accepts known host with matching key", func(t *testing.T) {
		t.Parallel()

		path := t.TempDir() + "/known_hosts"
		cb, err := NewHostKeyCallback(path)
		if err != nil {
			t.Fatalf("NewHostKeyCallback: %v", err)
		}

		key := mustGenerateKey(t)
		addr := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 22}

		// First connection - TOFU.
		if err := cb("192.0.2.1:22", addr, key.PublicKey()); err != nil {
			t.Fatalf("TOFU: %v", err)
		}

		// Create a new callback from the same file to simulate reconnection.
		cb2, err := NewHostKeyCallback(path)
		if err != nil {
			t.Fatalf("NewHostKeyCallback (reload): %v", err)
		}

		// Second connection with same key - should succeed.
		if err := cb2("192.0.2.1:22", addr, key.PublicKey()); err != nil {
			t.Fatalf("expected known host to be accepted: %v", err)
		}
	})

	t.Run("rejects known host with different key (MITM)", func(t *testing.T) {
		t.Parallel()

		path := t.TempDir() + "/known_hosts"
		cb, err := NewHostKeyCallback(path)
		if err != nil {
			t.Fatalf("NewHostKeyCallback: %v", err)
		}

		key1 := mustGenerateKey(t)
		key2 := mustGenerateKey(t)
		addr := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 22}

		// First connection with key1 - TOFU.
		if err := cb("192.0.2.1:22", addr, key1.PublicKey()); err != nil {
			t.Fatalf("TOFU: %v", err)
		}

		// Create a new callback from the same file.
		cb2, err := NewHostKeyCallback(path)
		if err != nil {
			t.Fatalf("NewHostKeyCallback (reload): %v", err)
		}

		// Connection with different key - should be rejected.
		err = cb2("192.0.2.1:22", addr, key2.PublicKey())
		if err == nil {
			t.Fatal("expected MITM detection to reject different key")
		}
		if !strings.Contains(err.Error(), "MITM") && !strings.Contains(err.Error(), "mismatch") {
			t.Errorf("expected MITM-related error, got: %v", err)
		}
	})

	t.Run("different hosts can have different keys", func(t *testing.T) {
		t.Parallel()

		path := t.TempDir() + "/known_hosts"
		cb, err := NewHostKeyCallback(path)
		if err != nil {
			t.Fatalf("NewHostKeyCallback: %v", err)
		}

		key1 := mustGenerateKey(t)
		key2 := mustGenerateKey(t)
		addr1 := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 22}
		addr2 := &net.TCPAddr{IP: net.ParseIP("192.0.2.2"), Port: 22}

		// Add two different hosts with different keys.
		if err := cb("192.0.2.1:22", addr1, key1.PublicKey()); err != nil {
			t.Fatalf("host1: %v", err)
		}
		if err := cb("192.0.2.2:22", addr2, key2.PublicKey()); err != nil {
			t.Fatalf("host2: %v", err)
		}

		// Create a new callback and verify both are accepted.
		cb2, err := NewHostKeyCallback(path)
		if err != nil {
			t.Fatalf("NewHostKeyCallback (reload): %v", err)
		}

		if err := cb2("192.0.2.1:22", addr1, key1.PublicKey()); err != nil {
			t.Fatalf("host1 should be accepted: %v", err)
		}
		if err := cb2("192.0.2.2:22", addr2, key2.PublicKey()); err != nil {
			t.Fatalf("host2 should be accepted: %v", err)
		}
	})

	t.Run("works with existing known_hosts file", func(t *testing.T) {
		t.Parallel()

		// Create a known_hosts file with an existing entry.
		path := t.TempDir() + "/known_hosts"
		key := mustGenerateKey(t)

		// Write a known_hosts entry manually.
		line := "192.0.2.1 " + key.PublicKey().Type() + " " +
			base64Encode(key.PublicKey().Marshal()) + "\n"
		if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
			t.Fatalf("writing known_hosts: %v", err)
		}

		cb, err := NewHostKeyCallback(path)
		if err != nil {
			t.Fatalf("NewHostKeyCallback: %v", err)
		}

		addr := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 22}
		if err := cb("192.0.2.1:22", addr, key.PublicKey()); err != nil {
			t.Fatalf("expected existing entry to be accepted: %v", err)
		}
	})
}

// base64Encode encodes bytes to base64 for known_hosts format.
func base64Encode(data []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	result := make([]byte, ((len(data)+2)/3)*4)
	for i, j := 0, 0; i < len(data); i, j = i+3, j+4 {
		var val uint32
		switch len(data) - i {
		default:
			val = uint32(data[i])<<16 | uint32(data[i+1])<<8 | uint32(data[i+2])
			result[j] = alphabet[val>>18&0x3f]
			result[j+1] = alphabet[val>>12&0x3f]
			result[j+2] = alphabet[val>>6&0x3f]
			result[j+3] = alphabet[val&0x3f]
		case 2:
			val = uint32(data[i])<<16 | uint32(data[i+1])<<8
			result[j] = alphabet[val>>18&0x3f]
			result[j+1] = alphabet[val>>12&0x3f]
			result[j+2] = alphabet[val>>6&0x3f]
			result[j+3] = '='
		case 1:
			val = uint32(data[i]) << 16
			result[j] = alphabet[val>>18&0x3f]
			result[j+1] = alphabet[val>>12&0x3f]
			result[j+2] = '='
			result[j+3] = '='
		}
	}
	return string(result)
}
