package ssh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/die-net/conduit/internal/testutil"
)

func TestClientServerIntegration(t *testing.T) {
	t.Parallel()

	// Generate test keys for auth and host key verification.
	serverHostKey := mustGenerateKey(t)
	clientKey := mustGenerateKey(t)
	wrongClientKey := mustGenerateKey(t)
	wrongHostKey := mustGenerateKey(t)

	tests := []struct {
		name         string
		serverConfig func() ServerConfig
		clientConfig func(serverAddr string) ClientConfig
		wantConnErr  string // Error substring expected from DialContext (empty = success)
	}{
		// Password authentication tests
		{
			name: "password auth success",
			serverConfig: func() ServerConfig {
				return ServerConfig{
					HostKeys:         []ssh.Signer{serverHostKey},
					PasswordCallback: SimplePasswordAuth("user", "correctpass"),
				}
			},
			clientConfig: func(_ string) ClientConfig {
				return ClientConfig{
					Username:        "user",
					Password:        "correctpass",
					HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // Test.
				}
			},
		},
		{
			name: "password auth wrong password",
			serverConfig: func() ServerConfig {
				return ServerConfig{
					HostKeys:         []ssh.Signer{serverHostKey},
					PasswordCallback: SimplePasswordAuth("user", "correctpass"),
				}
			},
			clientConfig: func(_ string) ClientConfig {
				return ClientConfig{
					Username:        "user",
					Password:        "wrongpass",
					HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // Test.
				}
			},
			wantConnErr: "unable to authenticate",
		},
		{
			name: "password auth wrong username",
			serverConfig: func() ServerConfig {
				return ServerConfig{
					HostKeys:         []ssh.Signer{serverHostKey},
					PasswordCallback: SimplePasswordAuth("user", "pass"),
				}
			},
			clientConfig: func(_ string) ClientConfig {
				return ClientConfig{
					Username:        "wronguser",
					Password:        "pass",
					HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // Test.
				}
			},
			wantConnErr: "unable to authenticate",
		},

		// Public key authentication tests
		{
			name: "pubkey auth success",
			serverConfig: func() ServerConfig {
				return ServerConfig{
					HostKeys:          []ssh.Signer{serverHostKey},
					PublicKeyCallback: publicKeyAuth(clientKey.PublicKey()),
				}
			},
			clientConfig: func(_ string) ClientConfig {
				return ClientConfig{
					Username:        "user",
					Signers:         []ssh.Signer{clientKey},
					HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // Test.
				}
			},
		},
		{
			name: "pubkey auth wrong key",
			serverConfig: func() ServerConfig {
				return ServerConfig{
					HostKeys:          []ssh.Signer{serverHostKey},
					PublicKeyCallback: publicKeyAuth(clientKey.PublicKey()),
				}
			},
			clientConfig: func(_ string) ClientConfig {
				return ClientConfig{
					Username:        "user",
					Signers:         []ssh.Signer{wrongClientKey},
					HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // Test.
				}
			},
			wantConnErr: "unable to authenticate",
		},

		// Host key verification tests
		{
			name: "host key verification success",
			serverConfig: func() ServerConfig {
				return ServerConfig{
					HostKeys:         []ssh.Signer{serverHostKey},
					PasswordCallback: SimplePasswordAuth("user", "pass"),
				}
			},
			clientConfig: func(_ string) ClientConfig {
				return ClientConfig{
					Username:        "user",
					Password:        "pass",
					HostKeyCallback: fixedHostKey(serverHostKey.PublicKey()),
				}
			},
		},
		{
			name: "host key verification mismatch",
			serverConfig: func() ServerConfig {
				return ServerConfig{
					HostKeys:         []ssh.Signer{serverHostKey},
					PasswordCallback: SimplePasswordAuth("user", "pass"),
				}
			},
			clientConfig: func(_ string) ClientConfig {
				return ClientConfig{
					Username:        "user",
					Password:        "pass",
					HostKeyCallback: fixedHostKey(wrongHostKey.PublicKey()),
				}
			},
			wantConnErr: "host key mismatch",
		},

		// Combined authentication tests
		{
			name: "password and key offered, server accepts password",
			serverConfig: func() ServerConfig {
				return ServerConfig{
					HostKeys:         []ssh.Signer{serverHostKey},
					PasswordCallback: SimplePasswordAuth("user", "pass"),
					// No PublicKeyCallback - server only accepts password
				}
			},
			clientConfig: func(_ string) ClientConfig {
				return ClientConfig{
					Username:        "user",
					Password:        "pass",
					Signers:         []ssh.Signer{clientKey},     // Also offer key
					HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // Test.
				}
			},
		},
		{
			name: "password and key offered, server accepts key",
			serverConfig: func() ServerConfig {
				return ServerConfig{
					HostKeys:          []ssh.Signer{serverHostKey},
					PublicKeyCallback: publicKeyAuth(clientKey.PublicKey()),
					// No PasswordCallback - server only accepts key
				}
			},
			clientConfig: func(_ string) ClientConfig {
				return ClientConfig{
					Username:        "user",
					Password:        "wrongpass", // Wrong password, but key is correct
					Signers:         []ssh.Signer{clientKey},
					HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // Test.
				}
			},
		},
		{
			name: "server requires key but client only has password",
			serverConfig: func() ServerConfig {
				return ServerConfig{
					HostKeys:          []ssh.Signer{serverHostKey},
					PublicKeyCallback: publicKeyAuth(clientKey.PublicKey()),
					// No PasswordCallback
				}
			},
			clientConfig: func(_ string) ClientConfig {
				return ClientConfig{
					Username:        "user",
					Password:        "pass",
					HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // Test.
				}
			},
			wantConnErr: "unable to authenticate",
		},
		{
			name: "server requires password but client only has key",
			serverConfig: func() ServerConfig {
				return ServerConfig{
					HostKeys:         []ssh.Signer{serverHostKey},
					PasswordCallback: SimplePasswordAuth("user", "pass"),
					// No PublicKeyCallback
				}
			},
			clientConfig: func(_ string) ClientConfig {
				return ClientConfig{
					Username:        "user",
					Signers:         []ssh.Signer{clientKey},
					HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // Test.
				}
			},
			wantConnErr: "unable to authenticate",
		},

		// Both auth methods accepted by server
		{
			name: "server accepts both, client uses password",
			serverConfig: func() ServerConfig {
				return ServerConfig{
					HostKeys:          []ssh.Signer{serverHostKey},
					PasswordCallback:  SimplePasswordAuth("user", "pass"),
					PublicKeyCallback: publicKeyAuth(clientKey.PublicKey()),
				}
			},
			clientConfig: func(_ string) ClientConfig {
				return ClientConfig{
					Username:        "user",
					Password:        "pass",
					HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // Test.
				}
			},
		},
		{
			name: "server accepts both, client uses key",
			serverConfig: func() ServerConfig {
				return ServerConfig{
					HostKeys:          []ssh.Signer{serverHostKey},
					PasswordCallback:  SimplePasswordAuth("user", "pass"),
					PublicKeyCallback: publicKeyAuth(clientKey.PublicKey()),
				}
			},
			clientConfig: func(_ string) ClientConfig {
				return ClientConfig{
					Username:        "user",
					Signers:         []ssh.Signer{clientKey},
					HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // Test.
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			// Start echo server for tunnel destination.
			echoLn, echoStop := testutil.StartEchoTCPServer(ctx, t)
			defer echoStop()

			// Start SSH server.
			sshSrv, err := NewServer("127.0.0.1:0", tt.serverConfig())
			if err != nil {
				t.Fatalf("NewServer: %v", err)
			}
			defer sshSrv.Close()

			go func() {
				_ = sshSrv.Serve(ctx)
			}()

			// Create client.
			clientCfg := tt.clientConfig(sshSrv.Addr().String())
			clientCfg.DialTimeout = 2 * time.Second
			clientCfg.NegotiationTimeout = 2 * time.Second

			client, err := NewClient(sshSrv.Addr().String(), clientCfg, &net.Dialer{})
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			defer client.Close()

			// Try to establish a tunnel.
			conn, err := client.DialContext(ctx, "tcp", echoLn.Addr().String())

			if tt.wantConnErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got success", tt.wantConnErr)
				}
				if !strings.Contains(err.Error(), tt.wantConnErr) {
					t.Fatalf("expected error containing %q, got: %v", tt.wantConnErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("DialContext: %v", err)
			}
			defer conn.Close()

			// Verify tunnel works.
			testutil.AssertEcho(t, conn, conn, []byte("integration-test"))
		})
	}
}

func TestClientServerMultipleChannels(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hostKey := mustGenerateKey(t)

	echoLn, echoStop := testutil.StartEchoTCPServer(ctx, t)
	defer echoStop()

	sshSrv, err := NewServer("127.0.0.1:0", ServerConfig{
		HostKeys:         []ssh.Signer{hostKey},
		PasswordCallback: SimplePasswordAuth("user", "pass"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sshSrv.Close()

	go func() {
		_ = sshSrv.Serve(ctx)
	}()

	client, err := NewClient(sshSrv.Addr().String(), ClientConfig{
		Username:           "user",
		Password:           "pass",
		HostKeyCallback:    ssh.InsecureIgnoreHostKey(), //nolint:gosec // Test.
		DialTimeout:        2 * time.Second,
		NegotiationTimeout: 2 * time.Second,
	}, &net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// Open multiple channels on the same SSH connection.
	for i := range 5 {
		conn, err := client.DialContext(ctx, "tcp", echoLn.Addr().String())
		if err != nil {
			t.Fatalf("channel %d: %v", i, err)
		}
		testutil.AssertEcho(t, conn, conn, []byte("channel-test"))
		_ = conn.Close()
	}
}

func TestClientServerChannelToUnreachable(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hostKey := mustGenerateKey(t)

	sshSrv, err := NewServer("127.0.0.1:0", ServerConfig{
		HostKeys:         []ssh.Signer{hostKey},
		PasswordCallback: SimplePasswordAuth("user", "pass"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sshSrv.Close()

	go func() {
		_ = sshSrv.Serve(ctx)
	}()

	client, err := NewClient(sshSrv.Addr().String(), ClientConfig{
		Username:           "user",
		Password:           "pass",
		HostKeyCallback:    ssh.InsecureIgnoreHostKey(), //nolint:gosec // Test.
		DialTimeout:        2 * time.Second,
		NegotiationTimeout: 2 * time.Second,
	}, &net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// Try to open a channel to an unreachable destination.
	// Use a port that's unlikely to be listening.
	_, err = client.DialContext(ctx, "tcp", "127.0.0.1:1")
	if err == nil {
		t.Fatal("expected error dialing unreachable destination")
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Logf("got error: %v (expected connection refused)", err)
	}

	// The SSH transport should still be healthy - verify by opening
	// a successful channel to a listening port.
	echoLn, echoStop := testutil.StartEchoTCPServer(ctx, t)
	defer echoStop()

	conn, err := client.DialContext(ctx, "tcp", echoLn.Addr().String())
	if err != nil {
		t.Fatalf("expected transport to remain healthy: %v", err)
	}
	defer conn.Close()
	testutil.AssertEcho(t, conn, conn, []byte("still-works"))
}

// mustGenerateKey generates an Ed25519 key for testing.
func mustGenerateKey(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// publicKeyAuth returns a PublicKeyCallback that accepts only the given public key.
func publicKeyAuth(allowed ssh.PublicKey) func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
	return func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if bytes.Equal(key.Marshal(), allowed.Marshal()) {
			return &ssh.Permissions{}, nil
		}
		return nil, errors.New("key not authorized")
	}
}

// fixedHostKey returns a HostKeyCallback that only accepts the given host key.
func fixedHostKey(expected ssh.PublicKey) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if bytes.Equal(key.Marshal(), expected.Marshal()) {
			return nil
		}
		return errors.New("host key mismatch")
	}
}
