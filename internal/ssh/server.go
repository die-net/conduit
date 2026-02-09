package ssh

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"
)

// Server is an SSH server that supports TCP tunneling via direct-tcpip channels.
//
// This implements the server-side of SSH dynamic port forwarding, allowing
// clients to open "direct-tcpip" channels to forward TCP connections through
// the SSH server to arbitrary destinations.
type Server struct {
	config   *ssh.ServerConfig
	listener net.Listener
	dialer   ContextDialer

	mu       sync.Mutex
	closed   bool
	wg       sync.WaitGroup
	shutdown chan struct{}
}

// ServerConfig holds configuration for the SSH server.
type ServerConfig struct {
	// HostKeys are the server's private host key(s). At least one is required.
	HostKeys []ssh.Signer

	// PasswordCallback authenticates users by password. At least one of
	// PasswordCallback or PublicKeyCallback must be set.
	PasswordCallback func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error)

	// PublicKeyCallback authenticates users by public key.
	PublicKeyCallback func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error)

	// Dialer is used to establish outbound connections for direct-tcpip channels.
	// If nil, a default net.Dialer is used.
	Dialer ContextDialer
}

// directTCPIPPayload is the payload for direct-tcpip channel requests.
type directTCPIPPayload struct {
	Host       string
	Port       uint32
	OriginHost string
	OriginPort uint32
}

// NewServer creates a new SSH tunnel server listening on the given address.
//
// The server accepts SSH connections and handles "direct-tcpip" channel requests
// by dialing the requested destination and proxying data bidirectionally.
func NewServer(addr string, cfg ServerConfig) (*Server, error) {
	if cfg.PasswordCallback == nil && cfg.PublicKeyCallback == nil {
		return nil, errors.New("ssh server: at least one auth callback required")
	}

	sshConfig := &ssh.ServerConfig{
		PasswordCallback:  cfg.PasswordCallback,
		PublicKeyCallback: cfg.PublicKeyCallback,
	}

	if len(cfg.HostKeys) == 0 {
		return nil, errors.New("ssh server: at least one host key required")
	}
	for _, key := range cfg.HostKeys {
		sshConfig.AddHostKey(key)
	}

	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("ssh server listen: %w", err)
	}

	dialer := cfg.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}

	s := &Server{
		config:   sshConfig,
		listener: ln,
		dialer:   dialer,
		shutdown: make(chan struct{}),
	}

	return s, nil
}

// Addr returns the server's listen address.
func (s *Server) Addr() net.Addr {
	return s.listener.Addr()
}

// Serve accepts and handles SSH connections until the server is closed.
//
// This method blocks until Close is called or an unrecoverable error occurs.
func (s *Server) Serve(ctx context.Context) error {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return fmt.Errorf("ssh server accept: %w", err)
		}

		s.wg.Go(func() {
			s.handleConn(ctx, conn)
		})
	}
}

// Close stops accepting new connections and waits for existing connections to finish.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.shutdown)
	s.mu.Unlock()

	err := s.listener.Close()
	s.wg.Wait()
	return err
}

// handleConn handles a single SSH connection.
func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.config)
	if err != nil {
		return
	}
	defer sshConn.Close()

	// Discard global requests (we don't support any).
	go ssh.DiscardRequests(reqs)

	// Merge context cancellation with server shutdown.
	// Close the SSH connection when shutdown is requested to unblock the
	// channel loop below.
	ctx, cancel := context.WithCancel(ctx)
	context.AfterFunc(ctx, func() {
		_ = sshConn.Close()
	})

	go func() {
		select {
		case <-ctx.Done():
		case <-s.shutdown:
			cancel()
		}
	}()

	var wg sync.WaitGroup
	for newChan := range chans {
		if newChan.ChannelType() != "direct-tcpip" {
			_ = newChan.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}

		wg.Go(func() {
			s.handleDirectTCPIP(ctx, newChan)
		})
	}
	wg.Wait()
}

// handleDirectTCPIP handles a direct-tcpip channel request.
func (s *Server) handleDirectTCPIP(ctx context.Context, newChan ssh.NewChannel) {
	var payload directTCPIPPayload
	if err := ssh.Unmarshal(newChan.ExtraData(), &payload); err != nil {
		_ = newChan.Reject(ssh.Prohibited, "invalid direct-tcpip payload")
		return
	}

	addr := net.JoinHostPort(payload.Host, fmt.Sprint(payload.Port))
	dst, err := s.dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		_ = newChan.Reject(ssh.ConnectionFailed, fmt.Sprintf("dial %s: %v", addr, err))
		return
	}

	ch, reqs, err := newChan.Accept()
	if err != nil {
		_ = dst.Close()
		return
	}

	// Discard channel-specific requests.
	go ssh.DiscardRequests(reqs)

	// Proxy data bidirectionally.
	go func() {
		defer ch.Close()
		defer dst.Close()

		done := make(chan struct{}, 2)

		go func() {
			_, _ = io.Copy(dst, ch)
			done <- struct{}{}
		}()

		go func() {
			_, _ = io.Copy(ch, dst)
			done <- struct{}{}
		}()

		// Wait for one direction to finish, then close both.
		<-done
	}()
}

// generateHostKey generates a random RSA host key for the server.
func generateHostKey() (ssh.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(key)
}

// SimplePasswordAuth returns a PasswordCallback that authenticates against
// a single username/password pair.
func SimplePasswordAuth(username, password string) func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
		if conn.User() != username || string(pass) != password {
			return nil, errors.New("invalid credentials")
		}
		return &ssh.Permissions{}, nil
	}
}

// ListenAndServe is a convenience function that creates a server and starts serving.
//
// It blocks until ctx is canceled or an error occurs.
func ListenAndServe(ctx context.Context, addr string, cfg ServerConfig) error {
	srv, err := NewServer(addr, cfg)
	if err != nil {
		return err
	}

	context.AfterFunc(ctx, func() {
		_ = srv.Close()
	})

	return srv.Serve(ctx)
}
