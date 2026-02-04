package socks5

import (
	"fmt"
	"net"
	"testing"

	"golang.org/x/sync/errgroup"
)

// TestClientDialToServer is an integration test that makes sure our SOCKS5
// client and server implementations agree on the basics of setting up a
// connection, including auth.
func TestClientDialToServer(t *testing.T) {
	tests := []struct {
		name          string
		clientAuth    Auth
		serverAuth    Auth
		serverAbort   bool
		connectRefuse bool
		wantClientErr bool
		wantServerErr bool
	}{
		{
			name: "no_auth",
		},
		{
			name:       "user_pass",
			clientAuth: Auth{Username: "user", Password: "pass"},
			serverAuth: Auth{Username: "user", Password: "pass"},
		},
		{
			name:       "client has userpath but server doesnt require",
			clientAuth: Auth{Username: "user", Password: "pass"},
		},
		{
			name:          "server requires userpass but client has none",
			serverAuth:    Auth{Username: "user", Password: "pass"},
			wantClientErr: true,
			wantServerErr: true,
		},
		{
			name:          "auth failure",
			clientAuth:    Auth{Username: "user", Password: "wrong"},
			serverAuth:    Auth{Username: "user", Password: "pass"},
			wantClientErr: true,
			wantServerErr: true,
		},
		{
			name:          "connect failure",
			connectRefuse: true,
			wantClientErr: true,
		},
		{
			name:          "server abort during negotiation",
			serverAbort:   true,
			wantClientErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			g := errgroup.Group{}
			g.Go(func() error {
				if tt.serverAbort {
					_ = serverConn.Close()
					return nil
				}

				if tt.serverAuth.Username == "" {
					if err := ServerNegotiateNoAuth(serverConn); err != nil {
						return err
					}
				} else {
					if err := ServerNegotiate(serverConn, tt.serverAuth); err != nil {
						return err
					}
				}

				req, err := ServerReadRequest(serverConn)
				if err != nil {
					return err
				}
				if req.Cmd != CmdConnect {
					return fmt.Errorf("unexpected command: %d", req.Cmd)
				}
				if tt.connectRefuse {
					WriteConnectionRefusedReply(serverConn, req.Atyp)
					return nil
				}

				return WriteSuccessReply(serverConn, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345})
			})

			clientErr := ClientDial(clientConn, tt.clientAuth, "127.0.0.1:80")
			if (clientErr != nil) != tt.wantClientErr {
				t.Fatalf("client err=%v wantErr=%v", clientErr, tt.wantClientErr)
			}

			serverErr := g.Wait()
			if (serverErr != nil) != tt.wantServerErr {
				t.Fatalf("server err=%v wantErr=%v", serverErr, tt.wantServerErr)
			}
		})
	}
}
