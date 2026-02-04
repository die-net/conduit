package socks5

import (
	"fmt"
	"net"
	"testing"

	"golang.org/x/sync/errgroup"
)

func TestClientDialToServer(t *testing.T) {
	tests := []struct {
		name string
		auth Auth
	}{
		{name: "no_auth"},
		{name: "user_pass", auth: Auth{Username: "user", Password: "pass"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			g := errgroup.Group{}
			g.Go(func() error {
				if tt.auth.Username == "" {
					if err := ServerNegotiateNoAuth(serverConn); err != nil {
						return err
					}
				} else {
					if err := ServerNegotiate(serverConn, tt.auth); err != nil {
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

				return WriteSuccessReply(serverConn, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345})
			})

			if err := ClientDial(clientConn, tt.auth, "127.0.0.1:80"); err != nil {
				t.Fatal(err)
			}
			if err := g.Wait(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
