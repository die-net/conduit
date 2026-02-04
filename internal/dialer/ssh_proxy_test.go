package dialer

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/errgroup"

	"github.com/die-net/conduit/internal/testutil"
)

func TestSSHProxyDialer_DialContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	echoLn1 := testutil.StartEchoTCPServer(ctx, t)
	defer echoLn1.Close()
	echoLn2 := testutil.StartEchoTCPServer(ctx, t)
	defer echoLn2.Close()

	sshLn := startSSHDynamicForwardServer(ctx, t, "user", "pass")
	defer sshLn.Close()

	d := NewSSHProxyDialer(Config{DialTimeout: 2 * time.Second, NegotiationTimeout: 2 * time.Second}, sshLn.Addr().String(), "user", "pass")

	c1, err := d.DialContext(ctx, "tcp", echoLn1.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	testutil.AssertEcho(t, c1, c1, []byte("hello"))
	_ = c1.Close()

	c2, err := d.DialContext(ctx, "tcp", echoLn2.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	testutil.AssertEcho(t, c2, c2, []byte("hello2"))
}

type directTCPIPPayload struct {
	Host       string
	Port       uint32
	OriginHost string
	OriginPort uint32
}

func startSSHDynamicForwardServer(ctx context.Context, t *testing.T, username, password string) net.Listener {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &ssh.ServerConfig{
		PasswordCallback: func(meta ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if meta.User() != username || string(pass) != password {
				return nil, errors.New("invalid credentials")
			}
			return &ssh.Permissions{}, nil
		},
	}
	cfg.AddHostKey(signer)

	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()

		_, chans, reqs, err := ssh.NewServerConn(c, cfg)
		if err != nil {
			return
		}
		go ssh.DiscardRequests(reqs)

		for newChan := range chans {
			if newChan.ChannelType() != "direct-tcpip" {
				_ = newChan.Reject(ssh.UnknownChannelType, "unsupported channel")
				continue
			}

			var p directTCPIPPayload
			if err := ssh.Unmarshal(newChan.ExtraData(), &p); err != nil {
				_ = newChan.Reject(ssh.Prohibited, "bad direct-tcpip payload")
				continue
			}

			d := net.Dialer{}
			dst, err := d.DialContext(ctx, "tcp", net.JoinHostPort(p.Host, fmt.Sprint(p.Port)))
			if err != nil {
				_ = newChan.Reject(ssh.ConnectionFailed, "dial failed")
				continue
			}

			ch, reqs, err := newChan.Accept()
			if err != nil {
				_ = dst.Close()
				continue
			}
			go ssh.DiscardRequests(reqs)

			go func() {
				defer ch.Close()
				defer dst.Close()

				g := errgroup.Group{}
				g.Go(func() error {
					_, err := io.Copy(dst, ch)
					return err
				})
				g.Go(func() error {
					_, err := io.Copy(ch, dst)
					return err
				})
				_ = g.Wait()
			}()
		}
	}()

	return ln
}
