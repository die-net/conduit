package ssh

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/die-net/conduit/internal/testutil"
)

func TestClientServer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	echoLn, echoStop := testutil.StartEchoTCPServer(ctx, t)
	defer echoStop()

	hostKey, err := generateHostKey()
	if err != nil {
		t.Fatal(err)
	}

	sshSrv, err := NewServer("127.0.0.1:0", ServerConfig{
		PasswordCallback: SimplePasswordAuth("user", "pass"),
		HostKeys: []ssh.Signer{ hostKey },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sshSrv.Close()

	go func() {
		_ = sshSrv.Serve(ctx)
	}()

	nd := &net.Dialer{}
	client, err := NewClient(sshSrv.Addr().String(), ClientConfig{
		Username:           "user",
		Password:           "pass",
		HostKeyCallback:    ssh.InsecureIgnoreHostKey(), //nolint:gosec // Test server has random host key.
		DialTimeout:        2 * time.Second,
		NegotiationTimeout: 2 * time.Second,
	}, nd)
	if err != nil {
		t.Fatal(err)
	}

	c1, err := client.DialContext(ctx, "tcp", echoLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	testutil.AssertEcho(t, c1, c1, []byte("hello"))
	_ = c1.Close()

	c2, err := client.DialContext(ctx, "tcp", echoLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	testutil.AssertEcho(t, c2, c2, []byte("hello2"))
}
