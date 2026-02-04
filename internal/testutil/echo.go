package testutil

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
)

// StartEchoTCPServer starts a TCP listener on 127.0.0.1:0 and serves a single
// echo request.
//
// The server accepts exactly one connection, reads up to 1024 bytes, and writes
// back exactly what it read.
//
// The returned listener should be closed by the caller (typically via defer).
func StartEchoTCPServer(ctx context.Context, t *testing.T) net.Listener {
	t.Helper()

	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()

		buf := make([]byte, 1024)
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		_, _ = c.Write(buf[:n])
	}()

	return ln
}

// AssertEcho writes msg to w and asserts that reading from r yields the same
// bytes.
func AssertEcho(t *testing.T, w io.Writer, r io.Reader, msg []byte) {
	t.Helper()

	if _, err := w.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, msg) {
		t.Fatalf("expected %q got %q", string(msg), string(buf))
	}
}
