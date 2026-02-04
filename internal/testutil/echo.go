package testutil

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
)

// StartEchoTCPServer starts a TCP listener on 127.0.0.1:0.
//
// The server accepts connections, reads up to 1024 bytes, and writes back
// exactly what it read.
//
// The returned wait func closes the listener and waits for the handler
// goroutine(s) to exit.
func StartEchoTCPServer(ctx context.Context, t *testing.T) (net.Listener, func()) {
	t.Helper()

	return StartAcceptServer(ctx, t, func(c net.Conn) {
		buf := make([]byte, 1024)
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		_, _ = c.Write(buf[:n])
	})
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
