package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestSOCKS5ConnectDirect(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		c, _ := echoLn.Accept()
		if c == nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 1024)
		n, _ := c.Read(buf)
		_, _ = c.Write(buf[:n])
	}()

	cfg := Config{DialTimeout: 2 * time.Second, Forward: NewDirectForwarder(Config{DialTimeout: 2 * time.Second})}

	ln, err := ListenTCP("tcp", "127.0.0.1:0", net.KeepAliveConfig{Enable: false})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srv := NewSOCKS5Server(cfg)
	go func() { _ = srv.Serve(ln) }()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	br := bufio.NewReader(c)
	bw := bufio.NewWriter(c)

	// greeting
	_, _ = bw.Write([]byte{0x05, 0x01, 0x00})
	_ = bw.Flush()
	resp := make([]byte, 2)
	if _, err := br.Read(resp); err != nil {
		t.Fatal(err)
	}
	if resp[1] != 0x00 {
		t.Fatalf("expected noauth")
	}

	host, portStr, _ := net.SplitHostPort(echoLn.Addr().String())
	port, _ := net.LookupPort("tcp", portStr)

	// request
	_ = bw.WriteByte(0x05)
	_ = bw.WriteByte(0x01)
	_ = bw.WriteByte(0x00)
	_ = bw.WriteByte(0x01)
	_, _ = bw.Write(net.ParseIP(host).To4())
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, uint16(port))
	_, _ = bw.Write(pb)
	_ = bw.Flush()

	rep := make([]byte, 4)
	if _, err := br.Read(rep); err != nil {
		t.Fatal(err)
	}
	if rep[1] != 0x00 {
		t.Fatalf("expected success rep got %d", rep[1])
	}

	// consume bind addr+port (ipv4)
	_, _ = br.Discard(4 + 2)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	msg := []byte("hello")
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := br.Read(buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("expected %q got %q", string(msg), string(buf))
	}

	select {
	case <-ctx.Done():
		// ok
	default:
	}
}
