package socks5

import (
	"fmt"
	"net"

	txsocks5 "github.com/txthinking/socks5"
)

const (
	// CmdConnect is connect command
	CmdConnect = txsocks5.CmdConnect
)

type Auth struct {
	Username string
	Password string
}

func WriteCommandNotSupportedReply(conn net.Conn, atyp byte) {
	_, _ = newZeroAddrReply(txsocks5.RepCommandNotSupported, atyp).WriteTo(conn)
}

func WriteConnectionRefusedReply(conn net.Conn, atyp byte) {
	_, _ = newZeroAddrReply(txsocks5.RepConnectionRefused, atyp).WriteTo(conn)
}

func WriteSuccessReply(conn net.Conn, localAddr net.Addr) error {
	a, addr, port, err := txsocks5.ParseAddress(localAddr.String())
	if err != nil {
		return fmt.Errorf("parse local address %q: %w", localAddr.String(), err)
	}
	if a == txsocks5.ATYPDomain {
		addr = addr[1:]
	}
	if _, err := txsocks5.NewReply(txsocks5.RepSuccess, a, addr, port).WriteTo(conn); err != nil {
		return fmt.Errorf("success reply: %w", err)
	}
	return nil
}

func newZeroAddrReply(rep, atyp byte) *txsocks5.Reply {
	if atyp == txsocks5.ATYPIPv6 {
		return txsocks5.NewReply(rep, txsocks5.ATYPIPv6, []byte(net.IPv6zero), []byte{0x00, 0x00})
	}
	return txsocks5.NewReply(rep, txsocks5.ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
}

func writeNoAcceptableMethods(conn net.Conn) {
	// RFC 1928: 0xFF indicates no acceptable methods.
	_, _ = txsocks5.NewNegotiationReply(0xff).WriteTo(conn)
}
