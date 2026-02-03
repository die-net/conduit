package socks5

import (
	"fmt"
	"net"

	txsocks5 "github.com/txthinking/socks5"
)

func ServerNegotiate(conn net.Conn, auth Auth) error {
	neg, err := txsocks5.NewNegotiationRequestFrom(conn)
	if err != nil {
		return fmt.Errorf("negotiation request: %w", err)
	}

	if auth.Username != "" {
		if !containsMethod(neg.Methods, txsocks5.MethodUsernamePassword) {
			writeNoAcceptableMethods(conn)
			return fmt.Errorf("client does not support username/password")
		}
		if _, err := txsocks5.NewNegotiationReply(txsocks5.MethodUsernamePassword).WriteTo(conn); err != nil {
			return fmt.Errorf("negotiation reply: %w", err)
		}

		urq, err := txsocks5.NewUserPassNegotiationRequestFrom(conn)
		if err != nil {
			return fmt.Errorf("read userpass: %w", err)
		}
		if string(urq.Uname) != auth.Username || string(urq.Passwd) != auth.Password {
			_, _ = txsocks5.NewUserPassNegotiationReply(txsocks5.UserPassStatusFailure).WriteTo(conn)
			return fmt.Errorf("auth failed")
		}
		if _, err := txsocks5.NewUserPassNegotiationReply(txsocks5.UserPassStatusSuccess).WriteTo(conn); err != nil {
			return fmt.Errorf("write userpass: %w", err)
		}
		return nil
	}

	if !containsMethod(neg.Methods, txsocks5.MethodNone) {
		writeNoAcceptableMethods(conn)
		return fmt.Errorf("client does not support no-auth")
	}
	if _, err := txsocks5.NewNegotiationReply(txsocks5.MethodNone).WriteTo(conn); err != nil {
		return fmt.Errorf("negotiation reply: %w", err)
	}
	return nil
}

func ServerNegotiateNoAuth(conn net.Conn) error {
	return ServerNegotiate(conn, Auth{})
}

func ServerReadRequest(conn net.Conn) (*txsocks5.Request, error) {
	req, err := txsocks5.NewRequestFrom(conn)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	return req, nil
}

func containsMethod(methods []byte, want byte) bool {
	for _, m := range methods {
		if m == want {
			return true
		}
	}
	return false
}
