package socks5

import (
	"fmt"
	"net"

	txsocks5 "github.com/txthinking/socks5"
)

func ClientDial(conn net.Conn, auth Auth, address string) error {
	if err := ClientNegotiate(conn, auth); err != nil {
		return err
	}
	if err := ClientConnect(conn, address); err != nil {
		return err
	}
	return nil
}

func ClientNegotiate(conn net.Conn, auth Auth) error {
	methods := []byte{txsocks5.MethodNone}
	if auth.Username != "" {
		methods = append(methods, txsocks5.MethodUsernamePassword)
	}

	if _, err := txsocks5.NewNegotiationRequest(methods).WriteTo(conn); err != nil {
		return fmt.Errorf("write negotiation: %w", err)
	}

	neg, err := txsocks5.NewNegotiationReplyFrom(conn)
	if err != nil {
		return fmt.Errorf("read negotiation: %w", err)
	}

	switch neg.Method {
	case txsocks5.MethodNone:
		return nil
	case txsocks5.MethodUsernamePassword:
		if auth.Username == "" {
			return fmt.Errorf("server requires username/password")
		}

		if _, err := txsocks5.NewUserPassNegotiationRequest([]byte(auth.Username), []byte(auth.Password)).WriteTo(conn); err != nil {
			return fmt.Errorf("write userpass: %w", err)
		}
		rep, err := txsocks5.NewUserPassNegotiationReplyFrom(conn)
		if err != nil {
			return fmt.Errorf("read userpass: %w", err)
		}
		if rep.Status != txsocks5.UserPassStatusSuccess {
			return fmt.Errorf("auth failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported negotiation method: %d", neg.Method)
	}
}

func ClientConnect(conn net.Conn, address string) error {
	atyp, dstAddr, dstPort, err := txsocks5.ParseAddress(address)
	if err != nil {
		return fmt.Errorf("parse address: %w", err)
	}
	if atyp == txsocks5.ATYPDomain {
		dstAddr = dstAddr[1:]
	}

	if _, err := txsocks5.NewRequest(txsocks5.CmdConnect, atyp, dstAddr, dstPort).WriteTo(conn); err != nil {
		return fmt.Errorf("write request: %w", err)
	}

	rep, err := txsocks5.NewReplyFrom(conn)
	if err != nil {
		return fmt.Errorf("read reply: %w", err)
	}
	if rep.Rep != txsocks5.RepSuccess {
		return fmt.Errorf("connect failed")
	}
	return nil
}
