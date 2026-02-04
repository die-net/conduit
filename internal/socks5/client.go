package socks5

import (
	"errors"
	"fmt"
	"net"

	txsocks5 "github.com/txthinking/socks5"
)

// ClientDial performs SOCKS5 negotiation (optionally username/password) and a
// CONNECT request to address over conn.
func ClientDial(conn net.Conn, auth Auth, address string) error {
	if err := ClientNegotiate(conn, auth); err != nil {
		return err
	}
	return ClientConnect(conn, address)
}

// ClientNegotiate performs the SOCKS5 method negotiation on conn.
//
// If auth.Username is set, the client offers username/password authentication
// and will perform that sub-negotiation if selected by the server.
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
			return errors.New("server requires username/password")
		}

		if _, err := txsocks5.NewUserPassNegotiationRequest([]byte(auth.Username), []byte(auth.Password)).WriteTo(conn); err != nil {
			return fmt.Errorf("write userpass: %w", err)
		}
		rep, err := txsocks5.NewUserPassNegotiationReplyFrom(conn)
		if err != nil {
			return fmt.Errorf("read userpass: %w", err)
		}
		if rep.Status != txsocks5.UserPassStatusSuccess {
			return errors.New("auth failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported negotiation method: %d", neg.Method)
	}
}

// ClientConnect sends a SOCKS5 CONNECT request for address over conn and reads
// the server reply.
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
		return errors.New("connect failed")
	}
	return nil
}
