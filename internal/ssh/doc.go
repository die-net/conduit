// Package ssh provides an SSH client for tunneling TCP connections.
//
// The [Client] type manages a persistent SSH connection with automatic
// reconnection, multiplexing many TCP connections over a single SSH transport
// using "direct-tcpip" channels. This is equivalent to SSH dynamic port
// forwarding (ssh -D).
//
// Features:
//   - Lazy connection: SSH transport is established on first use
//   - Connection pooling: single transport shared across all channel dials
//   - Automatic reconnection: transport failures trigger reconnect and retry
//   - Context cancellation: callers can cancel individual channel dials
//   - Multiple auth methods: password, private key files, SSH agent
//   - Host key verification: known_hosts with trust-on-first-use (TOFU)
//
// Example usage:
//
//	signers, _ := ssh.LoadSigners("agent")
//	hostKeyCallback, _ := ssh.NewHostKeyCallback("~/.ssh/known_hosts")
//
//	client := ssh.NewClient("ssh.example.com:22", ssh.ClientConfig{
//	    Username:        "user",
//	    Signers:         signers,
//	    HostKeyCallback: hostKeyCallback,
//	}, &net.Dialer{})
//
//	conn, err := client.DialContext(ctx, "tcp", "internal.example.com:80")
package ssh
