package ssh

import (
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestNewServerValidation(t *testing.T) {
	t.Parallel()

	hostKey := mustGenerateKey(t)

	tests := []struct {
		name    string
		config  ServerConfig
		wantErr string
	}{
		{
			name:    "missing auth callback",
			config:  ServerConfig{HostKeys: []ssh.Signer{hostKey}},
			wantErr: "at least one auth callback required",
		},
		{
			name:    "missing host key",
			config:  ServerConfig{PasswordCallback: SimplePasswordAuth("u", "p")},
			wantErr: "at least one host key required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := NewServer("127.0.0.1:0", tt.config)
			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}
