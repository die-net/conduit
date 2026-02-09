package ssh

import (
	"net"
	"strings"
	"testing"
)

func TestNewClientValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		addr    string
		config  ClientConfig
		wantErr string
	}{
		{
			name:    "missing address",
			addr:    "",
			config:  ClientConfig{Username: "user", Password: "pass"},
			wantErr: "missing ssh address",
		},
		{
			name:    "missing username",
			addr:    "localhost:22",
			config:  ClientConfig{Password: "pass"},
			wantErr: "missing username",
		},
		{
			name:    "missing auth method",
			addr:    "localhost:22",
			config:  ClientConfig{Username: "user"},
			wantErr: "missing password or key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := NewClient(tt.addr, tt.config, &net.Dialer{})
			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}
