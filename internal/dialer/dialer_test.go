package dialer

import (
	"reflect"
	"testing"

	"github.com/die-net/conduit/internal/ssh"
)

func TestNew(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		upstream string
		wantType any
		wantErr  bool
	}{
		{
			name:     "direct",
			upstream: "direct://",
			wantType: &directDialer{},
		},
		{
			name:     "http default port",
			upstream: "http://proxy.example",
			wantType: &HTTPProxyDialer{},
		},
		{
			name:     "https default port",
			upstream: "https://proxy.example",
			wantType: &HTTPProxyDialer{},
		},
		{
			name:     "socks5 default port",
			upstream: "socks5://proxy.example",
			wantType: &SOCKS5ProxyDialer{},
		},
		{
			name:     "ssh default port",
			upstream: "ssh://user:pass@ssh.example",
			wantType: &ssh.Client{},
		},
		{
			name:     "scheme case-insensitive",
			upstream: "HTTp://proxy.example:80",
			wantType: &HTTPProxyDialer{},
		},
		{
			name:     "leading/trailing spaces are invalid",
			upstream: "  http://proxy.example:80 ",
			wantErr:  true,
		},
		{
			name:     "unsupported scheme",
			upstream: "gopher://example.com",
			wantErr:  true,
		},
		{
			name:     "missing scheme",
			upstream: "example.com:80",
			wantErr:  true,
		},
		{
			name:     "missing host",
			upstream: "http://",
			wantErr:  true,
		},
		{
			name:     "too few slashes",
			upstream: "http:/example.com",
			wantErr:  true,
		},
		{
			name:     "non-empty path",
			upstream: "http://example.com/foo",
			wantErr:  true,
		},
		{
			name:     "ssh missing username",
			upstream: "ssh://:pass@ssh.example:22",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := New(Config{}, tt.upstream)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if d == nil {
				t.Fatal("got nil dialer")
			}
			if tt.wantType != nil {
				gotType := reflect.TypeOf(d)
				wantType := reflect.TypeOf(tt.wantType)
				if gotType != wantType {
					t.Fatalf("got %s want %s", gotType, wantType)
				}
			}
		})
	}
}
