package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof" //nolint:gosec // Intentionally exposed on debug port.
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/pflag"
	"golang.org/x/sync/errgroup"

	"github.com/die-net/conduit/internal/conn"
	"github.com/die-net/conduit/internal/dialer"
	"github.com/die-net/conduit/internal/proxy"
	"github.com/die-net/conduit/internal/ssh"
	"github.com/die-net/conduit/internal/tproxy"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	var (
		httpListen   = pflag.String("http-listen", "", "HTTP proxy listen address (e.g. 127.0.0.1:8080). Empty disables.")
		socksListen  = pflag.String("socks5-listen", "", "SOCKS5 proxy listen address (e.g. 127.0.0.1:1080). Empty disables.")
		tproxyListen = pflag.String("tproxy-listen", "", "Transparent proxy listen address (e.g. 127.0.0.1:1234). Empty disables.")

		upstream = pflag.String("upstream", defaultUpstream(), "Upstream forwarding target URL: direct:// | http://[user:pass@]host:port | https://[user:pass@]host:port | socks5://[user:pass@]host:port | ssh://user[:pass]@host:port")

		debugListen        = pflag.String("debug-listen", "", "Debug HTTP listen address exposing /debug/pprof (e.g. 127.0.0.1:6060). Empty disables.")
		dialTimeout        = pflag.Duration("dial-timeout", 10*time.Second, "Timeout for outbound DNS lookup and TCP connect")
		httpIdleTimeout    = pflag.Duration("http-idle-timeout", 4*time.Minute, "Timeout for idle HTTP proxy connections")
		httpMaxIdleConns   = pflag.Int("http-max-idle-conns", 100, "Maximum number of idle HTTP proxy connections")
		negotiationTimeout = pflag.Duration("negotiation-timeout", 10*time.Second, "Timeout for protocol negotiation to set up connection")
		sshKeyPath         = pflag.String("ssh-key", defaultSSHKeyPath(), "SSH key source: 'agent' for SSH agent, path to private key file, or empty to disable")
		sshKnownHosts      = pflag.String("ssh-known-hosts", defaultSSHKnownHostsPath(), "Path to known_hosts file for SSH host key verification, or empty to disable")
		tcpKeepAlive       = pflag.String("tcp-keepalive", "45:45:3", "TCP keepalive: on|off|keepidle:keepintvl:keepcnt")
		verbose            = pflag.Bool("verbose", false, "Enable per-connection error logging")
	)

	if !tproxy.IsSupported {
		_ = pflag.CommandLine.MarkHidden("tproxy-listen")
	}

	pflag.CommandLine.SortFlags = false
	pflag.Parse()

	ka, err := parseTCPKeepAlive(*tcpKeepAlive)
	if err != nil {
		return fmt.Errorf("invalid --tcp-keepalive: %w", err)
	}

	if *httpListen == "" && *socksListen == "" && *tproxyListen == "" {
		return errors.New("no listeners enabled (set at least one of --http-listen, --socks5-listen, --tproxy-listen)")
	}

	cfg := proxy.Config{
		NegotiationTimeout: *negotiationTimeout,
		HTTPIdleTimeout:    *httpIdleTimeout,
		HTTPMaxIdleConns:   *httpMaxIdleConns,
		KeepAlive:          ka,
	}

	dialCfg := dialer.Config{
		DialTimeout:        *dialTimeout,
		NegotiationTimeout: cfg.NegotiationTimeout,
		KeepAlive:          cfg.KeepAlive,
		SSHKeyPath:         *sshKeyPath,
		SSHKnownHostsPath:  *sshKnownHosts,
	}

	cfg.Dialer, err = dialer.New(dialCfg, *upstream)
	if err != nil {
		return fmt.Errorf("invalid --upstream: %w", err)
	}

	g, ctx := errgroup.WithContext(context.Background())

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *debugListen != "" {
		debugSrv := &http.Server{Handler: http.DefaultServeMux} //nolint:gosec // Not concerned about timeouts on debug port.
		lc := net.ListenConfig{KeepAliveConfig: cfg.KeepAlive}
		debugLn, err := lc.Listen(ctx, "tcp", *debugListen)
		if err != nil {
			return fmt.Errorf("debug listen: %w", err)
		}
		context.AfterFunc(ctx, func() {
			_ = debugSrv.Close()
			_ = debugLn.Close()
		})

		g.Go(func() error {
			if err := debugSrv.Serve(debugLn); err != nil {
				return fmt.Errorf("debug serve: %w", err)
			}
			return nil
		})
		log.Printf("debug listening on %s", *debugListen)
	}

	if *httpListen != "" {
		ln, err := conn.ListenTCP("tcp", *httpListen, cfg.KeepAlive)
		if err != nil {
			return fmt.Errorf("http listen: %w", err)
		}
		srv := proxy.NewHTTPProxyServer(ctx, cfg)
		context.AfterFunc(ctx, func() {
			_ = srv.Close()
			_ = ln.Close()
		})

		g.Go(func() error {
			if err := srv.Serve(ln); err != nil {
				return fmt.Errorf("http proxy serve: %w", err)
			}
			return nil
		})
		log.Printf("http proxy listening on %s", *httpListen)
	}

	if *socksListen != "" {
		ln, err := conn.ListenTCP("tcp", *socksListen, cfg.KeepAlive)
		if err != nil {
			return fmt.Errorf("socks5 listen: %w", err)
		}
		s5 := proxy.NewSOCKS5Server(ctx, cfg, *verbose)
		context.AfterFunc(ctx, func() {
			_ = ln.Close()
		})

		g.Go(func() error {
			if err := s5.Serve(ln); err != nil {
				return fmt.Errorf("socks5 serve: %w", err)
			}
			return nil
		})

		log.Printf("socks5 proxy listening on %s", *socksListen)
	}

	if *tproxyListen != "" {
		ln, err := tproxy.ListenTransparentTCP(*tproxyListen, cfg.KeepAlive)
		if err != nil {
			return fmt.Errorf("tproxy listen: %w", err)
		}
		tsrv := tproxy.NewServer(ctx, cfg, *verbose)
		context.AfterFunc(ctx, func() {
			_ = ln.Close()
		})

		g.Go(func() error {
			if err := tsrv.Serve(ln); err != nil {
				return fmt.Errorf("tproxy serve: %w", err)
			}
			return nil
		})
		log.Printf("tproxy listening on %s", *tproxyListen)
	}

	err = g.Wait()
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}

	log.Print("shutting down")
	return err
}

func parseTCPKeepAlive(s string) (net.KeepAliveConfig, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return net.KeepAliveConfig{}, errors.New("empty")
	}
	if s == "on" {
		return net.KeepAliveConfig{Enable: true}, nil
	}
	if s == "off" {
		return net.KeepAliveConfig{Enable: false}, nil
	}

	parts := strings.Split(s, ":")
	if len(parts) != 3 {
		return net.KeepAliveConfig{}, errors.New("expected on|off|keepidle:keepintvl:keepcnt")
	}
	keepIdle, err := parsePositiveSeconds(parts[0])
	if err != nil {
		return net.KeepAliveConfig{}, fmt.Errorf("keepidle: %w", err)
	}
	keepIntvl, err := parsePositiveSeconds(parts[1])
	if err != nil {
		return net.KeepAliveConfig{}, fmt.Errorf("keepintvl: %w", err)
	}
	keepCnt, err := parsePositiveInt(parts[2])
	if err != nil {
		return net.KeepAliveConfig{}, fmt.Errorf("keepcnt: %w", err)
	}

	return net.KeepAliveConfig{
		Enable:   true,
		Idle:     keepIdle,
		Interval: keepIntvl,
		Count:    keepCnt,
	}, nil
}

func parsePositiveSeconds(s string) (time.Duration, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, err
	}
	if n <= 0 {
		return 0, errors.New("must be > 0")
	}
	return time.Duration(n) * time.Second, nil
}

func parsePositiveInt(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, err
	}
	if n <= 0 {
		return 0, errors.New("must be > 0")
	}
	return n, nil
}

func defaultUpstream() string {
	if p := os.Getenv("ALL_PROXY"); p != "" {
		return p
	}

	if p := os.Getenv("all_proxy"); p != "" {
		return p
	}

	return "direct://"
}

func defaultSSHKnownHostsPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".ssh", "known_hosts")
}

func defaultSSHKeyPath() string {
	if ssh.AgentAvailable() {
		return ssh.AgentAuthType
	}
	return ""
}
