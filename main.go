package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/pflag"

	"github.com/die-net/conduit/internal/dialer"
	"github.com/die-net/conduit/internal/proxy"
	"github.com/die-net/conduit/internal/tproxy"
)

func main() {
	var (
		httpListen   = pflag.String("http-listen", "", "HTTP proxy listen address (e.g. 127.0.0.1:8080). Empty disables.")
		socksListen  = pflag.String("socks5-listen", "", "SOCKS5 proxy listen address (e.g. 127.0.0.1:1080). Empty disables.")
		tproxyListen = pflag.String("tproxy-listen", "", "Transparent proxy listen address (Linux only). Empty disables.")
		debugListen  = pflag.String("debug-listen", "", "Debug HTTP listen address exposing /debug/pprof (e.g. 127.0.0.1:6060). Empty disables.")

		upstreamMode = pflag.String("upstream-mode", "direct", "Forwarding mode: direct|http|socks5")
		upstreamAddr = pflag.String("upstream-addr", "", "Upstream proxy address (IP:port) for upstream-mode http or socks5")

		dialTimeout       = pflag.Duration("dial-timeout", 10*time.Second, "Timeout for outbound TCP dials")
		ioTimeout         = pflag.Duration("io-timeout", 4*time.Minute, "If non-zero, set per-connection read/write deadlines to now+io-timeout")
		httpHeaderTimeout = pflag.Duration("http-header-timeout", 20*time.Second, "Timeout for reading HTTP request headers")
		httpIdleTimeout   = pflag.Duration("http-idle-timeout", 4*time.Minute, "Idle timeout for HTTP proxy server")

		tcpKeepAlive = pflag.String("tcp-keepalive", "45:45:3", "TCP keepalive: on|off|keepidle:keepintvl:keepcnt")
	)

	pflag.Parse()

	mode := strings.ToLower(strings.TrimSpace(*upstreamMode))
	if mode != "direct" && mode != "http" && mode != "socks5" {
		log.Fatalf("invalid --upstream-mode: %q", *upstreamMode)
	}
	if (mode == "http" || mode == "socks5") && strings.TrimSpace(*upstreamAddr) == "" {
		log.Fatalf("--upstream-addr is required for --upstream-mode=%s", mode)
	}

	ka, err := parseTCPKeepAlive(*tcpKeepAlive)
	if err != nil {
		log.Fatalf("invalid --tcp-keepalive: %v", err)
	}

	if *httpListen == "" && *socksListen == "" && *tproxyListen == "" {
		log.Fatalf("no listeners enabled (set at least one of --http-listen, --socks5-listen, --tproxy-listen)")
	}

	cfg := proxy.Config{
		DialTimeout:       *dialTimeout,
		IOTimeout:         *ioTimeout,
		HTTPHeaderTimeout: *httpHeaderTimeout,
		KeepAlive:         ka,
	}

	dialCfg := dialer.Config{
		DialTimeout: cfg.DialTimeout,
		IOTimeout:   cfg.IOTimeout,
		KeepAlive:   cfg.KeepAlive,
	}

	switch mode {
	case "direct":
		cfg.Dialer = dialer.NewDirectDialer(dialCfg)
	case "http":
		cfg.Dialer = dialer.NewHTTPProxyDialer(dialCfg, *upstreamAddr)
	case "socks5":
		cfg.Dialer = dialer.NewSOCKS5ProxyDialer(dialCfg, *upstreamAddr)
	default:
		log.Fatalf("unreachable upstream mode")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 4)

	if *debugListen != "" {
		debugSrv := &http.Server{Handler: http.DefaultServeMux}
		debugLn, err := net.Listen("tcp", *debugListen)
		if err != nil {
			log.Fatalf("debug listen: %v", err)
		}
		go func() {
			<-ctx.Done()
			_ = debugSrv.Close()
			_ = debugLn.Close()
		}()
		go func() {
			errCh <- debugSrv.Serve(debugLn)
		}()
		log.Printf("debug listening on %s", *debugListen)
	}

	if *httpListen != "" {
		ln, err := proxy.ListenTCP("tcp", *httpListen, cfg.KeepAlive)
		if err != nil {
			log.Fatalf("http listen: %v", err)
		}
		srv := proxy.NewHTTPProxyServer(cfg, *httpIdleTimeout)
		go func() {
			<-ctx.Done()
			_ = srv.Close()
			_ = ln.Close()
		}()
		go func() {
			errCh <- srv.Serve(ln)
		}()
		log.Printf("http proxy listening on %s", *httpListen)
	}

	if *socksListen != "" {
		ln, err := proxy.ListenTCP("tcp", *socksListen, cfg.KeepAlive)
		if err != nil {
			log.Fatalf("socks5 listen: %v", err)
		}
		s5 := proxy.NewSOCKS5Server(cfg)
		go func() {
			<-ctx.Done()
			_ = ln.Close()
		}()
		go func() {
			errCh <- s5.Serve(ln)
		}()
		log.Printf("socks5 proxy listening on %s", *socksListen)
	}

	if *tproxyListen != "" {
		ln, err := tproxy.ListenTransparentTCP(*tproxyListen, cfg.KeepAlive)
		if err != nil {
			log.Fatalf("tproxy listen: %v", err)
		}
		tsrv := tproxy.NewServer(cfg)
		go func() {
			<-ctx.Done()
			_ = ln.Close()
		}()
		go func() {
			errCh <- tsrv.Serve(ln)
		}()
		log.Printf("tproxy listening on %s", *tproxyListen)
	}

	select {
	case <-ctx.Done():
		log.Printf("shutting down")
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("server error: %v", err)
		}
	}

	for {
		select {
		case err := <-errCh:
			if err == nil {
				continue
			}
			if errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
				continue
			}
			fmt.Fprintln(os.Stderr, err)
		default:
			return
		}
	}
}

func parseTCPKeepAlive(s string) (net.KeepAliveConfig, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return net.KeepAliveConfig{}, fmt.Errorf("empty")
	}
	if s == "on" {
		return net.KeepAliveConfig{Enable: true}, nil
	}
	if s == "off" {
		return net.KeepAliveConfig{Enable: false}, nil
	}

	parts := strings.Split(s, ":")
	if len(parts) != 3 {
		return net.KeepAliveConfig{}, fmt.Errorf("expected on|off|keepidle:keepintvl:keepcnt")
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
		return 0, fmt.Errorf("must be > 0")
	}
	return time.Duration(n) * time.Second, nil
}

func parsePositiveInt(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, err
	}
	if n <= 0 {
		return 0, fmt.Errorf("must be > 0")
	}
	return n, nil
}
