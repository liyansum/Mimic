package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
)

type ServerConfig struct {
	ListenAddr    string `toml:"listen_addr"`
	CertFile      string `toml:"cert_file"`
	KeyFile       string `toml:"key_file"`
	Password      string `toml:"password"`
	FallbackAddr  string `toml:"fallback_addr"`
	MaxClients    int    `toml:"max_clients"`
	ReadTimeout   int    `toml:"read_timeout"`
	WriteTimeout  int    `toml:"write_timeout"`
	IdleTimeout   int    `toml:"idle_timeout"`
	EnableUDP     bool   `toml:"enable_udp"`
}

type ProxyServer struct {
	cfg      *ServerConfig
	upgrader *http.ServeMux

	udpSessions sync.Map // key: clientID:port, value: *net.UDPConn
}

func loadConfig(path string) (*ServerConfig, error) {
	var cfg ServerConfig
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (s *ProxyServer) authOK(r *http.Request) bool {
	auth := r.Header.Get("X-Auth")
	return auth != "" && auth == s.cfg.Password
}

func (s *ProxyServer) handleProxy(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	switch r.URL.Path {
	case "/proxy/tunnel":
		s.handleTCPTunnel(w, r)
	case "/proxy/udp":
		if s.cfg.EnableUDP {
			s.handleUDP(w, r)
		} else {
			http.Error(w, "UDP not enabled", http.StatusForbidden)
		}
	default:
		http.NotFound(w, r)
	}
}

func (s *ProxyServer) handleTCPTunnel(w http.ResponseWriter, r *http.Request) {
	host := r.Header.Get("X-Target-Host")
	port := r.Header.Get("X-Target-Port")
	if host == "" || port == "" {
		http.Error(w, "Missing target", http.StatusBadRequest)
		return
	}

	target, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 10*time.Second)
	if err != nil {
		http.Error(w, "Dial failed", http.StatusBadGateway)
		return
	}
	defer target.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	flusher, _ := w.(http.Flusher)
	w.WriteHeader(http.StatusOK)
	if flusher != nil {
		flusher.Flush()
	}

	ctx := r.Context()
	errCh := make(chan error, 2)

	// client → target
	go func() {
		_, e := io.Copy(target, r.Body)
		if conn, ok := target.(interface{ CloseWrite() error }); ok {
			_ = conn.CloseWrite()
		}
		errCh <- e
	}()

	// target → client
	go func() {
		buf := make([]byte, 32*1024)
		for {
			target.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, e := target.Read(buf)
			if n > 0 {
				if _, we := w.Write(buf[:n]); we != nil {
					errCh <- we
					return
				}
				if flusher != nil {
					flusher.Flush()
				}
			}
			if e != nil {
				errCh <- e
				return
			}
		}
	}()

	select {
	case <-ctx.Done():
	case <-errCh:
	}
}

type udpPacket struct {
	Host string
	Port int
	Data []byte
}

func (s *ProxyServer) handleUDP(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	dec := json.NewDecoder(r.Body)
	var pkt udpPacket
	if err := dec.Decode(&pkt); err != nil {
		http.Error(w, "Bad packet", http.StatusBadRequest)
		return
	}

	addr := fmt.Sprintf("%s:%d", pkt.Host, pkt.Port)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		http.Error(w, "Resolve fail", http.StatusBadRequest)
		return
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		http.Error(w, "Dial UDP fail", http.StatusBadGateway)
		return
	}
	defer conn.Close()

	_, err = conn.Write(pkt.Data)
	if err != nil {
		http.Error(w, "UDP write fail", http.StatusInternalServerError)
		return
	}

	buf := make([]byte, 65535)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := conn.ReadFrom(buf)
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		http.Error(w, "UDP read fail", http.StatusGatewayTimeout)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	if n > 0 {
		w.Write(buf[:n])
	}
}

func (s *ProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/proxy/") {
		s.handleProxy(w, r)
		return
	}

	// fallback
	resp, err := http.Get(s.cfg.FallbackAddr)
	if err != nil {
		http.Error(w, "Fallback unavailable", http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}

func main() {
	configPath := flag.String("c", "config.toml", "config path")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatal(err)
	}

	s := &ProxyServer{cfg: cfg}

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	srv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      s,
		TLSConfig:    tlsCfg,
		ReadTimeout:  time.Duration(cfg.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(cfg.WriteTimeout) * time.Second,
		IdleTimeout:  time.Duration(cfg.IdleTimeout) * time.Second,
	}

	log.Println("Listening on", cfg.ListenAddr)
	log.Fatal(srv.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile))
}
