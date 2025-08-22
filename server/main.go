// server.go
package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"golang.org/x/net/http2"
)

/*
Server:
- Config via TOML (-c config.toml)
- Proxy endpoints:
    POST /proxy/tcp  -> TCP tunnel (requires X-Auth-Password)
    POST /proxy/udp  -> UDP session (requires X-Auth-Password)
- Any other access to /proxy/* (including unauthenticated POSTs or GETs) will be forwarded to fallback (nginx)
  so that unauthenticated clients see normal site pages instead of proxy errors.
- UDP supports multi-source mapping (remote->local mapping) so multiple local UDP sources in one session work.
*/

type ServerConfig struct {
	Listen            string `toml:"listen"`
	Domain            string `toml:"domain"`
	CertFile          string `toml:"cert_file"`
	KeyFile           string `toml:"key_file"`
	AuthPassword      string `toml:"auth_password"`
	Fallback          string `toml:"fallback"`
	ReadTimeoutSec    int    `toml:"read_timeout_sec"`
	WriteTimeoutSec   int    `toml:"write_timeout_sec"`
	IdleTimeoutSec    int    `toml:"idle_timeout_sec"`
	MaxHTTP2Streams   uint32 `toml:"max_http2_streams"`
	UDPSessionIdleSec int    `toml:"udp_session_idle_sec"`
}

type ProxyServer struct {
	cfg      ServerConfig
	fallback *httputil.ReverseProxy

	udpSessions sync.Map
	wg          sync.WaitGroup
}

func loadConfig(path string) (ServerConfig, error) {
	var cfg ServerConfig
	_, err := toml.DecodeFile(path, &cfg)
	if err != nil {
		return cfg, err
	}
	if cfg.Listen == "" {
		cfg.Listen = ":443"
	}
	if cfg.ReadTimeoutSec == 0 {
		cfg.ReadTimeoutSec = 15
	}
	if cfg.WriteTimeoutSec == 0 {
		cfg.WriteTimeoutSec = 15
	}
	if cfg.IdleTimeoutSec == 0 {
		cfg.IdleTimeoutSec = 60
	}
	if cfg.MaxHTTP2Streams == 0 {
		cfg.MaxHTTP2Streams = 250
	}
	if cfg.UDPSessionIdleSec == 0 {
		cfg.UDPSessionIdleSec = 120
	}
	return cfg, nil
}

func NewProxyServer(cfg ServerConfig) *ProxyServer {
	var fb *httputil.ReverseProxy
	if cfg.Fallback != "" {
		u, _ := url.Parse("http://" + cfg.Fallback)
		fb = httputil.NewSingleHostReverseProxy(u)
	}
	return &ProxyServer{
		cfg:      cfg,
		fallback: fb,
	}
}

func (s *ProxyServer) Start(ctx context.Context) error {
	cert, err := tls.LoadX509KeyPair(s.cfg.CertFile, s.cfg.KeyFile)
	if err != nil {
		return fmt.Errorf("load cert/key: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
	}

	srv := &http.Server{
		Addr:         s.cfg.Listen,
		Handler:      s,
		TLSConfig:    tlsCfg,
		ReadTimeout:  time.Duration(s.cfg.ReadTimeoutSec) * time.Second,
		WriteTimeout: time.Duration(s.cfg.WriteTimeoutSec) * time.Second,
		IdleTimeout:  time.Duration(s.cfg.IdleTimeoutSec) * time.Second,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	http2Cfg := &http2.Server{
		MaxConcurrentStreams: s.cfg.MaxHTTP2Streams,
		MaxReadFrameSize:     1 << 20,
	}
	http2.ConfigureServer(srv, http2Cfg)

	go s.udpSessionJanitor(ctx)

	errCh := make(chan error, 1)
	go func() {
		log.Printf("server listening on %s, domain=%s fallback=%s", s.cfg.Listen, s.cfg.Domain, s.cfg.Fallback)
		errCh <- srv.ListenAndServeTLS("", "")
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		s.wg.Wait()
		return nil
	case err := <-errCh:
		return err
	}
}

func (s *ProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// standard security headers to mimic real site
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// Optional: strict SNI check for additional mimicry
	if r.TLS != nil && s.cfg.Domain != "" && r.TLS.ServerName != "" && r.TLS.ServerName != s.cfg.Domain {
		// If SNI mismatch, serve fallback to blend in
		s.forwardToFallback(w, r)
		return
	}

	// If request is intended for proxy endpoints:
	if strings.HasPrefix(r.URL.Path, "/proxy/") {
		// Only handle when authenticated AND proper POST for tcp/udp endpoints.
		// Otherwise forward to fallback (so unauthenticated scanners see normal site).
		if r.URL.Path == "/proxy/tcp" && r.Method == "POST" && s.checkAuth(r) {
			s.handleTCPTunnel(w, r)
			return
		}
		if r.URL.Path == "/proxy/udp" && r.Method == "POST" && s.checkAuth(r) {
			s.handleUDPSession(w, r)
			return
		}
		// Not authenticated / wrong method / other proxy paths -> forward to fallback
		s.forwardToFallback(w, r)
		return
	}

	// Non-proxy paths => fallback if configured, else 404
	if s.fallback != nil {
		r.Host = s.cfg.Domain
		s.fallback.ServeHTTP(w, r)
		return
	}
	http.NotFound(w, r)
}

func (s *ProxyServer) checkAuth(r *http.Request) bool {
	if s.cfg.AuthPassword == "" {
		return true
	}
	return r.Header.Get("X-Auth-Password") == s.cfg.AuthPassword
}

func (s *ProxyServer) forwardToFallback(w http.ResponseWriter, r *http.Request) {
	// if no fallback configured, return NotFound (but typical deployment should have fallback)
	if s.fallback == nil {
		http.NotFound(w, r)
		return
	}
	// create new request to fallback to avoid issues with consumed body
	req, err := http.NewRequest(r.Method, "http://"+s.cfg.Fallback+r.RequestURI, r.Body)
	if err != nil {
		http.Error(w, "Internal Error", http.StatusInternalServerError)
		return
	}
	for k, vs := range r.Header {
		if strings.EqualFold(k, "Connection") || strings.EqualFold(k, "Upgrade") || strings.EqualFold(k, "Proxy-Connection") {
			continue
		}
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if host == "" {
		host = r.RemoteAddr
	}
	req.Header.Set("Host", s.cfg.Domain)
	req.Header.Set("X-Forwarded-For", host)
	req.Header.Set("X-Forwarded-Proto", "https")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("fallback forward error: %v", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

/******** TCP tunnel ********/
func (s *ProxyServer) handleTCPTunnel(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	host := r.Header.Get("X-Target-Host")
	portStr := r.Header.Get("X-Target-Port")
	if host == "" || portStr == "" {
		// to be safe, fallback
		s.forwardToFallback(w, r)
		return
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		s.forwardToFallback(w, r)
		return
	}

	dst := net.JoinHostPort(host, strconv.Itoa(port))
	targetConn, err := net.DialTimeout("tcp", dst, 10*time.Second)
	if err != nil {
		// connection failure — but to avoid revealing, respond with BadGateway as normal reverse proxy would
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		flusher.Flush()
	}

	done := make(chan struct{})
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer close(done)
		_, _ = io.Copy(targetConn, r.Body)
		if tcp, ok := targetConn.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()

	buf := make([]byte, 32*1024)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		targetConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := targetConn.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			break
		}
	}
	<-done
}

/******** UDP session with multi-source mapping ********/

type UDPSession struct {
	id           string
	packetConn   net.PacketConn
	lastActive   time.Time
	remoteToLocal map[string]string // remoteAddr.String() -> localAddr string
	mu           sync.Mutex
	cancel       context.CancelFunc
	closed       bool
}

func (s *ProxyServer) handleUDPSession(w http.ResponseWriter, r *http.Request) {
	sessionID := r.Header.Get("X-Session-ID")
	if sessionID == "" {
		// fallback for safety
		s.forwardToFallback(w, r)
		return
	}

	pc, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		http.Error(w, "UDP unavailable", http.StatusInternalServerError)
		return
	}
	defer func() {
		pc.Close()
	}()

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	sess := &UDPSession{
		id:            sessionID,
		packetConn:    pc,
		lastActive:    time.Now(),
		remoteToLocal: make(map[string]string),
		cancel:        cancel,
	}

	s.udpSessions.Store(sessionID, sess)
	defer s.udpSessions.Delete(sessionID)

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		flusher.Flush()
	}

	clientErrCh := make(chan error, 1)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			frame, err := readFrame(r.Body)
			if err != nil {
				clientErrCh <- err
				return
			}
			if len(frame) < 1 {
				continue
			}
			l := int(frame[0])
			if len(frame) < 1+l {
				continue
			}
			localAddr := string(frame[1 : 1+l])
			socks5dgram := frame[1+l:]

			destAddr, payloadData, perr := parseSocks5UDPDatagram(socks5dgram)
			if perr != nil {
				continue
			}

			sess.mu.Lock()
			sess.remoteToLocal[destAddr.String()] = localAddr
			sess.lastActive = time.Now()
			sess.mu.Unlock()

			_, _ = sess.packetConn.WriteTo(payloadData, destAddr)
		}
	}()

	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return
		case err := <-clientErrCh:
			_ = err
			return
		default:
		}
		sess.packetConn.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, src, err := sess.packetConn.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				sess.mu.Lock()
				idle := time.Since(sess.lastActive)
				sess.mu.Unlock()
				if idle > time.Duration(s.cfg.UDPSessionIdleSec)*time.Second {
					return
				}
				continue
			}
			return
		}
		srcKey := src.String()
		sess.mu.Lock()
		localAddr, ok := sess.remoteToLocal[srcKey]
		sess.lastActive = time.Now()
		sess.mu.Unlock()
		if !ok {
			// no mapping: skip to avoid mis-delivery
			continue
		}
		packet := buildSocks5UDPDatagram(src, buf[:n])

		localBytes := []byte(localAddr)
		if len(localBytes) > 255 {
			continue
		}
		frame := make([]byte, 1+len(localBytes)+len(packet))
		frame[0] = byte(len(localBytes))
		copy(frame[1:1+len(localBytes)], localBytes)
		copy(frame[1+len(localBytes):], packet)

		if werr := writeFrame(w, frame); werr != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
}

func (s *ProxyServer) udpSessionJanitor(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			s.udpSessions.Range(func(k, v interface{}) bool {
				sess := v.(*UDPSession)
				sess.mu.Lock()
				idle := now.Sub(sess.lastActive)
				if idle > time.Duration(s.cfg.UDPSessionIdleSec)*time.Second {
					if !sess.closed {
						sess.closed = true
						sess.packetConn.Close()
					}
					s.udpSessions.Delete(k)
				}
				sess.mu.Unlock()
				return true
			})
		}
	}
}

/******** helpers ********/
func readFrame(r io.Reader) ([]byte, error) {
	var lenb [2]byte
	if _, err := io.ReadFull(r, lenb[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(lenb[:]))
	if n == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	return buf, err
}
func writeFrame(w io.Writer, payload []byte) error {
	if len(payload) > 0xFFFF {
		return fmt.Errorf("payload too large")
	}
	var lenb [2]byte
	binary.BigEndian.PutUint16(lenb[:], uint16(len(payload)))
	if _, err := w.Write(lenb[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func parseSocks5UDPDatagram(pkt []byte) (net.Addr, []byte, error) {
	if len(pkt) < 4 {
		return nil, nil, fmt.Errorf("too short")
	}
	if pkt[0] != 0x00 || pkt[1] != 0x00 || pkt[2] != 0x00 {
		return nil, nil, fmt.Errorf("bad header")
	}
	atyp := pkt[3]
	p := 4
	var host string
	switch atyp {
	case 0x01:
		if len(pkt) < p+4+2 {
			return nil, nil, fmt.Errorf("short ipv4")
		}
		host = net.IP(pkt[p : p+4]).String()
		p += 4
	case 0x03:
		if len(pkt) < p+1 {
			return nil, nil, fmt.Errorf("short domain")
		}
		dlen := int(pkt[p])
		p++
		if len(pkt) < p+dlen+2 {
			return nil, nil, fmt.Errorf("short domain2")
		}
		host = string(pkt[p : p+dlen])
		p += dlen
	case 0x04:
		if len(pkt) < p+16+2 {
			return nil, nil, fmt.Errorf("short ipv6")
		}
		host = net.IP(pkt[p : p+16]).String()
		p += 16
	default:
		return nil, nil, fmt.Errorf("unsupported atyp")
	}
	if len(pkt) < p+2 {
		return nil, nil, fmt.Errorf("no port")
	}
	port := int(binary.BigEndian.Uint16(pkt[p : p+2]))
	p += 2
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, nil, err
	}
	if len(pkt) < p {
		return nil, nil, fmt.Errorf("no data")
	}
	data := pkt[p:]
	return addr, data, nil
}

func buildSocks5UDPDatagram(src net.Addr, data []byte) []byte {
	udp := make([]byte, 0, 10+len(data))
	udp = append(udp, 0x00, 0x00, 0x00)
	host, portStr, _ := net.SplitHostPort(src.String())
	port := 0
	if portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}
	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		udp = append(udp, 0x01)
		udp = append(udp, ip4...)
	} else if ip6 := ip.To16(); ip6 != nil {
		udp = append(udp, 0x04)
		udp = append(udp, ip6...)
	} else {
		udp = append(udp, 0x03, byte(len(host)))
		udp = append(udp, []byte(host)...)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(port))
	udp = append(udp, pb[:]...)
	udp = append(udp, data...)
	return udp
}

/******** main ********/
func main() {
	cfgPath := flag.String("c", "", "config toml file path")
	flag.Parse()
	if *cfgPath == "" {
		fmt.Println("Usage: server -c config.toml")
		os.Exit(2)
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("load config error: %v", err)
	}
	ps := NewProxyServer(cfg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := ps.Start(ctx); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
