// client.go
package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"golang.org/x/net/http2"
)

/*
Client (summary):
- TOML config via -c
- Local SOCKS5 listener: supports CONNECT and UDP ASSOCIATE
- CONNECT => POST /proxy/tcp with X-Target-Host/X-Target-Port/X-Auth-Password (one HTTP/2 stream per connection)
- UDP ASSOCIATE => local UDP socket + POST /proxy/udp with X-Session-ID; frames carry localAddr so server maps responses back
- Semaphore limits concurrent http2 streams per connection
- Retries and context cancellation
*/

type ClientConfig struct {
	Server               string `toml:"server"`
	Password             string `toml:"password"`
	Socks5Listen         string `toml:"socks5_listen"`
	VerifyCert           bool   `toml:"verify_cert"`
	MaxConcurrentStreams int    `toml:"max_concurrent_streams"`
	ConnectRetry         int    `toml:"connect_retry"`
}

func loadClientConfig(path string) (ClientConfig, error) {
	var cfg ClientConfig
	_, err := toml.DecodeFile(path, &cfg)
	if err != nil {
		return cfg, err
	}
	if cfg.Socks5Listen == "" {
		cfg.Socks5Listen = "127.0.0.1:1080"
	}
	if cfg.MaxConcurrentStreams <= 0 {
		cfg.MaxConcurrentStreams = 200
	}
	if cfg.ConnectRetry <= 0 {
		cfg.ConnectRetry = 3
	}
	return cfg, nil
}

type Client struct {
	cfg        *ClientConfig
	httpClient *http.Client
	serverURL  string

	streamSem   chan struct{}
	udpSessions sync.Map
	wg          sync.WaitGroup
}

type localUDPSession struct {
	sessionID string
	localConn net.PacketConn
	lastSeen  map[string]time.Time
	mu        sync.Mutex
	cancel    context.CancelFunc
}

func NewClient(cfg ClientConfig) *Client {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: !cfg.VerifyCert,
		NextProtos:         []string{"h2", "http/1.1"},
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
	}
	tr := &http.Transport{
		TLSClientConfig:     tlsCfg,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   true,
	}
	http2.ConfigureTransport(tr)
	cli := &http.Client{Transport: tr, Timeout: 0}
	return &Client{
		cfg:        &cfg,
		httpClient: cli,
		serverURL:  "https://" + cfg.Server,
		streamSem:  make(chan struct{}, cfg.MaxConcurrentStreams),
	}
}

func (c *Client) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", c.cfg.Socks5Listen)
	if err != nil {
		return err
	}
	defer ln.Close()
	log.Printf("SOCKS5 listening %s -> server=%s", c.cfg.Socks5Listen, c.cfg.Server)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			log.Printf("accept error: %v", err)
			continue
		}
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			c.handleSocks5(conn)
		}()
	}
}

func (c *Client) handleSocks5(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 512)
	// handshake
	if _, err := io.ReadAtLeast(conn, buf[:2], 2); err != nil {
		return
	}
	if buf[0] != 0x05 {
		return
	}
	methods := int(buf[1])
	if methods > 0 {
		if _, err := io.ReadFull(conn, buf[:methods]); err != nil {
			return
		}
	}
	// no auth
	conn.Write([]byte{0x05, 0x00})

	// request
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return
	}
	if buf[0] != 0x05 {
		return
	}
	cmd := buf[1]
	atyp := buf[3]
	var host string
	switch atyp {
	case 0x01:
		if _, err := io.ReadFull(conn, buf[:4]); err != nil {
			return
		}
		host = net.IP(buf[:4]).String()
	case 0x03:
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return
		}
		dlen := int(buf[0])
		if dlen <= 0 {
			return
		}
		if _, err := io.ReadFull(conn, buf[:dlen]); err != nil {
			return
		}
		host = string(buf[:dlen])
	case 0x04:
		if _, err := io.ReadFull(conn, buf[:16]); err != nil {
			return
		}
		host = net.IP(buf[:16]).String()
	default:
		return
	}
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(buf[:2]))

	switch cmd {
	case 0x01: // CONNECT
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		target := net.JoinHostPort(host, strconv.Itoa(port))
		c.tcpConnectWithRetry(target, conn)
	case 0x03: // UDP ASSOCIATE
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		defer pc.Close()
		ua := pc.LocalAddr().(*net.UDPAddr)
		reply := make([]byte, 10)
		reply[0] = 0x05
		reply[1] = 0x00
		reply[2] = 0x00
		reply[3] = 0x01
		copy(reply[4:8], ua.IP.To4())
		binary.BigEndian.PutUint16(reply[8:10], uint16(ua.Port))
		conn.Write(reply)
		if err := c.startUDPSession(pc, conn); err != nil {
			log.Printf("udp session error: %v", err)
		}
	default:
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}
}

func (c *Client) tcpConnectWithRetry(target string, localConn net.Conn) {
	max := c.cfg.ConnectRetry
	backoff := 200 * time.Millisecond
	var err error
	for i := 0; i < max; i++ {
		err = c.tcpTunnel(target, localConn)
		if err == nil {
			return
		}
		time.Sleep(backoff)
		backoff *= 2
	}
	log.Printf("tcp tunnel failed to %s: %v", target, err)
}

func (c *Client) tcpTunnel(target string, localConn net.Conn) error {
	select {
	case c.streamSem <- struct{}{}:
	default:
		select {
		case c.streamSem <- struct{}{}:
		case <-time.After(5 * time.Second):
			return fmt.Errorf("no http2 stream slot")
		}
	}
	defer func() { <-c.streamSem }()

	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}

	pr, pw := io.Pipe()
	req, err := http.NewRequest("POST", c.serverURL+"/proxy/tcp", pr)
	if err != nil {
		return err
	}
	req.Header.Set("X-Target-Host", host)
	req.Header.Set("X-Target-Port", port)
	req.Header.Set("X-Auth-Password", c.cfg.Password)
	req.Header.Set("Content-Type", "application/octet-stream")

	go func() {
		_, _ = io.Copy(pw, localConn)
		_ = pw.Close()
	}()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return fmt.Errorf("status: %s", resp.Status)
	}

	done := make(chan struct{})
	go func() {
		defer resp.Body.Close()
		io.Copy(localConn, resp.Body)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(60 * time.Minute):
	}
	return nil
}

func (c *Client) startUDPSession(pc net.PacketConn, controlConn net.Conn) error {
	sessionID := fmt.Sprintf("%d-%d", time.Now().UnixNano(), rand.Int63())
	ctx, cancel := context.WithCancel(context.Background())
	localSess := &localUDPSession{
		sessionID: sessionID,
		localConn: pc,
		lastSeen:  make(map[string]time.Time),
		cancel:    cancel,
	}
	c.udpSessions.Store(sessionID, localSess)
	defer func() {
		c.udpSessions.Delete(sessionID)
		cancel()
	}()

	pr, pw := io.Pipe()
	req, err := http.NewRequest("POST", c.serverURL+"/proxy/udp", pr)
	if err != nil {
		return err
	}
	req = req.WithContext(ctx)
	req.Header.Set("X-Session-ID", sessionID)
	req.Header.Set("X-Auth-Password", c.cfg.Password)
	req.Header.Set("Content-Type", "application/octet-stream")

	writeErrCh := make(chan error, 1)
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		buf := make([]byte, 65535)
		for {
			pc.SetReadDeadline(time.Now().Add(60 * time.Second))
			n, src, err := pc.ReadFrom(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					select {
					case <-ctx.Done():
						writeErrCh <- ctx.Err()
						return
					default:
						continue
					}
				}
				writeErrCh <- err
				return
			}
			srcStr := src.String()
			localSess.mu.Lock()
			localSess.lastSeen[srcStr] = time.Now()
			localSess.mu.Unlock()

			localBytes := []byte(srcStr)
			if len(localBytes) > 255 {
				continue
			}
			frame := make([]byte, 1+len(localBytes)+n)
			frame[0] = byte(len(localBytes))
			copy(frame[1:1+len(localBytes)], localBytes)
			copy(frame[1+len(localBytes):], buf[:n])

			if err := writeFrame(pw, frame); err != nil {
				writeErrCh <- err
				return
			}
		}
	}()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		pw.Close()
		return err
	}
	if resp.StatusCode != http.StatusOK {
		pw.Close()
		resp.Body.Close()
		return fmt.Errorf("udp session status: %s", resp.Status)
	}

	readErrCh := make(chan error, 1)
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		defer resp.Body.Close()
		for {
			frame, rerr := readFrame(resp.Body)
			if rerr != nil {
				readErrCh <- rerr
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
			payload := frame[1+l:]
			addr, err := net.ResolveUDPAddr("udp", localAddr)
			if err != nil {
				continue
			}
			_, _ = pc.WriteTo(payload, addr)
		}
	}()

	select {
	case err := <-writeErrCh:
		_ = err
	case err := <-readErrCh:
		_ = err
	case <-time.After(30 * time.Minute):
	}

	pw.Close()
	resp.Body.Close()
	return nil
}

/******** frame helpers ********/
func writeFrame(w io.Writer, payload []byte) error {
	if len(payload) > 0xFFFF {
		return fmt.Errorf("payload too large")
	}
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], uint16(len(payload)))
	if _, err := w.Write(b[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}
func readFrame(r io.Reader) ([]byte, error) {
	var b [2]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(b[:]))
	if n == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	return buf, err
}

func main() {
	cfgPath := flag.String("c", "", "config toml file path")
	flag.Parse()
	if *cfgPath == "" {
		fmt.Println("Usage: client -c config.toml")
		os.Exit(2)
	}
	cfg, err := loadClientConfig(*cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	client := NewClient(cfg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := client.Start(ctx); err != nil {
		log.Fatalf("client start error: %v", err)
	}
	client.wg.Wait()
}
