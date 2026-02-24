package httpclient

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/proxy"
)

// RawResponse holds the unparsed, raw response data
type RawResponse struct {
	StatusCode int
	Headers    string
	Body       []byte
	Raw        []byte
}

// GetHeader extracts a header value from the raw headers string (case-insensitive key search).
func (r *RawResponse) GetHeader(key string) string {
	lowerKey := strings.ToLower(key)
	lines := strings.Split(r.Headers, "\r\n")
	for _, line := range lines {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			k := strings.TrimSpace(strings.ToLower(parts[0]))
			if k == lowerKey {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

type ConnectionPool struct {
	conns map[string][]net.Conn
	lock  sync.Mutex
}

var GlobalPool = &ConnectionPool{
	conns: make(map[string][]net.Conn),
}

func (p *ConnectionPool) Get(addr string) net.Conn {
	p.lock.Lock()
	defer p.lock.Unlock()
	if conns, ok := p.conns[addr]; ok && len(conns) > 0 {
		c := conns[len(conns)-1]
		p.conns[addr] = conns[:len(conns)-1]
		return c
	}
	return nil
}

func (p *ConnectionPool) Put(addr string, c net.Conn) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.conns[addr] = append(p.conns[addr], c)
}

// SendRawRequest sends a completely raw HTTP request over TCP or TLS.
// It randomizes TLS cipher suites to help bypass basic fingerprinting.
func SendRawRequest(targetURL string, rawRequest []byte, timeout time.Duration, proxyAddr string) (*RawResponse, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	address := net.JoinHostPort(host, port)

	// Try to get a connection from the pool
	// Note: Proxy connections are not pooled yet for simplicity, or we should key them by proxy too?
	// For now, let's bypass pool if proxy is used.
	var conn net.Conn
	var reused bool

	if proxyAddr == "" {
		conn = GlobalPool.Get(address)
		reused = conn != nil
	}

	if conn == nil {
		if u.Scheme == "https" {
			// Randomize TLS Ciphers for basic fingerprint evasion
			ciphers := []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			}

			// Shuffle ciphers (Go 1.20+ auto-seeds the global RNG)
			rand.Shuffle(len(ciphers), func(i, j int) {
				ciphers[i], ciphers[j] = ciphers[j], ciphers[i]
			})

			tlsConfig := &tls.Config{
				ServerName:         host,
				InsecureSkipVerify: true, // Often needed for WAF testing/bypassing
				CipherSuites:       ciphers,
				MinVersion:         tls.VersionTLS12,
				MaxVersion:         tls.VersionTLS13,
			}

			if proxyAddr != "" {
				// SOCKS5 Dialing for TLS
				dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
				if err != nil {
					return nil, fmt.Errorf("proxy init failed: %w", err)
				}
				// We need to use the proxy dialer to establish the connection, then wrap in TLS
				rawConn, err := dialer.Dial("tcp", address)
				if err != nil {
					return nil, fmt.Errorf("proxy dial failed: %w", err)
				}
				// Wrap with TLS
				tlsConn := tls.Client(rawConn, tlsConfig)
				// Handshake explicitly to catch errors early
				if err := tlsConn.Handshake(); err != nil {
					rawConn.Close()
					return nil, fmt.Errorf("TLS handshake through proxy failed: %w", err)
				}
				conn = tlsConn
			} else {
				dialer := &net.Dialer{Timeout: timeout}
				conn, err = tls.DialWithDialer(dialer, "tcp", address, tlsConfig)
				if err != nil {
					return nil, fmt.Errorf("TLS dial failed: %w", err)
				}
			}
		} else {
			// Plain HTTP
			if proxyAddr != "" {
				dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
				if err != nil {
					return nil, fmt.Errorf("proxy init failed: %w", err)
				}
				conn, err = dialer.Dial("tcp", address)
				if err != nil {
					return nil, fmt.Errorf("proxy dial failed: %w", err)
				}
			} else {
				// For plain TCP, we can set linger directly on the dialer control?
				// Actually net.DialTimeout doesn't expose it easily.
				dialer := &net.Dialer{
					Timeout: timeout,
					Control: func(network, address string, c syscall.RawConn) error {
						return c.Control(func(fd uintptr) {
							// Set SO_LINGER to 0 to force RST on close if needed
							syscall.SetsockoptLinger(int(fd), syscall.SOL_SOCKET, syscall.SO_LINGER, &syscall.Linger{Onoff: 1, Linger: 0})
						})
					},
				}
				conn, err = dialer.Dial("tcp", address)
				if err != nil {
					return nil, fmt.Errorf("TCP dial failed: %w", err)
				}
			}
		}
	}

	// Important: We do NOT defer conn.Close() here anymore if we want to reuse it.
	// Instead, we handle closure on error or pool return on success.

	// Set read/write deadlines
	conn.SetDeadline(time.Now().Add(timeout))

	// Write the raw request exactly as provided
	_, err = conn.Write(rawRequest)
	if err != nil {
		conn.Close()
		if reused {
			// Retry once with a fresh connection if the reused one failed
			return SendRawRequest(targetURL, rawRequest, timeout, proxyAddr)
		}
		return nil, fmt.Errorf("failed to write request: %w", err)
	}

	// Read the response
	// The problem: We want to reuse connections (to avoid TIME_WAIT/churn), but we don't want to drain 1GB bodies.
	// But HTTP/1.1 requires draining to reuse.
	// The only safe way to support both (Low Churn + Low Bandwidth) is to use `Connection: close` explicitly
	// OR use `Range` headers in the request (which not all servers respect).
	// If the user's Docker is dying, it's almost certainly socket exhaustion (TIME_WAIT).
	//
	// Fix: Since we can't drain safely, the user needs to tolerate connection closing.
	// We ensure we close ASAP.

	resp, err := parseRawResponse(conn)

	// Always close.
	conn.Close()

	if err != nil {
		if reused {
			// Can't happen now since we disabled reuse, but good practice for future
			return nil, err
		}
		return nil, err
	}

	return resp, nil
}

// parseRawResponse reads a raw HTTP response efficiently.
func parseRawResponse(conn net.Conn) (*RawResponse, error) {
	// Only read up to a reasonable header size + small body sample.
	// We don't need to download the full body if Content-Length is present.
	const HEADER_LIMIT = 8192 // 8KB for headers is usually plenty

	// Use a scanner-like approach or just read chunks
	var buf bytes.Buffer
	chunk := make([]byte, 4096)
	totalRead := 0

	// 1. Read until we find the header end (\r\n\r\n) or hit limit
	headerEnd := -1
	for {
		n, err := conn.Read(chunk)
		if n > 0 {
			buf.Write(chunk[:n])
			totalRead += n
		}

		if err != nil {
			if err == io.EOF || strings.Contains(err.Error(), "closed") || strings.Contains(err.Error(), "timeout") {
				break
			}
			return nil, fmt.Errorf("read error: %w", err)
		}

		// Check for header end in current buffer
		slice := buf.Bytes()
		if idx := bytes.Index(slice, []byte("\r\n\r\n")); idx != -1 {
			headerEnd = idx
			break
		} else if idx := bytes.Index(slice, []byte("\n\n")); idx != -1 {
			// Fallback for non-compliant servers
			headerEnd = idx
			break
		}

		if totalRead > HEADER_LIMIT {
			// Headers too long or just body data without proper separation?
			// Stop reading to save bandwidth
			break
		}
	}

	rawBytes := buf.Bytes()
	if len(rawBytes) == 0 {
		return nil, fmt.Errorf("empty response")
	}

	resp := &RawResponse{
		Raw: rawBytes, // Only contains what we read
	}

	// 2. Parse Headers
	if headerEnd != -1 {
		// Found explicit end
		sepLen := 4 // \r\n\r\n
		if bytes.Contains(rawBytes, []byte("\r\n\r\n")) {
			resp.Headers = string(rawBytes[:headerEnd])
		} else {
			resp.Headers = string(rawBytes[:headerEnd])
			sepLen = 2 // \n\n
		}

		// The body we accidentally read
		// resp.Body = rawBytes[headerEnd+sepLen:]
		// Actually, we don't *need* the body content for fuzzing usually, just the size.

		// 3. Determine Body (which might be partial)
		resp.Body = rawBytes[headerEnd+sepLen:]

		// IMPORTANT: If Content-Length header is present, we trust it for the "Size" calculation later
		// But in the RawResponse struct, Body is just the bytes we have.
		// The engine should be updated to check Content-Length header for filtering if available.
	} else {
		// No header end found? Treat all as partial body.
		resp.Body = rawBytes
	}

	// Parse status code from the first line
	firstLineEnd := strings.Index(resp.Headers, "\n")
	if firstLineEnd != -1 {
		firstLine := strings.TrimSpace(resp.Headers[:firstLineEnd])
		parts := strings.SplitN(firstLine, " ", 3)
		if len(parts) >= 2 {
			if code, err := strconv.Atoi(parts[1]); err == nil {
				resp.StatusCode = code
			}
		}
	}

	return resp, nil
}
