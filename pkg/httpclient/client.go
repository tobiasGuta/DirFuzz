package httpclient

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/proxy"
)

// RawResponse holds the unparsed, raw response data.
type RawResponse struct {
	StatusCode int
	Headers    string
	Body       []byte
	Raw        []byte
	Duration   time.Duration
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

// SendRawRequest sends a completely raw HTTP request over TCP or TLS.
// It randomizes TLS cipher suites to help bypass basic fingerprinting.
func SendRawRequest(targetURL string, rawRequest []byte, timeout time.Duration, proxyAddr string) (*RawResponse, error) {
	start := time.Now()

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

	var conn net.Conn

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
		rand.Shuffle(len(ciphers), func(i, j int) {
			ciphers[i], ciphers[j] = ciphers[j], ciphers[i]
		})

		tlsConfig := &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
			CipherSuites:       ciphers,
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS13,
		}

		if proxyAddr != "" {
			dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
			if err != nil {
				return nil, fmt.Errorf("proxy init failed: %w", err)
			}
			rawConn, err := dialer.Dial("tcp", address)
			if err != nil {
				return nil, fmt.Errorf("proxy dial failed: %w", err)
			}
			tlsConn := tls.Client(rawConn, tlsConfig)
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
			dialer := &net.Dialer{
				Timeout: timeout,
				Control: func(network, address string, c syscall.RawConn) error {
					return c.Control(func(fd uintptr) {
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

	defer conn.Close()

	// Set read/write deadlines
	conn.SetDeadline(time.Now().Add(timeout))

	// Write the raw request exactly as provided
	_, err = conn.Write(rawRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to write request: %w", err)
	}

	// Read and parse the response
	resp, err := parseRawResponse(conn)
	if err != nil {
		return nil, err
	}

	resp.Duration = time.Since(start)
	return resp, nil
}

// parseRawResponse reads a raw HTTP response efficiently.
func parseRawResponse(conn net.Conn) (*RawResponse, error) {
	const HEADER_LIMIT = 8192

	var buf bytes.Buffer
	chunk := make([]byte, 4096)
	totalRead := 0

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

		slice := buf.Bytes()
		if idx := bytes.Index(slice, []byte("\r\n\r\n")); idx != -1 {
			headerEnd = idx
			break
		} else if idx := bytes.Index(slice, []byte("\n\n")); idx != -1 {
			headerEnd = idx
			break
		}

		if totalRead > HEADER_LIMIT {
			break
		}
	}

	rawBytes := buf.Bytes()
	if len(rawBytes) == 0 {
		return nil, fmt.Errorf("empty response")
	}

	resp := &RawResponse{
		Raw: rawBytes,
	}

	if headerEnd != -1 {
		sepLen := 4
		if !bytes.Contains(rawBytes[:headerEnd+4], []byte("\r\n\r\n")) {
			sepLen = 2
		}
		resp.Headers = string(rawBytes[:headerEnd])
		resp.Body = rawBytes[headerEnd+sepLen:]
	} else {
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
