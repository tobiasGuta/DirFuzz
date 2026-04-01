package httpclient

import (
	"bytes"
	"compress/gzip"
	"context"
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

// MaxBodySize limits response body reading to prevent memory exhaustion
const MaxBodySize = 5 * 1024 * 1024 // 5MB

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
	return SendRawRequestWithContext(context.Background(), targetURL, rawRequest, timeout, proxyAddr, false)
}

// SendRawRequestWithContext sends a raw HTTP request with context support and TLS control.
func SendRawRequestWithContext(ctx context.Context, targetURL string, rawRequest []byte, timeout time.Duration, proxyAddr string, insecure bool) (*RawResponse, error) {
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
			InsecureSkipVerify: insecure,
			CipherSuites:       ciphers,
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS13,
		}

		if proxyAddr != "" {
			// Parse proxy URL for authentication
			var proxyAuth *proxy.Auth
			proxyURL := proxyAddr

			// Check for user:pass@host:port format
			if strings.Contains(proxyAddr, "@") {
				parts := strings.SplitN(proxyAddr, "@", 2)
				if len(parts) == 2 && strings.Contains(parts[0], ":") {
					authParts := strings.SplitN(parts[0], ":", 2)
					proxyAuth = &proxy.Auth{
						User:     authParts[0],
						Password: authParts[1],
					}
					proxyURL = parts[1]
				}
			}

			dialer, err := proxy.SOCKS5("tcp", proxyURL, proxyAuth, proxy.Direct)
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
			// Check context before dial
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			conn, err = tls.DialWithDialer(dialer, "tcp", address, tlsConfig)
			if err != nil {
				return nil, fmt.Errorf("TLS dial failed: %w", err)
			}
		}
	} else {
		// Plain HTTP
		if proxyAddr != "" {
			// Parse proxy URL for authentication
			var proxyAuth *proxy.Auth
			proxyURL := proxyAddr

			// Check for user:pass@host:port format
			if strings.Contains(proxyAddr, "@") {
				parts := strings.SplitN(proxyAddr, "@", 2)
				if len(parts) == 2 && strings.Contains(parts[0], ":") {
					authParts := strings.SplitN(parts[0], ":", 2)
					proxyAuth = &proxy.Auth{
						User:     authParts[0],
						Password: authParts[1],
					}
					proxyURL = parts[1]
				}
			}

			dialer, err := proxy.SOCKS5("tcp", proxyURL, proxyAuth, proxy.Direct)
			if err != nil {
				return nil, fmt.Errorf("proxy init failed: %w", err)
			}
			conn, err = dialer.Dial("tcp", address)
			if err != nil {
				return nil, fmt.Errorf("proxy dial failed: %w", err)
			}
		} else {
			// Check context before dial
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
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

	// Check context before write
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

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

// dechunkBody attempts to decode a chunked HTTP body.
func dechunkBody(body []byte) []byte {
	var dechunked bytes.Buffer
	buf := bytes.NewBuffer(body)

	for {
		line, err := buf.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Remove chunk extensions
		if idx := strings.IndexByte(line, ';'); idx != -1 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)

		chunkSize, err := strconv.ParseInt(line, 16, 64)
		if err != nil || chunkSize < 0 {
			// If we fail to parse on the first chunk, return original body
			if dechunked.Len() == 0 {
				return body
			}
			break
		}
		if chunkSize == 0 {
			break // End of chunks
		}

		chunk := make([]byte, chunkSize)
		_, err = io.ReadFull(buf, chunk)
		if err != nil {
			// Try to save whatever we got
			dechunked.Write(chunk)
			break
		}
		dechunked.Write(chunk)

		// read the trailing CRLF
		buf.ReadString('\n')
	}

	if dechunked.Len() > 0 {
		return dechunked.Bytes()
	}
	return body
}

// decompressGzip attempts to decompress a gzipped body.
func decompressGzip(body []byte) []byte {
	if len(body) == 0 {
		return body
	}
	reader, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return body
	}
	defer reader.Close()
	decompressed, err := io.ReadAll(reader)
	if err != nil && err != io.ErrUnexpectedEOF {
		if len(decompressed) == 0 {
			return body
		}
	}
	return decompressed
}

// parseRawResponse reads a raw HTTP response efficiently.
func parseRawResponse(conn net.Conn) (*RawResponse, error) {
	var buf bytes.Buffer
	chunk := make([]byte, 4096)

	headerParsed := false
	headerEndIdx := -1
	sepLen := 4
	contentLength := -1
	isChunked := false

	for {
		n, err := conn.Read(chunk)
		if n > 0 {
			buf.Write(chunk[:n])
		}

		rawBytes := buf.Bytes()

		if !headerParsed {
			if idx := bytes.Index(rawBytes, []byte("\r\n\r\n")); idx != -1 {
				headerEndIdx = idx
				sepLen = 4
				headerParsed = true
			} else if idx := bytes.Index(rawBytes, []byte("\n\n")); idx != -1 {
				headerEndIdx = idx
				sepLen = 2
				headerParsed = true
			}

			if headerParsed {
				headersStr := string(rawBytes[:headerEndIdx])
				lowerHeaders := strings.ToLower(headersStr)

				if strings.Contains(lowerHeaders, "transfer-encoding: chunked") {
					isChunked = true
				} else {
					lines := strings.Split(headersStr, "\n")
					for _, line := range lines {
						if strings.HasPrefix(strings.ToLower(line), "content-length:") {
							parts := strings.SplitN(line, ":", 2)
							if len(parts) == 2 {
								if cl, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil {
									contentLength = cl
								}
							}
						}
					}
				}
			}
		}

		if headerParsed {
			bodyLen := buf.Len() - (headerEndIdx + sepLen)
			if isChunked {
				// Chunked responses end with 0\r\n\r\n
				if bytes.HasSuffix(rawBytes, []byte("0\r\n\r\n")) || bytes.HasSuffix(rawBytes, []byte("0\n\n")) {
					break
				}
			} else if contentLength != -1 {
				if bodyLen >= contentLength {
					break
				}
			}
		}

		if err != nil {
			break
		}

		if buf.Len() > MaxBodySize {
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

	if headerEndIdx != -1 {
		resp.Headers = string(rawBytes[:headerEndIdx])
		resp.Body = rawBytes[headerEndIdx+sepLen:]
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

	needsUpdate := false

	// Dechunk if necessary
	if isChunked {
		resp.Body = dechunkBody(resp.Body)
		needsUpdate = true
	}

	// Decompress GZIP if necessary
	if strings.Contains(strings.ToLower(resp.GetHeader("Content-Encoding")), "gzip") {
		resp.Body = decompressGzip(resp.Body)
		needsUpdate = true
	}

	if needsUpdate {
		// Update the Raw bytes so the TUI presents a clean response
		var newRaw bytes.Buffer
		newRaw.WriteString(resp.Headers)
		newRaw.WriteString("\r\n\r\n")
		newRaw.Write(resp.Body)
		resp.Raw = newRaw.Bytes()
	}

	return resp, nil
}
