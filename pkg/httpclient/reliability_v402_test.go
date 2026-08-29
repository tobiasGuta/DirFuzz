package httpclient

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestV402ReplayPolicy(t *testing.T) {
	tests := []struct {
		method string
		want   bool
	}{
		{"GET", true}, {"HEAD", true}, {"OPTIONS", true}, {"TRACE", true},
		{"POST", false}, {"PATCH", false}, {"PUT", false}, {"DELETE", false},
	}
	for _, tc := range tests {
		raw := []byte(tc.method + " / HTTP/1.1\r\nHost: example.test\r\n\r\n")
		if got := requestReplaySafe(raw); got != tc.want {
			t.Fatalf("requestReplaySafe(%s) = %t, want %t", tc.method, got, tc.want)
		}
	}
}

func parseV402Response(t *testing.T, raw string) (*RawResponse, error) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	go func() {
		_, _ = io.WriteString(serverConn, raw)
		_ = serverConn.Close()
	}()
	defer clientConn.Close()
	return parseRawResponse(clientConn, false)
}

func TestV402RejectsConflictingContentLength(t *testing.T) {
	_, err := parseV402Response(t, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 10\r\n\r\nhello")
	if err == nil || !strings.Contains(err.Error(), "conflicting Content-Length") {
		t.Fatalf("expected conflicting Content-Length error, got %v", err)
	}
}

func TestV402AcceptsIdenticalContentLength(t *testing.T) {
	resp, err := parseV402Response(t, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello")
	if err != nil {
		t.Fatalf("parseRawResponse failed: %v", err)
	}
	if string(resp.Body) != "hello" || !resp.BodyComplete {
		t.Fatalf("unexpected response: body=%q complete=%t", resp.Body, resp.BodyComplete)
	}
}

func TestV402RejectsTransferEncodingWithContentLength(t *testing.T) {
	_, err := parseV402Response(t, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n")
	if err == nil || !strings.Contains(err.Error(), "ambiguous response framing") {
		t.Fatalf("expected ambiguous framing error, got %v", err)
	}
}

func TestV402RejectsNonFinalChunkedCoding(t *testing.T) {
	_, err := parseV402Response(t, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\n0\r\n\r\n")
	if err == nil || !strings.Contains(err.Error(), "chunked must appear exactly once and as the final coding") {
		t.Fatalf("expected invalid Transfer-Encoding error, got %v", err)
	}
}

func TestV402CancellationInterruptsRawRead(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	requestSeen := make(chan struct{})
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for {
			line, readErr := reader.ReadString('\n')
			if readErr != nil {
				return
			}
			if line == "\r\n" || line == "\n" {
				break
			}
		}
		close(requestSeen)
		_, _ = reader.ReadByte()
	}()

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	target := "http://" + ln.Addr().String()
	go func() {
		_, err := SendRawRequestWithContextPolicy(ctx, target, []byte("GET / HTTP/1.1\r\nHost: "+ln.Addr().String()+"\r\nConnection: close\r\n\r\n"), 5*time.Second, "", false, true)
		result <- err
	}()

	select {
	case <-requestSeen:
	case <-time.After(time.Second):
		t.Fatal("server did not receive request")
	}
	cancel()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(750 * time.Millisecond):
		t.Fatal("raw request did not stop promptly after cancellation")
	}
	<-serverDone
}
