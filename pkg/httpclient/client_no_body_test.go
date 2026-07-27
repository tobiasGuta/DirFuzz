package httpclient

import (
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestRequestExpectsNoResponseBody(t *testing.T) {
	tests := []struct {
		name       string
		rawRequest string
		want       bool
	}{
		{name: "HEAD", rawRequest: "HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n", want: true},
		{name: "case insensitive", rawRequest: "head / HTTP/1.1\nHost: example.com\n\n", want: true},
		{name: "GET", rawRequest: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := requestExpectsNoResponseBody([]byte(tc.rawRequest)); got != tc.want {
				t.Fatalf("requestExpectsNoResponseBody() = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestParseRawResponseFinishesAfterNoBodyHeaders(t *testing.T) {
	tests := []struct {
		name         string
		status       string
		statusCode   int
		expectNoBody bool
	}{
		{name: "HEAD response", status: "200 OK", statusCode: http.StatusOK, expectNoBody: true},
		{name: "informational response", status: "103 Early Hints", statusCode: http.StatusEarlyHints},
		{name: "no content response", status: "204 No Content", statusCode: http.StatusNoContent},
		{name: "not modified response", status: "304 Not Modified", statusCode: http.StatusNotModified},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			writeDone := make(chan error, 1)
			go func() {
				_, err := io.WriteString(serverConn,
					"HTTP/1.1 "+tc.status+"\r\n"+
						"Content-Length: 99\r\n"+
						"Connection: keep-alive\r\n\r\n")
				writeDone <- err
			}()

			type parseResult struct {
				resp *RawResponse
				err  error
			}
			resultCh := make(chan parseResult, 1)
			go func() {
				resp, err := parseRawResponse(clientConn, tc.expectNoBody)
				resultCh <- parseResult{resp: resp, err: err}
			}()

			select {
			case result := <-resultCh:
				if result.err != nil {
					t.Fatalf("parseRawResponse() failed: %v", result.err)
				}
				if result.resp.StatusCode != tc.statusCode {
					t.Fatalf("StatusCode = %d, want %d", result.resp.StatusCode, tc.statusCode)
				}
				if !result.resp.BodyComplete {
					t.Fatal("BodyComplete = false, want true for a response with no message body")
				}
				if len(result.resp.Body) != 0 {
					t.Fatalf("body length = %d, want 0", len(result.resp.Body))
				}
			case <-time.After(time.Second):
				t.Fatal("parseRawResponse waited for a body that response semantics prohibit")
			}

			if err := <-writeDone; err != nil {
				t.Fatalf("writing response headers failed: %v", err)
			}
		})
	}
}

func TestParseRawResponseStillWaitsForOrdinaryResponseBody(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	headersWritten := make(chan struct{})
	sendBody := make(chan struct{})
	writeDone := make(chan error, 1)
	go func() {
		if _, err := io.WriteString(serverConn,
			"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\n"); err != nil {
			writeDone <- err
			return
		}
		close(headersWritten)
		<-sendBody
		_, err := io.WriteString(serverConn, "hello")
		writeDone <- err
	}()

	type parseResult struct {
		resp *RawResponse
		err  error
	}
	resultCh := make(chan parseResult, 1)
	go func() {
		resp, err := parseRawResponse(clientConn, false)
		resultCh <- parseResult{resp: resp, err: err}
	}()

	<-headersWritten
	select {
	case result := <-resultCh:
		close(sendBody)
		t.Fatalf("parseRawResponse returned before the advertised body arrived: resp=%+v err=%v", result.resp, result.err)
	case <-time.After(50 * time.Millisecond):
	}

	close(sendBody)
	result := <-resultCh
	if result.err != nil {
		t.Fatalf("parseRawResponse() failed: %v", result.err)
	}
	if !result.resp.BodyComplete {
		t.Fatal("BodyComplete = false, want true")
	}
	if string(result.resp.Body) != "hello" {
		t.Fatalf("body = %q, want hello", result.resp.Body)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("writing response failed: %v", err)
	}
}

func TestParseRawResponseParsesStatusLineWithoutHeaders(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		_, _ = io.WriteString(serverConn, "HTTP/1.1 204 No Content\r\n\r\n")
	}()

	resp, err := parseRawResponse(clientConn, false)
	if err != nil {
		t.Fatalf("parseRawResponse() failed: %v", err)
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("StatusCode = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
	if len(resp.HeaderMap) != 0 {
		t.Fatalf("HeaderMap = %v, want no headers", resp.HeaderMap)
	}
}
