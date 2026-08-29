package engine

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func readV402Request(t *testing.T, raw []byte) (*http.Request, []byte) {
	t.Helper()
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		t.Fatalf("ReadRequest failed: %v\n%s", err, raw)
	}
	defer req.Body.Close()
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}
	return req, body
}

func TestV402AutomaticRetryPolicy(t *testing.T) {
	for _, method := range []string{"GET", "HEAD", "OPTIONS", "TRACE"} {
		if !automaticRetrySafe([]byte(method + " / HTTP/1.1\r\n\r\n")) {
			t.Fatalf("%s should be replay safe", method)
		}
	}
	for _, method := range []string{"POST", "PATCH", "PUT", "DELETE"} {
		if automaticRetrySafe([]byte(method + " / HTTP/1.1\r\n\r\n")) {
			t.Fatalf("%s should not be replayed automatically", method)
		}
	}
}

func TestV402Redirect307PreservesMethodAndBody(t *testing.T) {
	next, _ := url.Parse("https://example.test/next?x=1")
	raw := buildRequest("POST", "/start", "example.test", "DirFuzz/test", "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 3\r\n", "a=1")
	out, err := buildRedirectRequest(raw, http.StatusTemporaryRedirect, "https://example.test/start", next)
	if err != nil {
		t.Fatal(err)
	}
	req, body := readV402Request(t, out)
	if req.Method != http.MethodPost || string(body) != "a=1" {
		t.Fatalf("307 changed method/body: method=%s body=%q", req.Method, body)
	}
	if req.Host != "example.test" || req.URL.RequestURI() != "/next?x=1" {
		t.Fatalf("wrong redirect target: host=%q uri=%q", req.Host, req.URL.RequestURI())
	}
}

func TestV402Redirect303ConvertsPostToGet(t *testing.T) {
	next, _ := url.Parse("https://example.test/done")
	raw := buildRequest("POST", "/start", "example.test", "DirFuzz/test", "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 3\r\n", "a=1")
	out, err := buildRedirectRequest(raw, http.StatusSeeOther, "https://example.test/start", next)
	if err != nil {
		t.Fatal(err)
	}
	req, body := readV402Request(t, out)
	if req.Method != http.MethodGet || len(body) != 0 {
		t.Fatalf("303 did not switch to GET: method=%s body=%q", req.Method, body)
	}
	if req.Header.Get("Content-Length") != "" {
		t.Fatalf("GET redirect retained Content-Length: %q", req.Header.Get("Content-Length"))
	}
}

func TestV402CrossOriginRedirectDropsStandardCredentials(t *testing.T) {
	next, _ := url.Parse("https://other.test/next")
	raw := buildRequest("GET", "/start", "example.test", "DirFuzz/test", "Authorization: Bearer secret\r\nCookie: sid=secret\r\nX-Test: keep\r\n", "")
	out, err := buildRedirectRequest(raw, http.StatusFound, "https://example.test/start", next)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := readV402Request(t, out)
	if req.Header.Get("Authorization") != "" || req.Header.Get("Cookie") != "" {
		t.Fatalf("credentials leaked across origin: auth=%q cookie=%q", req.Header.Get("Authorization"), req.Header.Get("Cookie"))
	}
	if !strings.EqualFold(req.Header.Get("X-Test"), "keep") {
		t.Fatalf("non-credential header was unexpectedly removed: %q", req.Header.Get("X-Test"))
	}
}
