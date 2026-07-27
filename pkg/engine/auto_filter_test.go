package engine

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestAutoFilterFingerprintUsesCompoundResponseIdentity(t *testing.T) {
	base := makeAutoFilterFingerprint(http.StatusForbidden, 1234, " Text/HTML ", 0x1234, Forbidden403TypeGeneric403)

	if got := makeAutoFilterFingerprint(http.StatusForbidden, 1234, "text/html", 0x1234, Forbidden403TypeGeneric403); got != base {
		t.Fatalf("normalized equivalent fingerprint = %#v, want %#v", got, base)
	}

	tests := []struct {
		name        string
		fingerprint autoFilterFingerprint
	}{
		{
			name:        "status",
			fingerprint: makeAutoFilterFingerprint(http.StatusOK, 1234, "text/html", 0x1234, Forbidden403TypeGeneric403),
		},
		{
			name:        "content type",
			fingerprint: makeAutoFilterFingerprint(http.StatusForbidden, 1234, "application/json", 0x1234, Forbidden403TypeGeneric403),
		},
		{
			name:        "body hash",
			fingerprint: makeAutoFilterFingerprint(http.StatusForbidden, 1234, "text/html", 0x5678, Forbidden403TypeGeneric403),
		},
		{
			name:        "body size",
			fingerprint: makeAutoFilterFingerprint(http.StatusForbidden, 4321, "text/html", 0x1234, Forbidden403TypeGeneric403),
		},
		{
			name:        "403 classification",
			fingerprint: makeAutoFilterFingerprint(http.StatusForbidden, 1234, "text/html", 0x1234, Forbidden403TypeNginx403),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.fingerprint == base {
				t.Fatalf("fingerprint unexpectedly collapsed to %#v", base)
			}
		})
	}
}

func TestSmartAutoFilterDoesNotPromoteBodySizeToGlobalFilter(t *testing.T) {
	const bodySize = 1234
	blockedBody := strings.Repeat("x", bodySize)
	realBody := strings.Repeat("y", bodySize)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/blocked-"):
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(blockedBody))
		case r.URL.Path == "/real" || r.URL.Path == "/manual-real":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(realBody))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	eng := NewEngine(1, 100, 0.01)
	defer eng.Shutdown()
	eng.UpdateConfig(func(c *Config) {
		c.AllowPrivateTargets = true
		c.Methods = []string{http.MethodGet}
		c.AutoFilterThreshold = 2
		c.SimhashClusterLimit = 0
	})
	if err := eng.SetTarget(server.URL); err != nil {
		t.Fatalf("SetTarget() failed: %v", err)
	}
	eng.Start()

	runID := atomic.LoadInt64(&eng.RunID)
	eng.Submit(Job{Path: "/blocked-1", Method: http.MethodGet, RunID: runID})
	eng.Submit(Job{Path: "/blocked-2", Method: http.MethodGet, RunID: runID})
	eng.Wait()

	eng.Config.RLock()
	sizeGloballyFiltered := eng.Config.FilterSizes[bodySize]
	eng.Config.RUnlock()
	if sizeGloballyFiltered {
		t.Fatalf("smart auto-filter promoted response size %d into the global manual filter map", bodySize)
	}

	eng.Submit(Job{Path: "/real", Method: http.MethodGet, RunID: runID})
	eng.Wait()

	var resultPaths []string
	realKept := false
	for len(eng.Results) > 0 {
		result := <-eng.Results
		resultPaths = append(resultPaths, fmt.Sprintf("%s:%d", result.Path, result.StatusCode))
		if result.Path == "/real" && result.StatusCode == http.StatusOK && result.Size == bodySize {
			realKept = true
		}
	}
	if !realKept {
		t.Fatalf("same-size real 200 response was hidden; results = %v", resultPaths)
	}

	// Explicit user size filters remain global and authoritative.
	eng.AddFilterSize(bodySize)
	eng.Submit(Job{Path: "/manual-real", Method: http.MethodGet, RunID: runID})
	eng.Wait()
	for len(eng.Results) > 0 {
		result := <-eng.Results
		if result.Path == "/manual-real" {
			t.Fatalf("manual size filter did not suppress %s", result.Path)
		}
	}

	base := makeAutoFilterFingerprint(http.StatusForbidden, bodySize, "text/html", simhashBody([]byte(blockedBody)), Forbidden403TypeGeneric403)
	real := makeAutoFilterFingerprint(http.StatusOK, bodySize, "application/json", simhashBody([]byte(realBody)), "")
	if base == real {
		t.Fatal("blocked and real responses unexpectedly share an automatic fingerprint")
	}
}
