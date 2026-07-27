package engine

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"dirfuzz/pkg/httpclient"
)

func TestMeaningfulAccessImprovementRequiresBlockedTo2xxTransition(t *testing.T) {
	for _, original := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		for _, candidate := range []int{http.StatusOK, http.StatusCreated, http.StatusAccepted, http.StatusNoContent, http.StatusPartialContent} {
			if !isMeaningfulAccessImprovement(original, candidate) {
				t.Errorf("isMeaningfulAccessImprovement(%d, %d) = false, want true", original, candidate)
			}
		}
		for _, candidate := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusTooManyRequests, http.StatusInternalServerError} {
			if isMeaningfulAccessImprovement(original, candidate) {
				t.Errorf("isMeaningfulAccessImprovement(%d, %d) = true, want false", original, candidate)
			}
		}
	}

	if isMeaningfulAccessImprovement(http.StatusOK, http.StatusOK) {
		t.Fatal("an already-accessible response must not be labeled as a bypass")
	}

	blocked := &httpclient.RawResponse{StatusCode: http.StatusForbidden, Body: []byte("same block page")}
	samePageWithSuccessStatus := &httpclient.RawResponse{StatusCode: http.StatusOK, Body: []byte("same block page")}
	if isMeaningfulBypassResponse(blocked, samePageWithSuccessStatus) {
		t.Fatal("a 200 response containing the unchanged block page must not be labeled as a bypass")
	}
	granted := &httpclient.RawResponse{StatusCode: http.StatusOK, Body: []byte("private content")}
	if !isMeaningfulBypassResponse(blocked, granted) {
		t.Fatal("a blocked-to-200 transition with different content should be accepted")
	}
}

func TestConfigured403BypassRunsBeforeDisplaySizeFilter(t *testing.T) {
	const blockedBody = "blocked-response"
	const grantedBody = "authorized content"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-For") == "127.0.0.1" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(grantedBody))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(blockedBody))
	}))
	defer server.Close()

	eng := NewEngine(1, 100, 0.01)
	defer eng.Shutdown()
	eng.UpdateConfig(func(c *Config) {
		c.AllowPrivateTargets = true
		c.Methods = []string{http.MethodGet}
		c.FourOhThreeBypass = true
		c.AutoFilterThreshold = 0
		c.SimhashClusterLimit = 0
		c.FilterSizes[len(blockedBody)] = true
	})
	if err := eng.SetTarget(server.URL); err != nil {
		t.Fatalf("SetTarget() failed: %v", err)
	}
	eng.Start()

	runID := atomic.LoadInt64(&eng.RunID)
	eng.Submit(Job{Path: "/blocked", Method: http.MethodGet, RunID: runID})
	eng.Wait()

	var bypassResult *Result
	for len(eng.Results) > 0 {
		result := <-eng.Results
		for _, label := range result.Labels {
			if strings.HasPrefix(label, "BYPASS:") {
				copyResult := result
				bypassResult = &copyResult
			}
		}
	}
	if bypassResult == nil {
		t.Fatal("configured bypass did not run before the blocked response's display-size filter")
	}
	if bypassResult.StatusCode != http.StatusOK {
		t.Fatalf("bypass status = %d, want 200", bypassResult.StatusCode)
	}
}
