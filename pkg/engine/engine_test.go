package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"dirfuzz/pkg/httpclient"

	"golang.org/x/time/rate"
)

func TestSanitizeHeaderToken(t *testing.T) {
	got := sanitizeHeaderToken("X-Test\r\nInjected: 1\rValue\n")
	want := "X-TestInjected: 1Value"
	if got != want {
		t.Fatalf("sanitizeHeaderToken() = %q, want %q", got, want)
	}
}

func TestBuildRequestSetsAcceptEncodingIdentity(t *testing.T) {
	raw := string(buildRequest("GET", "/admin", "example.com", "DirFuzz/2.0", "", ""))
	if !strings.Contains(raw, "Accept-Encoding: identity\r\n") {
		t.Fatalf("request missing Accept-Encoding identity header: %q", raw)
	}
}

func TestExecuteRequestWithRetryDoesNotLogCanceledContextAsNetworkError(t *testing.T) {
	eng := NewEngine(1, 100, 0.01)
	defer eng.Shutdown()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	req := buildRequest(http.MethodGet, "/", "127.0.0.1", "DirFuzz/2.0", "", "")
	_, err := eng.executeRequestWithRetry(ctx, "http://127.0.0.1/", req, time.Second, "")
	if err == nil {
		t.Fatal("expected canceled context error")
	}
	if !isContextDoneError(ctx, err) {
		t.Fatalf("expected context cancellation error, got %v", err)
	}

	select {
	case ev := <-eng.LogEvents:
		t.Fatalf("expected no retry/network log for canceled context, got %s: %s", ev.Type, ev.Message)
	default:
	}
}

func TestCheckRecursiveWildcardFailsClosedOnEmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("test server does not support hijacking")
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Fatalf("hijack failed: %v", err)
		}
		conn.Close()
	}))
	defer server.Close()

	eng := NewEngine(1, 100, 0.01)
	defer eng.Shutdown()
	eng.Config.Lock()
	eng.Config.AllowPrivateTargets = true
	eng.Config.Unlock()
	eng.RefreshConfigSnapshot()
	if err := eng.SetTarget(server.URL); err != nil {
		t.Fatalf("SetTarget() failed: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	eng.scannerCtx.Store(&scannerContext{ctx: ctx, cancel: cancel})

	if !eng.checkRecursiveWildcard(ctx, "/jobs.php") {
		t.Fatal("expected recursive wildcard check to fail closed on empty response")
	}

	select {
	case ev := <-eng.LogEvents:
		t.Fatalf("expected quiet wildcard probe, got log event %s: %s", ev.Type, ev.Message)
	default:
	}
}

func TestCheckRecursiveWildcardTreatsAuthWallsAsWildcard(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
			}))
			defer server.Close()

			eng := NewEngine(1, 100, 0.01)
			defer eng.Shutdown()
			eng.Config.Lock()
			eng.Config.AllowPrivateTargets = true
			eng.Config.Unlock()
			eng.RefreshConfigSnapshot()
			if err := eng.SetTarget(server.URL); err != nil {
				t.Fatalf("SetTarget() failed: %v", err)
			}

			if !eng.checkRecursiveWildcard(context.Background(), "/jobs.php") {
				t.Fatalf("expected recursive wildcard check to treat %d as a wildcard auth wall", status)
			}
		})
	}
}

func TestRecursiveMirrorReferencePaths(t *testing.T) {
	got := recursiveMirrorReferencePaths("/api/api/user?debug=1")
	want := []string{"api/api", "api", "api/user"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("recursiveMirrorReferencePaths() = %v, want %v", got, want)
	}
}

func TestRecursiveMirrorDetectionSuppressesRepeatedResponses(t *testing.T) {
	eng := NewEngine(1, 100, 0.01)
	sig := makeRecursiveResponseSignature(200, 65, 1, 1, "application/json", 0x1234)
	otherSig := makeRecursiveResponseSignature(200, 66, 1, 1, "application/json", 0x1234)

	eng.recursiveTracker.RememberSignature("api", sig)
	eng.recursiveTracker.RememberSignature("api/user", sig)

	if !eng.recursiveTracker.IsMirror("api/api", sig) {
		t.Fatal("expected repeated API root response to be treated as a recursive mirror")
	}
	if !eng.recursiveTracker.IsMirror("api/user/api", sig) {
		t.Fatal("expected child that mirrors its parent API response to be suppressed")
	}
	if !eng.recursiveTracker.IsMirror("api/api/user", sig) {
		t.Fatal("expected collapsed duplicate segment to match canonical API sibling")
	}
	if eng.recursiveTracker.IsMirror("api/jobs", otherSig) {
		t.Fatal("first-level API child with a different response should not be treated as a recursive mirror")
	}
	if eng.recursiveTracker.IsMirror("api/user/api", otherSig) {
		t.Fatal("different response signatures should remain visible")
	}
}

func TestShouldPruneRecursiveBranchSkipsFontDirectory(t *testing.T) {
	body := []byte(`<html><body>
		<a href="inter.woff2">inter.woff2</a>
		<a href="icons.ttf">icons.ttf</a>
		<a href="brand.svg">brand.svg</a>
	</body></html>`)

	prune, reason := shouldPruneRecursiveBranch("includes/fonts", "text/html", body)
	if !prune {
		t.Fatalf("expected font directory to be pruned, reason=%q", reason)
	}
}

func TestShouldPruneRecursiveBranchKeepsInterestingDirectoryListing(t *testing.T) {
	body := []byte(`<html><body>
		<a href="config.php.bak">config.php.bak</a>
		<a href="admin.old">admin.old</a>
		<a href="logo.svg">logo.svg</a>
		<a href="style.css">style.css</a>
		<a href="inter.woff2">inter.woff2</a>
	</body></html>`)

	if prune, reason := shouldPruneRecursiveBranch("includes/backups", "text/html", body); prune {
		t.Fatalf("did not expect interesting listing to be pruned, reason=%q", reason)
	}
	if prune, reason := shouldPruneRecursiveBranch("includes/fonts", "text/html", body); prune {
		t.Fatalf("did not expect font listing with interesting files to be pruned, reason=%q", reason)
	}
}

func TestShouldPruneRecursiveBranchKeepsAPIRoutes(t *testing.T) {
	body := []byte(`{"endpoints":["/api/user","/api/jobs"]}`)

	if prune, reason := shouldPruneRecursiveBranch("api/jobs", "application/json", body); prune {
		t.Fatalf("did not expect API route to be pruned, reason=%q", reason)
	}
}

func TestClassify403(t *testing.T) {
	tests := []struct {
		name     string
		body     []byte
		headers  string
		expected string
	}{
		{
			name:     "Cloudflare WAF Block",
			body:     []byte("Attention Required! | Cloudflare"),
			headers:  "HTTP/1.1 403 Forbidden\r\nServer: cloudflare\r\n",
			expected: Forbidden403TypeCFWAFBlock,
		},
		{
			name:     "Cloudflare Admin 403",
			body:     []byte("request forbidden by administrative rules"),
			headers:  "HTTP/1.1 403 Forbidden\r\nCF-RAY: 123456789-SJC\r\n",
			expected: Forbidden403TypeCFAdmin403,
		},
		{
			name:     "Nginx 403",
			body:     []byte("<center>nginx</center>"),
			headers:  "HTTP/1.1 403 Forbidden\r\nServer: nginx\r\n",
			expected: Forbidden403TypeNginx403,
		},
		{
			name:     "Generic 403",
			body:     []byte("Forbidden"),
			headers:  "HTTP/1.1 403 Forbidden\r\n",
			expected: Forbidden403TypeGeneric403,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Classify403(tt.body, tt.headers); got != tt.expected {
				t.Errorf("Classify403() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestSimhashBodyIsStable(t *testing.T) {
	body := []byte("Page /foo not found")
	if got, want := simhashBody(body), simhashBody(body); got != want {
		t.Fatalf("simhashBody() = %d, want %d", got, want)
	}
}

func TestExecuteAuthMatrixRequestsDetectsPrivilegeEscalation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Cookie") {
		case "session=A":
			fmt.Fprintln(w, "admin area")
		case "session=B":
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintln(w, "forbidden")
		default:
			fmt.Fprintln(w, "public area")
		}
	}))
	defer server.Close()

	eng := NewEngine(1, 100, 0.01)
	eng.Config.Lock()
	eng.Config.AllowPrivateTargets = true
	eng.Config.AuthMatrix = map[string][]string{
		"unauth": {"Cookie: session=guest"},
		"user":   {"Cookie: session=B"},
		"admin":  {"Cookie: session=A"},
	}
	eng.Config.Unlock()
	eng.RefreshConfigSnapshot()
	if err := eng.SetTarget(server.URL); err != nil {
		t.Fatalf("SetTarget() failed: %v", err)
	}

	snap := eng.configSnap.Load()
	if snap == nil {
		t.Fatal("expected config snapshot")
	}

	resp, rawReq, method, finding, _, err := eng.executeAuthMatrixRequests(
		context.Background(),
		server.URL,
		"/admin",
		"example.com",
		"DirFuzz/2.0",
		"GET",
		map[string]string{},
		DefaultHTTPTimeout,
		"",
		snap.AuthMatrix,
	)
	if err != nil {
		t.Fatalf("executeAuthMatrixRequests() failed: %v", err)
	}
	if method != "GET" {
		t.Fatalf("method = %q, want GET", method)
	}
	if len(rawReq) == 0 {
		t.Fatal("expected raw request bytes to be returned")
	}
	if resp == nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("selected status = %v, want 200", func() any {
			if resp == nil {
				return nil
			}
			return resp.StatusCode
		}())
	}
	if finding == nil {
		t.Fatal("expected auth-matrix finding")
	}
	if !strings.Contains(strings.Join(finding.Labels, ","), "BAC") {
		t.Fatalf("finding labels = %v, want BAC label", finding.Labels)
	}
	if !strings.Contains(finding.Confidence, "user=403") {
		t.Fatalf("finding confidence = %q, want user=403", finding.Confidence)
	}
}

func TestLiveResponseHarvestQueuesDiscoveredEndpointsFromScanResults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api":
			http.Redirect(w, r, "/api/", http.StatusMovedPermanently)
		case "/api/":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"endpoints":["/api/user","/api/jobs"]}`))
		case "/api/user":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"user-ok"}`))
		case "/api/jobs":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"jobs-ok"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	wordlistPath := filepath.Join(tmpDir, "wordlist.txt")
	if err := os.WriteFile(wordlistPath, []byte("api\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() failed: %v", err)
	}

	eng := NewEngine(4, 100, 0.01)
	defer eng.Shutdown()

	eng.Config.Lock()
	eng.Config.AllowPrivateTargets = true
	eng.Config.FollowRedirects = true
	eng.Config.HarvestResponse = true
	eng.Config.HarvestResponseDepth = 2
	eng.Config.HarvestResponseFetch = 10
	eng.Config.Methods = []string{http.MethodGet}
	eng.Config.Unlock()
	eng.RefreshConfigSnapshot()

	if err := eng.SetTarget(server.URL); err != nil {
		t.Fatalf("SetTarget() failed: %v", err)
	}

	eng.Start()
	eng.KickoffScanner(wordlistPath, 0)
	go func() {
		eng.Wait()
		eng.Shutdown()
	}()

	var seen []string
	timeout := time.After(5 * time.Second)
	for {
		select {
		case res, ok := <-eng.Results:
			if !ok {
				goto done
			}
			if res.IsAutoFilter {
				continue
			}
			seen = append(seen, res.Path)
			if containsString(seen, "api") && containsString(seen, "/api/user") && containsString(seen, "/api/jobs") {
				eng.Shutdown()
			}
		case <-timeout:
			t.Fatalf("timed out waiting for scan results; got %v", seen)
		}
	}

done:
	for _, want := range []string{"api", "/api/user", "/api/jobs"} {
		if !containsString(seen, want) {
			t.Fatalf("live response harvest missing %q in %v", want, seen)
		}
	}
	if got := atomic.LoadInt64(&eng.HarvestedPaths); got < 2 {
		t.Fatalf("HarvestedPaths = %d, want at least 2 live discoveries", got)
	}
}

func TestDiscoverParamHitsBisectsHiddenParameters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("debug") != "" || r.URL.Query().Get("preview") != "" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, "mutated-response")
			return
		}
		fmt.Fprintln(w, "baseline-response")
	}))
	defer server.Close()

	eng := NewEngine(1, 100, 0.01)
	eng.Config.Lock()
	eng.Config.AllowPrivateTargets = true
	eng.Config.Unlock()
	if err := eng.SetTarget(server.URL); err != nil {
		t.Fatalf("SetTarget() failed: %v", err)
	}
	eng.RefreshConfigSnapshot()

	baseReq := buildRequest("GET", "/", "example.com", "DirFuzz/2.0", "", "")
	baseResp, err := eng.executeRequestWithRetry(context.Background(), server.URL, baseReq, DefaultHTTPTimeout, "")
	if err != nil {
		t.Fatalf("baseline request failed: %v", err)
	}
	baseSize, _, _, _, baseHash := computeResponseMetrics(baseResp, "GET")

	hits := eng.discoverParamHits(
		context.Background(),
		ParamTask{URL: server.URL, BaselineStatusCode: baseResp.StatusCode, BaselineSize: baseSize, BaselineHash: baseHash},
		[]string{"foo", "debug", "bar", "preview"},
		paramBaseline{statusCode: baseResp.StatusCode, size: baseSize, hash: baseHash},
		nil,
		eng.configSnap.Load(),
	)

	if len(hits) != 2 {
		t.Fatalf("discoverParamHits() returned %d hits, want 2", len(hits))
	}
	got := []string{hits[0].Params[0], hits[1].Params[0]}
	want := []string{"debug", "preview"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("discoverParamHits() params = %v, want %v", got, want)
	}
}

func TestSimhashSoft404Clustering(t *testing.T) {
	eng := NewEngine(1, 100, 0.01)
	eng.simhashTracker.Configure(3, 2)

	if eng.simhashTracker.IsSoftFour(0x1234567890abcdef) {
		t.Fatal("first cluster member should not be suppressed")
	}
	if !eng.simhashTracker.IsSoftFour(0x1234567890abcdee) {
		t.Fatal("second close cluster member should be suppressed at the limit")
	}
	if !eng.simhashTracker.IsSoftFour(0x1234567890abcded) {
		t.Fatal("subsequent close cluster member should stay suppressed")
	}
	if eng.simhashTracker.IsSoftFour(0xfedcba0987654321) {
		t.Fatal("distant hash should start a fresh cluster")
	}
}

func TestDefaultHeadResponsesAreNotSimhashFiltered(t *testing.T) {
	const responseCount = DefaultSimhashClusterLimit + 4

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("request method = %q, want HEAD", r.Method)
		}
		size := 1000 + len(r.URL.Path)
		w.Header().Set("Content-Length", strconv.Itoa(size))
		w.Header().Set("X-Response-Path", r.URL.Path)
		w.WriteHeader(http.StatusOK + len(r.URL.Path)%2)
	}))
	defer server.Close()

	eng := NewEngine(1, 100, 0.01)
	defer eng.Shutdown()
	eng.UpdateConfig(func(c *Config) {
		c.AllowPrivateTargets = true
		c.AutoFilterThreshold = 0
	})
	if err := eng.SetTarget(server.URL); err != nil {
		t.Fatalf("SetTarget() failed: %v", err)
	}

	eng.Start()
	runID := atomic.LoadInt64(&eng.RunID)
	for i := 0; i < responseCount; i++ {
		path := fmt.Sprintf("/head-result-%02d-%s", i, strings.Repeat("x", i))
		eng.Submit(Job{Path: path, RunID: runID})
	}
	eng.Wait()

	var results []Result
	for len(eng.Results) > 0 {
		results = append(results, <-eng.Results)
	}
	if len(results) != responseCount {
		t.Fatalf("kept %d of %d distinct HEAD responses; simhash suppressed %d",
			len(results), responseCount, atomic.LoadInt64(&eng.SimhashSuppressed))
	}
	for _, result := range results {
		if result.Method != http.MethodHead {
			t.Errorf("result method = %q, want HEAD", result.Method)
		}
	}
	if got := atomic.LoadInt64(&eng.SimhashSuppressed); got != 0 {
		t.Fatalf("SimhashSuppressed = %d, want 0 for HEAD responses", got)
	}
}

func TestApplyFiltersOnlyClustersUsableBodyHashes(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		resp       *httpclient.RawResponse
		bodyHash   uint64
		wantSecond bool
	}{
		{
			name:       "complete decoded GET body",
			method:     http.MethodGet,
			resp:       &httpclient.RawResponse{StatusCode: http.StatusOK, Body: []byte("usable body"), BodyComplete: true},
			bodyHash:   0x1234,
			wantSecond: false,
		},
		{
			name:       "HEAD method",
			method:     http.MethodHead,
			resp:       &httpclient.RawResponse{StatusCode: http.StatusOK, Body: []byte("unexpected body"), BodyComplete: true},
			bodyHash:   0x1234,
			wantSecond: true,
		},
		{
			name:       "empty body",
			method:     http.MethodGet,
			resp:       &httpclient.RawResponse{StatusCode: http.StatusOK, BodyComplete: true},
			bodyHash:   0x1234,
			wantSecond: true,
		},
		{
			name:       "encoded body",
			method:     http.MethodGet,
			resp:       &httpclient.RawResponse{StatusCode: http.StatusOK, Body: []byte("encoded"), BodyComplete: true, BodyEncoded: true},
			bodyHash:   0x1234,
			wantSecond: true,
		},
		{
			name:       "incomplete body",
			method:     http.MethodGet,
			resp:       &httpclient.RawResponse{StatusCode: http.StatusOK, Body: []byte("partial")},
			bodyHash:   0x1234,
			wantSecond: true,
		},
		{
			name:       "zero body hash",
			method:     http.MethodGet,
			resp:       &httpclient.RawResponse{StatusCode: http.StatusOK, Body: []byte("!!!"), BodyComplete: true},
			bodyHash:   0,
			wantSecond: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			eng := NewEngine(1, 100, 0.01)
			defer eng.Shutdown()
			eng.simhashTracker.Configure(0, 2)

			apply := func() bool {
				return eng.applyFilters(
					tc.resp,
					tc.method,
					len(tc.resp.Body), 0, 0,
					tc.bodyHash,
					"",
					false,
					nil, nil, nil,
					-1, -1, -1, -1,
					nil, nil,
					0, 0,
					false,
				)
			}
			if !apply() {
				t.Fatal("first response should not be suppressed")
			}
			if got := apply(); got != tc.wantSecond {
				t.Fatalf("second response kept = %t, want %t", got, tc.wantSecond)
			}
			wantSuppressed := int64(0)
			if !tc.wantSecond {
				wantSuppressed = 1
			}
			if got := atomic.LoadInt64(&eng.SimhashSuppressed); got != wantSuppressed {
				t.Fatalf("SimhashSuppressed = %d, want %d", got, wantSuppressed)
			}
		})
	}
}

func TestSimhashSeedBaseline(t *testing.T) {
	eng := NewEngine(1, 100, 0.01)
	eng.simhashTracker.Configure(3, 2)

	hash := uint64(0x1234567890abcdef)
	eng.simhashTracker.SeedBaseline(hash)

	if !eng.simhashTracker.IsSoftFour(hash) {
		t.Fatal("first check of seeded baseline should be suppressed immediately")
	}

	closeHash := uint64(0x1234567890abcdee)
	if !eng.simhashTracker.IsSoftFour(closeHash) {
		t.Fatal("close hash matching seeded baseline should be suppressed immediately")
	}

	distantHash := uint64(0xfedcba0987654321)
	if eng.simhashTracker.IsSoftFour(distantHash) {
		t.Fatal("distant hash should not be suppressed by seeded baseline")
	}
}

func TestSpiderChildJobIncrementsDepth(t *testing.T) {
	parent := Job{Path: "/page/1", Depth: 4, Method: "GET", RunID: 99}
	child := spiderChildJob(parent, "/page/2")

	if child.Path != "/page/2" {
		t.Fatalf("child path = %q, want %q", child.Path, "/page/2")
	}
	if child.Depth != parent.Depth+1 {
		t.Fatalf("child depth = %d, want %d", child.Depth, parent.Depth+1)
	}
	if child.Method != "GET" {
		t.Fatalf("child method = %q, want GET", child.Method)
	}
	if child.RunID != parent.RunID {
		t.Fatalf("child run ID = %d, want %d", child.RunID, parent.RunID)
	}
}

func TestAutoCalibrate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Wildcard response")
	}))
	defer server.Close()

	eng := NewEngine(1, 100, 0.01)
	eng.Config.Lock()
	eng.Config.AllowPrivateTargets = true
	eng.Config.Unlock()
	if err := eng.SetTarget(server.URL); err != nil {
		t.Fatalf("SetTarget() failed: %v", err)
	}

	if err := eng.AutoCalibrate(); err != nil {
		t.Fatalf("AutoCalibrate() failed: %v", err)
	}

	// This is a simplified check. A more robust test would inspect the filter.
	if len(eng.Config.FilterSizes) == 0 {
		t.Errorf("AutoCalibrate() did not add a filter size")
	}
}

func TestEngineCalibrateSoft404(t *testing.T) {
	soft404Body := "Custom Soft-404 error page: path is not found"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, soft404Body)
	}))
	defer server.Close()

	eng := NewEngine(1, 100, 0.01)
	eng.Config.Lock()
	eng.Config.AllowPrivateTargets = true
	eng.Config.SimhashThreshold = 3
	eng.Config.SimhashClusterLimit = 2
	eng.Config.DisableSoft404Calibration = false
	eng.Config.Unlock()

	if err := eng.SetTarget(server.URL); err != nil {
		t.Fatalf("SetTarget() failed: %v", err)
	}

	// Run calibration
	eng.CalibrateSoft404()

	// Verify that the soft-404 body hash is now suppressed on first check
	hash := simhashBody([]byte(soft404Body + "\n")) // Http server adds newline
	if !eng.simhashTracker.IsSoftFour(hash) {
		t.Fatal("expected soft-404 baseline to be suppressed immediately after calibration")
	}
}

func TestAutoCalibrateUsesNormalizedBodySize(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "missing %s", r.URL.Path)
	}))
	defer server.Close()

	eng := NewEngine(1, 100, 0.01)
	eng.Config.Lock()
	eng.Config.AllowPrivateTargets = true
	eng.Config.Unlock()
	if err := eng.SetTarget(server.URL); err != nil {
		t.Fatalf("SetTarget() failed: %v", err)
	}

	if err := eng.AutoCalibrate(); err != nil {
		t.Fatalf("AutoCalibrate() failed: %v", err)
	}

	expectedSize := len("missing /FUZZ")
	if !eng.Config.FilterSizes[expectedSize] {
		t.Fatalf("expected normalized filter size %d to be added; got %+v", expectedSize, eng.Config.FilterSizes)
	}
}

func TestAutoCalibrateUsesPayloadPlaceholderInBaseURL(t *testing.T) {
	var nonSearchCalls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/search" {
			n := atomic.AddInt32(&nonSearchCalls, 1)
			fmt.Fprintf(w, "wrong-route-%d", n)
			return
		}
		q := r.URL.Query().Get("q")
		fmt.Fprintf(w, "missing %s", q)
	}))
	defer server.Close()

	eng := NewEngine(1, 100, 0.01)
	eng.Config.Lock()
	eng.Config.AllowPrivateTargets = true
	eng.Config.Unlock()
	if err := eng.SetTarget(server.URL + "/search?q={PAYLOAD}"); err != nil {
		t.Fatalf("SetTarget() failed: %v", err)
	}

	if err := eng.AutoCalibrate(); err != nil {
		t.Fatalf("AutoCalibrate() failed: %v", err)
	}

	if atomic.LoadInt32(&nonSearchCalls) != 0 {
		t.Fatalf("expected calibration to use /search path only, got %d non-search calls", nonSearchCalls)
	}
	expectedSize := len("missing FUZZ")
	if !eng.Config.FilterSizes[expectedSize] {
		t.Fatalf("expected normalized filter size %d to be added; got %+v", expectedSize, eng.Config.FilterSizes)
	}
}

func TestIsSameSpiderScopeHostIgnoresPort(t *testing.T) {
	absSameHost, err := url.Parse("http://example.com:8080/admin")
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}
	if !isSameSpiderScopeHost("example.com", absSameHost) {
		t.Fatal("expected same hostname to match even when absolute URL includes port")
	}

	absDifferentHost, err := url.Parse("http://other.example.com:8080/admin")
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}
	if isSameSpiderScopeHost("example.com", absDifferentHost) {
		t.Fatal("expected different hostname to be rejected")
	}

	relative, err := url.Parse("/admin")
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}
	if !isSameSpiderScopeHost("example.com", relative) {
		t.Fatal("expected relative link to be accepted")
	}
}

func TestSetRPSUpdatesLimiterBurst(t *testing.T) {
	eng := NewEngine(50, 1000, 0.01)
	limiter := eng.getLimiter("example.com:443")
	if limiter.Burst() != eng.currentBurst {
		t.Fatalf("initial limiter burst = %d, want %d", limiter.Burst(), eng.currentBurst)
	}

	eng.SetRPS(1)

	if eng.currentLimit != rate.Limit(1) {
		t.Fatalf("currentLimit = %v, want %v", eng.currentLimit, rate.Limit(1))
	}
	if eng.currentBurst != MinRateLimitBurst {
		t.Fatalf("currentBurst = %d, want %d", eng.currentBurst, MinRateLimitBurst)
	}
	if limiter.Burst() != MinRateLimitBurst {
		t.Fatalf("existing limiter burst = %d, want %d", limiter.Burst(), MinRateLimitBurst)
	}

	newLimiter := eng.getLimiter("another.example.com:443")
	if newLimiter.Burst() != MinRateLimitBurst {
		t.Fatalf("new limiter burst = %d, want %d", newLimiter.Burst(), MinRateLimitBurst)
	}
}

func TestLoadResumeStateRestoresBloomFilter(t *testing.T) {
	tmpDir := t.TempDir()
	resumePath := filepath.Join(tmpDir, "resume.json")

	eng1 := NewEngine(2, 100, 0.01)
	eng1.ResumeFile = resumePath
	eng1.shardedFilter.TestAndAddString("GET:/admin")
	eng1.shardedFilter.TestAndAddString("GET:/secret")
	eng1.saveResumeState("wordlists/common.txt", 42, true)

	eng2 := NewEngine(2, 100, 0.01)
	eng2.ResumeFile = resumePath
	wordlist, line, err := eng2.LoadResumeState(resumePath)
	if err != nil {
		t.Fatalf("LoadResumeState() failed: %v", err)
	}
	if wordlist != "wordlists/common.txt" || line != 42 {
		t.Fatalf("resume state mismatch: wordlist=%q line=%d", wordlist, line)
	}
	if !eng2.shardedFilter.TestAndAddString("GET:/admin") {
		t.Fatal("expected restored bloom filter to mark GET:/admin as already seen")
	}
	if !eng2.shardedFilter.TestAndAddString("GET:/secret") {
		t.Fatal("expected restored bloom filter to mark GET:/secret as already seen")
	}
	if eng2.shardedFilter.TestAndAddString("GET:/new") {
		t.Fatal("expected unseen key to be accepted after bloom restore")
	}
}

func TestChangeWordlistConcurrency(t *testing.T) {
	// Create a dummy wordlist file
	tmpfile, err := os.CreateTemp("", "wordlist")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	if _, err := tmpfile.WriteString("test\n"); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	eng := NewEngine(10, 1000, 0.01)
	eng.SetTarget("http://localhost:12345") // Dummy target

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				_ = eng.ChangeWordlist(tmpfile.Name())
			}
		}()
	}
	wg.Wait()
}

func TestVerbTamperHeaders(t *testing.T) {
	tests := []struct {
		name   string
		method string
		want   map[string]string
	}{
		{
			name:   "GET returns nil",
			method: "GET",
			want:   nil,
		},
		{
			name:   "HEAD returns nil",
			method: "HEAD",
			want:   nil,
		},
		{
			name:   "DELETE returns override headers",
			method: "DELETE",
			want: map[string]string{
				"X-HTTP-Method-Override": "DELETE",
				"X-Forwarded-Method":     "DELETE",
				"X-Method-Override":      "DELETE",
			},
		},
		{
			name:   "PATCH returns override headers",
			method: "PATCH",
			want: map[string]string{
				"X-HTTP-Method-Override": "PATCH",
				"X-Forwarded-Method":     "PATCH",
				"X-Method-Override":      "PATCH",
			},
		},
		{
			name:   "POST returns override headers",
			method: "POST",
			want: map[string]string{
				"X-HTTP-Method-Override": "POST",
				"X-Forwarded-Method":     "POST",
				"X-Method-Override":      "POST",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := verbTamperHeaders(tt.method)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("verbTamperHeaders(%q) = %#v, want %#v", tt.method, got, tt.want)
			}
		})
	}
}

func TestWorkerFuzzesBodyPayloadWithoutAppendingURL(t *testing.T) {
	type observed struct {
		method string
		path   string
		otp    string
		action string
	}

	observedCh := make(chan observed, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm() failed: %v", err)
		}
		observedCh <- observed{
			method: r.Method,
			path:   r.URL.Path,
			otp:    r.Form.Get("otp"),
			action: r.Form.Get("action"),
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	eng := NewEngine(1, 100, 0.01)
	eng.UpdateConfig(func(c *Config) {
		c.AllowPrivateTargets = true
		c.RequestBody = "otp={PAYLOAD}&action="
	})
	if err := eng.SetTarget(server.URL + "/two_fa"); err != nil {
		t.Fatalf("SetTarget() failed: %v", err)
	}

	eng.Start()
	defer eng.Shutdown()

	runID := atomic.LoadInt64(&eng.RunID)
	eng.Submit(Job{Path: "1111", Depth: 0, Method: "POST", RunID: runID})
	eng.Wait()

	select {
	case got := <-observedCh:
		if got.method != "POST" {
			t.Fatalf("method = %q, want POST", got.method)
		}
		if got.path != "/two_fa" {
			t.Fatalf("path = %q, want /two_fa", got.path)
		}
		if got.otp != "1111" {
			t.Fatalf("otp = %q, want 1111", got.otp)
		}
		if got.action != "" {
			t.Fatalf("action = %q, want empty", got.action)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for worker request")
	}
}

func TestWorkerVerbTamperHonorsManualOverrideHeader(t *testing.T) {
	type observed struct {
		xHTTPMethodOverride string
		xForwardedMethod    string
		xMethodOverride     string
	}

	observedCh := make(chan observed, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observedCh <- observed{
			xHTTPMethodOverride: r.Header.Get("X-HTTP-Method-Override"),
			xForwardedMethod:    r.Header.Get("X-Forwarded-Method"),
			xMethodOverride:     r.Header.Get("X-Method-Override"),
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	eng := NewEngine(1, 100, 0.01)
	eng.Config.Lock()
	eng.Config.AllowPrivateTargets = true
	eng.Config.Unlock()
	if err := eng.SetTarget(server.URL); err != nil {
		t.Fatalf("SetTarget() failed: %v", err)
	}
	eng.UpdateConfig(func(c *Config) {
		c.VerbTamper = true
	})

	eng.Start()
	defer eng.Shutdown()

	runID := atomic.LoadInt64(&eng.RunID)
	eng.Submit(Job{
		Path:   "/tamper",
		Depth:  0,
		Method: "DELETE",
		RunID:  runID,
		ExtraHeaders: map[string]string{
			"X-HTTP-Method-Override": "PUT",
		},
	})
	eng.Wait()

	select {
	case got := <-observedCh:
		if got.xHTTPMethodOverride != "PUT" {
			t.Fatalf("manual override should win: got X-HTTP-Method-Override=%q, want %q", got.xHTTPMethodOverride, "PUT")
		}
		if got.xForwardedMethod != "DELETE" {
			t.Fatalf("expected auto X-Forwarded-Method to remain method value: got %q, want %q", got.xForwardedMethod, "DELETE")
		}
		if got.xMethodOverride != "DELETE" {
			t.Fatalf("expected auto X-Method-Override to remain method value: got %q, want %q", got.xMethodOverride, "DELETE")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for worker request")
	}
}

func TestSmartProxyCooldown(t *testing.T) {
	eng := NewEngine(1, 100, 0.01)

	eng.proxiesLock.Lock()
	eng.proxies = []smartProxy{
		{addr: "http://127.0.0.1:8081"},
		{addr: "http://127.0.0.1:8082"},
		{addr: "http://127.0.0.1:8083"},
	}
	eng.proxyDialer = true
	eng.proxiesLock.Unlock()

	// Initial rotation checks
	p1 := eng.GetNextProxy()
	p2 := eng.GetNextProxy()
	p3 := eng.GetNextProxy()

	// Assert simple round-robin first
	all := map[string]bool{p1: true, p2: true, p3: true}
	if len(all) != 3 {
		t.Fatalf("expected 3 distinct rotated proxies, got %v, %v, %v", p1, p2, p3)
	}

	// Block the second proxy
	blockedAddr := "http://127.0.0.1:8082"
	eng.ReportProxyStatus(blockedAddr, true)

	// Get next proxies: they should skip the blocked one and only return the other two
	for i := 0; i < 6; i++ {
		p := eng.GetNextProxy()
		if p == blockedAddr {
			t.Fatalf("blocked proxy %s returned while in cooldown", blockedAddr)
		}
	}

	// Recover the blocked proxy
	eng.ReportProxyStatus(blockedAddr, false)

	// Rotated proxy should reappear
	reappeared := false
	for i := 0; i < 6; i++ {
		if eng.GetNextProxy() == blockedAddr {
			reappeared = true
			break
		}
	}
	if !reappeared {
		t.Fatalf("blocked proxy %s should have returned to rotation after recovery", blockedAddr)
	}
}
