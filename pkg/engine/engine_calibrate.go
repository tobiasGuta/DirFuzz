package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// AutoCalibrate detects wildcard responses using randomised paths.
// Body comparison uses a normalised hash so that path-reflecting wildcard
// pages (which vary in size) are detected correctly.
func (e *Engine) AutoCalibrate() error {
	randoms := make([]string, CalibrationTestCount)
	for i := range randoms {
		randoms[i] = randomString(CalibrationRandomStringLen)
	}

	type sample struct {
		statusCode int
		bodyHash   [32]byte
		bodySize   int
	}

	var first *sample
	consistent := true

	for i := range randoms {
		word := randoms[i]
		currentBaseURL := e.BaseURL()
		fullURL := ""
		if strings.Contains(currentBaseURL, "{PAYLOAD}") {
			fullURL = strings.Replace(currentBaseURL, "{PAYLOAD}", word, 1)
		} else {
			fullURL = strings.TrimRight(currentBaseURL, "/") + "/" + word
		}

		parsedURL, errURL := url.Parse(fullURL)
		if errURL != nil {
			return fmt.Errorf("invalid calibration URL: %w", errURL)
		}
		reqPath := parsedURL.Path
		if parsedURL.RawQuery != "" {
			reqPath += "?" + parsedURL.RawQuery
		}
		if reqPath == "" {
			reqPath = "/"
		}

		var ua string
		if snapshot := e.configSnap.Load(); snapshot != nil {
			ua = snapshot.UserAgent
		} else {
			e.Config.RLock()
			ua = e.Config.UserAgent
			e.Config.RUnlock()
		}

		rawRequest := []byte(fmt.Sprintf(
			"GET %s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\nUser-Agent: %s\r\nAccept: */*\r\nAccept-Encoding: identity\r\n\r\n",
			reqPath, parsedURL.Host, ua,
		))

		var proxyAddr string
		if e.proxyDialer {
			proxyAddr = e.GetNextProxy()
		}

		sc := e.scannerCtx.Load()
		if sc == nil {
			return fmt.Errorf("scanner context not available")
		}

		resp, err := e.executeRequestWithRetry(sc.ctx, fullURL, rawRequest, CalibrationTimeout, proxyAddr)
		if err != nil {
			return fmt.Errorf("calibration request failed: %v", err)
		}

		// Normalise: replace the random string in the body before hashing so
		// that path-reflecting pages hash identically across requests.
		normBody := bytes.ReplaceAll(resp.Body, []byte(randoms[i]), []byte("FUZZ"))
		h := sha256.Sum256(normBody)

		s := &sample{
			statusCode: resp.StatusCode,
			bodyHash:   h,
			bodySize:   len(normBody),
		}

		if first == nil {
			first = s
		} else if s.statusCode != first.statusCode || s.bodyHash != first.bodyHash {
			consistent = false
			break
		}
	}

	if consistent && first != nil && first.statusCode > 0 {
		fmt.Fprintf(os.Stderr, "[+] Wildcard detected! Status: %d, normalised body hash consistent — filtering size: %d\n",
			first.statusCode, first.bodySize)
		e.AddFilterSize(first.bodySize)
	}

	return nil
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.IntN(len(letters))]
	}
	return string(b)
}

func (e *Engine) checkRecursiveWildcard(dirPath string) bool {
	e.Config.RLock()
	delay := e.Config.Delay
	e.Config.RUnlock()
	if delay > 0 {
		time.Sleep(delay)
	}

	currentBaseURL := e.BaseURL()
	word := strings.TrimSuffix(dirPath, "/") + "/" + randomString(RecursiveWildcardTestLen)
	if !strings.HasPrefix(word, "/") {
		word = "/" + word
	}
	fullURL := ""
	if strings.Contains(currentBaseURL, "{PAYLOAD}") {
		fullURL = strings.Replace(currentBaseURL, "{PAYLOAD}", word, 1)
	} else {
		fullURL = strings.TrimRight(currentBaseURL, "/") + word
	}

	parsedURL, errURL := url.Parse(fullURL)
	if errURL != nil {
		return true
	}

	reqPath := parsedURL.Path
	if parsedURL.RawQuery != "" {
		reqPath += "?" + parsedURL.RawQuery
	}
	if reqPath == "" {
		reqPath = "/"
	}

	var ua string
	if snapshot := e.configSnap.Load(); snapshot != nil {
		ua = snapshot.UserAgent
	} else {
		e.Config.RLock()
		ua = e.Config.UserAgent
		e.Config.RUnlock()
	}

	rawRequest := []byte(fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\nUser-Agent: %s\r\nAccept: */*\r\n\r\n",
		reqPath, parsedURL.Host, ua,
	))

	var proxyAddr string
	if e.proxyDialer {
		proxyAddr = e.GetNextProxy()
	}
	sc := e.scannerCtx.Load()
	if sc == nil {
		return true
	}
	resp, err := e.executeRequestOnceQuiet(sc.ctx, fullURL, rawRequest, RecursiveWildcardTimeout, proxyAddr)
	if err != nil {
		// Fail closed for recursion probes: if this endpoint drops or times out
		// on unknown children, recursing below it will amplify network errors.
		return true
	}
	// Treat permissive and redirect responses as wildcard indicators.
	// Some servers redirect unknown paths (e.g. /*) with 301/302 — these
	// should be treated as wildcard directories to avoid unbounded
	// recursive scanning.
	if resp.StatusCode == 200 || resp.StatusCode == 301 || resp.StatusCode == 302 {
		return true
	}
	return false
}

// CalibrateSoft404 performs a pre-flight calibration to generate baseline soft-404 SimHash values.
func (e *Engine) CalibrateSoft404() {
	e.Config.RLock()
	threshold := e.Config.SimhashThreshold
	limit := e.Config.SimhashClusterLimit
	insecure := e.Config.Insecure
	disabled := e.Config.DisableSoft404Calibration
	e.Config.RUnlock()

	if disabled {
		return
	}

	// If Simhash is disabled, skip calibration entirely to save traffic/time
	if threshold < 0 || limit <= 0 {
		return
	}

	paths := []string{
		"/chaos-random-af93k-123",
		"/nonexistent-page-chaos-abc",
		"/error-baseline-test-xyz",
	}

	e.targetLock.Lock()
	baseURL := e.baseURL
	e.targetLock.Unlock()
	if baseURL == "" {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	e.Config.RLock()
	allowPrivate := e.Config.AllowPrivateTargets
	e.Config.RUnlock()

	client, err := newHarvestClient(baseURL, 5*time.Second, insecure, false, allowPrivate)
	if err != nil {
		return
	}

	for _, p := range paths {
		targetURL := strings.TrimRight(baseURL, "/") + p
		req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
		if err != nil {
			continue
		}

		e.Config.RLock()
		for k, v := range e.Config.Headers {
			req.Header.Set(k, v)
		}
		e.Config.RUnlock()

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		// Only calibrate if status is 200/OK (Soft-404) or 204.
		if resp.StatusCode == 200 || resp.StatusCode == 204 {
			bodyHash := simhashBody(body)
			if bodyHash != 0 {
				e.simhashTracker.SeedBaseline(bodyHash)
				e.emitLogEvent(LogLevelInfo, LogCategoryFilter, EventSimhashCluster, fmt.Sprintf("seeded soft-404 simhash baseline for %s (hash %x)", p, bodyHash), nil)
			}
		}
	}
}
