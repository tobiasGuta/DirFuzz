package engine

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"dirfuzz/pkg/httpclient"
	"dirfuzz/pkg/netutil"
)

func validateOutboundHostname(hostname string, allowPrivate bool) error {
	if !allowPrivate && netutil.IsPrivateHost(hostname) {
		return fmt.Errorf("SSRF protection: target %q resolves to a private or loopback address", hostname)
	}
	return nil
}

func sanitizeHeaderToken(s string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}

// SetTarget sets the target URL and extracts the host.
// It rejects private/loopback IP ranges to prevent SSRF when driven via MCP.
func (e *Engine) SetTarget(targetURL string) error {
	targetURL = strings.ReplaceAll(targetURL, "{payload}", "{PAYLOAD}")

	u, err := url.Parse(targetURL)
	if err != nil {
		return err
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("invalid URL: missing scheme or host")
	}

	hostname := u.Hostname()
	// Respect engine-level override to allow private/loopback targets.
	e.Config.RLock()
	allow := e.Config.AllowPrivateTargets
	e.Config.RUnlock()
	if err := validateOutboundHostname(hostname, allow); err != nil {
		return err
	}

	e.targetLock.Lock()
	e.baseURL = targetURL
	e.host = u.Host
	if e.scopeDomain == "" {
		e.scopeDomain = hostname
	}
	e.targetLock.Unlock()
	if err := e.RefreshH2Client(); err != nil {
		return err
	}
	return nil
}

// RefreshH2Client rebuilds the shared HTTP/2 client when H2 mode is enabled.
// It is safe to call after the target URL changes or when H2 settings change.
func (e *Engine) RefreshH2Client() error {
	e.Config.RLock()
	h2Mode := e.Config.H2Mode
	streams := e.Config.H2ConcurrentStreams
	timeout := e.Config.Timeout
	insecure := e.Config.Insecure
	allowPrivate := e.Config.AllowPrivateTargets
	e.Config.RUnlock()

	if !h2Mode {
		e.H2Client = nil
		e.h2StreamSem = nil
		return nil
	}

	baseURL := e.BaseURL()
	if baseURL == "" {
		return fmt.Errorf("H2 mode requires a target URL")
	}
	if streams < 1 {
		streams = DefaultH2ConcurrentStreams
	}

	client, err := httpclient.NewH2ClientWithPrivatePolicy(baseURL, timeout, insecure, DefaultH2MaxHeaderListSize, allowPrivate)
	if err != nil {
		return err
	}
	e.H2Client = client
	e.h2StreamSem = make(chan struct{}, streams)
	return nil
}

func (e *Engine) BaseURL() string {
	e.targetLock.RLock()
	defer e.targetLock.RUnlock()
	return e.baseURL
}

func (e *Engine) Host() string {
	e.targetLock.RLock()
	defer e.targetLock.RUnlock()
	return e.host
}

func (e *Engine) followRedirectChain(
	ctx context.Context,
	initialResp *httpclient.RawResponse,
	targetURL, reqHost, ua string,
	headers map[string]string,
	maxRedirects int,
	proxyAddr string,
	timeout time.Duration,
) (*httpclient.RawResponse, string) {
	resp := initialResp
	finalURL := ""
	currentURL := targetURL
	ua = normalizeUserAgent(ua)
	if ua == "" {
		ua = "DirFuzz/2.0"
	}

	for i := 0; i < maxRedirects; i++ {
		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			break
		}
		location := resp.GetHeader("Location")
		if location == "" {
			break
		}

		baseURL, err := url.Parse(currentURL)
		if err == nil {
			if locURL, err := url.Parse(location); err == nil {
				location = baseURL.ResolveReference(locURL).String()
			}
		}

		parsedLoc, err := url.Parse(location)
		if err != nil {
			break
		}

		// SSRF guard on redirect destinations — allow override via config.
		e.Config.RLock()
		allow := e.Config.AllowPrivateTargets
		e.Config.RUnlock()
		if err := validateOutboundHostname(parsedLoc.Hostname(), allow); err != nil {
			break
		}

		reqPath := parsedLoc.Path
		if parsedLoc.RawQuery != "" {
			reqPath += "?" + parsedLoc.RawQuery
		}
		if reqPath == "" {
			reqPath = "/"
		}

		var headersStr strings.Builder
		for k, v := range headers {
			if strings.EqualFold(k, "User-Agent") {
				continue
			}
			headersStr.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
		}

		headersStrVal := headersStr.String()
		headersLower := strings.ToLower(headersStrVal)
		var defaultsBuilder strings.Builder
		if !strings.Contains(headersLower, "\nconnection:") && !strings.HasPrefix(headersLower, "connection:") {
			defaultsBuilder.WriteString("Connection: keep-alive\r\n")
		}
		if !strings.Contains(headersLower, "\naccept:") && !strings.HasPrefix(headersLower, "accept:") {
			defaultsBuilder.WriteString("Accept: */*\r\n")
		}
		
		rawReq := []byte(fmt.Sprintf(
			"GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n%s%s\r\n",
			reqPath, parsedLoc.Host, ua, headersStrVal, defaultsBuilder.String(),
		))

		nextResp, err := e.executeRequestWithRetry(ctx, location, rawReq, timeout, proxyAddr)
		if err != nil {
			break
		}
		resp = nextResp
		finalURL = location
		currentURL = location
	}

	return resp, finalURL
}

func (e *Engine) executeRequestWithRetry(ctx context.Context, targetURL string, rawRequest []byte, timeout time.Duration, proxyAddr string) (*httpclient.RawResponse, error) {
	e.Config.RLock()
	retries := e.Config.MaxRetries
	insecure := e.Config.Insecure
	h2Mode := e.Config.H2Mode
	antiBotFallback := e.Config.AntiBotFallback
	e.Config.RUnlock()

	if ctx == nil {
		ctx = context.Background()
	}

	if h2Mode && e.H2Client != nil {
		return e.executeH2RequestWithRetry(ctx, targetURL, rawRequest, timeout)
	}

	backoff := 1 * time.Second
	var (
		resp *httpclient.RawResponse
		err  error
	)
	for attempt := 0; attempt <= retries; attempt++ {
		resp, err = e.executeRequestOnce(ctx, targetURL, rawRequest, timeout, proxyAddr, insecure, h2Mode, antiBotFallback)
		if err == nil {
			e.mergeResponseCookies(targetURL, resp)
			
			// Inspect response footprint for health/block indicators
			isBlocked := resp.StatusCode == 429
			if !isBlocked {
				waf := FingerprintWAF(resp.Body, resp.Headers, resp.StatusCode, resp.Duration.Milliseconds())
				if waf.Detected {
					isBlocked = true
				}
			}
			
			e.ReportProxyStatus(proxyAddr, isBlocked)

			if retryResp, handled := e.handleAntiBotResponse(ctx, targetURL, rawRequest, timeout, proxyAddr, insecure, h2Mode, antiBotFallback, resp); handled {
				return retryResp, nil
			}
			return resp, nil
		}
		if isContextDoneError(ctx, err) {
			return nil, err
		}
		
		// If we hit connection error/timeout, report as failure/block candidate
		e.ReportProxyStatus(proxyAddr, true)

		e.emitLogEvent(LogLevelWarning, LogCategoryNetwork, EventRetryAttempt, fmt.Sprintf("request attempt %d failed: %v", attempt+1, err), map[string]interface{}{
			"attempt":     attempt + 1,
			"max_retries": retries,
			"target":      targetURL,
			"proxy":       proxyAddr,
			"error":       err.Error(),
		})
		if attempt < retries {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
				backoff *= 2
			}
		}
	}
	if err != nil {
		e.emitLogEvent(LogLevelError, LogCategoryNetwork, EventNetworkError, fmt.Sprintf("request failed after %d attempt(s): %v", retries+1, err), map[string]interface{}{
			"attempts": retries + 1,
			"target":   targetURL,
			"proxy":    proxyAddr,
			"error":    err.Error(),
		})
	}
	return resp, err
}

func (e *Engine) executeH2RequestWithRetry(ctx context.Context, targetURL string, rawRequest []byte, timeout time.Duration) (*httpclient.RawResponse, error) {
	e.Config.RLock()
	retries := e.Config.MaxRetries
	e.Config.RUnlock()

	if ctx == nil {
		ctx = context.Background()
	}

	backoff := 1 * time.Second
	var (
		resp *httpclient.RawResponse
		err  error
	)
	for attempt := 0; attempt <= retries; attempt++ {
		resp, err = e.executeH2Request(ctx, targetURL, rawRequest, timeout)
		if err == nil {
			return resp, nil
		}
		if isContextDoneError(ctx, err) {
			return nil, err
		}
		e.emitLogEvent(LogLevelWarning, LogCategoryNetwork, EventRetryAttempt, fmt.Sprintf("h2 attempt %d failed: %v", attempt+1, err), map[string]interface{}{
			"attempt":     attempt + 1,
			"max_retries": retries,
			"target":      targetURL,
			"error":       err.Error(),
		})
		if attempt < retries {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
				backoff *= 2
			}
		}
	}
	if err != nil {
		e.emitLogEvent(LogLevelError, LogCategoryNetwork, EventNetworkError, fmt.Sprintf("h2 request failed after %d attempt(s): %v", retries+1, err), map[string]interface{}{
			"attempts": retries + 1,
			"target":   targetURL,
			"error":    err.Error(),
		})
	}
	return resp, err
}

func isContextDoneError(ctx context.Context, err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	return ctx != nil && ctx.Err() != nil && errors.Is(err, ctx.Err())
}

func (e *Engine) executeH2Request(ctx context.Context, targetURL string, rawRequest []byte, timeout time.Duration) (*httpclient.RawResponse, error) {
	if e.H2Client == nil {
		if err := e.RefreshH2Client(); err != nil {
			return nil, err
		}
	}
	if e.H2Client == nil {
		return nil, fmt.Errorf("HTTP/2 client is not initialized")
	}

	if sem := e.h2StreamSem; sem != nil {
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	req, err := buildH2HTTPRequest(ctx, targetURL, rawRequest)
	if err != nil {
		return nil, err
	}
	e.requestsDispatched.Add(1)
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
		req = req.WithContext(ctx)
	}

	start := time.Now()
	resp, err := e.H2Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return rawResponseFromHTTPResponse(resp, start)
}

func buildH2HTTPRequest(ctx context.Context, targetURL string, rawRequest []byte) (*http.Request, error) {
	parsedTarget, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(rawRequest)))
	if err != nil {
		return nil, fmt.Errorf("failed to parse raw request: %w", err)
	}
	defer req.Body.Close()

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read raw request body: %w", err)
	}

	reqURL := *parsedTarget
	reqURL.Path = req.URL.Path
	reqURL.RawPath = req.URL.RawPath
	reqURL.RawQuery = req.URL.RawQuery
	reqURL.Fragment = ""
	if reqURL.Path == "" {
		reqURL.Path = "/"
	}

	outReq, err := http.NewRequestWithContext(ctx, req.Method, reqURL.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to build H2 request: %w", err)
	}
	outReq.Host = req.Host
	if outReq.Host == "" {
		outReq.Host = parsedTarget.Host
	}
	outReq.Header = req.Header.Clone()
	for _, key := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Transfer-Encoding", "Upgrade", "HTTP2-Settings"} {
		outReq.Header.Del(key)
	}
	return outReq, nil
}

func rawResponseFromHTTPResponse(resp *http.Response, start time.Time) (*httpclient.RawResponse, error) {
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, httpclient.MaxBodySize))
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var headersStr bytes.Buffer
	headersStr.WriteString(fmt.Sprintf("%s %s\r\n", resp.Proto, resp.Status))
	headerMap := make(map[string]string, len(resp.Header))
	for k, vals := range resp.Header {
		if len(vals) == 0 {
			continue
		}
		headerMap[strings.ToLower(k)] = vals[0]
		for _, v := range vals {
			headersStr.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
		}
	}

	var raw bytes.Buffer
	raw.WriteString(headersStr.String())
	raw.WriteString("\r\n")
	raw.Write(respBody)

	return &httpclient.RawResponse{
		StatusCode:   resp.StatusCode,
		Headers:      headersStr.String(),
		HeaderMap:    headerMap,
		Body:         respBody,
		Raw:          raw.Bytes(),
		Duration:     time.Since(start),
		BodyComplete: true,
	}, nil
}
