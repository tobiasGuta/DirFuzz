package engine

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dirfuzz/pkg/httpclient"

	"github.com/bits-and-blooms/bloom/v3"
	"golang.org/x/time/rate"
)

// Config holds the dynamic settings for the engine.
type Config struct {
	sync.RWMutex
	UserAgent   string
	Headers     map[string]string
	MatchCodes  map[int]bool
	FilterSizes map[int]bool
	IsPaused    bool
	Delay       time.Duration
	MaxWorkers  int // Controls active workers
	// Recursive settings
	Recursive    bool
	MaxDepth     int
	WordlistPath string // Store original path for recursion
	Extensions   []string
	Mutate       bool
}

// Job represents a single scan task
type Job struct {
	Path  string
	Depth int
}

// Engine represents the core memory queue system for the brute-forcer.
type Engine struct {
	jobs          chan Job
	wg            sync.WaitGroup
	filter        *bloom.BloomFilter
	filterLock    sync.Mutex
	numWorkers    int
	baseURL       string
	host          string
	Config        *Config
	scannerCtx    context.Context
	scannerCancel context.CancelFunc
	scannerWg     sync.WaitGroup
	Results       chan Result

	// Eagle Mode State (Previous Scan Data)
	PreviousState map[string]int // Map[Path]StatusCode

	// Proxy Rotation
	proxies     []string
	proxyIndex  uint64
	proxyDialer bool

	// Rate Limiter
	limiter *rate.Limiter

	// Progress tracking
	TotalLines     int64
	ProcessedLines int64

	// Dynamic worker management
	workerLock sync.Mutex

	// Telemetry (Atomic counters)
	Count200     int64
	Count403     int64
	Count404     int64
	Count429     int64
	Count500     int64
	CountConnErr int64

	// Smart Filter State
	fpMutex  sync.RWMutex
	fpCounts map[string]int // "Status:Size" -> count
}

// Result holds the details of a successful fuzzing hit.
type Result struct {
	Path          string            `json:"path"`
	StatusCode    int               `json:"status"`
	Size          int               `json:"length"`
	Headers       map[string]string `json:"headers,omitempty"`     // Captured interesting headers
	IsEagleAlert  bool              `json:"eagle_alert,omitempty"` // Flag for state changes
	OldStatusCode int               `json:"old_status,omitempty"`  // Previous status code (if Eagle Alert)
	IsAutoFilter  bool              `json:"auto_filter,omitempty"` // Flag for auto-filtering events
}

// String returns a string representation of the result for CLI output.
func (r Result) String() string {
	extras := ""
	if val, ok := r.Headers["Server"]; ok {
		extras += fmt.Sprintf(" [Server: %s]", val)
	}
	if val, ok := r.Headers["X-Powered-By"]; ok {
		extras += fmt.Sprintf(" [X-Powered-By: %s]", val)
	}
	return fmt.Sprintf("[+] HIT: %s (Status: %d, Size: %d)%s", r.Path, r.StatusCode, r.Size, extras)
}

// NewEngine initializes a new Engine with a worker pool and a Bloom filter.
// expectedItems: Estimated number of unique payloads (e.g., 10,000,000).
// falsePositiveRate: Acceptable false positive rate (e.g., 0.001 for 0.1%).
func NewEngine(numWorkers int, expectedItems uint, falsePositiveRate float64) *Engine {
	// Initialize with a default rate limit (can be updated via SetRPS)
	// Default to 50 RPS for safety
	defaultRPS := rate.Limit(50)
	burst := numWorkers // Allow burst equal to max concurrency
	if burst < 10 {
		burst = 10
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &Engine{
		// Buffer the channel to prevent the producer from blocking immediately
		jobs:       make(chan Job, numWorkers*10),
		filter:     bloom.NewWithEstimates(expectedItems, falsePositiveRate),
		numWorkers: numWorkers,
		limiter:    rate.NewLimiter(defaultRPS, burst),
		Config: &Config{
			UserAgent:   "DirFuzz/1.0",
			Headers:     make(map[string]string),
			MatchCodes:  make(map[int]bool),
			FilterSizes: make(map[int]bool),
			IsPaused:    false,
			Delay:       0,
			MaxWorkers:  numWorkers,
		},
		scannerCtx:    ctx,
		scannerCancel: cancel,
		Results:       make(chan Result, numWorkers*10),
		fpCounts:      make(map[string]int),
	}
}

// LoadProxies loads a list of SOCKS5 proxies from a file.
func (e *Engine) LoadProxies(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	var proxies []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			proxies = append(proxies, line)
		}
	}
	e.proxies = proxies
	if len(proxies) > 0 {
		e.proxyDialer = true
		fmt.Printf("[*] Loaded %d proxies from %s\n", len(proxies), path)
	}
	return scanner.Err()
}

// GetNextProxy returns the next proxy in the list using round-robin.
func (e *Engine) GetNextProxy() string {
	if len(e.proxies) == 0 {
		return ""
	}
	// Use atomic increment for thread safety
	idx := atomic.AddUint64(&e.proxyIndex, 1)
	return e.proxies[(idx-1)%uint64(len(e.proxies))]
}

// LoadPreviousScan loads a previous JSONL scan file for differential scanning.
func (e *Engine) LoadPreviousScan(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	if e.PreviousState == nil {
		e.PreviousState = make(map[string]int)
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var res Result
		if err := json.Unmarshal(scanner.Bytes(), &res); err != nil {
			continue // Skip malformed lines
		}
		// Populate the map with Path -> StatusCode
		e.PreviousState[res.Path] = res.StatusCode
	}
	return scanner.Err()
}

// SetRPS updates the rate limiter settings dynamically.
func (e *Engine) SetRPS(rps int) {
	if rps <= 0 {
		e.limiter.SetLimit(rate.Inf) // No limit
	} else {
		e.limiter.SetLimit(rate.Limit(rps))
	}
}

// ConfigureFilters sets the matching status codes and filtering sizes.
func (e *Engine) ConfigureFilters(mc []int, fs []int) {
	e.Config.Lock()
	defer e.Config.Unlock()
	for _, code := range mc {
		e.Config.MatchCodes[code] = true
	}
	for _, size := range fs {
		e.Config.FilterSizes[size] = true
	}
}

// UpdateUserAgent updates the User-Agent string safely.
func (e *Engine) UpdateUserAgent(ua string) {
	e.Config.Lock()
	defer e.Config.Unlock()
	e.Config.UserAgent = ua
}

// SetDelay sets the delay between requests for each worker.
func (e *Engine) SetDelay(d time.Duration) {
	e.Config.Lock()
	defer e.Config.Unlock()
	e.Config.Delay = d
}

// AddHeader adds or updates a custom header safely.
func (e *Engine) AddHeader(key, val string) {
	e.Config.Lock()
	defer e.Config.Unlock()
	e.Config.Headers[key] = val
}

// RemoveHeader removes a custom header safely.
func (e *Engine) RemoveHeader(key string) {
	e.Config.Lock()
	defer e.Config.Unlock()
	delete(e.Config.Headers, key)
}

// ConfigSnapshot creates a safe copy of the current configuration for display purposes.
func (e *Engine) ConfigSnapshot() (ua string, filters []int, headers map[string]string, delay time.Duration, extensions []string) {
	e.Config.RLock()
	defer e.Config.RUnlock()

	ua = e.Config.UserAgent
	delay = e.Config.Delay

	for size := range e.Config.FilterSizes {
		filters = append(filters, size)
	}

	headers = make(map[string]string)
	for k, v := range e.Config.Headers {
		headers[k] = v
	}

	extensions = make([]string, len(e.Config.Extensions))
	copy(extensions, e.Config.Extensions)

	return
}

// AddFilterSize adds a new size to the blacklist safely.
func (e *Engine) AddFilterSize(size int) {
	e.Config.Lock()
	defer e.Config.Unlock()
	e.Config.FilterSizes[size] = true
}

// RemoveFilterSize removes a size from the blacklist safely.
func (e *Engine) RemoveFilterSize(size int) {
	e.Config.Lock()
	defer e.Config.Unlock()
	delete(e.Config.FilterSizes, size)
}

// AddMatchCode adds a status code to the allowlist safely.
func (e *Engine) AddMatchCode(code int) {
	e.Config.Lock()
	defer e.Config.Unlock()
	e.Config.MatchCodes[code] = true
}

// RemoveMatchCode removes a status code from the allowlist safely.
func (e *Engine) RemoveMatchCode(code int) {
	e.Config.Lock()
	defer e.Config.Unlock()
	// Usually we might want to ensure at least one code? But user can remove all if they want (nothing will match).
	delete(e.Config.MatchCodes, code)
}

// AddExtension adds an extension to the list.
func (e *Engine) AddExtension(ext string) {
	e.Config.Lock()
	defer e.Config.Unlock()
	// Avoid duplicates? Since slice iteration is fast enough for small lists...
	for _, x := range e.Config.Extensions {
		if x == ext {
			return
		}
	}
	e.Config.Extensions = append(e.Config.Extensions, ext)
}

// RemoveExtension removes an extension from the list.
func (e *Engine) RemoveExtension(ext string) {
	e.Config.Lock()
	defer e.Config.Unlock()
	var newExts []string
	for _, x := range e.Config.Extensions {
		if x != ext {
			newExts = append(newExts, x)
		}
	}
	e.Config.Extensions = newExts
}

// SetMutation enables or disables smart mutation.
func (e *Engine) SetMutation(active bool) {
	e.Config.Lock()
	defer e.Config.Unlock()
	e.Config.Mutate = active
}

// SetPaused updates the paused state of the engine.
func (e *Engine) SetPaused(paused bool) {
	e.Config.Lock()
	defer e.Config.Unlock()
	e.Config.IsPaused = paused
}

// ChangeWordlist cancels the current scanner and starts a new one with the given path.
func (e *Engine) ChangeWordlist(path string) error {
	// Stop existing scanner
	e.scannerCancel()
	// Wait for the old scanner to finish/cleanup if necessary,
	// but since we just want to start a new one, we can just re-initialize context.

	// Create new context
	e.scannerCtx, e.scannerCancel = context.WithCancel(context.Background())

	// Start new scanner
	go e.StartWordlistScanner(path)
	return nil
}

// StartWordlistScanner reads from a Wordlist and submits payloads to the engine.
func (e *Engine) StartWordlistScanner(path string) {
	// Remember path for recursion
	e.Config.Lock()
	e.Config.WordlistPath = path
	e.Config.Unlock()

	file, err := os.Open(path)
	if err != nil {
		fmt.Printf("Error opening wordlist: %v\n", err)
		atomic.StoreInt64(&e.TotalLines, 0)
		return
	}
	defer file.Close()

	// Initial Scan to count total lines for progress bar
	// This can take a moment for large files, but is necessary for accurate progress
	atomic.StoreInt64(&e.ProcessedLines, 0)
	lineCount := int64(0)

	e.Config.RLock()
	extMultiplier := int64(len(e.Config.Extensions) + 1) // +1 for the base word
	e.Config.RUnlock()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lineCount++
	}
	atomic.StoreInt64(&e.TotalLines, lineCount*extMultiplier)

	// Re-open file for actual processing (rewind doesn't work well on all OS/file types with scanner)
	file.Close()
	file, err = os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	scanner = bufio.NewScanner(file)
	for scanner.Scan() {
		// Respect cancellation (e.g. from ChangeWordlist)
		select {
		case <-e.scannerCtx.Done():
			return
		default:
			// Check for pause
			e.Config.RLock()
			paused := e.Config.IsPaused
			e.Config.RUnlock()
			for paused {
				time.Sleep(100 * time.Millisecond)
				e.Config.RLock()
				paused = e.Config.IsPaused
				e.Config.RUnlock()

				// Also check cancellation while paused
				select {
				case <-e.scannerCtx.Done():
					return
				default:
				}
			}

			line := scanner.Text()
			if line != "" {
				// Extension Logic
				// 1. Send Base
				e.Submit(Job{Path: line, Depth: 0})

				// 2. Send Extensions
				e.Config.RLock()
				// Create copy to iterate safely
				exts := make([]string, len(e.Config.Extensions))
				copy(exts, e.Config.Extensions)
				e.Config.RUnlock()

				for _, ext := range exts {
					// Handle if user provided dot or not
					cleanExt := strings.TrimSpace(ext)
					if !strings.HasPrefix(cleanExt, ".") {
						cleanExt = "." + cleanExt
					}
					e.Submit(Job{Path: line + cleanExt, Depth: 0})
				}
			}
		}
	}
}

// SetTarget sets the target URL and extracts the host for raw requests.
func (e *Engine) SetTarget(targetURL string) error {
	u, err := url.Parse(targetURL)
	if err != nil {
		return err
	}
	e.baseURL = targetURL
	e.host = u.Host
	return nil
}

// AutoCalibrate attempts to detect wildcard responses.
func (e *Engine) AutoCalibrate() error {
	const randLen = 16
	randPaths := make([]string, 3)
	for i := 0; i < 3; i++ {
		randPaths[i] = "/" + randomString(randLen)
	}

	statusCode := -1
	bodySize := -1
	consistent := true

	for _, path := range randPaths {
		rawRequest := []byte(fmt.Sprintf(
			"GET %s HTTP/1.1\r\n"+
				"Host: %s\r\n"+
				"Connection: close\r\n"+
				"User-Agent: %s\r\n"+
				"Accept: */*\r\n"+
				"\r\n",
			path,
			e.host,
			e.Config.UserAgent,
		))

		// IMPORTANT: Ensure request to e.baseURL (full URL)
		// Auto calibration uses direct connection or proxy if loaded
		var proxyAddr string
		if e.proxyDialer {
			proxyAddr = e.GetNextProxy()
		}

		resp, err := httpclient.SendRawRequest(e.baseURL, rawRequest, 5*time.Second, proxyAddr)
		if err != nil {
			return fmt.Errorf("calibration request failed: %v", err)
		}

		if statusCode == -1 {
			statusCode = resp.StatusCode
			bodySize = len(resp.Body)
		} else {
			if resp.StatusCode != statusCode || len(resp.Body) != bodySize {
				consistent = false
				break
			}
		}
	}

	if consistent {
		fmt.Printf("[+] Wildcard detected! Filtering Status: %d, Size: %d\n", statusCode, bodySize)
		e.AddFilterSize(bodySize)
		// Optionally filter status code too? The prompt specifically said "inject that Body Size".
	}

	return nil
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzMJIKLOP0123456789"
	b := make([]byte, n)
	// Not cryptographically secure, but fine for fuzzing
	for i := range b {
		b[i] = letters[time.Now().UnixNano()%int64(len(letters))]
	}
	return string(b)
}

// checkRecursiveWildcard returns true if the directory responds to random paths with 200 OK.
// It uses a random string to probe the directory.
func (e *Engine) checkRecursiveWildcard(dirPath string) bool {
	// Respect the configured delay to avoid double-tapping the server instantly
	e.Config.RLock()
	delay := e.Config.Delay
	e.Config.RUnlock()
	if delay > 0 {
		time.Sleep(delay)
	}

	// Construct a random path
	randPath := dirPath
	if !strings.HasSuffix(randPath, "/") {
		randPath += "/"
	}
	randPath += randomString(12)

	// Build raw request
	rawRequest := []byte(fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Connection: close\r\n"+
			"User-Agent: %s\r\n"+
			"Accept: */*\r\n"+
			"\r\n",
		randPath,
		e.host,
		e.Config.UserAgent,
	))

	// Send probe
	// Use shorter timeout for check
	var proxyAddr string
	if e.proxyDialer {
		proxyAddr = e.GetNextProxy()
	}
	resp, err := httpclient.SendRawRequest(e.baseURL, rawRequest, 3*time.Second, proxyAddr)
	if err != nil {
		// If probe fails (timeout/connRefused), assume safe to proceed?
		// Or assume unstable. Let's assume safe, since wildcard usually means active server.
		return false
	}

	// 200 OK on random path -> Wildcard (Soft 404)
	// 403 Forbidden on random path -> Likely protected directory or WAF blocking
	// If a random file returns 403, scanning thousands of files will likely all be 403.
	// We should skip recursion in this case too to avoid spam.
	if resp.StatusCode == 200 || resp.StatusCode == 403 {
		// Log debug if needed, or just return true to skip
		// Also, if it's a 200 OK wildcard, maybe we SHOULD add it to filters if requested?
		// But doing so would kill valid pages of that size globally.
		// The user request suggests they want to see "auto calibration" actions in the config view.
		// If this function acts as a per-directory auto-calibration, it's invisible.
		return true
	}
	return false
}

// QueueSize returns the current number of jobs in the queue.
func (e *Engine) QueueSize() int {
	return len(e.jobs)
}

// Start spins up the initial worker pool.
func (e *Engine) Start() {
	e.workerLock.Lock()
	defer e.workerLock.Unlock()

	for i := 0; i < e.numWorkers; i++ {
		e.wg.Add(1)
		go e.worker(i)
	}
}

// SetWorkerCount adjusts the number of active workers dynamically.
func (e *Engine) SetWorkerCount(n int) {
	if n < 1 {
		n = 1
	}

	e.Config.Lock()
	e.Config.MaxWorkers = n
	e.Config.Unlock()

	e.workerLock.Lock()
	defer e.workerLock.Unlock()

	if n > e.numWorkers {
		diff := n - e.numWorkers
		for i := 0; i < diff; i++ {
			e.wg.Add(1)
			go e.worker(e.numWorkers + i)
		}
	}
	// Always update the tracking count
	e.numWorkers = n
}

// worker is the concurrent consumer that pulls from the jobs channel.
func (e *Engine) worker(id int) {
	// Ensure Done is called when the goroutine exits
	defer e.wg.Done()

	for job := range e.jobs {
		payload := job.Path
		depth := job.Depth

		// Thread-safe config read
		e.Config.RLock()
		maxWorkers := e.Config.MaxWorkers
		paused := e.Config.IsPaused
		e.Config.RUnlock()

		// Check if this worker ID is still valid within current pool size.
		// CRITICAL FIX: If we are scaling down, we must still process this payload
		// because we already took it from the channel. We will exit AFTER processing.
		shouldExit := id >= maxWorkers

		// Pause loop
		for paused {
			time.Sleep(100 * time.Millisecond)
			e.Config.RLock()
			paused = e.Config.IsPaused
			e.Config.RUnlock()
		}

		e.Config.RLock()
		ua := e.Config.UserAgent
		// delay is handled by limiter now
		// Create a copy of headers to avoid race conditions during iteration/map access in request construction
		headers := make(map[string]string)
		for k, v := range e.Config.Headers {
			headers[k] = v
		}
		// Copy matchCodes and filterSizes for safe read
		matchCodes := make(map[int]bool)
		for k, v := range e.Config.MatchCodes {
			matchCodes[k] = v
		}
		filterSizes := make(map[int]bool)
		for k, v := range e.Config.FilterSizes {
			filterSizes[k] = v
		}
		e.Config.RUnlock()

		// Global Rate Limiter Wait
		// This replaces the per-worker sleep and ensures perfect global RPS
		err := e.limiter.Wait(context.Background())
		if err != nil {
			// Context canceled?
			break
		}

		// Construct the raw request
		// Ensure payload starts with /
		if !strings.HasPrefix(payload, "/") {
			payload = "/" + payload
		}

		// Build headers string
		var headersStr strings.Builder
		for k, v := range headers {
			headersStr.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
		}

		// Using HEAD by default as requested to avoid full body downloads
		// Re-enabling Keep-Alive to avoid socket churning
		rawRequest := []byte(fmt.Sprintf(
			"HEAD %s HTTP/1.1\r\n"+
				"Host: %s\r\n"+
				"Connection: keep-alive\r\n"+
				"User-Agent: %s\r\n"+
				"%s"+
				"Accept: */*\r\n"+
				"\r\n",
			payload,
			e.host,
			ua,
			headersStr.String(),
		))

		target := e.baseURL

		// Handle Proxy Logic if enabled
		var proxyAddr string
		if e.proxyDialer {
			proxyAddr = e.GetNextProxy()
		}

		resp, err := httpclient.SendRawRequest(target, rawRequest, 5*time.Second, proxyAddr)
		atomic.AddInt64(&e.ProcessedLines, 1)

		if err != nil {
			// e.g. timeouts, connection refused
			atomic.AddInt64(&e.CountConnErr, 1)
			continue
		}

		// Update Stats Counters
		if resp.StatusCode == 200 {
			atomic.AddInt64(&e.Count200, 1)
		} else if resp.StatusCode == 403 {
			atomic.AddInt64(&e.Count403, 1)
		} else if resp.StatusCode == 404 {
			atomic.AddInt64(&e.Count404, 1)
		} else if resp.StatusCode == 429 {
			atomic.AddInt64(&e.Count429, 1)
		} else if resp.StatusCode >= 500 {
			atomic.AddInt64(&e.Count500, 1)
		}

		// Fallback: If HEAD fails (405 Method Not Allowed / 501 Not Implemented), retry with GET
		if resp.StatusCode == 405 || resp.StatusCode == 501 {
			// Construct a minimal GET request
			// We MUST force Connection: close and try to read only minimal data to be safe.
			rawGET := []byte(fmt.Sprintf(
				"GET %s HTTP/1.1\r\n"+
					"Host: %s\r\n"+
					"Connection: close\r\n"+
					"User-Agent: %s\r\n"+
					"%s"+ // Headers
					"Accept: */*\r\n"+
					"\r\n",
				payload,
				e.host,
				ua,
				headersStr.String(),
			))

			// Use the existing client. It already has built-in limits (8KB reads, SO_LINGER on close).
			// This effectively implements the "Safe Teardown" requested because:
			// 1. Connection: close tells server to disconnect.
			// 2. Client reads 8KB max (header extraction logic).
			// 3. Client forces Close() immediately after, triggering RST via SO_LINGER if customized.
			respFallback, errFallback := httpclient.SendRawRequest(target, rawGET, 5*time.Second, proxyAddr)
			if errFallback == nil {
				// Use the fallback response instead
				resp = respFallback
				// Update stats for the retry? Probably not double count, but let's assume retry supersedes.
				// The original 405/501 is effectively ignored.
			}
		}

		// Filtering Logic
		// 1. Check Status Code
		if len(matchCodes) > 0 && !matchCodes[resp.StatusCode] {
			continue
		}

		// 2. Check Body Size
		// Prefer Content-Length header if available, otherwise fallback to read body size.
		// This handles the new optimization where we don't download the full body.
		bodySize := len(resp.Body)
		clVal := resp.GetHeader("Content-Length")
		if clVal != "" {
			if s, err := strconv.Atoi(clVal); err == nil {
				bodySize = s
			}
		}

		if len(filterSizes) > 0 && filterSizes[bodySize] {
			continue
		}

		// Smart Filter Logic: Check for repetitive results (likely false positives)
		// Only track 200, 301, 302, 403 (common noise sources)
		// Also ensure we don't track empty body size errors if they are common (usually 0 is filterd anyway if empty)
		if resp.StatusCode == 200 || resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 403 {
			fpKey := fmt.Sprintf("%d:%d", resp.StatusCode, bodySize)

			e.fpMutex.Lock()
			e.fpCounts[fpKey]++
			count := e.fpCounts[fpKey]
			e.fpMutex.Unlock()

			// If we see the same status/size 15 times, consider blocking it
			if count == 15 {
				// We inject it into the filter immediately
				e.AddFilterSize(bodySize)

				// Notify via special result
				alert := Result{
					Path:         "AUTO-FILTER",
					StatusCode:   resp.StatusCode, // Reuse status for display
					Size:         bodySize,
					Headers:      map[string]string{"Msg": fmt.Sprintf("Auto-filtered repetitive size: %d", bodySize)},
					IsEagleAlert: false, // Don't use Eagle styling
					IsAutoFilter: true,  // Use new Auto Filter styling
				}
				// Non-blocking send or blocked? worker is single threaded here.
				// Assuming channel has capacity.
				e.Results <- alert
			}

			// If we already detected enough of these, drop this one.
			if count >= 15 {
				continue
			}
		}

		// Output result
		// Capture interesting headers for fingerprinting
		capturedHeaders := make(map[string]string)

		// Parse headers from the raw headers string
		// Improve parsing to handle \n or \r\n
		headerLines := strings.Split(strings.ReplaceAll(resp.Headers, "\r\n", "\n"), "\n")
		for _, line := range headerLines {
			if idx := strings.Index(line, ":"); idx != -1 {
				key := strings.TrimSpace(line[:idx])
				val := strings.TrimSpace(line[idx+1:])

				if strings.EqualFold(key, "Server") {
					capturedHeaders["Server"] = val
				}
				if strings.EqualFold(key, "X-Powered-By") {
					capturedHeaders["X-Powered-By"] = val
				}
			}
		}

		result := Result{
			Path:       payload,
			StatusCode: resp.StatusCode,
			Size:       bodySize,
			Headers:    capturedHeaders,
		}

		// Eagle Mode Check
		if e.PreviousState != nil {
			if oldStatus, exists := e.PreviousState[payload]; exists {
				if oldStatus != resp.StatusCode {
					result.IsEagleAlert = true
					result.OldStatusCode = oldStatus
				}
			}
		}

		e.Results <- result

		// Smart Mutation (-mutate)
		// Check for hits that look like files
		if resp.StatusCode == 200 || resp.StatusCode == 403 || resp.StatusCode == 301 {
			e.Config.RLock()
			doMutate := e.Config.Mutate
			e.Config.RUnlock()

			if doMutate {
				// Only mutate files (heuristic: has extension)
				// Requirement: "if the discovered path contains a file extension (using filepath.Ext(path) or checking for a .)"
				if strings.Contains(payload, ".") {
					// Launch in goroutine to avoid blocking the worker on channel send
					go func(basePath string) {
						// Required mutations: path + ".bak", path + ".old", path + ".save", path + "~", and path + ".swp"
						mutations := []string{".bak", ".old", ".save", "~", ".swp"}
						for _, m := range mutations {
							e.Submit(Job{Path: basePath + m, Depth: depth})
						}
					}(payload)
				}
			}
		}

		// Recursive Logic
		e.Config.RLock()
		doRecurse := e.Config.Recursive
		maxDepth := e.Config.MaxDepth
		wordlistPath := e.Config.WordlistPath
		e.Config.RUnlock()

		if doRecurse && depth < maxDepth {
			// We found a directory! (Assuming 2xx/3xx implies a accessible path)
			// But wait, 301 is a redirect, 200 is a file or dir listing.
			// Ideally we only recurse on directories.
			// For fuzzing, usually we treat any HIT as a potential directory if it doesn't have an extension?
			// Or just blindly recurse. Given the instruction "if recursive == true ... safely spawn ... to read wordlist again"

			// Perform wildcard verification synchronously within the worker
			// This ensures we rate-limit the checks and don't spawn thousands of goroutines that slam the server.
			if e.checkRecursiveWildcard(payload) {
				// It's a wildcard, skip recursion
				continue
			}

			// We spawn a goroutine to read the wordlist and queue jobs
			// This part is CPU/Disk bound, not Network bound, so it's fine to be async to keep the worker free.
			go func(basePath string, nextDepth int, wlPath string) {
				f, err := os.Open(wlPath)
				if err != nil {
					return
				}
				defer f.Close()

				// Scanner logic...
				scanner := bufio.NewScanner(f)
				for scanner.Scan() {
					word := scanner.Text()
					if word == "" {
						continue
					}

					// Construct new path: basePath + "/" + word
					// Ensure slashes
					newPath := basePath
					if !strings.HasSuffix(newPath, "/") {
						newPath += "/"
					}
					newPath += strings.TrimPrefix(word, "/")

					// Update TotalLines because recursive jobs extend the scan
					atomic.AddInt64(&e.TotalLines, 1)

					e.Submit(Job{Path: newPath, Depth: nextDepth})
				}
			}(payload, depth+1, wordlistPath)
		}

		if shouldExit {
			return
		}
	}
}

// Submit adds a payload to the queue if it passes the Bloom filter check.
func (e *Engine) Submit(job Job) {
	// The Bloom filter is not thread-safe for concurrent writes by default.
	// We lock it to ensure safe concurrent submissions if there are multiple producers.
	e.filterLock.Lock()
	isDuplicate := e.filter.TestAndAddString(job.Path)
	e.filterLock.Unlock()

	if isDuplicate {
		// Drop the payload instantly
		// Count as processed since we won't process it
		atomic.AddInt64(&e.ProcessedLines, 1)
		return
	}

	// Send to the worker queue
	e.jobs <- job
}

// Wait closes the jobs channel and waits for all workers to finish processing.
func (e *Engine) Wait() {
	close(e.jobs)
	e.wg.Wait()
	close(e.Results)
}
