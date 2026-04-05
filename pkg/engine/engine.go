package engine

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dirfuzz/pkg/httpclient"

	"github.com/bits-and-blooms/bloom/v3"
	"golang.org/x/time/rate"
)

// Config holds all runtime configuration for the engine.
type Config struct {
	sync.RWMutex
	UserAgent           string
	Headers             map[string]string
	MatchCodes          map[int]bool
	FilterSizes         map[int]bool
	MatchRegex          string
	FilterRegex         string
	Extensions          []string
	Methods             []string
	SmartAPI            bool
	Mutate              bool
	Recursive           bool
	MaxDepth            int
	IsPaused            bool
	Delay               time.Duration
	MaxWorkers          int
	FollowRedirects     bool
	MaxRedirects        int
	RequestBody         string
	FilterWords         int
	FilterLines         int
	MatchWords          int
	MatchLines          int
	OutputFormat        string
	FilterRTMin         time.Duration
	FilterRTMax         time.Duration
	ProxyOut            string
	WordlistPath        string
	OutputFile          string
	Timeout             time.Duration
	Insecure            bool
	AutoFilterThreshold int
	MaxRetries          int
}

// Job represents a single scan task.
type Job struct {
	Path   string
	Depth  int
	Method string
	RunID  int64
}

// Engine represents the core memory queue system for the brute-forcer.
type Engine struct {
	RunID         int64
	jobs          chan Job
	wg            sync.WaitGroup
	filter        *bloom.BloomFilter
	filterLock    sync.Mutex
	numWorkers    int
	targetLock    sync.RWMutex
	baseURL       string
	host          string
	Config        *Config
	scannerCtx    context.Context
	scannerCancel context.CancelFunc
	scannerWg     sync.WaitGroup
	activeJobs    sync.WaitGroup
	Results       chan Result

	// Eagle Mode State (Previous Scan Data)
	PreviousState map[string]int // Map[Path]StatusCode

	// Proxy Rotation
	proxies     []string
	proxyIndex  uint64
	proxyDialer bool

	// Rate Limiters (Per-Host)
	limiters     map[string]*rate.Limiter
	limitersLock sync.RWMutex
	currentLimit rate.Limit
	currentBurst int

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

	// RPS calculation
	lastProcessed int64
	lastTick      time.Time
	CurrentRPS    int64

	// Smart Filter State
	fpMutex           sync.RWMutex
	fpCounts          map[string]int
	manualFilterSizes map[int]bool
	autoFilterSizes   map[int]bool

	// Auto-throttle state
	autoThrottle    bool
	throttleRestore int

	// HEAD rejection cache
	headRejected int32 // atomic: 0=unknown 1=rejected

	// Resume support
	ResumeFile string

	// Compiled regexes (cached)
	matchRe  *regexp.Regexp
	filterRe *regexp.Regexp

	// Lua plugins
	matchPlugin  *PluginMatcher
	mutatePlugin *PluginMutator

	// Scope domain for recursion
	scopeDomain string
}

// Result holds the details of a successful fuzzing hit.
type Result struct {
	Path             string            `json:"path"`
	Method           string            `json:"method,omitempty"`
	StatusCode       int               `json:"status"`
	Forbidden403Type string            `json:"forbidden_403_type,omitempty"`
	Size             int               `json:"length"`
	Words            int               `json:"words,omitempty"`
	Lines            int               `json:"lines,omitempty"`
	ContentType      string            `json:"content_type,omitempty"`
	Duration         time.Duration     `json:"duration,omitempty"`
	Redirect         string            `json:"redirect,omitempty"`
	Headers          map[string]string `json:"headers,omitempty"`
	IsEagleAlert     bool              `json:"eagle_alert,omitempty"`
	OldStatusCode    int               `json:"old_status,omitempty"`
	IsAutoFilter     bool              `json:"auto_filter,omitempty"`
	URL              string            `json:"url,omitempty"`
	Request          string            `json:"request,omitempty"`
	Response         string            `json:"response,omitempty"`
}

const (
	Forbidden403TypeCFWAFBlock = "CF_WAF_BLOCK"
	Forbidden403TypeCFAdmin403 = "CF_ADMIN_403"
	Forbidden403TypeNginx403   = "NGINX_403"
	Forbidden403TypeGeneric403 = "GENERIC_403"
)

// String returns a string representation of the result for CLI output.
func (r Result) String() string {
	extras := ""
	if r.Redirect != "" {
		extras += fmt.Sprintf(" -> %s", r.Redirect)
	}
	if val, ok := r.Headers["Server"]; ok {
		extras += fmt.Sprintf(" [Server: %s]", val)
	}
	if val, ok := r.Headers["X-Powered-By"]; ok {
		extras += fmt.Sprintf(" [X-Powered-By: %s]", val)
	}
	if r.Forbidden403Type != "" {
		extras += fmt.Sprintf(" [%s]", r.Forbidden403Type)
	}
	if r.ContentType != "" {
		extras += fmt.Sprintf(" [%s]", r.ContentType)
	}
	if r.Duration > 0 {
		extras += fmt.Sprintf(" [%s]", r.Duration.Round(time.Millisecond))
	}
	methodStr := r.Method
	if methodStr == "" {
		methodStr = "HEAD/GET"
	}
	return fmt.Sprintf("[+] [%s] HIT: %s (Status: %d, Size: %d, Words: %d, Lines: %d)%s",
		methodStr, r.Path, r.StatusCode, r.Size, r.Words, r.Lines, extras)
}

// Classify403 identifies known types of 403 responses based on body/header signals.
func Classify403(body []byte, headers string) string {
	lowerBody := bytes.ToLower(body)
	hasCFWAFBlock := bytes.Contains(lowerBody, []byte("attention required! | cloudflare")) ||
		bytes.Contains(lowerBody, []byte("sorry, you have been blocked")) ||
		bytes.Contains(lowerBody, []byte("cf-error-details"))
	if hasCFWAFBlock {
		return Forbidden403TypeCFWAFBlock
	}

	hasCFAdmin403 := bytes.Contains(lowerBody, []byte("request forbidden by administrative rules"))
	hasNginx403 := bytes.Contains(lowerBody, []byte("<center>nginx</center>"))

	normalizedHeaders := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(headers, "\r\n", "\n"), "\r", "\n"))
	headerLines := strings.Split(normalizedHeaders, "\n")
	hasCfRay := false
	hasCfCacheStatus := false
	for _, line := range headerLines {
		idx := strings.Index(line, ":")
		if idx == -1 {
			continue
		}

		key := strings.TrimSpace(line[:idx])
		switch key {
		case "cf-ray":
			hasCfRay = true
		case "cf-cache-status":
			hasCfCacheStatus = true
		}
	}

	if hasCFAdmin403 && (hasCfRay || hasCfCacheStatus) {
		return Forbidden403TypeCFAdmin403
	}
	if hasNginx403 && !hasCfRay {
		return Forbidden403TypeNginx403
	}

	return Forbidden403TypeGeneric403
}

// ToCSV returns a CSV-formatted line for the result.
func (r Result) ToCSV() []string {
	methodStr := r.Method
	if methodStr == "" {
		methodStr = "GET"
	}
	return []string{
		methodStr,
		r.URL,
		r.Path,
		strconv.Itoa(r.StatusCode),
		strconv.Itoa(r.Size),
		strconv.Itoa(r.Words),
		strconv.Itoa(r.Lines),
		r.ContentType,
		r.Redirect,
		r.Duration.Round(time.Millisecond).String(),
	}
}

// NewEngine initializes a new Engine with a worker pool and a Bloom filter.
func NewEngine(numWorkers int, expectedItems uint, falsePositiveRate float64) *Engine {
	// Default to unlimited RPS — user controls via -delay flag
	burst := numWorkers
	if burst < MinRateLimitBurst {
		burst = MinRateLimitBurst
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &Engine{
		jobs:         make(chan Job, DefaultJobQueueSize),
		filter:       bloom.NewWithEstimates(expectedItems, falsePositiveRate),
		numWorkers:   numWorkers,
		limiters:     make(map[string]*rate.Limiter),
		currentLimit: rate.Inf,
		currentBurst: burst,
		Config: &Config{
			UserAgent:    "DirFuzz/2.0",
			Headers:      make(map[string]string),
			MatchCodes:   make(map[int]bool),
			FilterSizes:  make(map[int]bool),
			IsPaused:     false,
			Delay:        0,
			MaxWorkers:   numWorkers,
			MaxRedirects: DefaultMaxRedirects,
			FilterWords:  -1,
			FilterLines:  -1,
			MatchWords:   -1,
			MatchLines:   -1,
			OutputFormat: DefaultOutputFormat,
			Timeout:      DefaultHTTPTimeout,
			Insecure:     false,
		},
		scannerCtx:        ctx,
		scannerCancel:     cancel,
		Results:           make(chan Result, ResultsChannelSize),
		fpCounts:          make(map[string]int),
		manualFilterSizes: make(map[int]bool),
		autoFilterSizes:   make(map[int]bool),
		lastTick:          time.Now(),
		autoThrottle:      true,
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
			continue
		}
		e.PreviousState[res.Path] = res.StatusCode
	}
	return scanner.Err()
}

// SetRPS updates the rate limiter settings dynamically.
func (e *Engine) SetRPS(rps int) {
	var limit rate.Limit
	if rps <= 0 {
		limit = rate.Inf
	} else {
		limit = rate.Limit(rps)
	}

	e.limitersLock.Lock()
	e.currentLimit = limit
	for _, l := range e.limiters {
		l.SetLimit(limit)
	}
	e.limitersLock.Unlock()
}

// UpdateRateLimiterFromDelay updates the rate limiter based on the delay setting.
func (e *Engine) UpdateRateLimiterFromDelay() {
	e.Config.RLock()
	d := e.Config.Delay
	workers := e.Config.MaxWorkers
	e.Config.RUnlock()

	var limit rate.Limit
	var b int

	if d <= 0 {
		limit = rate.Inf
		b = workers
		if b < 10 {
			b = 10
		}
	} else {
		// Each worker sleeps `d` per request, so effective RPS = workers / d_seconds
		rps := float64(workers) / d.Seconds()
		if rps < 1 {
			rps = 1
		}
		limit = rate.Limit(rps)
		b = workers
	}

	e.limitersLock.Lock()
	e.currentLimit = limit
	e.currentBurst = b
	for _, l := range e.limiters {
		l.SetLimit(limit)
		l.SetBurst(b)
	}
	e.limitersLock.Unlock()
}

// getLimiter returns the rate limiter for a specific host, creating one if it doesn't exist.
func (e *Engine) getLimiter(host string) *rate.Limiter {
	e.limitersLock.RLock()
	l, exists := e.limiters[host]
	e.limitersLock.RUnlock()
	if exists {
		return l
	}

	e.limitersLock.Lock()
	defer e.limitersLock.Unlock()

	// Double-check after acquiring write lock
	if l, exists := e.limiters[host]; exists {
		return l
	}

	// Use current global limit and burst configs
	limit := e.currentLimit
	burst := e.currentBurst

	newLimiter := rate.NewLimiter(limit, burst)
	e.limiters[host] = newLimiter
	return newLimiter
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
		e.manualFilterSizes[size] = true
	}
}

// SetMatchRegex compiles and caches the match regex.
func (e *Engine) SetMatchRegex(pattern string) error {
	if pattern == "" {
		e.matchRe = nil
		return nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	e.matchRe = re
	e.Config.Lock()
	e.Config.MatchRegex = pattern
	e.Config.Unlock()
	return nil
}

// SetMatchPlugin sets the Lua match plugin
func (e *Engine) SetMatchPlugin(plugin *PluginMatcher) {
	e.matchPlugin = plugin
}

// SetMutatePlugin sets the Lua mutate plugin
func (e *Engine) SetMutatePlugin(plugin *PluginMutator) {
	e.mutatePlugin = plugin
}

// SetFilterRegex compiles and caches the filter regex.
func (e *Engine) SetFilterRegex(pattern string) error {
	if pattern == "" {
		e.filterRe = nil
		return nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	e.filterRe = re
	e.Config.Lock()
	e.Config.FilterRegex = pattern
	e.Config.Unlock()
	return nil
}

// UpdateUserAgent updates the User-Agent string safely.
func (e *Engine) UpdateUserAgent(ua string) {
	e.Config.Lock()
	defer e.Config.Unlock()
	normalized := normalizeUserAgent(ua)
	if normalized == "" {
		normalized = "DirFuzz/2.0"
	}
	e.Config.UserAgent = normalized
}

// normalizeUserAgent strips an accidental leading "User-Agent:" prefix from values.
func normalizeUserAgent(ua string) string {
	ua = strings.TrimSpace(ua)
	const prefix = "User-Agent:"
	if len(ua) >= len(prefix) && strings.EqualFold(ua[:len(prefix)], prefix) {
		ua = strings.TrimSpace(ua[len(prefix):])
	}
	return ua
}

// SetDelay sets the delay and updates the rate limiter accordingly.
func (e *Engine) SetDelay(d time.Duration) {
	e.Config.Lock()
	e.Config.Delay = d
	e.Config.Unlock()
	e.UpdateRateLimiterFromDelay()
}

// AddHeader adds or updates a custom header safely.
func (e *Engine) AddHeader(key, val string) {
	e.Config.Lock()
	defer e.Config.Unlock()
	if strings.EqualFold(strings.TrimSpace(key), "User-Agent") {
		e.Config.UserAgent = normalizeUserAgent(val)
		if e.Config.UserAgent == "" {
			e.Config.UserAgent = "DirFuzz/2.0"
		}
		for hk := range e.Config.Headers {
			if strings.EqualFold(hk, "User-Agent") {
				delete(e.Config.Headers, hk)
			}
		}
		return
	}
	e.Config.Headers[key] = val
}

// RemoveHeader removes a custom header safely.
func (e *Engine) RemoveHeader(key string) {
	e.Config.Lock()
	defer e.Config.Unlock()
	delete(e.Config.Headers, key)
}

// ConfigSnapshot creates a safe copy of the current configuration for display purposes.
func (e *Engine) ConfigSnapshot() (ua string, filters []int, headers map[string]string, delay time.Duration, exts []string, follow bool) {
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

	exts = make([]string, len(e.Config.Extensions))
	copy(exts, e.Config.Extensions)

	follow = e.Config.FollowRedirects

	return
}

// AddFilterSize adds a new size to the blacklist safely.
func (e *Engine) AddFilterSize(size int) {
	e.Config.Lock()
	defer e.Config.Unlock()
	e.Config.FilterSizes[size] = true
	e.manualFilterSizes[size] = true
	delete(e.autoFilterSizes, size)
}

// AddAutoFilterSize adds a runtime auto-filter size (separate from user-defined filters).
func (e *Engine) AddAutoFilterSize(size int) {
	e.Config.Lock()
	defer e.Config.Unlock()
	e.Config.FilterSizes[size] = true
	if !e.manualFilterSizes[size] {
		e.autoFilterSizes[size] = true
	}
}

// RemoveFilterSize removes a size from the blacklist safely.
func (e *Engine) RemoveFilterSize(size int) {
	e.Config.Lock()
	defer e.Config.Unlock()
	delete(e.Config.FilterSizes, size)
	delete(e.manualFilterSizes, size)
	delete(e.autoFilterSizes, size)
}

// clearAutoFilterSizes removes only runtime auto-filter sizes and keeps manual filters.
func (e *Engine) clearAutoFilterSizes() {
	e.Config.Lock()
	defer e.Config.Unlock()
	for size := range e.autoFilterSizes {
		if !e.manualFilterSizes[size] {
			delete(e.Config.FilterSizes, size)
		}
	}
	e.autoFilterSizes = make(map[int]bool)
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
	delete(e.Config.MatchCodes, code)
}

// AddExtension adds an extension to the list.
func (e *Engine) AddExtension(ext string) {
	e.Config.Lock()
	defer e.Config.Unlock()
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

// SetFollowRedirects enables redirect following.
func (e *Engine) SetFollowRedirects(follow bool) {
	e.Config.Lock()
	defer e.Config.Unlock()
	e.Config.FollowRedirects = follow
}

// Restart restarts the scanner with the current wordlist and new configurations.
func (e *Engine) Restart() error {
	e.Config.RLock()
	path := e.Config.WordlistPath
	e.Config.RUnlock()

	if path == "" {
		return fmt.Errorf("no wordlist currently loaded to restart")
	}

	return e.ChangeWordlist(path)
}

// ChangeWordlist cancels the current scanner and starts a new one with the given path.
func (e *Engine) ChangeWordlist(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("wordlist file does not exist: %s", path)
	}

	// Stop existing scanner
	e.scannerCancel()

	// Reset Bloom filter
	e.filterLock.Lock()
	e.filter = bloom.NewWithEstimates(DefaultBloomFilterSize, DefaultBloomFilterFP)
	e.filterLock.Unlock()

	// Reset counters
	atomic.StoreInt64(&e.ProcessedLines, 0)
	atomic.StoreInt64(&e.TotalLines, 0)
	atomic.StoreInt64(&e.Count200, 0)
	atomic.StoreInt64(&e.Count403, 0)
	atomic.StoreInt64(&e.Count404, 0)
	atomic.StoreInt64(&e.Count429, 0)
	atomic.StoreInt64(&e.Count500, 0)
	atomic.StoreInt64(&e.CountConnErr, 0)
	atomic.StoreInt64(&e.CurrentRPS, 0)
	atomic.StoreInt32(&e.headRejected, 0)

	// Reset auto-filter tracker
	e.fpMutex.Lock()
	e.fpCounts = make(map[string]int)
	e.fpMutex.Unlock()
	e.clearAutoFilterSizes()

	// Drain pending jobs safely — use a counter to limit drain attempts
drainLoop:
	for i := 0; i < cap(e.jobs)*2; i++ {
		select {
		case _, ok := <-e.jobs:
			if !ok {
				break drainLoop
			}
			e.activeJobs.Done()
		default:
			break drainLoop
		}
	}

	// Create new context
	e.scannerCtx, e.scannerCancel = context.WithCancel(context.Background())
	atomic.AddInt64(&e.RunID, 1)

	// Start new scanner
	e.KickoffScanner(path, 0)
	return nil
}

// KickoffScanner starts the wordlist scanner safely attached to the current context generation.
func (e *Engine) KickoffScanner(path string, startLine int64) {
	e.AddScanner()
	go e.StartWordlistScanner(e.scannerCtx, atomic.LoadInt64(&e.RunID), path, startLine)
}

// AddScanner increments the scanner waitgroup.
func (e *Engine) AddScanner() {
	e.scannerWg.Add(1)
}

// StartWordlistScanner reads from a Wordlist and submits payloads to the engine.
func (e *Engine) StartWordlistScanner(ctx context.Context, runID int64, path string, startLine int64) {
	defer e.scannerWg.Done()
	e.Config.Lock()
	e.Config.WordlistPath = path
	e.Config.Unlock()

	file, err := os.Open(path)
	if err != nil {
		e.Results <- Result{
			Path:         path,
			StatusCode:   0,
			IsAutoFilter: true,
			Headers:      map[string]string{"Msg": "Error opening wordlist: " + err.Error()},
		}
		atomic.StoreInt64(&e.TotalLines, 0)
		return
	}
	defer file.Close()

	// Count lines in single pass
	atomic.StoreInt64(&e.ProcessedLines, 0)
	lineCount := int64(0)

	e.Config.RLock()
	extMultiplier := int64(len(e.Config.Extensions) + 1)
	methods := e.Config.Methods
	smartAPI := e.Config.SmartAPI
	e.Config.RUnlock()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
		}

		line := scanner.Text()
		if line == "" {
			continue
		}

		methodMultiplier := int64(1)
		if len(methods) > 0 {
			if !smartAPI {
				methodMultiplier = int64(len(methods))
			} else if isAPIPath(line) {
				methodMultiplier = int64(len(methods))
			}
		}
		lineCount += methodMultiplier * extMultiplier
	}
	atomic.StoreInt64(&e.TotalLines, lineCount)

	// Re-open file for processing
	file.Close()
	file, err = os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	// Save resume state periodically
	lineNum := int64(0)

	scanner = bufio.NewScanner(file)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			e.saveResumeState(path, lineNum)
			return
		default:
			e.Config.RLock()
			paused := e.Config.IsPaused
			e.Config.RUnlock()
			for paused {
				time.Sleep(100 * time.Millisecond)
				e.Config.RLock()
				paused = e.Config.IsPaused
				e.Config.RUnlock()

				select {
				case <-ctx.Done():
					e.saveResumeState(path, lineNum)
					return
				default:
				}
			}

			line := scanner.Text()
			if line != "" {
				lineNum++
				e.Config.RLock()
				methods := e.Config.Methods
				smartAPI := e.Config.SmartAPI
				exts := make([]string, len(e.Config.Extensions))
				copy(exts, e.Config.Extensions)
				e.Config.RUnlock()

				var methodsToUse []string
				if len(methods) == 0 {
					methodsToUse = []string{""}
				} else if !smartAPI {
					methodsToUse = methods
				} else if isAPIPath(line) {
					methodsToUse = methods
				} else {
					methodsToUse = []string{""}
				}

				for _, method := range methodsToUse {
					e.Submit(Job{Path: line, Depth: 0, Method: method, RunID: runID})
					for _, ext := range exts {
						cleanExt := strings.TrimSpace(ext)
						if !strings.HasPrefix(cleanExt, ".") {
							cleanExt = "." + cleanExt
						}
						e.Submit(Job{Path: line + cleanExt, Depth: 0, Method: method, RunID: runID})
					}
				}
			}
		}
	}
}

// isAPIPath checks if a path looks like an API endpoint.
func isAPIPath(line string) bool {
	lower := strings.ToLower(line)
	return strings.Contains(lower, "api") || strings.Contains(lower, "v1") ||
		strings.Contains(lower, "v2") || strings.Contains(lower, "v3") ||
		strings.Contains(lower, "rest") || strings.Contains(lower, "graphql")
}

// saveResumeState saves the current scan position for resume support.
func (e *Engine) saveResumeState(wordlist string, lineNum int64) {
	if e.ResumeFile == "" {
		return
	}
	state := map[string]interface{}{
		"wordlist":  wordlist,
		"line":      lineNum,
		"processed": atomic.LoadInt64(&e.ProcessedLines),
		"total":     atomic.LoadInt64(&e.TotalLines),
		"target":    e.BaseURL(),
	}
	data, err := json.Marshal(state)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to marshal resume state: %v\n", err)
		return
	}
	if err := os.WriteFile(e.ResumeFile, data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to write resume file: %v\n", err)
	}
}

// LoadResumeState loads resume state and returns the line to skip to.
func (e *Engine) LoadResumeState(path string) (string, int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", 0, err
	}
	var state map[string]interface{}
	if err := json.Unmarshal(data, &state); err != nil {
		return "", 0, err
	}
	wordlist, _ := state["wordlist"].(string)
	lineF, _ := state["line"].(float64)
	return wordlist, int64(lineF), nil
}

// SetTarget sets the target URL and extracts the host for raw requests.
func (e *Engine) SetTarget(targetURL string) error {
	targetURL = strings.ReplaceAll(targetURL, "{payload}", "{PAYLOAD}")

	u, err := url.Parse(targetURL)
	if err != nil {
		return err
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("invalid URL: missing scheme or host")
	}
	e.targetLock.Lock()
	e.baseURL = targetURL
	e.host = u.Host
	if e.scopeDomain == "" {
		e.scopeDomain = u.Hostname()
	}
	e.targetLock.Unlock()
	return nil
}

// BaseURL returns the current target URL in a thread-safe manner.
func (e *Engine) BaseURL() string {
	e.targetLock.RLock()
	defer e.targetLock.RUnlock()
	return e.baseURL
}

// Host returns the current target host in a thread-safe manner.
func (e *Engine) Host() string {
	e.targetLock.RLock()
	defer e.targetLock.RUnlock()
	return e.host
}

// UpdateRPS calculates the current requests per second.
func (e *Engine) UpdateRPS() {
	now := time.Now()
	elapsed := now.Sub(e.lastTick).Seconds()
	if elapsed < 0.1 {
		return
	}
	current := atomic.LoadInt64(&e.ProcessedLines)
	delta := current - e.lastProcessed
	rps := int64(float64(delta) / elapsed)
	atomic.StoreInt64(&e.CurrentRPS, rps)
	e.lastProcessed = current
	e.lastTick = now
}

// AutoCalibrate attempts to detect wildcard responses.
func (e *Engine) AutoCalibrate() error {
	randPaths := make([]string, CalibrationTestCount)
	for i := 0; i < CalibrationTestCount; i++ {
		randPaths[i] = "/" + randomString(CalibrationRandomStringLen)
	}

	statusCode := -1
	bodySize := -1
	consistent := true

	for _, path := range randPaths {
		rawRequest := []byte(fmt.Sprintf(
			"GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: %s\r\nAccept: */*\r\n\r\n",
			path, e.Host(), e.Config.UserAgent,
		))

		var proxyAddr string
		if e.proxyDialer {
			proxyAddr = e.GetNextProxy()
		}

		resp, err := e.executeRequestWithRetry(e.scannerCtx, e.BaseURL(), rawRequest, CalibrationTimeout, proxyAddr)
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

	if consistent && statusCode > 0 {
		fmt.Printf("[+] Wildcard detected! Filtering Status: %d, Size: %d\n", statusCode, bodySize)
		e.AddFilterSize(bodySize)
	}

	return nil
}

// randomString generates a truly random string using math/rand/v2.
func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.IntN(len(letters))]
	}
	return string(b)
}

// checkRecursiveWildcard returns true if the directory responds to random paths with 200 OK.
func (e *Engine) checkRecursiveWildcard(dirPath string) bool {
	e.Config.RLock()
	delay := e.Config.Delay
	e.Config.RUnlock()
	if delay > 0 {
		time.Sleep(delay)
	}

	randPath := dirPath
	if !strings.HasSuffix(randPath, "/") {
		randPath += "/"
	}
	randPath += randomString(RecursiveWildcardTestLen)

	rawRequest := []byte(fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: %s\r\nAccept: */*\r\n\r\n",
		randPath, e.Host(), e.Config.UserAgent,
	))

	var proxyAddr string
	if e.proxyDialer {
		proxyAddr = e.GetNextProxy()
	}
	resp, err := e.executeRequestWithRetry(e.scannerCtx, e.BaseURL(), rawRequest, RecursiveWildcardTimeout, proxyAddr)
	if err != nil {
		return false
	}

	return resp.StatusCode == 200 || resp.StatusCode == 403
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
	if n < MinWorkerCount {
		n = MinWorkerCount
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
	e.numWorkers = n
	e.UpdateRateLimiterFromDelay()
}

// autoThrottleCheck handles automatic throttling when 429 responses spike.
func (e *Engine) autoThrottleCheck() {
	if !e.autoThrottle {
		return
	}
	count429 := atomic.LoadInt64(&e.Count429)
	if count429 > 0 && count429%AutoThrottleInterval == 0 {
		e.Config.RLock()
		currentWorkers := e.Config.MaxWorkers
		currentDelay := e.Config.Delay
		e.Config.RUnlock()

		// Save original worker count for restoration
		if e.throttleRestore == 0 {
			e.throttleRestore = currentWorkers
		}

		// Reduce workers by 50%, minimum threshold
		newWorkers := currentWorkers * ThrottleWorkerPercent / 100
		if newWorkers < MinThrottledWorkers {
			newWorkers = MinThrottledWorkers
		}

		// Increase delay
		newDelay := currentDelay + ThrottleDelayIncrease
		if newDelay > MaxThrottleDelay {
			newDelay = MaxThrottleDelay
		}

		e.SetWorkerCount(newWorkers)
		e.SetDelay(newDelay)

		e.Results <- Result{
			Path:         "AUTO-THROTTLE",
			StatusCode:   429,
			IsAutoFilter: true,
			Headers:      map[string]string{"Msg": fmt.Sprintf("429 detected! Workers: %d->%d, Delay: %s", currentWorkers, newWorkers, newDelay)},
		}
	}
}

// followRedirectChain follows HTTP redirects and returns the final response.
func (e *Engine) followRedirectChain(initialResp *httpclient.RawResponse, targetURL, reqHost, ua string, headers map[string]string, maxRedirects int, proxyAddr string) (*httpclient.RawResponse, string) {
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
			locURL, err := url.Parse(location)
			if err == nil {
				location = baseURL.ResolveReference(locURL).String()
			}
		}

		parsedLoc, err := url.Parse(location)
		if err != nil {
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

		rawReq := []byte(fmt.Sprintf(
			"GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: %s\r\n%sAccept: */*\r\n\r\n",
			reqPath, parsedLoc.Host, ua, headersStr.String(),
		))

		nextResp, err := e.executeRequestWithRetry(e.scannerCtx, location, rawReq, DefaultHTTPTimeout, proxyAddr)
		if err != nil {
			break
		}
		resp = nextResp
		finalURL = location
		currentURL = location
	}

	return resp, finalURL
}

// cleanupJob performs cleanup for a job and checks if worker should exit.
func (e *Engine) cleanupJob(shouldExit bool) bool {
	e.activeJobs.Done()
	return shouldExit
}

// worker is the concurrent consumer that pulls from the jobs channel.

// executeRequestWithRetry sends a raw HTTP request and retries on connection errors (err != nil) with exponential backoff.
func (e *Engine) executeRequestWithRetry(ctx context.Context, targetURL string, rawRequest []byte, timeout time.Duration, proxyAddr string) (*httpclient.RawResponse, error) {
	var resp *httpclient.RawResponse
	var err error

	e.Config.RLock()
	retries := e.Config.MaxRetries
	insecure := e.Config.Insecure
	e.Config.RUnlock()

	backoff := 1 * time.Second
	if ctx == nil {
		ctx = context.Background()
	}

	for attempt := 0; attempt <= retries; attempt++ {
		resp, err = httpclient.SendRawRequestWithContext(ctx, targetURL, rawRequest, timeout, proxyAddr, insecure)
		if err == nil {
			return resp, nil
		}

		if attempt < retries {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
				backoff *= 2
			}
		}
	}
	return resp, err
}

func (e *Engine) worker(id int) {
	defer e.wg.Done()

	for job := range e.jobs {
		if job.RunID != atomic.LoadInt64(&e.RunID) {
			e.activeJobs.Done()
			continue
		}

		payload := job.Path
		depth := job.Depth

		// Snapshot config once per job (performance: reduce lock contention)
		e.Config.RLock()
		maxWorkers := e.Config.MaxWorkers
		paused := e.Config.IsPaused
		ua := e.Config.UserAgent
		headers := make(map[string]string)
		for k, v := range e.Config.Headers {
			if strings.EqualFold(k, "User-Agent") {
				ua = v
				continue
			}
			headers[k] = v
		}
		matchCodes := make(map[int]bool)
		for k, v := range e.Config.MatchCodes {
			matchCodes[k] = v
		}
		filterSizes := make(map[int]bool)
		for k, v := range e.Config.FilterSizes {
			filterSizes[k] = v
		}
		followRedirects := e.Config.FollowRedirects
		maxRedirects := e.Config.MaxRedirects
		requestBody := e.Config.RequestBody
		filterWords := e.Config.FilterWords
		filterLines := e.Config.FilterLines
		matchWords := e.Config.MatchWords
		matchLines := e.Config.MatchLines
		filterRTMin := e.Config.FilterRTMin
		filterRTMax := e.Config.FilterRTMax
		proxyOut := e.Config.ProxyOut
		e.Config.RUnlock()

		shouldExit := id >= maxWorkers

		// Pause loop
		for paused {
			time.Sleep(100 * time.Millisecond)
			e.Config.RLock()
			paused = e.Config.IsPaused
			e.Config.RUnlock()
		}

		// Construct the full URL
		var fullURL string
		word := payload

		e.targetLock.RLock()
		currentBaseURL := e.baseURL
		e.targetLock.RUnlock()

		if strings.Contains(currentBaseURL, "{PAYLOAD}") {
			fullURL = strings.Replace(currentBaseURL, "{PAYLOAD}", word, 1)
		} else {
			if !strings.HasPrefix(word, "/") {
				word = "/" + word
			}
			fullURL = strings.TrimRight(currentBaseURL, "/") + word
		}

		parsedURL, errURL := url.Parse(fullURL)
		if errURL != nil {
			if e.cleanupJob(shouldExit) {
				return
			}
			continue
		}

		reqHost := parsedURL.Host

		// Rate limiter wait (Per-Host)
		if err := e.getLimiter(reqHost).Wait(context.Background()); err != nil {
			if e.cleanupJob(shouldExit) {
				return
			}
			continue
		}

		reqPath := parsedURL.Path
		if parsedURL.RawQuery != "" {
			reqPath += "?" + parsedURL.RawQuery
		}
		if reqPath == "" {
			reqPath = "/"
		}

		// Inject payload into User-Agent
		ua = normalizeUserAgent(strings.ReplaceAll(ua, "{PAYLOAD}", payload))
		if ua == "" {
			ua = "DirFuzz/2.0"
		}

		// Build headers string
		var headersStr strings.Builder
		for k, v := range headers {
			headersStr.WriteString(fmt.Sprintf("%s: %s\r\n", k, strings.ReplaceAll(v, "{PAYLOAD}", payload)))
		}

		var proxyAddr string
		if e.proxyDialer {
			proxyAddr = e.GetNextProxy()
		}

		var resp *httpclient.RawResponse
		var err error
		var successfulMethod string
		var rawRequest []byte

		if job.Method == "" {
			// If any body-based filtering is active, we must use GET to have a body to inspect.
			bodyFilterActive := e.matchRe != nil || e.filterRe != nil || filterWords >= 0 || filterLines >= 0 || matchWords >= 0 || matchLines >= 0

			if bodyFilterActive || atomic.LoadInt32(&e.headRejected) == 1 || followRedirects {
				// Skip HEAD, go straight to GET if following redirects because we want the real body
				successfulMethod = "GET"
				rawRequest = []byte(fmt.Sprintf(
					"GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: %s\r\n%sAccept: */*\r\n\r\n",
					reqPath, reqHost, ua, headersStr.String(),
				))
				resp, err = e.executeRequestWithRetry(e.scannerCtx, currentBaseURL, rawRequest, DefaultHTTPTimeout, proxyAddr)
			} else {
				successfulMethod = "HEAD"
				rawRequest = []byte(fmt.Sprintf(
					"HEAD %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: %s\r\n%sAccept: */*\r\n\r\n",
					reqPath, reqHost, ua, headersStr.String(),
				))
				resp, err = e.executeRequestWithRetry(e.scannerCtx, currentBaseURL, rawRequest, DefaultHTTPTimeout, proxyAddr)

				if err == nil && (resp.StatusCode == 405 || resp.StatusCode == 501) {
					// Cache: this host rejects HEAD
					atomic.StoreInt32(&e.headRejected, 1)
					successfulMethod = "GET"
					rawRequest = []byte(fmt.Sprintf(
						"GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: %s\r\n%sAccept: */*\r\n\r\n",
						reqPath, reqHost, ua, headersStr.String(),
					))
					respFB, errFB := e.executeRequestWithRetry(e.scannerCtx, currentBaseURL, rawRequest, DefaultHTTPTimeout, proxyAddr)
					if errFB == nil {
						resp = respFB
					} else {
						successfulMethod = "HEAD"
					}
				}
			}
			atomic.AddInt64(&e.ProcessedLines, 1)
		} else {
			successfulMethod = job.Method
			bodyContent := ""
			if requestBody != "" && (job.Method == "POST" || job.Method == "PUT" || job.Method == "PATCH") {
				bodyContent = strings.ReplaceAll(requestBody, "{PAYLOAD}", payload)
				headersStr.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(bodyContent)))
			} else if job.Method == "POST" || job.Method == "PUT" || job.Method == "PATCH" || job.Method == "DELETE" {
				headersStr.WriteString("Content-Length: 0\r\n")
			}

			rawRequest = []byte(fmt.Sprintf(
				"%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: %s\r\n%sAccept: */*\r\n\r\n%s",
				job.Method, reqPath, reqHost, ua, headersStr.String(), bodyContent,
			))

			resp, err = e.executeRequestWithRetry(e.scannerCtx, currentBaseURL, rawRequest, 5*time.Second, proxyAddr)
			atomic.AddInt64(&e.ProcessedLines, 1)
		}

		if err != nil {
			atomic.AddInt64(&e.CountConnErr, 1)
			if e.cleanupJob(shouldExit) {
				return
			}
			continue
		}

		// Update stats counters
		switch {
		case resp.StatusCode == 200:
			atomic.AddInt64(&e.Count200, 1)
		case resp.StatusCode == 403:
			atomic.AddInt64(&e.Count403, 1)
		case resp.StatusCode == 404:
			atomic.AddInt64(&e.Count404, 1)
		case resp.StatusCode == 429:
			atomic.AddInt64(&e.Count429, 1)
			e.autoThrottleCheck()
		case resp.StatusCode >= 500:
			atomic.AddInt64(&e.Count500, 1)
		}

		// Follow redirects if enabled
		var finalRedirectURL string
		originalStatusCode := resp.StatusCode
		if followRedirects && resp.StatusCode >= 300 && resp.StatusCode < 400 {
			resp, finalRedirectURL = e.followRedirectChain(resp, fullURL, reqHost, ua, headers, maxRedirects, proxyAddr)

			// Adjust stats based on the final resolved redirect response code
			if resp.StatusCode != originalStatusCode {
				switch {
				case resp.StatusCode == 200:
					atomic.AddInt64(&e.Count200, 1)
				case resp.StatusCode == 403:
					atomic.AddInt64(&e.Count403, 1)
				case resp.StatusCode == 404:
					atomic.AddInt64(&e.Count404, 1)
				}
			}
		}

		// Filtering Logic
		// 1. Check Status Code
		if len(matchCodes) > 0 && !matchCodes[resp.StatusCode] {
			if e.cleanupJob(shouldExit) {
				return
			}
			continue
		}

		// 2. Body Size
		bodySize := len(resp.Body)
		clVal := resp.GetHeader("Content-Length")
		if clVal != "" {
			if s, err := strconv.Atoi(clVal); err == nil {
				bodySize = s
			}
		}

		if len(filterSizes) > 0 && filterSizes[bodySize] {
			if e.cleanupJob(shouldExit) {
				return
			}
			continue
		}

		// 3. Word/Line count
		bodyStr := string(resp.Body)
		wordCount := len(strings.Fields(bodyStr))
		lineCount := strings.Count(bodyStr, "\n") + 1
		if len(bodyStr) == 0 {
			lineCount = 0
		}

		if filterWords >= 0 && wordCount == filterWords {
			if e.cleanupJob(shouldExit) {
				return
			}
			continue
		}
		if filterLines >= 0 && lineCount == filterLines {
			if e.cleanupJob(shouldExit) {
				return
			}
			continue
		}
		if matchWords >= 0 && wordCount != matchWords {
			if e.cleanupJob(shouldExit) {
				return
			}
			continue
		}
		if matchLines >= 0 && lineCount != matchLines {
			if e.cleanupJob(shouldExit) {
				return
			}
			continue
		}

		// 4. Body regex matching
		if e.matchRe != nil && !e.matchRe.Match(resp.Body) {
			if e.cleanupJob(shouldExit) {
				return
			}
			continue
		}
		if e.filterRe != nil && e.filterRe.Match(resp.Body) {
			if e.cleanupJob(shouldExit) {
				return
			}
			continue
		}

		// 5. Response time filtering
		if filterRTMin > 0 && resp.Duration < filterRTMin {
			if e.cleanupJob(shouldExit) {
				return
			}
			continue
		}
		if filterRTMax > 0 && resp.Duration > filterRTMax {
			if e.cleanupJob(shouldExit) {
				return
			}
			continue
		}

		forbidden403Type := ""
		if resp.StatusCode == 403 {
			classifyBody := resp.Body
			classifyHeaders := resp.Headers

			// Keep HEAD-first strategy, but enrich 403 classification with a one-off GET body.
			if successfulMethod == "HEAD" {
				followupGetRequest := []byte(fmt.Sprintf(
					"GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: %s\r\n%sAccept: */*\r\n\r\n",
					reqPath, reqHost, ua, headersStr.String(),
				))
				if followupResp, followupErr := e.executeRequestWithRetry(e.scannerCtx, currentBaseURL, followupGetRequest, 3*time.Second, proxyAddr); followupErr == nil {
					classifyBody = followupResp.Body
					classifyHeaders = followupResp.Headers
				}
			}

			forbidden403Type = Classify403(classifyBody, classifyHeaders)
		}

		// Smart Filter Logic
		if resp.StatusCode == 200 || resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 403 {
			fpKey := fmt.Sprintf("%d:%d", resp.StatusCode, bodySize)
			if resp.StatusCode == 403 {
				fpKey = fmt.Sprintf("403:%s:%d", forbidden403Type, bodySize)
			}

			e.fpMutex.Lock()
			e.fpCounts[fpKey]++
			count := e.fpCounts[fpKey]
			e.fpMutex.Unlock()

			if count == e.Config.AutoFilterThreshold {
				e.AddAutoFilterSize(bodySize)
				e.Results <- Result{
					Path:         "AUTO-FILTER",
					Method:       successfulMethod,
					StatusCode:   resp.StatusCode,
					Size:         bodySize,
					Headers:      map[string]string{"Msg": fmt.Sprintf("Auto-filtered repetitive size: %d", bodySize)},
					IsAutoFilter: true,
				}
			}
			if count >= e.Config.AutoFilterThreshold {
				if e.cleanupJob(shouldExit) {
					return
				}
				continue
			}
		}

		// Capture interesting headers
		capturedHeaders := make(map[string]string)
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
				if strings.EqualFold(key, "Cf-Ray") {
					capturedHeaders["Cf-Ray"] = val
				}
			}
		}

		contentType := resp.GetHeader("Content-Type")
		// Simplify content type for display
		if idx := strings.Index(contentType, ";"); idx != -1 {
			contentType = strings.TrimSpace(contentType[:idx])
		}

		result := Result{
			Path:        payload,
			Method:      successfulMethod,
			StatusCode:  resp.StatusCode,
			Size:        bodySize,
			Words:       wordCount,
			Lines:       lineCount,
			ContentType: contentType,
			Duration:    resp.Duration,
			Headers:     capturedHeaders,
			URL:         fullURL,
			Request:     string(rawRequest),
			Response:    string(resp.Raw),
		}

		if resp.StatusCode >= 300 && resp.StatusCode < 400 && !followRedirects {
			result.Redirect = resp.GetHeader("Location")
		}
		if finalRedirectURL != "" && resp.StatusCode >= 300 && resp.StatusCode < 400 {
			result.Redirect = finalRedirectURL
		}
		if resp.StatusCode == 403 {
			result.Forbidden403Type = forbidden403Type
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

		// Proxy-out replay: forward hit through external proxy (e.g. Burp)
		if proxyOut != "" {
			go e.replayThroughProxy(proxyOut, fullURL, successfulMethod, ua, headers, requestBody, payload)
		}

		// Smart Mutation
		if resp.StatusCode == 200 || resp.StatusCode == 403 || resp.StatusCode == 301 {
			e.Config.RLock()
			doMutate := e.Config.Mutate
			e.Config.RUnlock()

			if doMutate && strings.Contains(payload, ".") {
				go func(runID int64, basePath string, method string) {
					mutations := []string{".bak", ".old", ".save", "~", ".swp"}
					for _, m := range mutations {
						e.Submit(Job{Path: basePath + m, Depth: depth, Method: method, RunID: runID})
					}
				}(job.RunID, payload, job.Method)
			}
		}

		// Recursive Logic
		e.Config.RLock()
		doRecurse := e.Config.Recursive
		maxDepth := e.Config.MaxDepth
		wordlistPath := e.Config.WordlistPath
		e.Config.RUnlock()

		if doRecurse && depth < maxDepth {
			// Scope-aware: only recurse into paths on the same domain
			inScope := true
			if result.Redirect != "" {
				if parsedRedir, err := url.Parse(result.Redirect); err == nil && parsedRedir.Host != "" {
					e.targetLock.RLock()
					scopeDom := e.scopeDomain
					e.targetLock.RUnlock()
					redirHost := parsedRedir.Hostname()
					if redirHost != scopeDom && !strings.HasSuffix(redirHost, "."+scopeDom) {
						inScope = false
					}
				}
			}
			if inScope && !e.checkRecursiveWildcard(payload) {
				e.AddScanner()
				go func(runID int64, basePath string, nextDepth int, wlPath string) {
					defer e.scannerWg.Done()
					f, err := os.Open(wlPath)
					if err != nil {
						return
					}
					defer f.Close()

					e.Config.RLock()
					methods := e.Config.Methods
					smartAPI := e.Config.SmartAPI
					e.Config.RUnlock()

					scanner := bufio.NewScanner(f)
					for scanner.Scan() {
						word := scanner.Text()
						if word == "" {
							continue
						}

						newPath := basePath
						if !strings.HasSuffix(newPath, "/") {
							newPath += "/"
						}
						newPath += strings.TrimPrefix(word, "/")

						var methodsToUse []string
						if len(methods) == 0 {
							methodsToUse = []string{""}
						} else if !smartAPI {
							methodsToUse = methods
						} else if isAPIPath(newPath) {
							methodsToUse = methods
						} else {
							methodsToUse = []string{""}
						}

						for _, method := range methodsToUse {
							atomic.AddInt64(&e.TotalLines, 1)
							e.Submit(Job{Path: newPath, Depth: nextDepth, Method: method, RunID: runID})
						}
					}
				}(job.RunID, payload, depth+1, wordlistPath)
			}
		}

		e.activeJobs.Done()
		if shouldExit {
			return
		}
	}
}

// replayThroughProxy forwards a hit through an HTTP proxy (e.g. Burp Suite) for manual inspection.
func (e *Engine) replayThroughProxy(proxyAddr, fullURL, method, ua string, headers map[string]string, requestBody, payload string) {
	proxyURL, err := url.Parse(proxyAddr)
	if err != nil {
		return
	}

	transport := &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	if method == "" || method == "HEAD" {
		method = "GET"
	}

	var body io.Reader
	if requestBody != "" && (method == "POST" || method == "PUT" || method == "PATCH") {
		body = strings.NewReader(strings.ReplaceAll(requestBody, "{PAYLOAD}", payload))
	}

	req, err := http.NewRequest(method, fullURL, body)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", strings.ReplaceAll(ua, "{PAYLOAD}", payload))
	for k, v := range headers {
		req.Header.Set(k, strings.ReplaceAll(v, "{PAYLOAD}", payload))
	}

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

// Submit adds a payload to the queue if it passes the Bloom filter check.
func (e *Engine) Submit(job Job) {
	if job.RunID != atomic.LoadInt64(&e.RunID) {
		return
	}

	e.filterLock.Lock()
	filterKey := job.Path
	if job.Method != "" {
		filterKey = job.Method + ":" + job.Path
	}
	isDuplicate := e.filter.TestAndAddString(filterKey)
	e.filterLock.Unlock()

	if isDuplicate {
		atomic.AddInt64(&e.ProcessedLines, 1)
		return
	}

	e.activeJobs.Add(1)
	e.jobs <- job
}

// Wait waits for all scanners and jobs to finish.
// Note: We no longer close(e.jobs) or close(e.Results) here to allow
// the :restart command to safely reuse the channels without panicking.
func (e *Engine) Wait() {
	e.scannerWg.Wait()
	e.activeJobs.Wait()
}

// WriteResultCSV writes a CSV header to the given writer.
func WriteCSVHeader(w *csv.Writer) {
	w.Write([]string{"Method", "URL", "Path", "Status", "Size", "Words", "Lines", "ContentType", "Redirect", "Duration"})
}

type EngineConfigDump struct {
	Target     string
	Wordlist   string
	OutputFile string
	SmartAPI   bool
}

func (e *Engine) DumpMeta() EngineConfigDump {
	e.Config.RLock()
	defer e.Config.RUnlock()
	return EngineConfigDump{
		Target:     e.BaseURL(),
		Wordlist:   e.Config.WordlistPath,
		OutputFile: e.Config.OutputFile,
		SmartAPI:   e.Config.SmartAPI,
	}
}
