package engine

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/csv"
	"flag"
	"fmt"

	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"dirfuzz/pkg/fingerprint"
	"dirfuzz/pkg/httpclient"

	"github.com/bits-and-blooms/bloom/v3"
	interactclient "github.com/projectdiscovery/interactsh/pkg/client"
	"golang.org/x/time/rate"
)

var linkRegex = regexp.MustCompile(`(?i)(?:href|src|action)=['"]([^'"]+)['"]`)

type smartProxy struct {
	addr          string
	cooldownUntil time.Time
	failCount     int
}

// ─── Log events ───────────────────────────────────────────────────────────────

type LogLevel string

const (
	LogLevelDebug   LogLevel = "DEBUG"
	LogLevelInfo    LogLevel = "INFO"
	LogLevelWarning LogLevel = "WARNING"
	LogLevelError   LogLevel = "ERROR"
	LogLevelSuccess LogLevel = "SUCCESS"
)

type LogCategory string

const (
	LogCategorySystem    LogCategory = "SYSTEM"
	LogCategoryWorker    LogCategory = "WORKER"
	LogCategoryNetwork   LogCategory = "NETWORK"
	LogCategoryPlugin    LogCategory = "PLUGIN"
	LogCategoryDiscovery LogCategory = "DISCOVERY"
	LogCategoryFilter    LogCategory = "FILTER"
)

type EventType string

const (
	EventWorkerStarted             EventType = "WorkerStarted"
	EventWorkerStopped             EventType = "WorkerStopped"
	EventProxyRotated              EventType = "ProxyRotated"
	EventRateLimitHit              EventType = "RateLimitHit"
	EventRetryAttempt              EventType = "RetryAttempt"
	EventHarvestDiscovery          EventType = "HarvestDiscovery"
	EventHarvestParseError         EventType = "HarvestParseError"
	EventHarvestJSAnalysisComplete EventType = "HarvestJSAnalysisComplete"
	EventRecursivePruned           EventType = "RecursivePruned"
	EventAutoFilterTriggered       EventType = "AutoFilterTriggered"
	EventSimhashCluster            EventType = "SimhashCluster"
	EventWAFBypassAttempt          EventType = "WAFBypassAttempt"
	EventWAFBypassOutcome          EventType = "WAFBypassOutcome"
	EventTimingOracleStarted       EventType = "TimingOracleStarted"
	EventTimingOracleCalibrated    EventType = "TimingOracleCalibrated"
	EventNetworkError              EventType = "NetworkError"
)

type LogEvent struct {
	Timestamp time.Time              `json:"timestamp"`
	Level     LogLevel               `json:"level"`
	Category  LogCategory            `json:"category"`
	Type      EventType              `json:"type"`
	Message   string                 `json:"message"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// ─── Config types ─────────────────────────────────────────────────────────────

// SizeRange represents an inclusive min–max byte-size range used for filtering.
type SizeRange struct {
	Min int
	Max int
}

// Config holds all runtime configuration for the engine.
type Config struct {
	sync.RWMutex
	UserAgent            string
	Headers              map[string]string
	MatchCodes           map[int]bool
	FilterSizes          map[int]bool
	FilterSizeRanges     []SizeRange // NEW: filter responses whose size falls in any of these ranges
	MatchContentTypes    []string    // NEW: only surface responses whose Content-Type contains one of these strings
	FilterContentTypes   []string    // NEW: discard responses whose Content-Type contains any of these strings
	MatchRegex           string
	FilterRegex          string
	ExcludePathPatterns  []string
	Extensions           []string
	Methods              []string
	AuthMatrix           map[string][]string
	SmartAPI             bool
	Mutate               bool
	Recursive            bool
	RecursivePrune       bool
	MaxDepth             int
	IsPaused             bool
	Delay                time.Duration
	MaxWorkers           int
	FollowRedirects      bool
	MaxRedirects         int
	AllowPrivateTargets  bool
	RequestBody          string
	FilterWords          int
	FilterLines          int
	MatchWords           int
	MatchLines           int
	OutputFormat         string
	FilterRTMin          time.Duration
	FilterRTMax          time.Duration
	ProxyOut             string
	OOBEnabled           bool
	InteractshServer     string
	InteractshToken      string
	WordlistPath         string
	Nuclei               bool
	NucleiArgs           string
	OutputFile           string
	Timeout              time.Duration
	Insecure             bool
	AntiBotFallback      bool
	AutoFilterThreshold  int
	SimhashThreshold     int
	SimhashClusterLimit  int
	DisableSoft404Calibration bool
	H2Mode               bool
	H2ConcurrentStreams  int
	TimingOracle         bool
	TimeOracleK          float64
	TimeOracleN          int
	TimeTrim             bool
	Harvest              bool
	HarvestJS            bool
	HarvestAPI           bool
	HarvestResponse      bool
	HarvestPassive       bool
	HarvestSourceMaps    bool
	HarvestResponseDepth int
	HarvestResponseFetch int
	HarvestOTXKey        string
	ParamWordlist        []string
	EvasionLimit         int
	MaxRetries           int
	SaveRaw              bool // NEW: include raw request/response bytes in Result
	WAFEvasion           bool
	VerbTamper           bool
	FourOhThreeBypass    bool // retry 403s with path and header bypass techniques
	Spidering            bool // NEW: dynamic HTML/JS scraping
	WebhookURL           string
	WebhookOnNew         bool
	WebhookOnDrift       bool
}

// configSnapshot is an immutable view of the frequently-read configuration
// fields used by workers. Workers load a pointer to this snapshot once per
// job to avoid repeatedly allocating and copying maps on hot paths.
type configSnapshot struct {
	MaxWorkers           int
	IsPaused             bool
	UserAgent            string
	Headers              map[string]string
	MatchCodes           map[int]bool
	FilterSizes          map[int]bool
	FilterSizeRanges     []SizeRange
	MatchContentTypes    []string
	FilterContentTypes   []string
	ExcludePathRegexps   []*regexp.Regexp
	FollowRedirects      bool
	MaxRedirects         int
	RequestBody          string
	FilterWords          int
	FilterLines          int
	MatchWords           int
	MatchLines           int
	FilterRTMin          time.Duration
	FilterRTMax          time.Duration
	ProxyOut             string
	Timeout              time.Duration
	SaveRaw              bool
	AntiBotFallback      bool
	AuthMatrix           map[string][]string
	Methods              []string
	SmartAPI             bool
	Extensions           []string
	AutoFilterThreshold  int
	SimhashThreshold     int
	SimhashClusterLimit  int
	H2Mode               bool
	H2ConcurrentStreams  int
	TimingOracle         bool
	TimeOracleK          float64
	TimeOracleN          int
	TimeTrim             bool
	Harvest              bool
	HarvestJS            bool
	HarvestAPI           bool
	HarvestResponse      bool
	HarvestPassive       bool
	HarvestSourceMaps    bool
	HarvestResponseDepth int
	HarvestResponseFetch int
	HarvestOTXKey        string
	ParamWordlist        []string
	EvasionLimit         int
	Mutate               bool
	Recursive            bool
	RecursivePrune       bool
	MaxDepth             int
	WordlistPath         string
	WAFEvasion           bool
	VerbTamper           bool
	FourOhThreeBypass    bool
	Spidering            bool
	// HeadersTemplate is the pre-built header block (with any {PAYLOAD}
	// placeholders intact) that workers can quickly clone and substitute
	// the payload into without reconstructing the header map each job.
	HeadersTemplate string
}

// ─── Job & Result ─────────────────────────────────────────────────────────────

// JobType enumerates the possible classes of scan execution tasks.
type JobType string

const (
	JobTypeDiscovery  JobType = "discovery"
	JobTypeFuzz       JobType = "fuzz"
	JobTypeValidation JobType = "validation"
	JobTypeParamFuzz  JobType = "paramfuzz"
)

// Job represents a single scan task.
type Job struct {
	ID              string
	SessionID       string
	TargetID        string
	Type            JobType
	Path            string
	Depth           int
	HarvestDepth    int
	Method          string
	RunID           int64
	ExtraHeaders    map[string]string
	DiscoveryNodeID string
	PriorityScore   int
	Reason          JobReason
	CreatedAt       time.Time
}

// Result holds the details of a successful fuzzing hit.
//
// URL and Path intentionally overlap:
//   - URL is the fully qualified URL when the engine has a concrete target.
//   - Path is the discovered relative path or fallback identifier.
//
// Callers that need a stable absolute target should prefer URL when present and
// fall back to Path only for scans that were not started with SetTarget.
type Result struct {
	Path                  string            `json:"path"`
	DiscoveryNodeID       string            `json:"discovery_node_id,omitempty"`
	Method                string            `json:"method,omitempty"`
	StatusCode            int               `json:"status"`
	Forbidden403Type      string            `json:"forbidden_403_type,omitempty"`
	Size                  int               `json:"length"`
	Words                 int               `json:"words,omitempty"`
	Lines                 int               `json:"lines,omitempty"`
	ContentType           string            `json:"content_type,omitempty"`
	Labels                []string          `json:"labels,omitempty"`
	Confidence            string            `json:"confidence,omitempty"`
	Duration              time.Duration     `json:"duration,omitempty"`
	Redirect              string            `json:"redirect,omitempty"`
	Headers               map[string]string `json:"headers,omitempty"`
	IsEagleAlert          bool              `json:"eagle_alert,omitempty"`
	IsEagleNewEndpoint    bool              `json:"eagle_new_endpoint,omitempty"`
	StatusDrift           bool              `json:"status_drift,omitempty"`
	SizeDrift             bool              `json:"size_drift,omitempty"`
	OldStatusCode         int               `json:"old_status,omitempty"`
	IsAutoFilter          bool              `json:"auto_filter,omitempty"`
	URL                   string            `json:"url,omitempty"`
	Request               string            `json:"request,omitempty"`  // only populated when SaveRaw=true
	Response              string            `json:"response,omitempty"` // only populated when SaveRaw=true
	RequestBytes          []byte            `json:"-"`
	ResponseBytes         []byte            `json:"-"`
	Note                  string            `json:"note,omitempty"`
	MarkedInteresting     bool              `json:"marked_interesting,omitempty"`
	ContentDrift          bool              `json:"content_drift,omitempty"`
	OldSize               int               `json:"old_size,omitempty"`
	OldWords              int               `json:"old_words,omitempty"`
	DriftDeltaBytes       int               `json:"drift_delta_bytes,omitempty"`
	DiscoveredParams      []string          `json:"discovered_params,omitempty"`
	PreviousResponseBytes []byte            `json:"-"`
	AuthRoles             []AuthRoleDetail  `json:"auth_roles,omitempty"`
}

type AuthRoleDetail struct {
	Role          string `json:"role"`
	StatusCode    int    `json:"status"`
	Request       string `json:"request,omitempty"`
	Response      string `json:"response,omitempty"`
	RequestBytes  []byte `json:"-"`
	ResponseBytes []byte `json:"-"`
}

type previousScanEntry struct {
	StatusCode    int
	Size          int
	Words         int
	BodyHash      string
	ResponseBytes []byte
}

// replayTask carries everything needed to replay a hit through an outbound proxy.
type replayTask struct {
	proxyAddr   string
	fullURL     string
	method      string
	ua          string
	headers     map[string]string
	requestBody string
	payload     string
}

// scannerContext holds the engine's cancellation state safely
type scannerContext struct {
	ctx    context.Context
	cancel context.CancelFunc
}

func (e *Engine) emitLogEvent(level LogLevel, category LogCategory, typ EventType, message string, metadata map[string]interface{}) {
	if e == nil || e.LogEvents == nil {
		return
	}
	defer func() {
		_ = recover()
	}()
	ev := LogEvent{
		Timestamp: time.Now(),
		Level:     level,
		Category:  category,
		Type:      typ,
		Message:   message,
		Metadata:  metadata,
	}
	select {
	case e.LogEvents <- ev:
	default:
	}
}

// ─── Sharded Bloom Filter ─────────────────────────────────────────────────────

const bloomFilterShards = 32

type shardedBloomFilter struct {
	filters   []*bloom.BloomFilter
	locks     []sync.Mutex
	numShards uint32
}

func newShardedBloomFilter(numShards uint32, expectedItems uint, falsePositiveRate float64) *shardedBloomFilter {
	sbf := &shardedBloomFilter{
		filters:   make([]*bloom.BloomFilter, numShards),
		locks:     make([]sync.Mutex, numShards),
		numShards: numShards,
	}
	itemsPerShard := expectedItems / uint(numShards)
	if itemsPerShard == 0 {
		itemsPerShard = 1
	}
	for i := uint32(0); i < numShards; i++ {
		sbf.filters[i] = bloom.NewWithEstimates(itemsPerShard, falsePositiveRate)
	}
	return sbf
}

func (sbf *shardedBloomFilter) TestAndAddString(key string) bool {
	h := uint32(2166136261)
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= 16777619
	}
	shardIndex := h % sbf.numShards

	sbf.locks[shardIndex].Lock()
	isDuplicate := sbf.filters[shardIndex].TestAndAddString(key)
	sbf.locks[shardIndex].Unlock()
	return isDuplicate
}

func (sbf *shardedBloomFilter) marshalBinary() ([]byte, error) {
	var out bytes.Buffer
	if err := binary.Write(&out, binary.LittleEndian, sbf.numShards); err != nil {
		return nil, err
	}
	for i := uint32(0); i < sbf.numShards; i++ {
		sbf.locks[i].Lock()
		var shardBuf bytes.Buffer
		_, err := sbf.filters[i].WriteTo(&shardBuf)
		sbf.locks[i].Unlock()
		if err != nil {
			return nil, err
		}
		shardBytes := shardBuf.Bytes()
		if err := binary.Write(&out, binary.LittleEndian, uint64(len(shardBytes))); err != nil {
			return nil, err
		}
		if _, err := out.Write(shardBytes); err != nil {
			return nil, err
		}
	}
	return out.Bytes(), nil
}

func (sbf *shardedBloomFilter) unmarshalBinary(data []byte) error {
	r := bytes.NewReader(data)
	var numShards uint32
	if err := binary.Read(r, binary.LittleEndian, &numShards); err != nil {
		return err
	}
	if numShards != sbf.numShards {
		return fmt.Errorf("bloom shard mismatch: file=%d engine=%d", numShards, sbf.numShards)
	}

	for i := uint32(0); i < sbf.numShards; i++ {
		var shardLen uint64
		if err := binary.Read(r, binary.LittleEndian, &shardLen); err != nil {
			return err
		}
		if shardLen > uint64(r.Len()) {
			return fmt.Errorf("invalid bloom shard length %d", shardLen)
		}
		shardBytes := make([]byte, shardLen)
		if _, err := io.ReadFull(r, shardBytes); err != nil {
			return err
		}

		sbf.locks[i].Lock()
		_, err := sbf.filters[i].ReadFrom(bytes.NewReader(shardBytes))
		sbf.locks[i].Unlock()
		if err != nil {
			return err
		}
	}
	return nil
}

// JobReason traces why a specific job was created.
type JobReason string

const (
	ReasonWordlist  JobReason = "wordlist"
	ReasonJSExtract JobReason = "js_extract"
	ReasonOpenAPI   JobReason = "openapi"
	ReasonFeedback  JobReason = "feedback"
)

// EngineMetrics tracks the operational efficiency of the intelligence layer.
type EngineMetrics struct {
	RequestsSent    atomic.Int64
	NodesDiscovered atomic.Int64
	NodesTested     atomic.Int64
	NodesConfirmed  atomic.Int64
	FindingsCreated atomic.Int64
	QueueDepth      atomic.Int64
	WorkerCount     atomic.Int64
	GraphSize       atomic.Int64

	ActionsGenerated  atomic.Int64
	ActionsSkipped    atomic.Int64
	CircuitBreaks     atomic.Int64
	NegativeCacheHits atomic.Int64
}

// ─── Engine ───────────────────────────────────────────────────────────────────

// Engine represents the core memory-queue system for the brute-forcer.
//
// Concurrency contract:
//   - Stats and EvasionSummaryRows are safe to call from any goroutine.
//   - Results and LogEvents are owned by the engine and may be read concurrently;
//     only Shutdown closes them.
//   - Start, KickoffScanner, and Shutdown coordinate internal goroutines and may
//     be invoked by theMCP/CLI orchestration layer without external locking.
type Engine struct {
	RunID         int64
	jobs          JobQueue
	wg            sync.WaitGroup
	shardedFilter *shardedBloomFilter
	numWorkers    int
	targetLock    sync.RWMutex
	baseURL       string
	host          string
	Config        *Config
	scannerCtx    atomic.Pointer[scannerContext]
	scannerWg     sync.WaitGroup
	activeJobs    sync.WaitGroup
	Results       chan Result
	LogEvents     chan LogEvent

	// Passive Tech Fingerprinting
	fingerprinter *fingerprint.Fingerprinter
	detectedTech  sync.Map // Keyed by "hostname:tech" — prevents log flooding per host

	// Nuclei Subprocess Integration
	nucleiCmd   *exec.Cmd
	nucleiStdin io.WriteCloser
	nucleiWg    sync.WaitGroup
	nucleiMu    sync.Mutex
	nucleiSeen  sync.Map

	// Eagle Mode State
	PreviousState map[string]previousScanEntry
	eagleLock     sync.RWMutex

	// Proxy Rotation
	proxiesLock  sync.Mutex
	proxies      []smartProxy
	proxyIndex   uint64
	proxyDialer  bool

	// Rate Limiters (Per-Host)
	limiters     map[string]*rate.Limiter
	limitersLock sync.RWMutex
	currentLimit rate.Limit
	currentBurst int

	// Progress tracking
	TotalLines         int64
	ProcessedLines     int64
	requestsDispatched atomic.Int64
	resultsCollected   atomic.Int64
	startedAtUnix      atomic.Int64
	isRunning          atomic.Bool
	activeWorkers      atomic.Int64

	// Worker management
	workerLock   sync.Mutex
	workerStopCh chan struct{}

	// Telemetry (Atomic counters)
	Count200             int64
	Count403             int64
	Count404             int64
	Count429             int64
	Count500             int64
	CountConnErr         int64
	AutoFilterSuppressed int64
	SimhashSuppressed    int64
	HarvestedPaths       int64

	// RPS calculation
	// `lastProcessed` and `lastTick` are accessed concurrently; use
	// atomic operations on the int64 fields to avoid data races.
	lastProcessed int64 // atomic: last processed count snapshot
	lastTick      int64 // atomic: unixNano timestamp of last tick
	CurrentRPS    int64

	// Smart Filter State
	fpMutex           sync.RWMutex
	fpCounts          map[string]int
	manualFilterSizes map[int]bool
	autoFilterSizes   map[int]bool
	simhashTracker    *SimhashTracker
	evasionAttempted  *ConcurrentMap[string, []string]
	EvasionScoreboard *EvasionScoreboard
	wafStateMu        sync.RWMutex
	wafDetected       bool
	wafVendorGuess    string

	// HTTP/2 client path.
	H2Client    *http.Client
	h2StreamSem chan struct{}

	// Anti-bot fallback state shared across workers.
	antiBot *antiBotManager

	// Timing oracle state (calibrated at scan startup when enabled).
	timingOracle *TimingOracle

	// Auto-throttle state
	autoThrottle     bool
	alreadyThrottled int32 // atomic: prevents repeated firing

	// Per-host HEAD rejection cache (replaces the single global headRejected flag)
	headRejectedHosts sync.Map // map[string]*int32

	// TUIDropped counts results the TUI channel dropped due to backpressure.
	TUIDropped int64
	// LogEventsDropped counts system log events dropped on the TUI fanout path.
	LogEventsDropped atomic.Int64

	// Resume support
	ResumeFile string

	// Discovery Graph
	DiscoveryGraph *DiscoveryGraph

	// Feedback Adapter
	EvidenceExtractor EvidenceExtractor

	// Recursive scanning state encapsulated in a tracker
	recursiveTracker RecursiveTracker

	// Compiled regexes (cached)
	matchRe  atomic.Pointer[regexp.Regexp]
	filterRe atomic.Pointer[regexp.Regexp]

	// Out-of-band interaction client for blind vulnerability detection.
	InteractshClient      *interactclient.Client
	InteractshPayload     string
	interactshClientOwned bool
	interactshMu          sync.RWMutex

	// Scope domain for recursion
	scopeDomain string

	// Bounded concurrency for source-map harvesting tasks.
	sourceMapSem chan struct{}
	// Bounded concurrency for 403/401 bypass micro-tasks.
	bypassSem chan struct{}

	// Bounded outbound proxy replay queue + workers
	replayCh chan replayTask
	// Bounded hidden-parameter fuzzing queue + workers.
	paramTaskChan   chan ParamTask
	paramTaskSeen   *ConcurrentMap[string, struct{}]
	paramHitSeen    *ConcurrentMap[string, struct{}]
	paramHintsSeen  *ConcurrentMap[string, string]
	phpParamTargets *ConcurrentMap[string, ParamTask]
	paramTasksWg    sync.WaitGroup
	// Cached immutable config snapshot read by workers.
	configSnap atomic.Pointer[configSnapshot]
	
	// Config snapshot debouncing state
	configSnapMu    sync.Mutex
	configSnapTimer *time.Timer
	// Cached outbound HTTP clients for proxy replay to avoid creating a new
	// Transport/Client per replay task (reduces GC pressure and enables
	// connection/TLS session reuse).
	replayClients sync.Map // map[string]*http.Client
	paramFuzzWg   sync.WaitGroup
	// Ensure Shutdown only runs once to avoid double-closing channels.
	shutdownOnce       sync.Once
	changeWordlistLock sync.Mutex
}

// ─── Constant classification strings ─────────────────────────────────────────

const (
	Forbidden403TypeCFWAFBlock = "CF_WAF_BLOCK"
	Forbidden403TypeCFAdmin403 = "CF_ADMIN_403"
	Forbidden403TypeNginx403   = "NGINX_403"
	Forbidden403TypeGeneric403 = "GENERIC_403"
)

const (
	paramTaskQueueSize = 256
)

// ─── Result helpers ───────────────────────────────────────────────────────────

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
	if len(r.DiscoveredParams) > 0 {
		extras += fmt.Sprintf(" [Params: %s]", strings.Join(r.DiscoveredParams, ","))
	}
	if len(r.Labels) > 0 {
		extras += fmt.Sprintf(" [Labels: %s]", strings.Join(r.Labels, ","))
	}
	if r.Confidence != "" {
		extras += fmt.Sprintf(" [Conf: %s]", r.Confidence)
	}
	methodStr := r.Method
	if methodStr == "" {
		methodStr = "HEAD/GET"
	}
	return fmt.Sprintf("[+] [%s] HIT: %s (Status: %d, Size: %d, Words: %d, Lines: %d)%s",
		methodStr, r.Path, r.StatusCode, r.Size, r.Words, r.Lines, extras)
}

func (r Result) EagleSummary() string {
	parts := make([]string, 0, 4)
	if r.IsEagleNewEndpoint {
		parts = append(parts, fmt.Sprintf("new endpoint [%d]", r.StatusCode))
	}
	if r.StatusDrift {
		parts = append(parts, fmt.Sprintf("status %d -> %d", r.OldStatusCode, r.StatusCode))
	}
	if r.SizeDrift {
		parts = append(parts, fmt.Sprintf("size %d -> %d bytes", r.OldSize, r.Size))
	}
	if r.ContentDrift {
		if r.OldWords != r.Words && (r.OldWords > 0 || r.Words > 0) {
			parts = append(parts, fmt.Sprintf("content changed (%d -> %d words)", r.OldWords, r.Words))
		} else {
			parts = append(parts, "content changed")
		}
	}
	if len(parts) == 0 {
		return "change detected"
	}
	return strings.Join(parts, "; ")
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

// Classify403 identifies known types of 403 responses based on body/header signals.
var (
	wafCFAttention = []byte("attention required! | cloudflare")
	wafCFBlocked   = []byte("sorry, you have been blocked")
	wafCFError     = []byte("cf-error-details")
	wafCFAdmin     = []byte("request forbidden by administrative rules")
	wafNginx       = []byte("<center>nginx</center>")
)

func containsFold(b, sub []byte) bool {
	if len(sub) == 0 {
		return true
	}
	if len(b) < len(sub) {
		return false
	}
	for i := 0; i <= len(b)-len(sub); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			c := b[i+j]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c != sub[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func Classify403(body []byte, headers string) string {
	const maxScan = 8 * 1024
	limit := maxScan
	if len(body) < limit {
		limit = len(body)
	}
	scanBuf := body[:limit]

	hasCFWAFBlock := containsFold(scanBuf, wafCFAttention) ||
		containsFold(scanBuf, wafCFBlocked) ||
		containsFold(scanBuf, wafCFError)
	if hasCFWAFBlock {
		return Forbidden403TypeCFWAFBlock
	}

	hasCFAdmin403 := containsFold(scanBuf, wafCFAdmin)
	hasNginx403 := containsFold(scanBuf, wafNginx)

	hasCfRay := false
	hasCfCacheStatus := false

	start := 0
	for start < len(headers) {
		end := strings.IndexByte(headers[start:], '\n')
		if end == -1 {
			end = len(headers)
		} else {
			end += start
		}
		line := headers[start:end]
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		idx := strings.IndexByte(line, ':')
		if idx != -1 {
			key := strings.TrimSpace(line[:idx])
			if strings.EqualFold(key, "cf-ray") {
				hasCfRay = true
			} else if strings.EqualFold(key, "cf-cache-status") {
				hasCfCacheStatus = true
			}
		}
		start = end + 1
	}

	if hasCFAdmin403 && (hasCfRay || hasCfCacheStatus) {
		return Forbidden403TypeCFAdmin403
	}
	if hasNginx403 && !hasCfRay {
		return Forbidden403TypeNginx403
	}
	return Forbidden403TypeGeneric403
}

// WriteCSVHeader writes a CSV header to the given writer.
func WriteCSVHeader(w *csv.Writer) {
	w.Write([]string{"Method", "URL", "Path", "Status", "Size", "Words", "Lines", "ContentType", "Redirect", "Duration"})
}

// ─── Engine constructor ───────────────────────────────────────────────────────

// NewEngine initialises a new Engine with a worker pool and a Bloom filter.
func NewEngine(numWorkers int, expectedItems uint, falsePositiveRate float64) *Engine {
	burst := numWorkers
	if burst < MinRateLimitBurst {
		burst = MinRateLimitBurst
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Create bounded replay queue and start workers.
	replayCh := make(chan replayTask, ReplayQueueSize)
	sourceMapConcurrency := numWorkers
	if sourceMapConcurrency < 1 {
		sourceMapConcurrency = 1
	}

	e := &Engine{
		jobs:          NewPriorityQueue(DefaultJobQueueSize),
		shardedFilter: newShardedBloomFilter(bloomFilterShards, expectedItems, falsePositiveRate),
		numWorkers:    numWorkers,
		limiters:      make(map[string]*rate.Limiter),
		currentLimit:  rate.Inf,
		currentBurst:  burst,
		fingerprinter: fingerprint.NewFingerprinter(),
		Config: &Config{
			UserAgent:           "DirFuzz/2.0",
			Headers:             make(map[string]string),
			MatchCodes:          make(map[int]bool),
			FilterSizes:         make(map[int]bool),
			IsPaused:            false,
			Delay:               0,
			MaxWorkers:          numWorkers,
			MaxRedirects:        DefaultMaxRedirects,
			FilterWords:         -1,
			FilterLines:         -1,
			MatchWords:          -1,
			MatchLines:          -1,
			OutputFormat:        DefaultOutputFormat,
			Timeout:             DefaultHTTPTimeout,
			Insecure:            false,
			AntiBotFallback:     true,
			AllowPrivateTargets: false,
			RecursivePrune:      true,
			AutoFilterThreshold: DefaultAutoFilterThreshold,
			SimhashThreshold:    DefaultSimhashThreshold,
			SimhashClusterLimit: DefaultSimhashClusterLimit,
			DisableSoft404Calibration: flag.Lookup("test.v") != nil,
			H2ConcurrentStreams: DefaultH2ConcurrentStreams,
			TimeOracleK:         TimingOracleDefaultK,
			TimeOracleN:         TimingOracleDefaultRepeatN,
			EvasionLimit:        DefaultEvasionLimit,
		},
		Results:           make(chan Result, ResultsChannelSize),
		LogEvents:         make(chan LogEvent, 5000),
		antiBot:           newAntiBotManager(),
		fpCounts:          make(map[string]int),
		manualFilterSizes: make(map[int]bool),
		autoFilterSizes:   make(map[int]bool),
		simhashTracker:    NewSimhashTracker(DefaultSimhashThreshold, DefaultSimhashClusterLimit),
		EvasionScoreboard: NewEvasionScoreboard(),
		lastTick:          time.Now().UnixNano(),
		autoThrottle:      true,
		sourceMapSem:      make(chan struct{}, sourceMapConcurrency),
		bypassSem:         make(chan struct{}, 20),
		replayCh:          replayCh,
		workerStopCh:      make(chan struct{}),
		DiscoveryGraph:    NewDiscoveryGraph(),
		EvidenceExtractor: DefaultEvidenceExtractor{},
	}

	e.recursiveTracker = NewRecursiveTracker(e)

	e.paramTaskSeen = NewConcurrentMap[string, struct{}]()
	e.paramHitSeen = NewConcurrentMap[string, struct{}]()
	e.paramHintsSeen = NewConcurrentMap[string, string]()
	e.phpParamTargets = NewConcurrentMap[string, ParamTask]()
	e.evasionAttempted = NewConcurrentMap[string, []string]()

	e.scannerCtx.Store(&scannerContext{ctx: ctx, cancel: cancel})

	// Launch bounded replay workers.
	for i := 0; i < ReplayWorkers; i++ {
		go func() {
			for task := range replayCh {
				e.execReplay(task)
			}
		}()
	}

	paramWorkers := numWorkers / 4
	if paramWorkers < 1 {
		paramWorkers = 1
	}
	e.paramTaskChan = make(chan ParamTask, paramTaskQueueSize)
	e.startParamFuzzWorkers(paramWorkers)

	// Initialize worker-facing immutable config snapshot.
	e.buildAndStoreConfigSnapshot()

	return e
}

// ─── Proxy helpers ────────────────────────────────────────────────────────────

// LoadProxies loads a list of proxies from a file (SOCKS5 or HTTP).
func (e *Engine) LoadProxies(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	var list []smartProxy
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			list = append(list, smartProxy{addr: line})
		}
	}
	e.proxiesLock.Lock()
	e.proxies = list
	e.proxiesLock.Unlock()

	if len(list) > 0 {
		e.proxyDialer = true
		fmt.Printf("[*] Loaded %d proxies from %s\n", len(list), path)
	}
	return scanner.Err()
}

// GetNextProxy returns the next available proxy in the list, skipping those in cooldown.
func (e *Engine) GetNextProxy() string {
	e.proxiesLock.Lock()
	defer e.proxiesLock.Unlock()

	if len(e.proxies) == 0 {
		return ""
	}

	now := time.Now()
	n := len(e.proxies)

	// Attempt to find the next active (non-cooldown) proxy in round-robin sequence
	for i := 0; i < n; i++ {
		idx := (e.proxyIndex) % uint64(n)
		e.proxyIndex++
		p := e.proxies[idx]
		if p.cooldownUntil.IsZero() || now.After(p.cooldownUntil) {
			return p.addr
		}
	}

	// Dynamic fallback: If all proxies are currently in cooldown, fallback to the one
	// with the earliest cooldown expiry time to maintain fuzzer velocity.
	var bestIdx = 0
	var bestTime = e.proxies[0].cooldownUntil
	for i := 1; i < n; i++ {
		if e.proxies[i].cooldownUntil.Before(bestTime) {
			bestTime = e.proxies[i].cooldownUntil
			bestIdx = i
		}
	}

	return e.proxies[bestIdx].addr
}

// ReportProxyStatus updates the health state of a proxy.
// If isBlocked is true, it triggers an exponential backoff cooldown.
func (e *Engine) ReportProxyStatus(addr string, isBlocked bool) {
	if addr == "" {
		return
	}
	e.proxiesLock.Lock()
	defer e.proxiesLock.Unlock()

	for i := range e.proxies {
		if e.proxies[i].addr == addr {
			if isBlocked {
				e.proxies[i].failCount++
				// Backoff formula: 2 ^ failCount * 15 seconds, capped at 10 minutes max.
				backoffSecs := (1 << e.proxies[i].failCount) * 15
				if backoffSecs > 600 {
					backoffSecs = 600
				}
				e.proxies[i].cooldownUntil = time.Now().Add(time.Duration(backoffSecs) * time.Second)
				e.emitLogEvent(LogLevelWarning, LogCategoryNetwork, EventProxyRotated, fmt.Sprintf("proxy %s blocked, cooling down for %d seconds (fails: %d)", addr, backoffSecs, e.proxies[i].failCount), map[string]interface{}{
					"proxy":     addr,
					"cooldown":  backoffSecs,
					"fail_count": e.proxies[i].failCount,
				})
			} else {
				e.proxies[i].failCount = 0
				e.proxies[i].cooldownUntil = time.Time{}
			}
			break
		}
	}
}

// ─── Wordlist scanner ─────────────────────────────────────────────────────────

// Restart restarts the scanner with the current wordlist.
func (e *Engine) Restart() error {
	e.Config.RLock()
	path := e.Config.WordlistPath
	e.Config.RUnlock()
	if path == "" {
		return fmt.Errorf("no wordlist currently loaded to restart")
	}
	return e.ChangeWordlist(path)
}

// ChangeWordlist cancels the current scanner and starts a new one.
func (e *Engine) ChangeWordlist(path string) error {
	e.changeWordlistLock.Lock()
	defer e.changeWordlistLock.Unlock()

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("wordlist file does not exist: %s", path)
	}

	if oldCtx := e.scannerCtx.Load(); oldCtx != nil && oldCtx.cancel != nil {
		oldCtx.cancel()
		e.scannerWg.Wait() // Ensure old scanner has completely stopped before resetting state
	}

	// Drain any in-flight replay tasks from the old wordlist
drainLoop:
	for {
		select {
		case <-e.replayCh:
		default:
			break drainLoop
		}
	}

	e.workerLock.Lock()
	e.workerStopCh = make(chan struct{})
	e.workerLock.Unlock()

	e.shardedFilter = newShardedBloomFilter(bloomFilterShards, DefaultBloomFilterSize, DefaultBloomFilterFP)

	atomic.StoreInt64(&e.ProcessedLines, 0)
	atomic.StoreInt64(&e.TotalLines, 0)
	atomic.StoreInt64(&e.Count200, 0)
	atomic.StoreInt64(&e.Count403, 0)
	atomic.StoreInt64(&e.Count404, 0)
	atomic.StoreInt64(&e.Count429, 0)
	atomic.StoreInt64(&e.Count500, 0)
	atomic.StoreInt64(&e.CountConnErr, 0)
	atomic.StoreInt64(&e.CurrentRPS, 0)
	atomic.StoreInt32(&e.alreadyThrottled, 0)
	atomic.StoreInt64(&e.HarvestedPaths, 0)
	e.evasionAttempted.Clear()
	e.recursiveTracker.Clear()
	e.EvasionScoreboard = NewEvasionScoreboard()
	e.headRejectedHosts.Range(func(k, _ interface{}) bool {
		e.headRejectedHosts.Delete(k)
		return true
	})

	e.fpMutex.Lock()
	e.fpCounts = make(map[string]int)
	e.fpMutex.Unlock()
	e.clearAutoFilterSizes()
	e.simhashTracker.Clear()

	atomic.StoreInt64(&e.AutoFilterSuppressed, 0)
	atomic.StoreInt64(&e.SimhashSuppressed, 0)

	// Install a pre-cancelled sentinel context so any goroutine that races to
	// call Submit() after this point will either:
	//   (a) see ctx.Done() in the select and call activeJobs.Done() directly, or
	//   (b) succeed in sending to e.jobs (which we will drain below).
	// This closes the window where a new live context could be loaded.
	sentinelCtx, sentinelCancel := context.WithCancel(context.Background())
	sentinelCancel() // immediately cancelled
	e.scannerCtx.Store(&scannerContext{ctx: sentinelCtx, cancel: sentinelCancel})

	// Drain Results concurrently so workers blocked on `e.Results <- res` can
	// proceed and call activeJobs.Done(). Without this, ChangeWordlist deadlocks
	// when nobody else is consuming Results (e.g. in tests, or a full buffer).
	stopDrain := make(chan struct{})
	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		for {
			select {
			case <-e.Results:
				// discard — caller is restarting the scan
			case <-stopDrain:
				return
			}
		}
	}()

	// Drain the jobs queue in a loop until activeJobs reaches zero.
	// We must loop because Submit does activeJobs.Add(1) BEFORE sending to the
	// channel — a job may land in the queue after a previous drainJobs call
	// returned but before activeJobs reaches zero. Polling every millisecond is
	// cheap compared to the alternatives.
	for {
		e.drainJobs()
		// Use a short-lived WaitGroup trick: if the counter is already 0 this
		// returns immediately; otherwise we yield briefly and drain again.
		done := make(chan struct{})
		go func() {
			e.activeJobs.Wait()
			close(done)
		}()
		select {
		case <-done:
			// activeJobs reached zero — we're clean.
			close(stopDrain)
			<-drainDone
			goto startNewScan
		case <-time.After(time.Millisecond):
			// Still pending; drain the queue again and retry.
		}
	}

startNewScan:
	// Now install the real live context and start the new scan.
	ctx, cancel := context.WithCancel(context.Background())
	e.scannerCtx.Store(&scannerContext{ctx: ctx, cancel: cancel})

	atomic.AddInt64(&e.RunID, 1)

	e.KickoffScanner(path, 0)
	return nil
}

// drainJobs safely drains all pending jobs from the jobs queue.
func (e *Engine) drainJobs() {
	count := e.jobs.Drain()
	for i := 0; i < count; i++ {
		e.activeJobs.Done()
	}
}

// KickoffScanner starts the wordlist scanner.
//
// It is safe to call after Start from a coordinating goroutine; the scanner
// goroutine itself is owned by the engine and is drained by Shutdown.
func (e *Engine) KickoffScanner(path string, startLine int64) {
	e.AddScanner()
	sc := e.scannerCtx.Load()
	if sc != nil {
		runID := atomic.LoadInt64(&e.RunID)

		if e.shouldRunPassiveHarvest() {
			e.AddScanner()
			go e.StartPassiveHarvesting(sc.ctx, runID, e.BaseURL())
		}
		go e.StartWordlistScanner(sc.ctx, runID, path, startLine)
	}
}

func (e *Engine) AddScanner() { e.scannerWg.Add(1) }

// StartWordlistScanner reads from a wordlist and submits payloads to the engine
// in a SINGLE pass, updating TotalLines atomically as it goes.
func (e *Engine) StartWordlistScanner(ctx context.Context, runID int64, path string, startLine int64) {
	defer e.scannerWg.Done()
	e.Config.Lock()
	e.Config.WordlistPath = path
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()

	file, err := os.Open(path)
	if err != nil {
		res := Result{
			Path:         path,
			StatusCode:   0,
			IsAutoFilter: true,
			Headers:      map[string]string{"Msg": "Error opening wordlist: " + err.Error()},
		}
		e.handleResultWithContext(ctx, res)
		return
	}
	defer file.Close()

	lineNum := int64(0)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	// Load methods/smartAPI/extensions from the immutable snapshot once and
	// refresh only when the snapshot pointer changes. This avoids taking
	// the config RLock for every wordlist line.
	snap := e.configSnap.Load()
	var methods []string
	var smartAPI bool
	var exts []string
	if snap != nil {
		methods = snap.Methods
		smartAPI = snap.SmartAPI
		exts = make([]string, len(snap.Extensions))
		copy(exts, snap.Extensions)
	} else {
		e.Config.RLock()
		methods = e.Config.Methods
		smartAPI = e.Config.SmartAPI
		exts = make([]string, len(e.Config.Extensions))
		copy(exts, e.Config.Extensions)
		e.Config.RUnlock()
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			e.saveResumeState(path, lineNum, true)
			return
		default:
		}

		// Respect pause. Use the snapshot first; fall back to the lock if
		// the snapshot isn't available.
		var paused bool
		if s := e.configSnap.Load(); s != nil {
			paused = s.IsPaused
		} else {
			e.Config.RLock()
			paused = e.Config.IsPaused
			e.Config.RUnlock()
		}
		for paused {
			time.Sleep(100 * time.Millisecond)
			select {
			case <-ctx.Done():
				e.saveResumeState(path, lineNum, true)
				return
			default:
			}
			if s := e.configSnap.Load(); s != nil {
				paused = s.IsPaused
			} else {
				e.Config.RLock()
				paused = e.Config.IsPaused
				e.Config.RUnlock()
			}
		}

		line := strings.TrimRight(scanner.Text(), "\r")
		if line == "" {
			continue
		}
		lineNum++

		select {
		case <-ticker.C:
			e.saveResumeState(path, lineNum, false)
		default:
		}

		if lineNum <= startLine {
			continue
		}

		// Refresh locals if the global snapshot changed.
		if cur := e.configSnap.Load(); cur != snap && cur != nil {
			snap = cur
			methods = snap.Methods
			smartAPI = snap.SmartAPI
			exts = make([]string, len(snap.Extensions))
			copy(exts, snap.Extensions)
		}

		if pathExcludedByRegexps(line, snap.ExcludePathRegexps) {
			continue
		}

		methodsToUse := resolveMethodsForPath(line, methods, smartAPI)
		for _, method := range methodsToUse {
			// Increment total for this base path.
			atomic.AddInt64(&e.TotalLines, 1)
			e.Submit(Job{Path: line, Depth: 0, Method: method, RunID: runID})
			for _, ext := range exts {
				cleanExt := strings.TrimSpace(ext)
				if !strings.HasPrefix(cleanExt, ".") {
					cleanExt = "." + cleanExt
				}
				if pathExcludedByRegexps(line+cleanExt, snap.ExcludePathRegexps) {
					continue
				}
				atomic.AddInt64(&e.TotalLines, 1)
				e.Submit(Job{Path: line + cleanExt, Depth: 0, Method: method, RunID: runID})
			}
		}
	}

	if err := scanner.Err(); err != nil {
		res := Result{
			Path:         path,
			StatusCode:   0,
			IsAutoFilter: true,
			Headers:      map[string]string{"Msg": "Wordlist scan error: " + err.Error()},
		}
		e.handleResultWithContext(ctx, res)
	}
}

// resolveMethodsForPath returns the HTTP methods to use for a given path,
// taking into account SmartAPI mode.
func resolveMethodsForPath(line string, methods []string, smartAPI bool) []string {
	if len(methods) == 0 {
		return []string{""}
	}
	if !smartAPI || isAPIPath(line) {
		return methods
	}
	return []string{""}
}

type Estimate struct {
	BaseWords       int64
	Extensions      int
	Methods         int
	EstimatedJobs   int64
	Recursive       bool
	MaxDepth        int
	RecursiveWorst  int64
	RecursiveCapped bool
}

func (e *Engine) EstimateWordlist(path string, startLine int64) (Estimate, error) {
	e.Config.RLock()
	methods := append([]string(nil), e.Config.Methods...)
	smartAPI := e.Config.SmartAPI
	extensions := append([]string(nil), e.Config.Extensions...)
	recursive := e.Config.Recursive
	maxDepth := e.Config.MaxDepth
	e.Config.RUnlock()

	file, err := os.Open(path)
	if err != nil {
		return Estimate{}, err
	}
	defer file.Close()

	var jobs int64
	var words int64
	lineNum := int64(0)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		if line == "" {
			continue
		}
		lineNum++
		if lineNum <= startLine {
			continue
		}
		words++
		methodCount := int64(len(resolveMethodsForPath(line, methods, smartAPI)))
		jobs += methodCount * int64(1+len(extensions))
	}
	if err := scanner.Err(); err != nil {
		return Estimate{}, err
	}

	methodCount := len(methods)
	if methodCount == 0 {
		methodCount = 1
	}
	est := Estimate{
		BaseWords:      words,
		Extensions:     len(extensions),
		Methods:        methodCount,
		EstimatedJobs:  jobs,
		Recursive:      recursive,
		MaxDepth:       maxDepth,
		RecursiveWorst: jobs,
	}
	if recursive && maxDepth > 0 {
		worst := jobs
		level := jobs
		for depth := 1; depth <= maxDepth; depth++ {
			if level > 1_000_000_000/maxInt64(jobs, 1) {
				est.RecursiveCapped = true
				worst = 1_000_000_000
				break
			}
			level *= maxInt64(jobs, 1)
			worst += level
			if worst > 1_000_000_000 {
				est.RecursiveCapped = true
				worst = 1_000_000_000
				break
			}
		}
		est.RecursiveWorst = worst
	}
	return est, nil
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// isAPIPath returns true when the path segment looks like an API endpoint.
// Uses segment-boundary matching to avoid false positives like /overview1.
var apiPathRe = regexp.MustCompile(`(?i)(^|/)(v\d+|api|rest|graphql)(/|$)`)

func isAPIPath(line string) bool {
	return apiPathRe.MatchString(line)
}

// ─── Worker management ────────────────────────────────────────────────────────

func (e *Engine) QueueSize() int { return e.jobs.Len() }

// NumWorkers returns the configured worker count for the engine.
func (e *Engine) NumWorkers() int {
	e.workerLock.Lock()
	defer e.workerLock.Unlock()
	return e.numWorkers
}

// Start launches the configured worker pool.
//
// Call Start once per engine instance before KickoffScanner. The method is
// concurrency-safe with Shutdown, but callers should not invoke it repeatedly
// on the same engine because it would spawn duplicate workers.
func (e *Engine) Start() {
	e.workerLock.Lock()
	defer e.workerLock.Unlock()
	if err := e.ensureInteractshClient(); err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] OOB client offline (network block detected)\n")
	}
	now := time.Now().UTC().UnixNano()
	e.startedAtUnix.CompareAndSwap(0, now)
	e.isRunning.Store(true)

	if err := e.startNuclei(); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Warning: failed to start Nuclei integration: %v\n", err)
	}

	e.CalibrateSoft404()

	for i := 0; i < e.numWorkers; i++ {
		e.wg.Add(1)
		e.activeWorkers.Add(1)
		e.emitLogEvent(LogLevelInfo, LogCategoryWorker, EventWorkerStarted, fmt.Sprintf("worker %d started", i), map[string]interface{}{"worker_id": i})
		go e.worker(i)
	}
}

func (e *Engine) SetWorkerCount(n int) {
	if n < MinWorkerCount {
		n = MinWorkerCount
	}
	e.Config.Lock()
	e.Config.MaxWorkers = n
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()

	e.workerLock.Lock()
	defer e.workerLock.Unlock()

	if n > e.numWorkers {
		// Grow the pool
		diff := n - e.numWorkers
		for i := 0; i < diff; i++ {
			e.wg.Add(1)
			e.activeWorkers.Add(1)
			workerID := e.numWorkers + i
			e.emitLogEvent(LogLevelInfo, LogCategoryWorker, EventWorkerStarted, fmt.Sprintf("worker %d started", workerID), map[string]interface{}{"worker_id": workerID, "new_size": n})
			go e.worker(workerID)
		}
	} else if n < e.numWorkers {
		// Shrink the pool
		diff := e.numWorkers - n
		sc := e.scannerCtx.Load()
		ctx := context.Background()
		if sc != nil && sc.ctx != nil {
			ctx = sc.ctx
		}
		for i := 0; i < diff; i++ {
			go func() {
				select {
				case e.workerStopCh <- struct{}{}:
				case <-ctx.Done():
				}
			}()
		}
	}

	e.numWorkers = n
	e.UpdateRateLimiterFromDelay()
}

// autoThrottleCheck reduces workers/increases delay on repeated 429s.
// A guard prevents it from firing again once throttling is already applied.
func (e *Engine) autoThrottleCheck() {
	if !e.autoThrottle {
		return
	}
	count429 := atomic.LoadInt64(&e.Count429)
	if count429 > 0 && count429%AutoThrottleInterval == 0 {
		// Only fire once per AutoThrottleInterval batch.
		if !atomic.CompareAndSwapInt32(&e.alreadyThrottled, 0, 1) {
			return
		}
		// Reset so the next batch can trigger again.
		go func() {
			time.Sleep(5 * time.Second)
			atomic.StoreInt32(&e.alreadyThrottled, 0)
		}()

		e.Config.RLock()
		currentWorkers := e.Config.MaxWorkers
		currentDelay := e.Config.Delay
		e.Config.RUnlock()

		newWorkers := currentWorkers * ThrottleWorkerPercent / 100
		if newWorkers < MinThrottledWorkers {
			newWorkers = MinThrottledWorkers
		}
		newDelay := currentDelay + ThrottleDelayIncrease
		if newDelay > MaxThrottleDelay {
			newDelay = MaxThrottleDelay
		}

		e.SetWorkerCount(newWorkers)
		e.SetDelay(newDelay)
		e.emitLogEvent(LogLevelWarning, LogCategorySystem, EventRateLimitHit, fmt.Sprintf("auto-throttle applied: workers %d -> %d, delay %s", currentWorkers, newWorkers, newDelay), map[string]interface{}{
			"current_workers": currentWorkers,
			"new_workers":     newWorkers,
			"new_delay_ms":    newDelay.Milliseconds(),
		})

		res := Result{
			Path:         "AUTO-THROTTLE",
			StatusCode:   429,
			IsAutoFilter: true,
			Headers:      map[string]string{"Msg": fmt.Sprintf("429 spike! Workers: %d→%d, Delay: %s", currentWorkers, newWorkers, newDelay)},
		}
		e.handleResultNonBlocking(res)
	}
}

// ─── RPS tracking ─────────────────────────────────────────────────────────────

func (e *Engine) UpdateRPS() {
	nowNano := time.Now().UnixNano()
	lastTick := atomic.LoadInt64(&e.lastTick)
	elapsed := float64(nowNano-lastTick) / 1e9
	if elapsed < 0.1 {
		return
	}
	current := atomic.LoadInt64(&e.ProcessedLines)
	lastProcessed := atomic.LoadInt64(&e.lastProcessed)
	delta := current - lastProcessed
	atomic.StoreInt64(&e.CurrentRPS, int64(float64(delta)/elapsed))
	atomic.StoreInt64(&e.lastProcessed, current)
	atomic.StoreInt64(&e.lastTick, nowNano)
}

// ─── Request helpers ───────────────────────────────────────────────────────────

func (e *Engine) headRejectedForHost(host string) *int32 {
	val, _ := e.headRejectedHosts.LoadOrStore(host, new(int32))
	return val.(*int32)
}

func (e *Engine) isHeadRejected(host string) bool {
	return atomic.LoadInt32(e.headRejectedForHost(host)) == 1
}

func (e *Engine) markHeadRejected(host string) {
	atomic.StoreInt32(e.headRejectedForHost(host), 1)
}

// ─── Worker helper functions ───────────────────────────────────────────────────

func fullURLForPayload(baseURL, payload, requestBody string) string {
	if strings.Contains(baseURL, "{PAYLOAD}") {
		return strings.Replace(baseURL, "{PAYLOAD}", payload, 1)
	}
	if strings.Contains(requestBody, "{PAYLOAD}") {
		return baseURL
	}
	word := payload
	if !strings.HasPrefix(word, "/") {
		word = "/" + word
	}
	return strings.TrimRight(baseURL, "/") + word
}

// buildRequest constructs a raw HTTP request byte slice.
func buildRequest(method, reqPath, reqHost, ua, headersStr, bodyContent string) []byte {
	// Prevent CRLF injection in the request line.
	reqPath = strings.ReplaceAll(reqPath, "\r", "")
	reqPath = strings.ReplaceAll(reqPath, "\n", "")

	reqHost = strings.ReplaceAll(reqHost, "\r", "")
	reqHost = strings.ReplaceAll(reqHost, "\n", "")

	ua = strings.ReplaceAll(ua, "\r", "")
	ua = strings.ReplaceAll(ua, "\n", "")

	// For headersStr, strip double CRLF to prevent premature body termination.
	for strings.Contains(headersStr, "\r\n\r\n") {
		headersStr = strings.ReplaceAll(headersStr, "\r\n\r\n", "\r\n")
	}

	headersLower := strings.ToLower(headersStr)
	var defaultsBuilder strings.Builder
	if !strings.Contains(headersLower, "\nconnection:") && !strings.HasPrefix(headersLower, "connection:") {
		defaultsBuilder.WriteString("Connection: keep-alive\r\n")
	}
	if !strings.Contains(headersLower, "\naccept:") && !strings.HasPrefix(headersLower, "accept:") {
		defaultsBuilder.WriteString("Accept: */*\r\n")
	}
	if !strings.Contains(headersLower, "\naccept-encoding:") && !strings.HasPrefix(headersLower, "accept-encoding:") {
		defaultsBuilder.WriteString("Accept-Encoding: identity\r\n")
	}
	defaultsStr := defaultsBuilder.String()

	if bodyContent != "" {
		return []byte(fmt.Sprintf(
			"%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n%s%s\r\n%s",
			method, reqPath, reqHost, ua, headersStr, defaultsStr, bodyContent,
		))
	}
	return []byte(fmt.Sprintf(
		"%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n%s%s\r\n",
		method, reqPath, reqHost, ua, headersStr, defaultsStr,
	))
}

func spiderChildJob(parent Job, newPath string) Job {
	return Job{
		Path:   newPath,
		Depth:  parent.Depth + 1,
		Method: "GET",
		RunID:  parent.RunID,
	}
}

func isASCII(b []byte) bool {
	for i := 0; i < len(b); i++ {
		if b[i] >= 0x80 {
			return false
		}
	}
	return true
}

func computeResponseMetrics(resp *httpclient.RawResponse, successfulMethod string) (bodySize, wordCount, lineCount int, contentType string, bodyHash uint64) {
	bodySize = len(resp.Body)
	wordCount = -1
	lineCount = -1

	if resp.BodyEncoded {
		bodySize = -1
	} else {
		if successfulMethod == "HEAD" {
			clVal := resp.GetHeader("Content-Length")
			if clVal != "" {
				if s, parseErr := strconv.Atoi(clVal); parseErr == nil {
					bodySize = s
				}
			}
		}

		if len(resp.Body) == 0 {
			wordCount = 0
			lineCount = 0
		} else {
			wordCount = 0
			lineCount = 0
			inWord := false

			if isASCII(resp.Body) {
				for i := 0; i < len(resp.Body); i++ {
					b := resp.Body[i]
					if b == '\n' {
						lineCount++
					}
					isSpace := b == ' ' || b == '\t' || b == '\r' || b == '\n' || b == '\v' || b == '\f'
					if isSpace {
						if inWord {
							inWord = false
						}
					} else {
						if !inWord {
							wordCount++
							inWord = true
						}
					}
				}
			} else {
				for i := 0; i < len(resp.Body); {
					r, size := utf8.DecodeRune(resp.Body[i:])
					i += size
					if r == '\n' {
						lineCount++
					}
					if unicode.IsSpace(r) {
						if inWord {
							inWord = false
						}
					} else {
						if !inWord {
							wordCount++
							inWord = true
						}
					}
				}
			}
			lineCount = lineCount + 1
		}
	}

	contentType = resp.GetHeader("Content-Type")
	if idx := strings.Index(contentType, ";"); idx != -1 {
		contentType = strings.TrimSpace(contentType[:idx])
	}
	bodyHash = simhashBody(resp.Body)
	return
}

func isSameSpiderScopeHost(baseHostname string, parsedLink *url.URL) bool {
	if !parsedLink.IsAbs() {
		return true
	}
	return strings.EqualFold(parsedLink.Hostname(), baseHostname)
}

// applyFilters returns true when the result should be kept (not filtered).
func (e *Engine) applyFilters(
	resp *httpclient.RawResponse,
	bodySize, wordCount, lineCount int,
	bodyHash uint64,
	contentType string,
	forceKeep bool,
	filterSizes map[int]bool,
	filterSizeRanges []SizeRange,
	matchCodes map[int]bool,
	filterWords, filterLines, matchWords, matchLines int,
	matchContentTypes, filterContentTypes []string,
	filterRTMin, filterRTMax time.Duration,
	skipRT bool,
) bool {
	if forceKeep {
		return true
	}
	// 1. Status code.
	if len(matchCodes) > 0 && !matchCodes[resp.StatusCode] {
		return false
	}
	// 2. Exact size filter.
	if len(filterSizes) > 0 && filterSizes[bodySize] {
		return false
	}
	// 3. Size range filter.
	for _, r := range filterSizeRanges {
		// If bodySize is unknown (-1) do not match any size ranges.
		if bodySize >= 0 && bodySize >= r.Min && bodySize <= r.Max {
			return false
		}
	}
	// 4. Word / line counts.
	if filterWords >= 0 && wordCount == filterWords {
		return false
	}
	if filterLines >= 0 && lineCount == filterLines {
		return false
	}
	if matchWords >= 0 && wordCount != matchWords {
		return false
	}
	if matchLines >= 0 && lineCount != matchLines {
		return false
	}
	// 5. Body regex.
	if mRe := e.matchRe.Load(); mRe != nil {
		if resp.BodyEncoded || !mRe.Match(resp.Body) {
			return false
		}
	}
	if fRe := e.filterRe.Load(); fRe != nil && !resp.BodyEncoded && fRe.Match(resp.Body) {
		return false
	}
	// 6. Response time.
	if !skipRT {
		if filterRTMin > 0 && resp.Duration < filterRTMin {
			return false
		}
		if filterRTMax > 0 && resp.Duration > filterRTMax {
			return false
		}
	}
	// 7. Content-type match.
	ctLower := strings.ToLower(contentType)
	if len(matchContentTypes) > 0 {
		matched := false
		for _, ct := range matchContentTypes {
			if strings.Contains(ctLower, ct) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	// 8. Content-type filter.
	for _, ct := range filterContentTypes {
		if strings.Contains(ctLower, ct) {
			return false
		}
	}
	// 9. SimHash soft-404 clustering.
	if e.simhashTracker.IsSoftFour(bodyHash) {
		atomic.AddInt64(&e.SimhashSuppressed, 1)
		e.emitLogEvent(LogLevelWarning, LogCategoryFilter, EventSimhashCluster, fmt.Sprintf("simhash cluster suppressed body hash %x", bodyHash), map[string]interface{}{
			"body_hash": bodyHash,
			"status":    resp.StatusCode,
			"size":      bodySize,
		})
		return false
	}
	return true
}

// ─── Lifecycle ────────────────────────────────────────────────────────────────

func (e *Engine) Wait() {
	e.scannerWg.Wait()
	e.activeJobs.Wait()
	e.paramTasksWg.Wait()
}

// Shutdown requests a graceful stop and closes the result/log channels.
//
// It is safe to call multiple times; only the first call performs teardown.
func (e *Engine) Shutdown() {
	e.shutdownOnce.Do(func() {
		e.isRunning.Store(false)
		// Signal scanners to stop producing new jobs.
		if sc := e.scannerCtx.Load(); sc != nil && sc.cancel != nil {
			sc.cancel()
		}

		// Wait for all scanner goroutines to finish. This ensures no more
		// jobs will be submitted.
		e.scannerWg.Wait()

		// Wait for any in-flight work spawned by scanners, including source-map
		// harvesters, before closing the jobs channel. This avoids closing the
		// queue while auxiliary harvest goroutines are still trying to submit
		// follow-up paths.
		e.activeJobs.Wait()

		// Now that producers are stopped, it's safe to close the jobs channel.
		// This will signal the worker goroutines to exit their range loop
		// once they have finished processing all queued jobs.
		e.jobs.Close()

		// Wait for all worker goroutines to finish.
		e.wg.Wait()

		e.closeInteractshClient()

		// Drain and stop the hidden-parameter worker pool after the main
		// directory scan workers have finished submitting tasks.
		if e.paramTaskChan != nil {
			close(e.paramTaskChan)
			e.paramFuzzWg.Wait()
		}

		// Close replay channel, stopping replay workers.
		close(e.replayCh)

		// Close idle connections on cached replay transports so they don't
		// leak goroutines or hold resources after shutdown.
		e.replayClients.Range(func(k, v interface{}) bool {
			if client, ok := v.(*http.Client); ok {
				if tr, ok := client.Transport.(*http.Transport); ok {
					tr.CloseIdleConnections()
				}
			}
			return true
		})

		// Cleanly shut down Nuclei integration
		e.stopNuclei()

		// Finally, shut down the main results channel
		close(e.LogEvents)
		close(e.Results)
	})
}

// ─── Meta ─────────────────────────────────────────────────────────────────────

type EngineConfigDump struct {
	Target     string
	Wordlist   string
	OutputFile string
	SmartAPI   bool
}

type RuntimeConfigSnapshot struct {
	Timeout     time.Duration
	RequestBody string
	FilterWords int
	SaveRaw     bool
	ProxyOut    string
	Methods     []string
}

func (e *Engine) RuntimeSnapshot() RuntimeConfigSnapshot {
	s := e.configSnap.Load()
	if s == nil {
		e.buildAndStoreConfigSnapshot()
		s = e.configSnap.Load()
	}
	if s == nil {
		return RuntimeConfigSnapshot{}
	}
	return RuntimeConfigSnapshot{
		Timeout:     s.Timeout,
		RequestBody: s.RequestBody,
		FilterWords: s.FilterWords,
		SaveRaw:     s.SaveRaw,
		ProxyOut:    s.ProxyOut,
		Methods:     append([]string(nil), s.Methods...),
	}
}

func (e *Engine) DumpMeta() EngineConfigDump {
	target := e.BaseURL()
	e.Config.RLock()
	defer e.Config.RUnlock()
	return EngineConfigDump{
		Target:     target,
		Wordlist:   e.Config.WordlistPath,
		OutputFile: e.Config.OutputFile,
		SmartAPI:   e.Config.SmartAPI,
	}
}
