package engine

import "time"

// Bloom Filter Configuration
const (
	DefaultBloomFilterSize = 10_000_000 // Expected number of items
	DefaultBloomFilterFP   = 0.001      // False positive rate (0.1%)
)

// Auto-Filter Thresholds
const (
	DefaultAutoFilterThreshold = 15 // Default number of identical responses before auto-filtering
)

// HTTP Client Configuration
const (
	DefaultHTTPTimeout = 5 * time.Second
	DefaultConnTimeout = 3 * time.Second
	DefaultReadTimeout = 5 * time.Second
	MaxBodySize        = 5 * 1024 * 1024 // 5MB max response body size
)

// Worker Configuration
const (
	DefaultWorkerCount  = 50
	DefaultJobQueueSize = DefaultWorkerCount * 10 // jobs channel buffer = workers * 10
	MinWorkerCount      = 1
	MinRateLimitBurst   = 10
)

// Calibration Settings
const (
	CalibrationRandomStringLen = 16
	CalibrationTestCount       = 10
	CalibrationTimeout         = 5 * time.Second
)

// Recursion Settings
const (
	DefaultMaxDepth          = 3
	RecursiveWildcardTestLen = 12
	RecursiveWildcardTimeout = 3 * time.Second
	DefaultMaxRedirects      = 5
)

// Auto-Throttle Settings
const (
	AutoThrottleInterval  = 10 // Check every N 429s
	MinThrottledWorkers   = 5  // Minimum workers when throttled
	ThrottleWorkerPercent = 50 // Reduce workers by 50%
	ThrottleDelayIncrease = 200 * time.Millisecond
	MaxThrottleDelay      = 5 * time.Second
)

// Output Settings
const (
	DefaultOutputFormat = "jsonl"
	ResultsChannelSize  = DefaultWorkerCount * 10 // results channel buffer = workers * 10
)

// Mutation Settings
const (
	DefaultMutations = ".bak,.old,.save,~,.swp"
)
